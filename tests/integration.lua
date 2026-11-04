local api, uv = vim.api, vim.uv
local root = assert(vim.env.SOFTENCRYPT_TEST_ROOT)
local source = assert(vim.env.SOFTENCRYPT_PLUGIN)
vim.o.shadafile = '' -- Test disabling a real ShaDa destination, including :wshada.
vim.o.shada = "!,'100,<50,s10,h"
vim.o.swapfile = true
vim.o.undofile = true
vim.cmd('filetype plugin indent on')
vim.cmd('syntax on')
vim.cmd('source ' .. vim.fn.fnameescape(source))

local answers, prompts = {}, 0
vim.fn.inputsecret = function()
  prompts = prompts + 1
  assert(#answers > 0, 'unexpected passphrase prompt')
  return table.remove(answers, 1)
end
vim.fn.input = function() return root .. '/converted.md.gpg' end
local function input(...)
  assert(#answers == 0, 'unconsumed prompt responses')
  answers = { ... }
end
local function equal(actual, expected, label)
  assert(vim.deep_equal(actual, expected), (label or 'mismatch') .. '\nexpected: '
    .. vim.inspect(expected) .. '\nactual: ' .. vim.inspect(actual))
end
local function edit(name) vim.cmd.edit(vim.fn.fnameescape(name)) end
local function command_fails(command, pattern)
  local ok, err = pcall(vim.cmd, command)
  assert(not ok, 'unexpected success: ' .. command)
  if pattern then assert(tostring(err):find(pattern, 1, true), tostring(err)) end
end
local function read(name)
  local fd = assert(uv.fs_open(name, 'r', 0))
  local data = assert(uv.fs_read(fd, assert(uv.fs_fstat(fd)).size, 0))
  assert(uv.fs_close(fd))
  return data
end
local function write(name, data)
  local fd = assert(uv.fs_open(name, 'w', 384))
  assert(uv.fs_write(fd, data, 0))
  assert(uv.fs_close(fd))
end
local function decrypted(name, passphrase)
  local r = vim.system({ 'gpg', '--no-options', '--batch', '--no-tty', '--no-keyring',
    '--pinentry-mode', 'loopback', '--no-symkey-cache', '--passphrase-fd', '0',
    '--decrypt', name }, { stdin = passphrase .. '\n' }):wait()
  assert(r.code == 0, r.stderr)
  return r.stdout
end
local function fixture(name, contents, passphrase)
  local r = vim.system({ 'gpg', '--no-options', '--batch', '--no-tty', '--no-keyring',
    '--pinentry-mode', 'loopback', '--no-symkey-cache', '--passphrase-fd', '0',
    '--symmetric', '--output', '-' }, { stdin = passphrase .. '\n' .. contents }):wait()
  assert(r.code == 0, r.stderr)
  write(name, r.stdout)
end
local function wipe() vim.cmd('bwipeout!') end
local completed = 0
local function test(name, fn)
  fn()
  assert(#answers == 0, name .. ': unconsumed responses')
  completed = completed + 1
  print('PASS ' .. name)
end

-- Exercise decoding and publication independently of a working GPG agent.
-- This transport returns its input unchanged; it is never used by real-GPG tests.
local function with_dummy_gpg(fn)
  local system, executable = vim.system, vim.fn.executable
  vim.fn.executable = function(name) return name == 'gpg' and 1 or executable(name) end
  vim.system = function(_, options)
    local data = options.stdin:match('^[^\n]*\n(.*)$')
    return { wait = function() return { code = 0, stdout = data } end }
  end
  local ok, err = pcall(fn)
  vim.system, vim.fn.executable = system, executable
  assert(ok, err)
end

with_dummy_gpg(function()
  test('malformed BOM text stays locked instead of silently replacing bytes', function()
    local name = root .. '/malformed.txt.gpg'
    local contents = '\255\254a\0b' -- UTF-16LE BOM followed by an incomplete code unit.
    write(name, contents)
    input('dummy secret')
    command_fails('edit ' .. name, 'invalid text encoding')
    equal(api.nvim_buf_get_name(0), name)
    equal(api.nvim_buf_get_lines(0, 0, -1, true), { '' })
    command_fails('write!', 'locked')
    equal(read(name), contents)
    wipe()
  end)

  test('valid BOM text still round trips', function()
    for i, contents in ipairs({ '\255\254a\0\n\0', '\239\187\191hello\n' }) do
      local name = root .. '/valid-bom-' .. i .. '.txt.gpg'
      write(name, contents)
      input('dummy secret')
      edit(name)
      vim.cmd('write')
      equal(read(name), contents)
      wipe()
    end
  end)

  test('failed publication preserves pending edits and cleans temporary files', function()
    vim.cmd('enew')
    api.nvim_buf_set_lines(0, 0, -1, true, { 'pending publication' })
    local destination = root .. '/unpublished.txt.gpg'
    input('dummy secret', 'dummy secret')
    local link = uv.fs_link
    uv.fs_link = function() return nil, 'injected link failure' end
    local ok, err = pcall(vim.cmd, 'EncryptSetup ' .. destination)
    uv.fs_link = link
    assert(not ok and tostring(err):find('encrypted save failed', 1, true), tostring(err))
    assert(not uv.fs_stat(destination))
    assert(vim.bo.modified)
    local scanner = assert(uv.fs_scandir(root))
    while true do
      local name = uv.fs_scandir_next(scanner)
      if not name then break end
      assert(not name:match('^%.softencrypt%-'), 'temporary file was not cleaned up')
    end
    wipe()
  end)

  test('cleanup failure after publication commits state and warns', function()
    vim.cmd('enew')
    api.nvim_buf_set_lines(0, 0, -1, true, { 'published contents' })
    local destination = root .. '/published.txt.gpg'
    input('dummy secret', 'dummy secret')
    local unlink, notify = uv.fs_unlink, vim.notify
    local temporary, warnings = nil, {}
    uv.fs_unlink = function(name)
      if vim.fs.basename(name):match('^%.softencrypt%-') then
        temporary = name
        return nil, 'injected cleanup failure'
      end
      return unlink(name)
    end
    vim.notify = function(message, level)
      if level == vim.log.levels.WARN then warnings[#warnings + 1] = message end
    end
    local ok, err = pcall(vim.cmd, 'EncryptSetup ' .. destination)
    uv.fs_unlink, vim.notify = unlink, notify
    assert(ok, err)
    equal(read(destination), 'published contents\n')
    equal(api.nvim_buf_get_name(0), root .. '/published.txt')
    equal(vim.b.softencrypt_path, destination)
    assert(not vim.bo.modified)
    assert(temporary and uv.fs_stat(temporary))
    assert(#warnings == 1 and warnings[1]:find(temporary, 1, true))
    api.nvim_buf_set_lines(0, 0, -1, true, { 'another edit' })
    command_fails('write', 'one hard link')
    assert(vim.bo.modified)
    assert(unlink(temporary))
    wipe()
    input('dummy secret')
    edit(destination)
    vim.cmd('write')
    equal(read(destination), 'published contents\n')
    wipe()
  end)
end)

if vim.env.SOFTENCRYPT_TEST_REGRESSIONS_ONLY == '1' then
  print(('ALL %d REGRESSION GROUPS PASSED (dummy GPG transport)'):format(completed))
  vim.cmd('qa!')
end

test('new buffer, detection, setup, encrypted write, and reload', function()
  edit(root .. '/notes.md.gpg')
  equal(vim.bo.filetype, 'markdown', 'new buffer filetype')
  command_fails('write', 'locked')
  assert(not uv.fs_stat(root .. '/notes.md.gpg'))
  api.nvim_buf_set_lines(0, 0, -1, true, { '# MEMORY_ONLY_SENTINEL', 'hello' })
  input('test secret', 'test secret')
  vim.cmd('EncryptSetup')
  equal(api.nvim_buf_get_name(0), root .. '/notes.md')
  equal(vim.b.softencrypt_path, root .. '/notes.md.gpg')
  equal(decrypted(vim.b.softencrypt_path, 'test secret'), '# MEMORY_ONLY_SENTINEL\nhello\n')
  assert(not uv.fs_stat(root .. '/notes.md'))
  equal(bit.band(uv.fs_stat(vim.b.softencrypt_path).mode, 511), 384, 'permissions')
  assert(not vim.bo.swapfile and not vim.bo.undofile)
  equal(vim.o.shadafile, 'NONE')
  api.nvim_buf_set_lines(0, 1, 2, true, { 'edited' })
  local count = prompts
  vim.cmd('write')
  equal(prompts, count, 'save must not prompt')
  assert(not vim.bo.modified)
  equal(decrypted(vim.b.softencrypt_path, 'test secret'), '# MEMORY_ONLY_SENTINEL\nedited\n')
  wipe()
  count = prompts
  input('test secret')
  edit(root .. '/notes.md.gpg')
  equal(prompts, count + 1, 'open prompts exactly once')
  equal(vim.bo.filetype, 'markdown')
  assert(vim.bo.syntax == 'markdown' or vim.b.ts_highlight, 'normal Markdown highlighting was not initialized')
  assert(vim.b.did_ftplugin)
  equal(api.nvim_buf_get_lines(0, 0, -1, true), { '# MEMORY_ONLY_SENTINEL', 'edited' })
  wipe()
end)

test('existing plaintext source and unsaved changes', function()
  write(root .. '/source.md', 'original source\n')
  edit(root .. '/source.md')
  api.nvim_buf_set_lines(0, 0, -1, true, { 'unsaved encrypted content' })
  local old_ftplugin = vim.b.did_ftplugin
  input('conversion secret', 'conversion secret')
  vim.cmd('EncryptSetup')
  equal(read(root .. '/source.md'), 'original source\n')
  equal(decrypted(root .. '/converted.md.gpg', 'conversion secret'), 'unsaved encrypted content\n')
  equal(vim.b.did_ftplugin, old_ftplugin)
  api.nvim_buf_set_lines(0, 0, -1, true, { 'later encrypted content' })
  vim.cmd('write')
  equal(read(root .. '/source.md'), 'original source\n')
  wipe()
end)

test('wrong passphrase stays protected and can retry', function()
  input('wrong secret')
  command_fails('edit ' .. root .. '/notes.md.gpg', 'unlock failed')
  equal(api.nvim_buf_get_lines(0, 0, -1, true), { '' })
  command_fails('write!', 'locked')
  input('test secret')
  vim.cmd('EncryptUnlock')
  equal(vim.bo.filetype, 'markdown')
  wipe()
end)

test('alternate write routes and rename are blocked', function()
  input('test secret')
  edit(root .. '/notes.md.gpg')
  command_fails('write ' .. root .. '/leak.txt')
  command_fails('1write ' .. root .. '/range.txt')
  command_fails('write >> ' .. root .. '/append.txt')
  command_fails('saveas ' .. root .. '/saveas.txt')
  command_fails('file ' .. root .. '/renamed.txt')
  -- Pipe-only commands do not trigger filter events and create no Nvim temp file.
  vim.cmd('%!cat')
  vim.cmd('set shelltemp')
  command_fails('write !cat')
  command_fails('%!cat')
  vim.cmd('set noshelltemp')
  for _, name in ipairs({ 'leak.txt', 'range.txt', 'append.txt', 'saveas.txt', 'renamed.txt' }) do
    assert(not uv.fs_stat(root .. '/' .. name), name .. ' was created')
  end
  equal(api.nvim_buf_get_name(0), root .. '/notes.md')
  vim.cmd('setlocal swapfile undofile')
  assert(not vim.bo.swapfile and not vim.bo.undofile)
  vim.cmd('set shadafile=' .. root .. '/leaked.shada')
  equal(vim.o.shadafile, 'NONE')
  vim.fn.setreg('a', 'MEMORY_ONLY_SENTINEL')
  vim.fn.histadd('search', 'MEMORY_ONLY_SENTINEL')
  vim.cmd('wshada! ' .. root .. '/leaked.shada')
  -- Explicit filenames override shadafile=NONE on 0.12.5. Zero content limits
  -- prevent registers/history/globals from being serialized even in that case.
  assert(not read(root .. '/leaked.shada'):find('MEMORY_ONLY_SENTINEL', 1, true))
  wipe()
end)

test('external modifications are not overwritten, even with bang', function()
  input('test secret')
  edit(root .. '/notes.md.gpg')
  local original = read(vim.b.softencrypt_path)
  write(vim.b.softencrypt_path, original .. 'external')
  api.nvim_buf_set_lines(0, 0, 1, true, { 'changed in memory' })
  command_fails('write!', 'changed externally')
  equal(read(vim.b.softencrypt_path), original .. 'external')
  assert(vim.bo.modified)
  write(vim.b.softencrypt_path, original)
  wipe()
end)

test('setup mismatch and existing destination preserve buffer and target', function()
  edit(root .. '/cancel.txt')
  api.nvim_buf_set_lines(0, 0, -1, true, { 'keep me' })
  local name = api.nvim_buf_get_name(0)
  input('a', 'b')
  command_fails('EncryptSetup ' .. root .. '/cancel.txt.gpg', 'do not match')
  equal(api.nvim_buf_get_name(0), name)
  assert(vim.bo.modified)
  assert(not uv.fs_stat(root .. '/cancel.txt.gpg'))
  command_fails('EncryptSetup ' .. root .. '/notes.md.gpg', 'will not overwrite')
  equal(api.nvim_buf_get_lines(0, 0, -1, true), { 'keep me' })
  wipe()
end)

test('passphrase change commits only after successful write', function()
  input('test secret')
  edit(root .. '/notes.md.gpg')
  input('replacement secret', 'replacement secret')
  vim.cmd('EncryptChangePassphrase')
  equal(decrypted(vim.b.softencrypt_path, 'replacement secret'), '# MEMORY_ONLY_SENTINEL\nedited\n')
  api.nvim_buf_set_lines(0, 0, -1, true, { 'new contents' })
  vim.cmd('write')
  equal(decrypted(vim.b.softencrypt_path, 'replacement secret'), 'new contents\n')
  wipe()
end)

test('custom filename and content detection run after decryption', function()
  api.nvim_create_autocmd('BufReadPre', { pattern = '*.special', callback = function()
    equal(api.nvim_buf_get_name(0), root .. '/custom.special')
    vim.b.custom_pre_read = true
  end })
  api.nvim_create_autocmd('BufReadPost', { pattern = '*.special', callback = function()
    equal(api.nvim_buf_get_lines(0, 0, 1, true)[1], 'custom contents')
    vim.bo.filetype = 'lua'
    vim.b.custom_detected = true
  end })
  fixture(root .. '/custom.special.gpg', 'custom contents\n', 'custom secret')
  input('custom secret')
  edit(root .. '/custom.special.gpg')
  equal(vim.bo.filetype, 'lua')
  assert(vim.b.custom_pre_read and vim.b.custom_detected and vim.b.did_ftplugin)
  wipe()
  fixture(root .. '/script.gpg', '#!/bin/sh\necho hello\n', 'script secret')
  input('script secret')
  edit(root .. '/script.gpg')
  equal(vim.bo.filetype, 'sh')
  wipe()
end)

test('GPG and disk write failures preserve ciphertext and passphrase', function()
  input('replacement secret')
  edit(root .. '/notes.md.gpg')
  local original = read(vim.b.softencrypt_path)
  api.nvim_buf_set_lines(0, 0, -1, true, { 'pending changes' })
  local original_system = vim.system
  vim.system = function() return { wait = function() return { code = 1, stderr = 'injected failure' } end } end
  command_fails('write', 'GPG encryption failed')
  vim.system = original_system
  equal(read(vim.b.softencrypt_path), original)
  assert(vim.bo.modified)
  local original_write = uv.fs_write
  uv.fs_write = function() return nil, 'injected disk full' end
  input('not committed', 'not committed')
  command_fails('EncryptChangePassphrase', 'encrypted save failed')
  uv.fs_write = original_write
  equal(read(vim.b.softencrypt_path), original)
  assert(vim.bo.modified)
  vim.cmd('write')
  equal(decrypted(vim.b.softencrypt_path, 'replacement secret'), 'pending changes\n')
  local scanner = assert(uv.fs_scandir(root))
  while true do
    local name = uv.fs_scandir_next(scanner)
    if not name then break end
    assert(not name:match('^%.softencrypt%-'), 'ciphertext temporary file was not cleaned up')
  end
  wipe()
end)

test('unloading forgets the passphrase; write hooks and update work', function()
  input('replacement secret')
  edit(root .. '/notes.md.gpg')
  local buf = api.nvim_get_current_buf()
  local pre, post = 0, 0
  api.nvim_create_autocmd('BufWritePre', { buffer = buf, callback = function() pre = pre + 1 end })
  api.nvim_create_autocmd('BufWritePost', { buffer = buf, callback = function() post = post + 1 end })
  assert(not vim.bo.modified, 'reopened buffer unexpectedly modified')
  vim.cmd('update')
  equal(pre, 1) -- Neovim invokes BufWriteCmd even for unmodified :update.
  api.nvim_buf_set_lines(0, 0, -1, true, { 'updated' })
  vim.cmd('update')
  equal(pre, 2)
  equal(post, 2)
  vim.cmd('bdelete')
  input('replacement secret')
  vim.cmd('buffer ' .. buf)
  equal(api.nvim_buf_get_lines(0, 0, -1, true), { 'updated' })
  wipe()
end)

test('unnamed setup supports escaped spaces and shell characters in names', function()
  vim.cmd('enew')
  api.nvim_buf_set_lines(0, 0, -1, true, { 'MEMORY_ONLY_SENTINEL safe argv' })
  local destination = root .. '/space ; dollar$ file.txt.gpg'
  input('name secret', 'name secret')
  vim.cmd('EncryptSetup ' .. vim.fn.fnameescape(destination))
  equal(vim.b.softencrypt_path, destination)
  equal(decrypted(destination, 'name secret'), 'MEMORY_ONLY_SENTINEL safe argv\n')
  wipe()
end)

test('conversion preserves an empty file versus a single newline', function()
  for i, contents in ipairs({ '', '\n' }) do
    local name = root .. '/convert-empty-' .. i .. '.txt'
    write(name, contents)
    edit(name)
    input('empty secret', 'empty secret')
    vim.cmd('EncryptSetup ' .. name .. '.gpg')
    equal(decrypted(name .. '.gpg', 'empty secret'), contents)
    wipe()
  end
end)

test('encoding, BOM, line endings, and absent final newline round trip', function()
  local variants = {
    { 'dos', 'first\r\nsecond\r\n' },
    { 'no-eol', 'first\nsecond' },
    { 'empty', '' },
    { 'utf8-bom', '\239\187\191hello\n' },
    { 'latin1', 'caf\233\n' },
    { 'utf16', '\255\254h\0i\0\r\0\n\0' },
    { 'one-newline', '\n' },
    { 'mixed-eol', 'first\r\nsecond\nthird\r\n' },
  }
  for _, variant in ipairs(variants) do
    local name = root .. '/' .. variant[1] .. '.txt.gpg'
    fixture(name, variant[2], 'format secret')
    input('format secret')
    edit(name)
    vim.cmd('write')
    equal(decrypted(name, 'format secret'), variant[2], variant[1])
    wipe()
  end
end)

test('mixed line endings open as unix with visible CRs', function()
  fixture(root .. '/mixed.txt.gpg', 'a\r\nb\n', 'mixed secret')
  input('mixed secret')
  edit(root .. '/mixed.txt.gpg')
  equal(vim.bo.fileformat, 'unix')
  equal(api.nvim_buf_get_lines(0, 0, -1, true), { 'a\r', 'b' })
  wipe()
end)

test('decode failure leaves the buffer locked under its encrypted name', function()
  fixture(root .. '/binary.txt.gpg', 'a\0b\n', 'binary secret')
  input('binary secret')
  command_fails('edit ' .. root .. '/binary.txt.gpg', 'NUL')
  equal(api.nvim_buf_get_name(0), root .. '/binary.txt.gpg')
  equal(vim.bo.filetype, '')
  command_fails('write!', 'locked')
  wipe()
end)

test('hidden encrypted buffers save correctly via :wall', function()
  input('replacement secret')
  edit(root .. '/notes.md.gpg')
  local buf = api.nvim_get_current_buf()
  vim.bo.bufhidden = 'hide'
  api.nvim_buf_set_lines(buf, 0, -1, true, { 'hidden save' })
  vim.cmd('enew')
  api.nvim_buf_set_lines(0, 0, -1, true, { 'scratch' })
  vim.bo.buftype = 'nofile'
  vim.cmd('wall')
  assert(not vim.bo[buf].modified)
  equal(decrypted(root .. '/notes.md.gpg', 'replacement secret'), 'hidden save\n')
  vim.cmd('bwipeout! ' .. buf)
  wipe()
end)

test('symlinks, hard links, and filename collisions are rejected', function()
  fixture(root .. '/link-target.txt.gpg', 'link target\n', 'link secret')
  assert(uv.fs_symlink(root .. '/link-target.txt.gpg', root .. '/linked.md.gpg'))
  command_fails('edit ' .. root .. '/linked.md.gpg', 'no symlinks')
  wipe()
  assert(uv.fs_link(root .. '/notes.md.gpg', root .. '/hard.md.gpg'))
  command_fails('edit ' .. root .. '/hard.md.gpg', 'no symlinks')
  wipe()
  assert(uv.fs_unlink(root .. '/hard.md.gpg'))
  edit(root .. '/notes.md')
  vim.cmd('enew')
  command_fails('edit ' .. root .. '/notes.md.gpg', 'already belongs')
  wipe()
end)

print(('ALL %d TEST GROUPS PASSED'):format(completed))
vim.cmd('qa!')
