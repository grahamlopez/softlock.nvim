-- Drop this file into stdpath('config') .. '/plugin/softlock.lua'.
-- Requires Neovim >= 0.12.3 and GnuPG >= 2.2. No keys or GPG config needed.
-- Private state deliberately contains the passphrase; never put it in b:/g:.
if vim.g.loaded_softlock then return end
if vim.fn.has('nvim-0.12.3') == 0 then
  vim.notify('softlock.lua requires Neovim 0.12.3+', vim.log.levels.ERROR)
  return
end
vim.g.loaded_softlock = true

local api, uv = vim.api, vim.uv
local group = api.nvim_create_augroup('SoftLock', { clear = true })
---@class SoftLockState
---@field storage string Encrypted destination; the buffer uses its underlying name.
---@field locked boolean Locked states never permit writes.
---@field passphrase? string Present only while unlocked; dropped on unload.
---@field snapshot? table Last observed ciphertext stat for conflict detection.
---@field renaming? boolean Allows only the plugin's own buffer renames.
---@field empty? boolean Whether the last decoded/encoded text was empty.
---@field empty_tick? integer Changedtick associated with that empty text.

---@type table<integer, SoftLockState>
local states = {}
local max_bytes = 16 * 1024 * 1024
local no_shada_contents = "'0,<0,s0,:0,/0,@0,f0"
local shada_disabled = false
local read_buffer, write_buffer

local function fail(message) error('SoftLock: ' .. message, 0) end
local function path(name) return vim.fs.normalize(vim.fn.fnamemodify(name, ':p')) end
local function inner(name) return name:gsub('%.gpg$', '') end

local function harden(buf)
  shada_disabled = true
  vim.o.shada = no_shada_contents
  vim.o.shadafile = 'NONE'
  vim.bo[buf].swapfile = false
  vim.bo[buf].undofile = false
  vim.bo[buf].modeline = false
  vim.bo[buf].autoread = false
end

local function stat(name)
  local value, err, code = uv.fs_lstat(name)
  if not value and code ~= 'ENOENT' then fail('cannot inspect destination: ' .. tostring(err)) end
  if value and (value.type ~= 'file' or value.nlink ~= 1) then
    fail('only regular files with one hard link are supported (no symlinks)')
  end
  return value
end

local function same(a, b)
  if not a or not b then return a == b end
  return a.dev == b.dev and a.ino == b.ino and a.size == b.size
    and a.mtime.sec == b.mtime.sec and a.mtime.nsec == b.mtime.nsec
    and a.ctime.sec == b.ctime.sec and a.ctime.nsec == b.ctime.nsec
end

local function check_unchanged(name, expected)
  if not same(stat(name), expected) then
    fail('encrypted destination changed externally; refusing to overwrite it')
  end
end

local function read_file(name)
  local before = stat(name)
  if not before then fail('encrypted file does not exist') end
  if before.size > max_bytes * 2 then fail('encrypted file exceeds the size limit') end
  local fd, err = uv.fs_open(name, 'r', 0)
  if not fd then fail('cannot read encrypted file: ' .. tostring(err)) end
  local data, read_err = uv.fs_read(fd, before.size, 0)
  uv.fs_close(fd)
  if not data then fail('cannot read encrypted file: ' .. tostring(read_err)) end
  check_unchanged(name, before)
  return data, before
end

-- The first stdin line is consumed by --passphrase-fd; the rest is file data.
-- vim.system uses pipes, never a shell, filter file, argv secret, or env secret.
local function gpg_result(data, passphrase, decrypt)
  if vim.fn.executable('gpg') ~= 1 then fail('gpg is not installed or not on PATH') end
  -- GPG does not reliably create its home for this --no-keyring invocation.
  -- Initialize it ourselves rather than requiring the user to run another tool.
  local configured_home = vim.env.GNUPGHOME
  local home = path(configured_home and configured_home ~= '' and configured_home or vim.fn.expand('~/.gnupg'))
  if vim.fn.isdirectory(home) == 0 then
    local ok = pcall(vim.fn.mkdir, home, 'p', 448) -- 0700; leave existing modes alone.
    if not ok or vim.fn.isdirectory(home) == 0 then
      fail('cannot create GPG home directory: ' .. home)
    end
  end
  local args = {
    'gpg', '--no-options', '--homedir', home, '--batch', '--no-tty', '--no-keyring',
    '--pinentry-mode', 'loopback', '--no-symkey-cache', '--passphrase-fd', '0',
    '--output', '-',
  }
  if decrypt then
    vim.list_extend(args, { '--max-output', tostring(max_bytes), '--decrypt' })
  else
    vim.list_extend(args, { '--cipher-algo', 'AES256', '--compress-algo', 'none', '--symmetric' })
  end
  return vim.system(args, { stdin = passphrase .. '\n' .. data }):wait(60000)
end

local function crypt(data, passphrase, decrypt)
  local result = gpg_result(data, passphrase, decrypt)
  if result.code ~= 0 then
    -- Do not echo GPG's stderr: decrypted packet metadata may be sensitive.
    local message = decrypt and 'unlock failed (wrong passphrase, damaged file, or GPG error)'
      or 'GPG encryption failed; the previous file has not been replaced'
    fail(message .. ' (exit ' .. tostring(result.code) .. '; run :SoftLockCheck for diagnostics)')
  end
  return result.stdout
end

local function check_gpg()
  -- Only this synthetic input reaches GPG, so its stderr contains no document
  -- packet metadata or user passphrase. Never retry a real document to diagnose it.
  local sample, passphrase = 'softlock.lua diagnostic text\n', 'softlock.lua diagnostic passphrase'
  local ok, err = pcall(function()
    local encrypted = gpg_result(sample, passphrase, false)
    if encrypted.code ~= 0 then
      fail('GPG diagnostic encryption failed (exit ' .. tostring(encrypted.code) .. '):\n'
        .. (encrypted.stderr or '(no diagnostic output)'))
    end
    local decrypted = gpg_result(encrypted.stdout, passphrase, true)
    if decrypted.code ~= 0 then
      fail('GPG diagnostic decryption failed (exit ' .. tostring(decrypted.code) .. '):\n'
        .. (decrypted.stderr or '(no diagnostic output)'))
    end
    if decrypted.stdout ~= sample then fail('GPG diagnostic round trip returned unexpected data') end
  end)
  if ok then
    vim.notify('SoftLock: GPG encryption/decryption check passed (' .. vim.fn.exepath('gpg') .. ')')
  else
    vim.notify(tostring(err), vim.log.levels.ERROR)
  end
end

local function ask_passphrase(confirm)
  local function ask(prompt)
    local ok, value = pcall(vim.fn.inputsecret, prompt)
    vim.cmd('redraw')
    if not ok or value == '' then fail('cancelled') end
    if value:find('[\r\n%z]') then fail('passphrases cannot contain newline or NUL characters') end
    return value
  end
  local value = ask('Encryption passphrase: ')
  if confirm and ask('Confirm passphrase: ') ~= value then fail('passphrases do not match') end
  return value
end

local boms = {
  { '\255\254\0\0', 'ucs-4le' }, { '\0\0\254\255', 'ucs-4be' },
  { '\239\187\191', 'utf-8' }, { '\255\254', 'utf-16le' }, { '\254\255', 'utf-16be' },
}

local function convert(data, from, to)
  if from == to then return data end
  local ok, value = pcall(vim.iconv, data, from, to)
  if not ok or value == nil then fail('cannot convert text from ' .. from .. ' to ' .. to) end
  return value
end

local function valid_utf8(data)
  -- iconv's replacement behavior differs across systems; use a strict validator.
  local function continuation(x) return x and x >= 128 and x <= 191 end
  local i = 1
  while i <= #data do
    local a, b, c, d = data:byte(i, i + 3)
    if a < 128 then i = i + 1
    elseif a >= 194 and a <= 223 and continuation(b) then i = i + 2
    elseif a >= 224 and a <= 239 and continuation(b) and continuation(c)
      and (a ~= 224 or b >= 160) and (a ~= 237 or b <= 159) then i = i + 3
    elseif a >= 240 and a <= 244 and continuation(b) and continuation(c) and continuation(d)
      and (a ~= 240 or b >= 144) and (a ~= 244 or b <= 143) then i = i + 4
    else return false end
  end
  return true
end

local function decode(data, buf)
  if #data > max_bytes then fail('plaintext exceeds the 16 MiB size limit') end
  local encoding, bomb, text
  local candidates = vim.split(vim.o.fileencodings, ',', { trimempty = true })
  if #candidates == 0 then candidates = { 'utf-8' } end
  for _, candidate in ipairs(candidates) do
    if candidate == 'ucs-bom' then
      for _, entry in ipairs(boms) do
        if data:sub(1, #entry[1]) == entry[1] then
          encoding, bomb = entry[2], true
          local payload = data:sub(#entry[1] + 1)
          text = convert(payload, encoding, 'utf-8')
          if convert(text, 'utf-8', encoding) ~= payload then
            fail('unsupported or invalid text encoding')
          end
          break
        end
      end
    elseif candidate == 'utf-8' or candidate == 'utf8' then
      if valid_utf8(data) then encoding, text = 'utf-8', data end
    else
      local ok, converted = pcall(convert, data, candidate, 'utf-8')
      if ok and convert(converted, 'utf-8', candidate) == data then
        encoding, text = candidate, converted
      end
    end
    if text then break end
  end
  if not text or not valid_utf8(text) then fail('unsupported or invalid text encoding') end
  if text:find('\0', 1, true) then fail('binary files containing NUL are unsupported') end
  local formats = vim.split(vim.o.fileformats, ',', { trimempty = true })
  local format = vim.bo[buf].fileformat
  if #formats > 0 then
    local function allowed(name) return vim.list_contains(formats, name) end
    local _, newlines = text:gsub('\n', '')
    if newlines > 0 then
      -- Like Vim: dos only when every NL follows a CR, unless unix is not allowed.
      local _, crlfs = text:gsub('\r\n', '')
      if allowed('dos') and (crlfs == newlines or not allowed('unix')) then format = 'dos'
      elseif allowed('unix') then format = 'unix'
      else format = formats[1] end
    elseif text:find('\r', 1, true) and allowed('mac') then format = 'mac'
    else format = formats[1] end
  end
  local separator = format == 'mac' and '\r' or '\n'
  local eol = text:sub(-#separator) == separator and #text > 0
  local lines = vim.split(text, separator, { plain = true })
  if eol then table.remove(lines) end
  if format == 'dos' then
    for i, line in ipairs(lines) do
      -- Strip CR only when followed by LF, including the last terminated line.
      if i < #lines or eol then lines[i] = line:gsub('\r$', '') end
    end
  end
  if #lines == 0 then lines = { '' } end
  return lines, encoding, format, not not bomb, eol, text == ''
end

local function encode(buf)
  local bo = vim.bo[buf]
  if bo.binary then fail('binary mode is unsupported') end
  local separator = ({ unix = '\n', dos = '\r\n', mac = '\r' })[bo.fileformat]
  local lines = api.nvim_buf_get_lines(buf, 0, -1, true)
  for _, line in ipairs(lines) do
    if line:find('\n', 1, true) or line:find('\0', 1, true) then fail('binary buffer contents are unsupported') end
  end
  local text = table.concat(lines, separator)
  local state = states[buf]
  local empty_buffer = #lines == 1 and lines[1] == ''
  local preserve_empty = empty_buffer and (
    (state and not state.locked and state.empty and state.empty_tick == api.nvim_buf_get_changedtick(buf))
    or ((not state or state.locked)
      and api.nvim_buf_call(buf, function() return vim.fn.wordcount().bytes end) == 0))
  if (bo.endofline or bo.fixendofline) and not preserve_empty then text = text .. separator end
  local encoding = bo.fileencoding ~= '' and bo.fileencoding or 'utf-8'
  local data = convert(text, 'utf-8', encoding)
  if convert(data, encoding, 'utf-8') ~= text then fail('text cannot be represented in the selected encoding') end
  if bo.bomb then
    local prefix
    for _, entry in ipairs(boms) do if entry[2] == encoding then prefix = entry[1] end end
    if not prefix then fail('BOM is unsupported for the selected encoding') end
    data = prefix .. data
  end
  if #data > max_bytes then fail('plaintext exceeds the 16 MiB size limit') end
  return data, text == ''
end

local function atomic_write(name, data, expected)
  check_unchanged(name, expected)
  local random = assert(uv.random(12))
  local suffix = (random:gsub('.', function(c) return ('%02x'):format(c:byte()) end))
  local temporary = vim.fs.joinpath(vim.fs.dirname(name), '.softlock-' .. suffix)
  local fd, err = uv.fs_open(temporary, 'wx', 384) -- 0600, ciphertext only
  if not fd then fail('cannot create encrypted temporary file: ' .. tostring(err)) end
  local ok, write_err = pcall(function()
    local offset = 0
    while offset < #data do
      local count, why = uv.fs_write(fd, data:sub(offset + 1), offset)
      if not count or count == 0 then fail('cannot write ciphertext: ' .. tostring(why)) end
      offset = offset + count
    end
    assert(uv.fs_fsync(fd))
    assert(uv.fs_close(fd))
    fd = nil
    check_unchanged(name, expected)
    if expected then
      assert(uv.fs_rename(temporary, name))
    else
      -- Atomic no-clobber publication: another process cannot win an exists check.
      assert(uv.fs_link(temporary, name))
    end
  end)
  if fd then uv.fs_close(fd) end
  if not ok then uv.fs_unlink(temporary); fail('encrypted save failed: ' .. tostring(write_err)) end
  -- link/rename is the commit point. Cleanup failure must not undo activation
  -- or report a failed save after the destination has already been published.
  local cleanup_failed = not expected and not uv.fs_unlink(temporary)
  if cleanup_failed then
    vim.notify('SoftLock: saved, but could not remove ' .. temporary
      .. '; remove this ciphertext temporary file and reopen before saving again', vim.log.levels.WARN)
  end
  -- Persist the directory entry too. The new ciphertext is already published,
  -- so a failure here only warns rather than reporting the save as failed.
  local dir = uv.fs_open(vim.fs.dirname(name), 'r', 0)
  local synced = dir and uv.fs_fsync(dir)
  if dir then uv.fs_close(dir) end
  if not synced then
    vim.notify('SoftLock: saved, but could not sync the destination directory', vim.log.levels.WARN)
  end
  -- A failed unlink leaves our own second hard link. Retain the committed
  -- snapshot, but keep ordinary stat() strict so further writes are refused.
  if cleanup_failed then return assert(uv.fs_lstat(name)) end
  return stat(name)
end

local function collision(buf, logical, storage)
  for _, other in ipairs(api.nvim_list_bufs()) do
    if other ~= buf and api.nvim_buf_is_valid(other) then
      local name = api.nvim_buf_get_name(other)
      if name ~= '' and path(name) == logical then fail('underlying filename already belongs to buffer ' .. other) end
      if states[other] and states[other].storage == storage then fail('encrypted file already belongs to buffer ' .. other) end
    end
  end
end

local function rename(buf, state, name)
  state.renaming = true
  local ok, err = pcall(api.nvim_buf_set_name, buf, name)
  state.renaming = false
  if not ok then fail('cannot assign underlying filename: ' .. tostring(err)) end
end

local function guard(buf, storage)
  if states[buf] then return states[buf] end
  local state = { storage = storage, locked = true }
  states[buf] = state
  harden(buf)
  vim.b[buf].softlock_path = storage
  local function on(event, callback)
    api.nvim_create_autocmd(event, { group = group, buffer = buf, callback = callback })
  end
  on('BufWriteCmd', function(event) write_buffer(buf, event.match) end)
  on({ 'FileWriteCmd', 'FileAppendCmd', 'FilterWritePre', 'FilterReadPre' }, function()
    fail('alternate/partial writes, appends, and temporary-file filters are disabled for encrypted buffers')
  end)
  on('BufReadCmd', function(event)
    -- The global *.gpg handler owns reads under the encrypted filename.
    if not event.match:match('%.gpg$') then read_buffer(buf, state) end
  end)
  on('BufFilePre', function()
    if not state.renaming then fail('renaming encrypted buffers is disabled') end
  end)
  on('FileChangedShell', function() vim.v.fcs_choice = '' end)
  on('BufUnload', function() state.passphrase, state.locked = nil, true end)
  on('BufWipeout', function() if not state.renaming then states[buf] = nil end end)
  return state
end

read_buffer = function(buf, state)
  harden(buf)
  state.passphrase, state.locked = nil, true
  local logical = inner(state.storage)
  collision(buf, logical, state.storage)
  if not stat(state.storage) then
    if state.snapshot then fail('encrypted file was removed externally') end
    api.nvim_exec_autocmds('BufNewFile', { pattern = logical, modeline = false })
    harden(buf)
    return
  end
  local ciphertext, snapshot = read_file(state.storage)
  local passphrase = ask_passphrase(false)
  local plaintext = crypt(ciphertext, passphrase, true)
  -- Decode before renaming or firing hooks so a failure leaves the buffer untouched.
  local lines, encoding, format, bomb, eol, empty = decode(plaintext, buf)
  rename(buf, state, logical)
  api.nvim_exec_autocmds('BufReadPre', { pattern = logical, modeline = false })
  harden(buf)
  local bo = vim.bo[buf]
  bo.modifiable = true
  local levels = bo.undolevels
  bo.undolevels = -1
  api.nvim_buf_set_lines(buf, 0, -1, true, lines)
  bo.undolevels = levels
  bo.fileencoding, bo.fileformat, bo.bomb, bo.endofline = encoding, format, bomb, eol
  bo.fixendofline = false
  state.snapshot, state.passphrase, state.locked = snapshot, passphrase, false
  state.empty, state.empty_tick = empty, api.nvim_buf_get_changedtick(buf)
  bo.modified = false
  -- The buffer has its normal name AND decoded contents before detection runs.
  api.nvim_exec_autocmds('BufReadPost', { pattern = logical, modeline = false })
  harden(buf)
end

write_buffer = function(buf, destination, replacement_passphrase)
  local state = states[buf]
  if not state or state.locked or not state.passphrase then fail('buffer is locked; use :SoftLockSetup or :SoftLockUnlock') end
  if destination and destination ~= '' and path(destination) ~= path(api.nvim_buf_get_name(buf)) then
    fail('alternate destinations are disabled; use ordinary :w')
  end
  if vim.bo[buf].readonly then fail('buffer is readonly') end
  if vim.v.cmdarg ~= '' then fail('++ write modifiers are unsupported') end
  harden(buf)
  api.nvim_exec_autocmds('BufWritePre', { pattern = api.nvim_buf_get_name(buf), modeline = false })
  harden(buf)
  local tick = api.nvim_buf_get_changedtick(buf)
  local plaintext, empty = encode(buf)
  local ciphertext = crypt(plaintext, replacement_passphrase or state.passphrase, false)
  state.snapshot = atomic_write(state.storage, ciphertext, state.snapshot)
  state.empty, state.empty_tick = empty, tick
  if replacement_passphrase then state.passphrase = replacement_passphrase end
  if api.nvim_buf_get_changedtick(buf) == tick then vim.bo[buf].modified = false end
  api.nvim_exec_autocmds('BufWritePost', { pattern = api.nvim_buf_get_name(buf), modeline = false })
  harden(buf)
  vim.notify('Encrypted: ' .. state.storage)
end

local function setup(options)
  local buf = api.nvim_get_current_buf()
  local previous = states[buf]
  if previous and not previous.locked then fail('already encrypted; use :SoftLockChangePassphrase') end
  if vim.bo[buf].buftype ~= '' then fail('setup requires a normal text buffer') end
  local name = api.nvim_buf_get_name(buf)
  local destination = options.fargs[1] or ''
  if destination == '' then
    if previous then destination = previous.storage
    else
      destination = vim.fn.input({ prompt = 'Encrypted destination: ', default = name ~= '' and name .. '.gpg' or '', completion = 'file' })
    end
  end
  if destination == '' then fail('cancelled') end
  destination = path(destination)
  if not destination:match('%.gpg$') or inner(destination) == destination or vim.fs.basename(destination) == '.gpg' then
    fail('destination must have an underlying filename followed by .gpg')
  end
  if stat(destination) then fail('setup will not overwrite an existing file; use :SoftLockUnlock to open it') end
  local logical = inner(destination)
  collision(buf, logical, destination)
  harden(buf) -- Remains in force even if setup is cancelled or fails.
  local passphrase = ask_passphrase(true)
  local plaintext, empty = encode(buf)
  local ciphertext = crypt(plaintext, passphrase, false)
  local snapshot = atomic_write(destination, ciphertext, nil)
  local state = previous or guard(buf, destination)
  local renamed, rename_err = pcall(rename, buf, state, logical)
  if not renamed then
    state.locked, state.passphrase = true, nil
    fail('ciphertext was saved to ' .. destination .. ', but buffer activation failed: ' .. tostring(rename_err))
  end
  state.storage, state.snapshot, state.passphrase, state.locked = destination, snapshot, passphrase, false
  state.empty, state.empty_tick = empty, api.nvim_buf_get_changedtick(buf)
  vim.b[buf].softlock_path = destination
  vim.bo[buf].modified = false
  -- Preserve an existing buffer's ftplugin state; initialize a new buffer normally.
  if vim.bo[buf].filetype == '' then
    api.nvim_exec_autocmds('BufReadPost', { pattern = logical, modeline = false })
  end
  harden(buf)
  vim.notify('Encrypted: ' .. destination .. ' (previous plaintext files are unchanged)')
end

api.nvim_create_autocmd('BufNew', {
  group = group, pattern = '*.gpg',
  callback = function(event) guard(event.buf, path(event.file)) end,
})
api.nvim_create_autocmd('BufReadCmd', {
  group = group, pattern = '*.gpg',
  callback = function(event)
    local state = guard(event.buf, path(event.file))
    read_buffer(event.buf, state)
  end,
})
api.nvim_create_autocmd('OptionSet', {
  group = group, pattern = { 'swapfile', 'undofile', 'modeline', 'autoread', 'shada', 'shadafile' },
  callback = function(event)
    if event.match == 'shadafile' or event.match == 'shada' then
      if shada_disabled then vim.o.shada, vim.o.shadafile = no_shada_contents, 'NONE' end
    else
      local buf = api.nvim_get_current_buf()
      if states[buf] then harden(buf) end
    end
  end,
})

api.nvim_create_user_command('SoftLockSetup', setup, { nargs = '?', complete = 'file', desc = 'Encrypt the current buffer to a new .gpg file' })
api.nvim_create_user_command('SoftLockCheck', check_gpg, { desc = 'Diagnose GPG using dummy text, without accessing the current buffer' })
api.nvim_create_user_command('SoftLockUnlock', function()
  local buf = api.nvim_get_current_buf()
  local state = states[buf]
  if not state then fail('not an encrypted buffer') end
  if not state.locked then fail('buffer is already unlocked') end
  if vim.bo[buf].modified then fail('buffer has changes; discard them explicitly with :edit! before unlocking') end
  read_buffer(buf, state)
end, { desc = 'Retry unlocking an encrypted file' })
api.nvim_create_user_command('SoftLockChangePassphrase', function()
  local buf = api.nvim_get_current_buf()
  if not states[buf] or states[buf].locked then fail('unlock an encrypted buffer first') end
  write_buffer(buf, nil, ask_passphrase(true))
end, { desc = 'Change the passphrase and save the encrypted buffer' })
