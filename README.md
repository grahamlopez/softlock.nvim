# softencrypt

A single-file Neovim plugin for passphrase-encrypted text files using GnuPG.
Experimental; not intended for critical data. Requires Neovim 0.12.3+, GnuPG 2.2+,
and Linux. No keys or GPG configuration are needed under normal defaults.

**Opening an encrypted buffer disables ShaDa persistence for the rest of the
Neovim session, including ordinary buffers.** Swap, persistent undo, modelines,
and automatic reloading are disabled for encrypted buffers.

## Install

With lazy.nvim (replace `OWNER`):

```lua
{ 'OWNER/softencrypt', lazy = false }
```

Other plugin managers work too; load the repository at startup. No `setup()` call
is needed.

Or copy [plugin/softencrypt.lua](plugin/softencrypt.lua) to
`~/.config/nvim/plugin/softencrypt.lua` and restart Neovim. For other config
locations, use `stdpath('config') .. '/plugin/'`. Remove any previous copy of
`plugin/encrypt.lua` before installing.

## Usage

Create an encrypted file:

```vim
:edit notes.md.gpg
:EncryptSetup
```

Enter and confirm a passphrase. Setup saves immediately. Opening an existing
`.gpg` file prompts once; normal `:write`, `:update`, `:write!`, and `:wq` then save
ciphertext without prompting again.

Convert the current buffer, including unsaved edits:

```vim
:EncryptSetup
" Prompts for a destination, suggesting the current filename plus .gpg.
:EncryptSetup another-name.md.gpg
" Uses an explicit destination.
```

Setup never overwrites an existing destination. Original plaintext files and any
previous swap, undo, or backup copies remain your responsibility. Cancelling the
passphrase prompt leaves persistence protections enabled.

| Command | Action |
| --- | --- |
| `:EncryptSetup [path.gpg]` | Encrypt the current buffer to a new file. |
| `:EncryptUnlock` | Retry a cancelled or failed unlock. |
| `:EncryptChangePassphrase` | Confirm a new passphrase and save immediately. |
| `:EncryptCheck` | Diagnose GPG using dummy text. |

Empty passphrases cancel; newline and NUL characters are unsupported. Use a strong
passphrase: files permit offline password guessing. Passphrases stay in private
Lua state until the buffer is unloaded or wiped; hidden buffers remain unlocked.

The buffer uses the underlying name (`notes.md`); `b:softencrypt_path` holds the
ciphertext path. Normal filetype detection and read/write hooks run against the
underlying name. No plaintext file is created there. See `:help softencrypt` when
installed as a repository.

## Protections and limits

- Saves use owner-only ciphertext temporary files, sync their contents, and
  publish atomically. Plaintext and passphrases travel through pipes, without a
  shell or secrets in command arguments or environment variables. Pre-publication
  failures preserve the previous ciphertext and passphrase; pending edits remain
  modified. Directory-sync failures after publication warn instead of failing.
  If temporary-file cleanup fails after publication, the save succeeds with a
  warning; remove the named ciphertext temporary file and reopen before saving.
- External changes are checked even with `:write!`. There is no cross-process
  lock against a writer racing the final rename. Saves replace the inode, set
  permissions to 0600, and do not preserve extended attributes or ACLs.
- Alternate destinations, range writes, appends, buffer renames, and shell filters
  backed by temporary files are blocked. Pipe-only filters remain possible.
- Only local regular storage files with one hard link are supported. Visible
  symlinks are refused, though Neovim can resolve an alias before the plugin sees
  it. Remote URLs and binary data are unsupported; plaintext is limited to 16 MiB.
- Text encodings, BOMs, Unix/DOS/configured Mac line endings, and absent final
  newlines are preserved. Mixed CR-LF/LF text opens as Unix with visible CRs.
  A logical name or storage path owned by another buffer is rejected.
- ShaDa content limits and `shadafile=NONE` prevent ordinary session persistence,
  including explicit `:wshada` exports of registers/history/globals. Existing
  ShaDa files are not cleaned. Memory-only undo, registers, and histories work.

Trusted Neovim configuration is required. Other plugins, deliberate exports such
as `:wundo`, `:redir`, and `writefile()`, or copying text into an ordinary file can
persist plaintext. Integrations requiring a real plaintext file cannot use this
storage model. OS swap, hibernation, crash dumps, and external processes are
outside scope. Do not use another encryption plugin for the same `.gpg` files.

## Development

Run `python3 tests/run.py` for integration tests with real Neovim and GPG in a
disposable GPG home. `python3 tests/run.py --trace` also checks Neovim's write
syscalls for a plaintext sentinel using strace; trace output stays in memory.
Tests cover editing, encoding fidelity, persistence protections, and save failures.
Use `--regressions-only` to run the decoding/publication cases with a dummy GPG
transport when an agent is unavailable.

## License

[MIT](LICENSE). Provided as is, without warranty; see the license for the liability
disclaimer.
