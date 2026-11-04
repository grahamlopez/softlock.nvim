"""Run real GPG/Neovim integration tests in an isolated, disposable home."""
import os
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

repo = Path(__file__).resolve().parents[1]
regressions_only = "--regressions-only" in sys.argv
with tempfile.TemporaryDirectory(prefix="nve-", dir="/tmp") as directory:
    root = Path(directory)
    gpg_home = root / "gpg"
    gpg_home.mkdir(mode=0o700)
    env = dict(os.environ, GNUPGHOME=str(gpg_home), SOFTLOCK_TEST_ROOT=str(root),
               SOFTLOCK_PLUGIN=str(repo / "plugin/softlock.lua"),
               SOFTLOCK_TEST_SCRIPT=str(repo / "tests/integration.lua"),
               SOFTLOCK_TEST_REGRESSIONS_ONLY="1" if regressions_only else "0",
               XDG_STATE_HOME=str(root / "state"), XDG_CACHE_HOME=str(root / "cache"),
               XDG_DATA_HOME=str(root / "data"), NVIM_LOG_FILE=str(root / "nvim.log"))
    try:
        script = """lua vim.schedule(function()
          local ok, err = xpcall(function() dofile(vim.env.SOFTLOCK_TEST_SCRIPT) end, debug.traceback)
          if not ok then print(err); vim.cmd('cquit') end
        end)"""
        command = ["nvim", "--headless", "-u", "NONE", "-i", "NONE", "-c", script]
        tracing = "--trace" in sys.argv
        if tracing:
            command = ["strace", "-yy", "-s", "65535", "-e",
                       "trace=write,writev,pwrite64", *command]
        result = subprocess.run(command, env=env, timeout=180, capture_output=True)
        output = (result.stdout + result.stderr).decode(errors="replace")
        if not tracing or result.returncode:
            print(output)
        if result.returncode:
            raise SystemExit(result.returncode)
        if tracing:
            # Capture trace in Python memory, never a trace file containing pipe data.
            for line in output.splitlines():
                match = re.match(r"(?:write|writev|pwrite64)\(\d+<([^>]+)>", line)
                if match and match[1].startswith("/") and not match[1].startswith("/dev/"):
                    assert "MEMORY_ONLY_SENTINEL" not in line, line
            print("PASS syscall trace: no sentinel written by Neovim to a regular file")
            print("PASS integration suite")

        if regressions_only:
            raise SystemExit(0)

        # Exercise real plugin autoload, startup file opening, and :wq as well.
        init = root / "init.lua"
        init.write_text(
            "vim.opt.runtimepath = {" + json.dumps(str(repo)) + ", vim.env.VIMRUNTIME}\n"
            "vim.cmd('filetype plugin indent on')\n"
            "vim.fn.inputsecret = function() return 'replacement secret' end\n"
        )
        check = """lua assert(vim.g.loaded_softlock); assert(vim.bo.filetype == 'markdown');
          assert(vim.b.did_ftplugin); assert(vim.o.shadafile == 'NONE'); assert(not vim.bo.swapfile)"""
        result = subprocess.run(["nvim", "--headless", "-u", str(init), "-i", "NONE",
                                 str(root / "notes.md.gpg"), "-c", check, "-c", "wq"],
                                env=env, timeout=30, capture_output=True)
        if result.returncode:
            print((result.stdout + result.stderr).decode(errors="replace"))
            raise SystemExit(result.returncode)
        print("PASS single-file plugin autoload, startup unlock, filetype, and :wq")
        for candidate in root.rglob("*"):
            if not candidate.is_symlink() and candidate.is_file():
                assert b"MEMORY_ONLY_SENTINEL" not in candidate.read_bytes(), candidate
        print("PASS artifact scan: no plaintext sentinel in any generated regular file")
    finally:
        if not regressions_only:
            subprocess.run(["gpgconf", "--homedir", str(gpg_home), "--kill", "gpg-agent"],
                           capture_output=True, timeout=10)
