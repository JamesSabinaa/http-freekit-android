"""Execute the workflow's real Bash cleanup, without an emulator or ADB device."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest


def bash_executable():
    explicit = os.environ.get("BASH_EXECUTABLE")
    if explicit:
        return explicit
    found = shutil.which("bash")
    if found and "WindowsApps" not in found:
        return found
    if os.name == "nt":
        candidate = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/bin/bash.exe"
        if candidate.is_file():
            return str(candidate)
    raise RuntimeError("Bash is required for native cleanup checks; set BASH_EXECUTABLE")


class NativeCleanupTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bash = bash_executable()
        workflow = Path(__file__).resolve().parents[2] / ".github/workflows/native-engine-runtime.yml"
        text = workflow.read_text()
        cleanup = re.search(r"^          cleanup\(\) \{\n.*?^          \}", text, re.MULTILINE | re.DOTALL)
        trap = re.search(r"^          trap (?!-)[^\n]* EXIT$", text, re.MULTILINE)
        if cleanup is None or trap is None:
            raise AssertionError("The native workflow cleanup/trap could not be extracted")
        cls.cleanup = textwrap.dedent(cleanup.group())
        cls.trap = trap.group().strip()

    def execute_cleanup(self, requested, explicit):
        with tempfile.TemporaryDirectory(prefix="freekit-cleanup-") as directory:
            script, audit = Path(directory) / "check.bash", Path(directory) / "audit.txt"
            prefix = '''set -e
record=$1
requested=$2
adb() { printf 'adb\n' >> "$record"; return 1; }
kill() {
  local result
  if builtin kill "$@"; then result=0; else result=$?; fi
  printf 'kill:%s\n' "$result" >> "$record"
  return "$result"
}
wait() {
  local result
  if builtin wait "$@"; then result=0; else result=$?; fi
  if builtin kill -0 "$emulator_pid" 2>/dev/null; then
    printf 'wait:alive\n' >> "$record"
  else
    printf 'wait:gone\n' >> "$record"
  fi
  return "$result"
}
sleep 30 >/dev/null 2>&1 &
emulator_pid=$!
printf 'pid:%s\n' "$emulator_pid" >> "$record"
builtin kill -0 "$emulator_pid"
'''
            ending = 'cleanup "$requested"\nexit "$requested"\n' if explicit else 'exit "$requested"\n'
            script.write_text(prefix + self.cleanup + "\n" + self.trap + "\n" + ending)
            try:
                result = subprocess.run([self.bash, "--noprofile", "--norc", script.as_posix(), audit.as_posix(), str(requested)],
                                        capture_output=True, text=True, timeout=10)
                lines = audit.read_text().splitlines()
                self.assertEqual(result.returncode, requested, result.stderr)
                self.assertEqual(lines.count("adb"), 1, lines)
                self.assertEqual(lines.count("kill:0"), 1, lines)
                self.assertEqual(lines.count("wait:gone"), 1, lines)
                self.assertNotIn("wait:alive", lines)
            finally:
                # Only the child created by this uniquely owned fixture may
                # remain if a future regression prevents cleanup from running.
                lines = audit.read_text().splitlines() if audit.exists() else []
                if "wait:gone" not in lines:
                    pids = [line[4:] for line in lines if line.startswith("pid:")]
                    for pid in pids:
                        if pid.isdigit():
                            subprocess.run([self.bash, "--noprofile", "--norc", "-c", 'kill "$1" 2>/dev/null || true', "fixture-cleanup", pid],
                                           capture_output=True, timeout=3, check=False)

    def test_explicit_cleanup_preserves_status_and_joins_child_once(self):
        for status in (0, 7, 124):
            with self.subTest(status=status):
                self.execute_cleanup(status, explicit=True)

    def test_exit_trap_preserves_status_and_joins_child_once(self):
        for status in (0, 7, 124):
            with self.subTest(status=status):
                self.execute_cleanup(status, explicit=False)


if __name__ == "__main__":
    unittest.main()
