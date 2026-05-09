from __future__ import annotations

import importlib.util
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class PackagingSmokeTests(unittest.TestCase):
    def test_github_action_script_forwards_strict_gate_argument(self) -> None:
        repo = Path(__file__).parents[1]
        action = (repo / "action.yml").read_text(encoding="utf-8")
        script = (repo / "scripts" / "github_action.sh").read_text(encoding="utf-8")
        self.assertIn("strict:", action)
        self.assertIn("RED_WIDOW_STRICT: ${{ inputs.strict }}", action)
        self.assertIn('python_cmd="${PYTHON:-python}"', action)
        self.assertIn('python_cmd="python3"', action)
        self.assertIn('"$python_cmd" -m pip install "$GITHUB_ACTION_PATH"', action)
        self.assertIn('python_cmd="${PYTHON:-python}"', script)
        self.assertIn('python_cmd="python3"', script)

        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            bin_dir = temp / "bin"
            bin_dir.mkdir()
            arg_log = temp / "red-widow-args.log"
            output_dir = temp / "results"
            workspace = temp / "workspace"
            workspace.mkdir()
            python = bin_dir / "python"
            python.write_text(
                f"#!/usr/bin/env bash\nexec {shlex.quote(sys.executable)} \"$@\"\n",
                encoding="utf-8",
            )
            python.chmod(0o755)
            red_widow = bin_dir / "red-widow"
            red_widow.write_text(
                """#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$RED_WIDOW_ARG_LOG"
format=""
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "--format" ]]; then
    format="$2"
    shift 2
    continue
  fi
  shift
done
if [[ "$format" == "json" ]]; then
  printf '{"decision":"PASS"}\\n'
else
  printf 'Decision: PASS\\n'
fi
""",
                encoding="utf-8",
            )
            red_widow.chmod(0o755)
            env = os.environ.copy()
            env.update(
                {
                    "PATH": str(bin_dir) + os.pathsep + env.get("PATH", ""),
                    "RED_WIDOW_ARG_LOG": str(arg_log),
                    "RED_WIDOW_OUTPUT_DIR": str(output_dir),
                    "RED_WIDOW_WORKSPACE": str(workspace),
                    "RED_WIDOW_OFFLINE": "true",
                    "RED_WIDOW_STRICT": "true",
                }
            )

            result = subprocess.run(
                ["bash", str(repo / "scripts" / "github_action.sh")],
                cwd=repo,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            lines = arg_log.read_text(encoding="utf-8").splitlines()
        gate_lines = [line for line in lines if line.startswith("gate ")]
        inventory_lines = [line for line in lines if line.startswith("inventory ")]
        self.assertEqual(len(gate_lines), 3)
        self.assertEqual(len(inventory_lines), 2)
        self.assertTrue(all("--strict" in line.split() for line in gate_lines))
        self.assertTrue(all("--strict" not in line.split() for line in inventory_lines))

    def test_wheel_installs_entry_point_and_core_commands(self) -> None:
        if importlib.util.find_spec("build.__main__") is None:
            self.skipTest("python build module is required for wheel smoke test")

        repo = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            dist = temp / "dist"
            venv = temp / "venv"

            build_result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "build",
                    "--wheel",
                    "--no-isolation",
                    "--outdir",
                    str(dist),
                ],
                cwd=repo,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(build_result.returncode, 0, build_result.stderr)

            wheels = sorted(dist.glob("red_widow-*.whl"))
            self.assertEqual(len(wheels), 1, [str(path) for path in wheels])

            venv_result = subprocess.run(
                [sys.executable, "-m", "venv", str(venv)],
                cwd=repo,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(venv_result.returncode, 0, venv_result.stderr)

            python = _venv_python(venv)
            install_result = subprocess.run(
                [str(python), "-m", "pip", "install", str(wheels[0])],
                cwd=repo,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(install_result.returncode, 0, install_result.stderr)

            red_widow = _venv_script(venv, "red-widow")
            help_result = subprocess.run(
                [str(red_widow), "--help"],
                cwd=temp,
                capture_output=True,
                text=True,
                check=False,
            )
            gate_result = subprocess.run(
                [str(red_widow), "gate", "--workspace", str(temp), "--offline"],
                cwd=temp,
                capture_output=True,
                text=True,
                check=False,
            )
            approve_result = subprocess.run(
                [
                    str(red_widow),
                    "approve",
                    "--workspace",
                    str(temp),
                    "--offline",
                    "--lockfile",
                    str(temp / "red-widow.lock.json"),
                ],
                cwd=temp,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("Red Widow scans", help_result.stdout)
        self.assertEqual(gate_result.returncode, 0, gate_result.stderr)
        self.assertIn("Decision: PASS", gate_result.stdout)
        self.assertEqual(approve_result.returncode, 0, approve_result.stderr)
        self.assertIn("Wrote lockfile:", approve_result.stdout)


def _venv_python(venv: Path) -> Path:
    if sys.platform == "win32":
        return venv / "Scripts" / "python.exe"
    return venv / "bin" / "python"


def _venv_script(venv: Path, name: str) -> Path:
    if sys.platform == "win32":
        return venv / "Scripts" / f"{name}.exe"
    return venv / "bin" / name
