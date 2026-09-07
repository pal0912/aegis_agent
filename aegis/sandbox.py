"""Ephemeral, host-isolated code execution sandbox for AegisAgent V2.

Enforces static AST inspection, module allowlisting/denylisting, temporary directory isolation,
stripped environment variables, and strict process execution timeouts.
"""

import ast
import logging
import os
import subprocess
import sys
import tempfile
from typing import Any, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class IsolatedCodeSandbox:
    """Ephemeral, network-isolated Python code execution sandbox."""

    # Banned modules that must never be imported in sandboxed execution
    BANNED_MODULES: Set[str] = {
        "subprocess",
        "os",
        "sys",
        "shutil",
        "ctypes",
        "socket",
        "http",
        "urllib",
        "requests",
        "aiohttp",
        "httpx",
        "multiprocessing",
        "threading",
        "pty",
        "pathlib",
        "builtins",
        "importlib",
        "inspect",
        "posix",
        "nt",
        "platform",
        "signal",
        "resource",
        "gc",
        "winreg",
        "_winapi",
    }

    # Banned functions, builtins, and attribute accesses
    BANNED_CALLS_AND_ATTRS: Set[str] = {
        "__import__",
        "eval",
        "exec",
        "globals",
        "locals",
        "compile",
        "open",
        "__builtins__",
        "__subclasses__",
        "__globals__",
        "__code__",
        "__bases__",
        "__mro__",
    }

    def __init__(self, default_timeout_sec: float = 5.0) -> None:
        """Initialize IsolatedCodeSandbox with configurable execution timeout.

        Args:
            default_timeout_sec: Maximum execution duration in seconds before SIGKILL/terminate.
        """
        self.default_timeout_sec = default_timeout_sec

    def inspect_ast(self, code: str) -> Tuple[bool, Optional[str]]:
        """Perform pre-execution static AST security analysis on candidate Python code.

        Args:
            code: Source code string to inspect.

        Returns:
            Tuple of (is_safe: bool, violation_reason: Optional[str]).
        """
        if not code or not code.strip():
            return True, None

        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return False, f"AST Parse Error: Invalid Python syntax at line {e.lineno}: {e.msg}"
        except Exception as e:
            return False, f"AST Parse Error: {e}"

        for node in ast.walk(tree):
            # Check direct imports (e.g., import os, import subprocess)
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_pkg = alias.name.split(".")[0]
                    if root_pkg in self.BANNED_MODULES:
                        return False, f"Banned module import detected: '{alias.name}'"

            # Check from-imports (e.g., from os import system, from subprocess import Popen)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    root_pkg = node.module.split(".")[0]
                    if root_pkg in self.BANNED_MODULES:
                        return False, f"Banned module from-import detected: '{node.module}'"
                for alias in node.names:
                    if alias.name in self.BANNED_MODULES or alias.name in self.BANNED_CALLS_AND_ATTRS:
                        return False, f"Banned symbol imported: '{alias.name}'"

            # Check direct function calls (e.g., eval(), exec(), __import__())
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in self.BANNED_CALLS_AND_ATTRS:
                        return False, f"Banned builtin execution call: '{node.func.id}()'"
                elif isinstance(node.func, ast.Attribute):
                    if node.func.attr in self.BANNED_CALLS_AND_ATTRS:
                        return False, f"Banned method/attribute execution call: '.{node.func.attr}()'"

            # Check dangerous attribute accesses (e.g., obj.__subclasses__, obj.__globals__)
            elif isinstance(node, ast.Attribute):
                if node.attr in self.BANNED_CALLS_AND_ATTRS:
                    return False, f"Banned attribute access: '{node.attr}'"

            # Check identifier reference to dangerous builtins
            elif isinstance(node, ast.Name):
                if node.id in self.BANNED_CALLS_AND_ATTRS:
                    return False, f"Banned identifier reference: '{node.id}'"

        return True, None

    def execute_sandboxed(
        self,
        code: str,
        timeout_sec: Optional[float] = None,
    ) -> dict[str, Any]:
        """Execute Python code in an isolated, ephemeral sandbox environment.

        Args:
            code: Python code string to run.
            timeout_sec: Optional timeout override in seconds.

        Returns:
            Dict containing stdout, stderr, exit_code, violation, and sandboxed status.
        """
        timeout = timeout_sec if timeout_sec is not None else self.default_timeout_sec

        # Step 1: Pre-Execution Static AST Inspection
        is_safe, violation = self.inspect_ast(code)
        if not is_safe:
            logger.warning("Code execution rejected by AST filter: %s", violation)
            return {
                "stdout": "",
                "stderr": f"Security Violation: {violation}",
                "exit_code": -1,
                "violation": violation,
                "sandboxed": True,
            }

        # Step 2: Build stripped environment variables
        stripped_env: dict[str, str] = {
            "PYTHONUNBUFFERED": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        if os.name == "nt":
            if "SYSTEMROOT" in os.environ:
                stripped_env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
            if "WINDIR" in os.environ:
                stripped_env["WINDIR"] = os.environ["WINDIR"]
            if "PATH" in os.environ:
                stripped_env["PATH"] = os.environ.get("PATH", "")

        # Step 3: Run inside an ephemeral temporary directory
        with tempfile.TemporaryDirectory(prefix="aegis_sandbox_") as temp_dir:
            script_path = os.path.join(temp_dir, "sandbox_exec.py")
            try:
                with open(script_path, "w", encoding="utf-8") as f:
                    f.write(code)

                process = subprocess.run(
                    [sys.executable, "-I", "-S", script_path],
                    cwd=temp_dir,
                    env=stripped_env,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )

                return {
                    "stdout": process.stdout,
                    "stderr": process.stderr,
                    "exit_code": process.returncode,
                    "violation": None if process.returncode == 0 else f"Process exited with code {process.returncode}",
                    "sandboxed": True,
                }

            except subprocess.TimeoutExpired as e:
                logger.warning("Sandbox execution timed out after %.2f seconds", timeout)
                stdout = e.stdout.decode("utf-8", errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
                stderr = e.stderr.decode("utf-8", errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
                return {
                    "stdout": stdout,
                    "stderr": f"{stderr}\nExecution timed out after {timeout:.1f} seconds.",
                    "exit_code": -2,
                    "violation": f"Execution timeout exceeded ({timeout:.1f}s)",
                    "sandboxed": True,
                }
            except Exception as e:
                logger.error("Sandbox execution failed with system error: %s", e)
                return {
                    "stdout": "",
                    "stderr": f"Execution failed: {e}",
                    "exit_code": -3,
                    "violation": str(e),
                    "sandboxed": True,
                }
