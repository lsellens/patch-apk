import subprocess, re, os, sys
from typing import List, Optional, Tuple

from Log import Log

class ADBError(RuntimeError): pass

class ADBHelper:
   
    def __init__(self, serial: Optional[str] = None):
        self.serial = serial
        self._check_adb()

    # -------------------- Public APIs --------------------

    def get_packages(self, pattern: Optional[str] = None) -> List[str]:
        out = self._run_adb(["shell", "pm", "list", "packages"])
        pkgs = []
        for line in out.splitlines():
            if line.startswith("package:"):
                name = line[8:].strip()
                if pattern is None or pattern.lower() in name.lower():
                    pkgs.append(name)
        return sorted(pkgs)

    def get_apk_paths(self, package: str, user: Optional[str] = "0") -> Tuple[str, List[str]]:
        if user is not None:
            resolved_user, paths = self._pm_path_for_user(package, user)
            if paths:
                return resolved_user, paths

        users = self._list_users()
        try_order = [u for u in users if u != (user or "0")] if user else users
        for u in try_order:
            resolved_user, paths = self._pm_path_for_user(package, u)
            if paths:
                return resolved_user, paths
        Log.abort(f"Package '{package}' not found for any user: {users}")

    def pull_files(self, remote_paths: List[str], dest_dir: str, prefix: str) -> List[str]:
        """
        Pull each remote path to dest_dir.
        Returns list of local file paths.
        """
        os.makedirs(dest_dir, exist_ok=True)
        local_paths = []
        for rp in remote_paths:
            name = f"{os.path.basename(rp)}"
            dp = os.path.join(dest_dir, name)
            cmd = self._adb_cmd(["pull", rp, dp])
            self._run(cmd, "adb pull failed")
            local_paths.append(dp)
            Log.verbose(f" Pulled: {rp} -> {dp}")
        return local_paths

    def install_apk(self, apk_path: str, user: str, replace: bool = True) -> None:
        args = ["install"]
        if replace:
            args.append("-r")
        args += ["--user", user, apk_path]
        cmd = self._adb_cmd(args)
        self._run(cmd, "adb install failed")

    def uninstall_pkg(self, package: str, user: str) -> None:
        cmd = self._adb_cmd(["uninstall", package])
        # Best-effort; don't raise on non-zero (maybe not installed for that user)
        self._run(cmd, raise_on_error=False)

    # -------------------- Internals --------------------

    def _pm_path_for_user(self, package: str, user: str) -> Tuple[str, List[str]]:
        Log.verbose(f"[ADB] pm path --user {user} {package}")
        try:
            out = self._run_adb(["shell", "pm", "path", "--user", user, package], allowed_result_codes=[0, 1])
        except ADBError:
            return user, []
        paths = [line[8:].strip() for line in out.splitlines() if line.startswith("package:")]
        return user, paths

    def _list_users(self) -> List[str]:
        out = self._run_adb(["shell", "pm", "list", "users"])
        return re.findall(r"UserInfo{(\d+):", out)

    def _check_adb(self):
        try:
            self._run_adb(["devices"])
        except ADBError as e:
            Log.abort("adb not available or device list inaccessible")

    def _adb_cmd(self, tail: List[str]) -> List[str]:
        cmd = ["adb"]
        if self.serial:
            cmd += ["-s", self.serial]
        cmd += tail

        Log.verbose("[ADB] " + " ".join(cmd))
        return cmd

    def _run_adb(self, args: List[str], allowed_result_codes: List[int] = [0]) -> str:
        cmd = self._adb_cmd(args)
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if not proc.returncode in allowed_result_codes:
            Log.abort(proc.stderr.strip() or proc.stdout.strip() or "ADB command failed")
        return proc.stdout

    def _run(self, cmd: List[str], err: str = "command failed", raise_on_error: bool = True) -> None:
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.stdout:
            Log.verbose(proc.stdout)
        if proc.returncode != 0 and proc.stderr:
            Log.verbose(proc.stderr)
        if raise_on_error and proc.returncode != 0:
            Log.abort(proc.stderr.strip() or proc.stdout.strip() or err)
