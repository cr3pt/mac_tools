"""Cross‑platform deployment CLI.
Replaces the old ``deploy.sh`` script. It creates a virtual environment,
installs system packages (if possible) and Python dependencies, then starts
Docker Compose.
"""
import os
import sys
import subprocess
import platform
from pathlib import Path

def _run_cmd(cmd: list[str]):
    subprocess.run(cmd, check=True)

def _install_system_packages():
    system = platform.system()
    if system == "Linux":
        # Try to install required packages via apt (Debian/Ubuntu)
        try:
            _run_cmd(["sudo", "apt-get", "update"])
            _run_cmd([
                "sudo", "apt-get", "install", "-y",
                "yara", "libyara-dev", "gcc", "git", "curl",
                "qemu-utils", "tshark", "tcpdump",
                "build-essential", "libpq-dev",
            ])
        except Exception as e:
            print(f"[WARN] Could not install system packages: {e}")
    elif system == "Darwin":
        try:
            _run_cmd(["brew", "install", "yara", "qemu", "wireshark"])
        except Exception as e:
            print(f"[WARN] Could not install system packages on macOS: {e}")
    else:
        print("[INFO] No automatic system‑package installation for this OS.")

def _create_venv():
    venv_path = Path(".venv")
    if not venv_path.exists():
        _run_cmd([sys.executable, "-m", "venv", str(venv_path)])
    # Upgrade pip and install requirements
    pip = venv_path / "bin" / "pip"
    _run_cmd([str(pip), "install", "--upgrade", "pip"])
    _run_cmd([str(pip), "install", "-r", "requirements.txt"])

def _run_compose():
    # Use docker compose (v2) if available
    compose_cmd = ["docker", "compose", "up", "-d"]
    try:
        _run_cmd(compose_cmd)
    except Exception:
        # fallback to legacy docker-compose
        _run_cmd(["docker-compose", "up", "-d"])

def main():
    print("[INFO] Starting deployment...")
    _install_system_packages()
    _create_venv()
    _run_compose()
    print("[INFO] Deployment finished. Services are up.")

if __name__ == "__main__":
    main()

