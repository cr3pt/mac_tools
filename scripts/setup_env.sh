#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENV_DIR="$REPO_ROOT/.venv"
REQS="$REPO_ROOT/requirements.txt"
REQS_DEV="$REPO_ROOT/requirements-dev.txt"
UPLOAD_DIR="/tmp/noriben_uploads"

echo "Noriben SOC -- automated environment setup"
echo "Repository: $REPO_ROOT"

OS=$(uname -s)

install_ubuntu(){
  echo "Detected Ubuntu/Debian. Installing packages with apt..."
  sudo apt-get update -qq
  sudo apt-get install -y --no-install-recommends build-essential libpq-dev python3-venv python3-pip python3-dev yara clamav qemu-system-x86 qemu-utils redis-server postgresql postgresql-contrib docker.io docker-compose-plugin || true
  # enable services
  sudo systemctl enable --now redis-server || true
  sudo systemctl enable --now postgresql || true
}

install_macos(){
  echo "Detected macOS. Installing packages with Homebrew..."
  if ! command -v brew >/dev/null 2>&1; then
    echo "Homebrew not found. Installing Homebrew (you may be prompted for your password)..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    echo "After brew install, you may need to add brew to PATH."
  fi
  brew update || true
  brew install python@3.11 postgresql libpq yara clamav qemu redis docker || true
  # Start services (postgres/redis) via brew
  brew services start postgresql || true
  brew services start redis || true
}

create_venv_and_pip(){
  echo "Creating virtualenv and installing Python dependencies..."
  if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
  fi
  # shellcheck source=/dev/null
  source "$VENV_DIR/bin/activate"
  pip install --upgrade pip
  if [ -f "$REQS" ]; then
    pip install -r "$REQS"
  fi
  if [ -f "$REQS_DEV" ]; then
    pip install -r "$REQS_DEV"
  fi
}

setup_db(){
  if command -v psql >/dev/null 2>&1; then
    echo "Attempting to create Postgres role/database 'noriben' (password: noriben123) if missing..."
    if [ "$OS" = "Linux" ]; then
      sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='noriben'" | grep -q 1 || sudo -u postgres psql -c "CREATE USER noriben WITH PASSWORD 'noriben123';"
      sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='noriben'" | grep -q 1 || sudo -u postgres psql -c "CREATE DATABASE noriben OWNER noriben;"
    else
      # macOS: try as current user (Homebrew postgres commonly uses current user)
      if psql -c "SELECT 1" >/dev/null 2>&1; then
        psql -tc "SELECT 1 FROM pg_roles WHERE rolname='noriben'" | grep -q 1 || psql -c "CREATE USER noriben WITH PASSWORD 'noriben123';"
        psql -tc "SELECT 1 FROM pg_database WHERE datname='noriben'" | grep -q 1 || psql -c "CREATE DATABASE noriben OWNER noriben;"
      else
        echo "Postgres is installed but not accepting local connections. Please create role/db manually."
      fi
    fi
  else
    echo "psql not found; skipping DB creation. Install postgresql and re-run to enable DB setup."
  fi
}

create_upload_dir(){
  echo "Ensuring upload directory exists: $UPLOAD_DIR"
  mkdir -p "$UPLOAD_DIR"
  chmod 700 "$UPLOAD_DIR" || true
}

post_install_notes(){
  cat <<'EOF'

Installation finished (best-effort). Next steps:
- Activate virtualenv: source .venv/bin/activate
- Start a celery worker: celery -A noriben_soc.tasks.celery_app worker --loglevel=info
- Run the API: uvicorn noriben_soc.api.main:app --host 0.0.0.0 --port 8000
- Copy .env.example to .env and adjust DATABASE_URL / CELERY_BROKER if needed.

If Postgres DB creation failed, create a role and DB named 'noriben' with password 'noriben123' or update DATABASE_URL in .env.

EOF
}

main(){
  case "$OS" in
    Linux*) install_ubuntu ;; 
    Darwin*) install_macos ;; 
    *) echo "Unsupported OS: $OS"; exit 1 ;;
  esac

  create_venv_and_pip
  create_upload_dir
  setup_db
  post_install_notes
}

main "$@"
