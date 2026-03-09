#!/bin/bash
# ============================================================
#  noriben_parallels_setup.sh
#  Automatyzacja środowiska Noriben + Parallels na macOS
#
#  Co robi ten skrypt:
#  1. Sprawdza i instaluje wymagane narzędzia (prlctl, python3, itp.)
#  2. Sprawdza obecność VM Parallels + konfiguruje snapshot
#  3. Kopiuje próbkę do VM przez Parallels Guest Tools
#  4. Uruchamia Noriben.py w VM (+ Procmon + próbka)
#  5. Czeka na zakończenie analizy (konfigurowalny timeout)
#  6. Kopiuje wyniki z VM na hosta
#  7. Przywraca VM do czystego snapshota (gotowy na kolejną próbkę)
#  8. Generuje raport HTML ze znaleziskami
#
#  Wymagania hosta (Mac):
#    - Parallels Desktop 18+ (prlctl w PATH)
#    - python3
#    - pip3
#
#  Wymagania wewnątrz Windows VM:
#    - Python 3.x (C:\Python3\python.exe)
#    - Sysinternals Procmon (C:\Tools\procmon64.exe)
#    - Noriben.py (C:\Tools\Noriben.py)
#    - Parallels Guest Tools (do kopiowania plików)
# ============================================================

set -euo pipefail

VERSION="1.0.0"

# ─── Kolory ───────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

# ─── Konfiguracja — DOSTOSUJ DO SWOJEGO ŚRODOWISKA ───────────
# Nazwa VM w Parallels (dokładnie jak w Parallels Desktop)
VM_NAME="${VM_NAME:-Windows 11 Malware}"

# Nazwa snapshota — czyste, bazowe środowisko Windows
VM_SNAPSHOT="${VM_SNAPSHOT:-Baseline_Clean}"

# Dane logowania do Windows VM
VM_USER="${VM_USER:-Administrator}"
VM_PASS="${VM_PASS:-password}"

# Ścieżki wewnątrz Windows VM
VM_PYTHON="C:\\Python3\\python.exe"
VM_NORIBEN="C:\\Tools\\Noriben.py"
VM_PROCMON="C:\\Tools\\procmon64.exe"
VM_MALWARE_DIR="C:\\Malware"
VM_OUTPUT_DIR="C:\\NoribenLogs"

# Ścieżki na hoście macOS
HOST_RESULTS_DIR="${HOME}/NoribenResults"
HOST_TOOLS_DIR="${HOME}/NoribenTools"

# Timeouty
ANALYSIS_TIMEOUT="${ANALYSIS_TIMEOUT:-300}"    # 5 minut analizy Noriben
VM_BOOT_TIMEOUT=120                            # 2 minuty na boot VM
VM_COPY_TIMEOUT=30                             # 30s na kopiowanie pliku

# ─── Zmienne globalne ─────────────────────────────────────────
SAMPLE_FILE=""
SAMPLE_BASENAME=""
SESSION_ID=""
SESSION_DIR=""
LOG_FILE=""
SPINNER_PID=""

# ═════════════════════════════════════════════════════════════
# HELPERS
# ═════════════════════════════════════════════════════════════

spinner_chars="⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

start_spinner() {
    local msg="$1"
    (
        local i=0
        while true; do
            printf "\r${CYAN}${spinner_chars:$i:1}${RESET} $msg   "
            i=$(( (i+1) % ${#spinner_chars} ))
            sleep 0.1
        done
    ) &
    SPINNER_PID=$!
}

stop_spinner() {
    [[ -n "$SPINNER_PID" ]] && kill "$SPINNER_PID" 2>/dev/null || true
    wait "$SPINNER_PID" 2>/dev/null || true
    SPINNER_PID=""
    printf "\r\033[K"
}

log()      { echo -e "${BOLD}[•]${RESET} $*";  echo "[INFO] $(date '+%H:%M:%S') $*" >> "$LOG_FILE" 2>/dev/null || true; }
log_ok()   { echo -e "${GREEN}[✓]${RESET} $*"; echo "[OK]   $(date '+%H:%M:%S') $*" >> "$LOG_FILE" 2>/dev/null || true; }
log_warn() { echo -e "${YELLOW}[!]${RESET} $*";echo "[WARN] $(date '+%H:%M:%S') $*" >> "$LOG_FILE" 2>/dev/null || true; }
log_err()  { echo -e "${RED}[✗]${RESET} $*";   echo "[ERR]  $(date '+%H:%M:%S') $*" >> "$LOG_FILE" 2>/dev/null || true; }
section()  {
    echo -e "\n${CYAN}${BOLD}╔══════════════════════════════════════════╗"
    printf   "${CYAN}${BOLD}║  %-40s║\n" "$*"
    echo -e  "╚══════════════════════════════════════════╝${RESET}"
    echo -e "\n=== $* ===" >> "$LOG_FILE" 2>/dev/null || true
}

print_banner() {
    echo -e "${CYAN}${BOLD}"
    cat <<'BANNER'
  ╔══════════════════════════════════════════════════════╗
  ║   🧪 Noriben + Parallels Sandbox Automation         ║
  ║   macOS Host → Windows VM → Noriben Analysis        ║
  ║                                                      ║
  ║   Pełna automatyzacja: boot → analiza → raport      ║
  ╚══════════════════════════════════════════════════════╝
BANNER
    echo -e "${RESET}"
}

# ═════════════════════════════════════════════════════════════
# KROK 0 — SPRAWDZENIE I INSTALACJA NARZĘDZI (HOST)
# ═════════════════════════════════════════════════════════════

check_host_tools() {
    section "SPRAWDZENIE NARZĘDZI NA HOŚCIE (macOS)"

    local all_ok=true

    # prlctl — CLI Parallels Desktop
    if ! command -v prlctl &>/dev/null; then
        log_err "prlctl nie znaleziony!"
        echo ""
        echo -e "  ${RED}Parallels Desktop nie jest zainstalowany lub prlctl nie jest w PATH.${RESET}"
        echo ""
        echo -e "  Sprawdź:"
        echo -e "  ${DIM}ls /usr/local/bin/prlctl${RESET}"
        echo -e "  ${DIM}ls /Applications/Parallels\\ Desktop.app/Contents/MacOS/prlctl${RESET}"
        echo ""
        echo -e "  Możesz też dodać do PATH:"
        echo -e "  ${DIM}export PATH=\"\$PATH:/Applications/Parallels Desktop.app/Contents/MacOS\"${RESET}"
        all_ok=false
    else
        local prl_ver
        prl_ver=$(prlctl --version 2>/dev/null | head -1)
        log_ok "Parallels: $prl_ver"
    fi

    # python3
    if ! command -v python3 &>/dev/null; then
        log_warn "python3 nie znaleziony — próba instalacji przez Homebrew..."
        if command -v brew &>/dev/null; then
            brew install python3 >> "$LOG_FILE" 2>&1 && log_ok "python3 zainstalowany" || {
                log_err "Nie udało się zainstalować python3"; all_ok=false
            }
        else
            log_err "Zainstaluj python3: https://python.org lub brew install python3"
            all_ok=false
        fi
    else
        log_ok "python3: $(python3 --version)"
    fi

    # pip packages na hoście (do generowania raportów HTML)
    if command -v python3 &>/dev/null; then
        for pkg in jinja2 yara-python; do
            if ! python3 -c "import ${pkg//-/_}" &>/dev/null 2>&1; then
                log_warn "Brak pakietu Python: $pkg — instaluję..."
                pip3 install "$pkg" --quiet 2>/dev/null || \
                pip3 install "$pkg" --quiet --break-system-packages 2>/dev/null || \
                log_warn "Nie udało się zainstalować $pkg (opcjonalne)"
            else
                log_ok "Python: $pkg dostępny"
            fi
        done
    fi

    # Homebrew + narzędzia pomocnicze
    if command -v brew &>/dev/null; then
        for tool in "yara" "clamav"; do
            if ! command -v "$tool" &>/dev/null; then
                log_warn "Opcjonalne narzędzie niedostępne: $tool"
                read -r -p "$(echo -e "  ${YELLOW}Zainstalować $tool? [t/N]${RESET} ")" c
                [[ "$c" =~ ^[tTyY]$ ]] && brew install "$tool" >> "$LOG_FILE" 2>&1 && log_ok "$tool zainstalowany"
            else
                log_ok "$tool: $(command -v "$tool")"
            fi
        done
    fi

    $all_ok || { echo -e "\n${RED}Brak wymaganych narzędzi — popraw konfigurację i spróbuj ponownie.${RESET}"; exit 1; }
}

# ═════════════════════════════════════════════════════════════
# KROK 1 — PRZYGOTOWANIE PLIKÓW DO POBRANIA W VM
# ═════════════════════════════════════════════════════════════

download_noriben_tools() {
    section "POBIERANIE NORIBEN I SYSINTERNALS"

    mkdir -p "$HOST_TOOLS_DIR"

    # Pobierz Noriben.py
    local noriben_path="$HOST_TOOLS_DIR/Noriben.py"
    if [[ ! -f "$noriben_path" ]]; then
        log "Pobieranie Noriben.py z GitHub..."
        if curl -fsSL \
            "https://raw.githubusercontent.com/Rurik/Noriben/master/Noriben.py" \
            -o "$noriben_path" 2>/dev/null; then
            log_ok "Noriben.py pobrany: $noriben_path"
        else
            log_err "Nie udało się pobrać Noriben.py — sprawdź połączenie"
            log_warn "Pobierz ręcznie: https://github.com/Rurik/Noriben/blob/master/Noriben.py"
            log_warn "Zapisz jako: $noriben_path"
        fi
    else
        log_ok "Noriben.py już istnieje: $noriben_path"
    fi

    # Procmon — wymaga ręcznego pobrania (Sysinternals EULA)
    local procmon_note="$HOST_TOOLS_DIR/PROCMON_DOWNLOAD.txt"
    if [[ ! -f "$HOST_TOOLS_DIR/procmon64.exe" ]]; then
        cat > "$procmon_note" <<'NOTE'
Pobierz Procmon ręcznie (wymaga akceptacji EULA Sysinternals):

  https://learn.microsoft.com/en-us/sysinternals/downloads/procmon

  Lub przez winget w Windows VM:
    winget install Microsoft.Sysinternals.ProcessMonitor

  Lub przez Chocolatey:
    choco install procmon

Skopiuj procmon64.exe do: C:\Tools\procmon64.exe w VM
NOTE
        log_warn "Procmon wymaga ręcznego pobrania — instrukcje w: $procmon_note"
    else
        log_ok "procmon64.exe znaleziony w $HOST_TOOLS_DIR"
    fi

    # Skrypt PowerShell do instalacji w VM
    local ps_setup="$HOST_TOOLS_DIR/vm_setup.ps1"
    cat > "$ps_setup" <<'PSEOF'
# vm_setup.ps1 — Uruchom w Windows VM jako Administrator
# Instaluje Python 3, Procmon i konfiguruje środowisko Noriben

Write-Host "=== Konfiguracja VM dla Noriben ===" -ForegroundColor Cyan

# Katalogi
$dirs = @("C:\Tools", "C:\Malware", "C:\NoribenLogs", "C:\Python3")
foreach ($d in $dirs) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    Write-Host "[OK] Katalog: $d" -ForegroundColor Green
}

# Sprawdź Python
if (-not (Test-Path "C:\Python3\python.exe")) {
    Write-Host "[!] Pobieranie Python 3.11..." -ForegroundColor Yellow
    $pyUrl = "https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe"
    $pyInst = "$env:TEMP\python_installer.exe"
    Invoke-WebRequest -Uri $pyUrl -OutFile $pyInst
    Start-Process -FilePath $pyInst -ArgumentList "/quiet InstallAllUsers=1 TargetDir=C:\Python3 PrependPath=1" -Wait
    Write-Host "[OK] Python zainstalowany" -ForegroundColor Green
} else {
    Write-Host "[OK] Python: $(& C:\Python3\python.exe --version)" -ForegroundColor Green
}

# Sprawdź winget / pobierz Procmon
if (-not (Test-Path "C:\Tools\procmon64.exe")) {
    Write-Host "[!] Próba instalacji Procmon przez winget..." -ForegroundColor Yellow
    try {
        winget install Microsoft.Sysinternals.ProcessMonitor --silent --accept-eula
        $procmonPath = "$env:ProgramFiles\Sysinternals Suite\Procmon64.exe"
        if (Test-Path $procmonPath) {
            Copy-Item $procmonPath "C:\Tools\procmon64.exe"
            Write-Host "[OK] Procmon skopiowany do C:\Tools" -ForegroundColor Green
        }
    } catch {
        Write-Host "[!] Pobierz Procmon ręcznie z: https://learn.microsoft.com/sysinternals/downloads/procmon" -ForegroundColor Red
        Write-Host "    Skopiuj do: C:\Tools\procmon64.exe" -ForegroundColor Red
    }
} else {
    Write-Host "[OK] Procmon: C:\Tools\procmon64.exe" -ForegroundColor Green
}

# Wyłącz Windows Defender Real-Time (dla analizy malware)
Write-Host "[!] Wyłączanie Windows Defender Real-Time Protection..." -ForegroundColor Yellow
Set-MpPreference -DisableRealtimeMonitoring $true 2>$null
Add-MpPreference -ExclusionPath "C:\Malware" 2>$null
Add-MpPreference -ExclusionPath "C:\NoribenLogs" 2>$null
Add-MpPreference -ExclusionPath "C:\Tools" 2>$null
Write-Host "[OK] Defender skonfigurowany (wykluczone: C:\Malware, C:\Tools)" -ForegroundColor Green

# Wyłącz UAC (dla automatyzacji)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "EnableLUA" -Value 0 2>$null
Write-Host "[OK] UAC wyłączone" -ForegroundColor Green

# Wyłącz automatyczne aktualizacje
Stop-Service wuauserv -Force 2>$null
Set-Service wuauserv -StartupType Disabled 2>$null
Write-Host "[OK] Windows Update wyłączone" -ForegroundColor Green

# Ustaw statyczne DNS (blokada sieci - opcjonalne)
# netsh interface ip set dns "Ethernet" static 127.0.0.1

Write-Host ""
Write-Host "=== Konfiguracja zakonczona! ===" -ForegroundColor Green
Write-Host "Teraz:"
Write-Host "  1. Skopiuj Noriben.py do C:\Tools\Noriben.py"
Write-Host "  2. Upewnij się ze Procmon jest w C:\Tools\procmon64.exe"
Write-Host "  3. Uruchom snapshot: Parallels -> Snapshots -> Take Snapshot"
Write-Host "     Nazwa snapshota: $($env:VM_SNAPSHOT -ne '' ? $env:VM_SNAPSHOT : 'Baseline_Clean')"
PSEOF
    log_ok "Skrypt konfiguracyjny VM: $ps_setup"
}

# ═════════════════════════════════════════════════════════════
# KROK 2 — ZARZĄDZANIE VM PARALLELS
# ═════════════════════════════════════════════════════════════

get_vm_status() {
    prlctl status "$VM_NAME" 2>/dev/null | awk '{print $NF}' || echo "unknown"
}

vm_exists() {
    prlctl list --all 2>/dev/null | grep -q "$VM_NAME"
}

list_available_vms() {
    echo -e "\n${BOLD}Dostępne VM w Parallels:${RESET}"
    prlctl list --all 2>/dev/null | tee -a "$LOG_FILE" || echo "  (brak VM lub brak dostępu)"
}

list_snapshots() {
    echo -e "\n${BOLD}Snapshoty VM '$VM_NAME':${RESET}"
    prlctl snapshot-list "$VM_NAME" 2>/dev/null | tee -a "$LOG_FILE" || \
        echo "  (brak snapshotów lub VM nie istnieje)"
}

revert_to_snapshot() {
    section "PRZYWRACANIE SNAPSHOTA '$VM_SNAPSHOT'"

    # Pobierz ID snapshota
    local snap_id
    snap_id=$(prlctl snapshot-list "$VM_NAME" 2>/dev/null | \
        grep -i "$VM_SNAPSHOT" | awk '{print $1}' | head -1)

    if [[ -z "$snap_id" ]]; then
        log_err "Snapshot '$VM_SNAPSHOT' nie znaleziony!"
        list_snapshots
        echo ""
        echo -e "  ${YELLOW}Utwórz snapshot w Parallels Desktop:${RESET}"
        echo -e "  1. Uruchom i skonfiguruj Windows VM"
        echo -e "  2. Parallels Desktop → Actions → Take Snapshot"
        echo -e "  3. Nazwij go: ${BOLD}$VM_SNAPSHOT${RESET}"
        echo -e "  Lub zmień VM_SNAPSHOT w tym skrypcie."
        exit 1
    fi

    log "Przywracanie snapshota: $snap_id ($VM_SNAPSHOT)..."
    start_spinner "Przywracanie snapshota..."
    prlctl snapshot-switch "$VM_NAME" --id "$snap_id" >> "$LOG_FILE" 2>&1
    stop_spinner
    log_ok "Snapshot przywrócony"
}

start_vm() {
    section "URUCHAMIANIE VM"
    local status
    status=$(get_vm_status)

    if [[ "$status" == "running" ]]; then
        log_ok "VM już działa"
        return
    fi

    log "Uruchamianie VM '$VM_NAME'..."
    start_spinner "Uruchamianie Windows VM..."
    prlctl start "$VM_NAME" >> "$LOG_FILE" 2>&1
    stop_spinner

    # Czekaj aż VM będzie gotowa (Guest Tools response)
    log "Czekam na gotowość systemu Windows (max ${VM_BOOT_TIMEOUT}s)..."
    local waited=0
    while [[ $waited -lt $VM_BOOT_TIMEOUT ]]; do
        if prlctl exec "$VM_NAME" cmd /c "echo ready" &>/dev/null 2>&1; then
            log_ok "VM gotowa po ${waited}s"
            sleep 5  # Dodatkowe 5s na pełne załadowanie pulpitu
            return
        fi
        sleep 3
        ((waited+=3)) || true
        printf "\r${DIM}  Czekam... ${waited}/${VM_BOOT_TIMEOUT}s${RESET}"
    done
    printf "\r\033[K"
    log_warn "VM nie odpowiedziała w ciągu ${VM_BOOT_TIMEOUT}s — kontynuuję..."
}

stop_vm() {
    log "Zatrzymywanie VM..."
    prlctl stop "$VM_NAME" --kill >> "$LOG_FILE" 2>&1 || true
    log_ok "VM zatrzymana"
}

# ═════════════════════════════════════════════════════════════
# KROK 3 — KOPIOWANIE PLIKÓW DO VM
# ═════════════════════════════════════════════════════════════

copy_to_vm() {
    local src="$1"
    local dst="$2"

    log "Kopiuję do VM: $(basename "$src") → $dst"
    if timeout "$VM_COPY_TIMEOUT" prlctl exec "$VM_NAME" \
        cmd /c "mkdir ${dst%\\*} 2>nul & exit 0" >> "$LOG_FILE" 2>&1; then
        true
    fi

    # Użyj prlctl copy (Guest Tools)
    if prlctl copy "$VM_NAME" "$src" "$dst" >> "$LOG_FILE" 2>&1; then
        log_ok "Skopiowano: $(basename "$src")"
        return 0
    fi

    # Fallback: przez shared folder jeśli skonfigurowany
    log_warn "prlctl copy nieudane — próba przez exec..."
    local b64
    b64=$(base64 -i "$src")
    prlctl exec "$VM_NAME" powershell -Command \
        "[IO.File]::WriteAllBytes('$dst', [Convert]::FromBase64String('$b64'))" \
        >> "$LOG_FILE" 2>&1 && log_ok "Skopiowano przez base64" || \
        { log_err "Nie udało się skopiować $src do VM"; return 1; }
}

copy_from_vm() {
    local src_vm="$1"    # Ścieżka Windows w VM
    local dst_host="$2"  # Ścieżka na hoście

    log "Kopiuję z VM: $src_vm → $dst_host"
    if prlctl copy "$VM_NAME" "$src_vm" "$dst_host" --from-guest >> "$LOG_FILE" 2>&1; then
        log_ok "Pobrano: $(basename "$src_vm")"
        return 0
    fi

    # Fallback: zip i base64
    log_warn "Próba przez PowerShell/base64..."
    local tmp_b64="$dst_host.b64"
    prlctl exec "$VM_NAME" powershell -Command \
        "[Convert]::ToBase64String([IO.File]::ReadAllBytes('$src_vm'))" \
        > "$tmp_b64" 2>/dev/null && \
    base64 -d "$tmp_b64" > "$dst_host" && rm -f "$tmp_b64" && \
    log_ok "Pobrano przez base64" || \
    log_err "Nie udało się pobrać: $src_vm"
}

# ═════════════════════════════════════════════════════════════
# KROK 4 — PRZYGOTOWANIE VM (katalogi, Noriben, Procmon)
# ═════════════════════════════════════════════════════════════

prepare_vm_environment() {
    section "PRZYGOTOWANIE ŚRODOWISKA W VM"

    # Utwórz katalogi w VM
    for dir in "C:\\Tools" "C:\\Malware" "C:\\NoribenLogs"; do
        prlctl exec "$VM_NAME" cmd /c "mkdir $dir 2>nul & exit 0" \
            >> "$LOG_FILE" 2>&1 || true
        log_ok "Katalog VM: $dir"
    done

    # Skopiuj Noriben.py jeśli dostępny lokalnie
    if [[ -f "$HOST_TOOLS_DIR/Noriben.py" ]]; then
        copy_to_vm "$HOST_TOOLS_DIR/Noriben.py" "C:\\Tools\\Noriben.py"
    else
        # Pobierz bezpośrednio w VM przez PowerShell
        log "Pobieranie Noriben.py bezpośrednio w VM..."
        prlctl exec "$VM_NAME" powershell -Command \
            "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/Rurik/Noriben/master/Noriben.py' -OutFile 'C:\Tools\Noriben.py'" \
            >> "$LOG_FILE" 2>&1 && log_ok "Noriben.py pobrany w VM" || \
            log_err "Nie udało się pobrać Noriben.py — skopiuj ręcznie do C:\\Tools\\Noriben.py"
    fi

    # Skopiuj procmon64.exe jeśli dostępny
    if [[ -f "$HOST_TOOLS_DIR/procmon64.exe" ]]; then
        copy_to_vm "$HOST_TOOLS_DIR/procmon64.exe" "C:\\Tools\\procmon64.exe"
    else
        log_warn "procmon64.exe nie znaleziony w $HOST_TOOLS_DIR"
        log_warn "Próba pobrania przez winget w VM..."
        prlctl exec "$VM_NAME" powershell -Command \
            "winget install Microsoft.Sysinternals.ProcessMonitor --silent --accept-eula" \
            >> "$LOG_FILE" 2>&1 || \
        log_warn "Pobierz Procmon ręcznie: https://learn.microsoft.com/sysinternals/downloads/procmon"
    fi

    # Sprawdź Python w VM
    log "Sprawdzanie Python w VM..."
    if ! prlctl exec "$VM_NAME" cmd /c "C:\\Python3\\python.exe --version" \
        >> "$LOG_FILE" 2>&1; then
        log_warn "Python nie znaleziony w C:\\Python3\\"
        log_warn "Uruchom $HOST_TOOLS_DIR/vm_setup.ps1 jako Administrator w VM"
        log_warn "Lub zainstaluj Python ręcznie i ustaw VM_PYTHON w skrypcie"
    else
        log_ok "Python dostępny w VM"
    fi

    # Wyłącz Defender dla katalogów roboczych
    log "Konfiguracja Windows Defender (wykluczenia)..."
    prlctl exec "$VM_NAME" powershell -Command \
        "Add-MpPreference -ExclusionPath 'C:\Malware','C:\NoribenLogs','C:\Tools' 2>\$null; \
         Set-MpPreference -DisableRealtimeMonitoring \$true 2>\$null" \
        >> "$LOG_FILE" 2>&1 && log_ok "Defender skonfigurowany" || true
}

# ═════════════════════════════════════════════════════════════
# KROK 5 — URUCHOMIENIE NORIBEN W VM
# ═════════════════════════════════════════════════════════════

run_noriben_analysis() {
    local sample_vm_path="$1"
    section "URUCHOMIENIE NORIBEN W VM"

    local timeout_min=$(( ANALYSIS_TIMEOUT / 60 ))
    echo -e "${YELLOW}${BOLD}"
    echo "  ┌─────────────────────────────────────────────────────┐"
    echo "  │  Noriben monitoruje system Windows podczas analizy  │"
    echo "  │  Próbka:   $(basename "$sample_vm_path")$(printf '%*s' $((40 - ${#sample_vm_path})) '')│"
    printf "  │  Timeout:  %-40s│\n" "${ANALYSIS_TIMEOUT}s (${timeout_min} min)"
    echo "  │  Monitor:  procesy, rejestr, sieć, pliki            │"
    echo "  └─────────────────────────────────────────────────────┘"
    echo -e "${RESET}"

    # Wyczyść poprzednie logi
    prlctl exec "$VM_NAME" cmd /c \
        "del /Q C:\\NoribenLogs\\* 2>nul & exit 0" >> "$LOG_FILE" 2>&1 || true

    # Skonstruuj komendę Noriben
    # Użyj --headless (bez otwierania pliku po zakończeniu)
    # --generalize zastępuje ścieżki zmiennymi %ENV%
    local noriben_cmd="${VM_PYTHON} ${VM_NORIBEN} \
        --cmd \"${sample_vm_path}\" \
        --timeout ${ANALYSIS_TIMEOUT} \
        --output C:\\NoribenLogs \
        --headless \
        --generalize"

    log "Uruchamianie Noriben (timeout: ${ANALYSIS_TIMEOUT}s)..."
    log "Komenda: $noriben_cmd"

    local analysis_start
    analysis_start=$(date +%s)

    # Pokaż live progress podczas analizy
    echo ""
    local elapsed=0
    local pct=0

    # Uruchom Noriben w tle (przez prlctl exec)
    prlctl exec "$VM_NAME" powershell -Command \
        "Start-Process -FilePath '${VM_PYTHON}' \
         -ArgumentList '${VM_NORIBEN}','--cmd','${sample_vm_path}','--timeout','${ANALYSIS_TIMEOUT}','--output','C:\NoribenLogs','--headless','--generalize' \
         -Wait -NoNewWindow -RedirectStandardOutput 'C:\NoribenLogs\noriben_stdout.txt' \
         -RedirectStandardError 'C:\NoribenLogs\noriben_stderr.txt'" \
        >> "$LOG_FILE" 2>&1 &
    local prlctl_pid=$!

    # Progress bar podczas oczekiwania
    while kill -0 $prlctl_pid 2>/dev/null; do
        elapsed=$(( $(date +%s) - analysis_start ))
        pct=$(( elapsed * 100 / (ANALYSIS_TIMEOUT + 30) ))
        [[ $pct -gt 100 ]] && pct=100

        local bar_filled=$(( pct * 40 / 100 ))
        local bar_empty=$(( 40 - bar_filled ))
        local bar
        bar=$(printf '%*s' "$bar_filled" '' | tr ' ' '█')
        bar+=$(printf '%*s' "$bar_empty" '' | tr ' ' '░')

        printf "\r  ${CYAN}[${bar}]${RESET} ${elapsed}s / ${ANALYSIS_TIMEOUT}s  "
        sleep 2
    done
    printf "\r\033[K"

    wait $prlctl_pid 2>/dev/null || true

    local analysis_end
    analysis_end=$(date +%s)
    local duration=$(( analysis_end - analysis_start ))

    log_ok "Analiza zakończona po ${duration}s"

    # Poczekaj chwilę aż Noriben zapisze pliki
    sleep 3
}

# ═════════════════════════════════════════════════════════════
# KROK 6 — KOPIOWANIE WYNIKÓW Z VM
# ═════════════════════════════════════════════════════════════

collect_results() {
    section "POBIERANIE WYNIKÓW Z VM"

    # Znajdź pliki Noriben w VM
    local noriben_files
    noriben_files=$(prlctl exec "$VM_NAME" powershell -Command \
        "Get-ChildItem 'C:\NoribenLogs' | Select-Object -ExpandProperty Name" \
        2>/dev/null || echo "")

    if [[ -z "$noriben_files" ]]; then
        log_warn "Brak plików wyników w C:\\NoribenLogs"
        log_warn "Analiza mogła się nie uruchomić — sprawdź VM ręcznie"
        return 1
    fi

    log "Pliki wyników:"
    echo "$noriben_files" | while read -r f; do
        echo -e "  ${GREEN}→${RESET} $f"
    done

    # Zipuj wyniki w VM i skopiuj ZIP
    local zip_vm="C:\\NoribenLogs\\results_${SESSION_ID}.zip"
    log "Kompresowanie wyników w VM..."
    prlctl exec "$VM_NAME" powershell -Command \
        "Compress-Archive -Path 'C:\NoribenLogs\*' -DestinationPath '$zip_vm' -Force" \
        >> "$LOG_FILE" 2>&1 || {
        log_warn "Compress-Archive niedostępne — kopiuję pliki po kolei..."
        # Fallback: kopiuj pliki jeden po jednym
        echo "$noriben_files" | while IFS= read -r fname; do
            [[ -z "$fname" ]] && continue
            copy_from_vm "C:\\NoribenLogs\\$fname" "$SESSION_DIR/$fname" || true
        done
        return 0
    }

    # Skopiuj ZIP
    local local_zip="$SESSION_DIR/results_${SESSION_ID}.zip"
    copy_from_vm "$zip_vm" "$local_zip"

    if [[ -f "$local_zip" ]]; then
        log "Rozpakowywanie wyników..."
        unzip -q "$local_zip" -d "$SESSION_DIR/" 2>/dev/null && \
            { log_ok "Wyniki rozpakowane do: $SESSION_DIR"; rm -f "$local_zip"; } || \
            log_warn "Błąd rozpakowywania — ZIP dostępny: $local_zip"
    fi
}

# ═════════════════════════════════════════════════════════════
# KROK 7 — ANALIZA WYNIKÓW NORIBEN (na hoście)
# ═════════════════════════════════════════════════════════════

analyze_noriben_results() {
    section "ANALIZA WYNIKÓW NORIBEN"

    # Znajdź pliki TXT (raport) i CSV (raw data)
    local txt_report
    txt_report=$(find "$SESSION_DIR" -name "Noriben_*.txt" 2>/dev/null | head -1)
    local csv_data
    csv_data=$(find "$SESSION_DIR" -name "Noriben_*.csv" 2>/dev/null | head -1)

    if [[ -z "$txt_report" ]]; then
        log_warn "Nie znaleziono raportu TXT Noriben w $SESSION_DIR"
        log_warn "Dostępne pliki:"
        ls -la "$SESSION_DIR/" 2>/dev/null || true
        return 1
    fi

    log_ok "Raport Noriben: $txt_report"
    echo ""

    # Wyświetl raport
    echo -e "${BOLD}═══ ZAWARTOŚĆ RAPORTU NORIBEN ═══${RESET}"
    cat "$txt_report" | tee -a "$LOG_FILE"

    # Analiza IOC z raportu
    echo ""
    section "WYKRYTE WSKAŹNIKI (IOC)"

    local -A ioc_categories=(
        ["Połączenia sieciowe"]="TCP|UDP|DNS|HTTP|connect"
        ["Nowe procesy"]="CreateProcess|Process Create"
        ["Zapis do rejestru"]="RegSetValue|RegCreateKey|HKCU|HKLM"
        ["Nowe pliki"]="CreateFile|WriteFile|\.exe|\.dll|\.bat|\.ps1"
        ["Usunięte pliki"]="DeleteFile|Remove-Item"
        ["Załadowane DLL"]="LoadLibrary|Load Image"
        ["Persistence"]="Run|RunOnce|Startup|LaunchAgent|Schedule"
    )

    local total_ioc=0
    for category in "${!ioc_categories[@]}"; do
        local pattern="${ioc_categories[$category]}"
        local matches
        matches=$(grep -iE "$pattern" "$txt_report" 2>/dev/null | \
            grep -v "^#\|^-\|Procmon\|Noriben" | head -10 || true)
        if [[ -n "$matches" ]]; then
            echo -e "\n  ${RED}[IOC]${RESET} ${BOLD}$category${RESET}"
            echo "$matches" | while IFS= read -r line; do
                echo -e "    ${YELLOW}→${RESET} $line"
            done
            ((total_ioc++)) || true
        fi
    done

    [[ $total_ioc -eq 0 ]] && log_ok "Brak wyraźnych IOC w raporcie" || \
        log_warn "Wykryto $total_ioc kategorii IOC"

    # Jeśli dostępny CSV — zlicz zdarzenia
    if [[ -n "$csv_data" && -f "$csv_data" ]]; then
        echo ""
        log "Statystyki zdarzeń (CSV):"
        local total_events
        total_events=$(wc -l < "$csv_data" 2>/dev/null || echo "?")
        log "  Łączna liczba zdarzeń: $total_events"

        # Top procesy
        log "  Najaktywniejsze procesy:"
        awk -F',' 'NR>1 {print $2}' "$csv_data" 2>/dev/null | \
            sort | uniq -c | sort -rn | head -10 | \
            while read -r count proc; do
                echo -e "    ${count}x ${proc}"
            done | tee -a "$LOG_FILE" || true
    fi

    # Skanowanie YARA (jeśli dostępne)
    if command -v yara &>/dev/null && [[ -f "$txt_report" ]]; then
        echo ""
        log "Skanowanie YARA na raporcie Noriben..."
        local yara_rules="$SESSION_DIR/ioc_rules.yar"
        cat > "$yara_rules" <<'YARARULES'
rule NetworkActivity {
    meta: description = "Aktywność sieciowa wykryta przez Noriben"
    strings:
        $tcp = "TCP" nocase
        $dns = "DNS" nocase
        $http = "http" nocase
        $ip = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+/
    condition: 2 of them
}
rule RegistryPersistence {
    meta: description = "Zapis do kluczy Run/Startup"
    strings:
        $run1 = "CurrentVersion\\Run" nocase
        $run2 = "RunOnce" nocase
        $startup = "Startup" nocase
    condition: 1 of them
}
rule DroppedExecutable {
    meta: description = "Tworzenie pliku wykonywalnego"
    strings:
        $exe = ".exe" nocase
        $dll = ".dll" nocase
        $bat = ".bat" nocase
        $ps1 = ".ps1" nocase
    condition: 2 of them
}
YARARULES
        yara "$yara_rules" "$txt_report" 2>/dev/null | \
            while IFS= read -r hit; do
                log_warn "YARA: $hit"
            done || log_ok "YARA: brak dopasowań"
    fi

    # ClamAV na raporcie + sample
    if command -v clamscan &>/dev/null; then
        echo ""
        log "Skanowanie ClamAV na próbce..."
        start_spinner "ClamAV..."
        local clam_result
        if clam_result=$(clamscan -q "$SAMPLE_FILE" 2>&1); then
            stop_spinner; log_ok "ClamAV: CZYSTY"
        else
            stop_spinner; log_err "ClamAV: WYKRYTO! $clam_result"
        fi
    fi
}

# ═════════════════════════════════════════════════════════════
# KROK 8 — GENEROWANIE RAPORTU HTML
# ═════════════════════════════════════════════════════════════

generate_html_report() {
    section "GENEROWANIE RAPORTU HTML"

    local txt_report
    txt_report=$(find "$SESSION_DIR" -name "Noriben_*.txt" 2>/dev/null | head -1)
    local html_out="$SESSION_DIR/analysis_report_${SESSION_ID}.html"

    local sha256
    sha256=$(shasum -a 256 "$SAMPLE_FILE" | awk '{print $1}')
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    local file_type
    file_type=$(file -b "$SAMPLE_FILE")
    local file_size
    file_size=$(du -sh "$SAMPLE_FILE" | cut -f1)

    local noriben_content=""
    [[ -n "$txt_report" && -f "$txt_report" ]] && \
        noriben_content=$(cat "$txt_report" | \
            sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')

    cat > "$html_out" <<HTMLEOF
<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Noriben Analysis — ${SAMPLE_BASENAME}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Courier New', monospace;
    background: #0d1117;
    color: #c9d1d9;
    padding: 30px;
    line-height: 1.6;
  }
  h1 { color: #58a6ff; font-size: 1.8em; margin-bottom: 5px; }
  h2 { color: #79c0ff; font-size: 1.2em; margin: 25px 0 10px; border-left: 3px solid #388bfd; padding-left: 10px; }
  .header { border-bottom: 1px solid #30363d; padding-bottom: 20px; margin-bottom: 25px; }
  .subtitle { color: #8b949e; font-size: 0.9em; }
  .meta-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 15px;
    margin: 20px 0;
  }
  .meta-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 15px;
  }
  .meta-label { color: #8b949e; font-size: 0.8em; text-transform: uppercase; }
  .meta-value { color: #e6edf3; font-size: 0.95em; margin-top: 4px; word-break: break-all; }
  .meta-value.hash { font-size: 0.75em; color: #3fb950; }
  pre {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 20px;
    overflow-x: auto;
    white-space: pre-wrap;
    font-size: 0.85em;
    line-height: 1.5;
    max-height: 600px;
    overflow-y: auto;
  }
  .badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 0.75em;
    font-weight: bold;
    margin: 2px;
  }
  .badge-blue   { background: #1c3a5e; color: #58a6ff; }
  .badge-green  { background: #0d2818; color: #3fb950; }
  .badge-yellow { background: #3d2f0e; color: #e3b341; }
  .badge-red    { background: #3d1c1c; color: #f85149; }
  .vt-link {
    display: inline-block;
    background: #1c3a5e;
    color: #58a6ff;
    padding: 8px 16px;
    border-radius: 6px;
    text-decoration: none;
    margin-top: 10px;
  }
  .vt-link:hover { background: #2d5a8e; }
  footer { color: #8b949e; font-size: 0.8em; margin-top: 40px; border-top: 1px solid #30363d; padding-top: 15px; }
  .config-table { width: 100%; border-collapse: collapse; }
  .config-table td { padding: 6px 10px; border-bottom: 1px solid #21262d; }
  .config-table tr:last-child td { border-bottom: none; }
  .config-table td:first-child { color: #8b949e; width: 180px; }
</style>
</head>
<body>

<div class="header">
  <h1>🔬 Noriben Sandbox Analysis</h1>
  <p class="subtitle">Parallels Desktop + Noriben + Sysinternals Procmon</p>
  <p class="subtitle" style="margin-top:5px">Analiza: $ts | Sesja: $SESSION_ID</p>
</div>

<h2>📁 Informacje o próbce</h2>
<div class="meta-grid">
  <div class="meta-card">
    <div class="meta-label">Nazwa pliku</div>
    <div class="meta-value">${SAMPLE_BASENAME}</div>
  </div>
  <div class="meta-card">
    <div class="meta-label">Typ pliku</div>
    <div class="meta-value">${file_type}</div>
  </div>
  <div class="meta-card">
    <div class="meta-label">Rozmiar</div>
    <div class="meta-value">${file_size}</div>
  </div>
  <div class="meta-card">
    <div class="meta-label">SHA256</div>
    <div class="meta-value hash">${sha256}</div>
  </div>
</div>

<h2>⚙️ Konfiguracja analizy</h2>
<div class="meta-card">
<table class="config-table">
  <tr><td>VM</td><td>${VM_NAME}</td></tr>
  <tr><td>Snapshot</td><td>${VM_SNAPSHOT}</td></tr>
  <tr><td>Timeout analizy</td><td>${ANALYSIS_TIMEOUT}s ($(( ANALYSIS_TIMEOUT/60 )) min)</td></tr>
  <tr><td>Noriben</td><td>${VM_NORIBEN}</td></tr>
  <tr><td>Procmon</td><td>${VM_PROCMON}</td></tr>
</table>
</div>

<h2>🔗 Sprawdź w VirusTotal</h2>
<a class="vt-link" href="https://www.virustotal.com/gui/file/${sha256}" target="_blank">
  🔍 Otwórz w VirusTotal →
</a>

<h2>📋 Raport Noriben</h2>
$(if [[ -n "$noriben_content" ]]; then
    echo "<pre>$noriben_content</pre>"
else
    echo "<div class='meta-card'><div class='meta-value' style='color:#f85149'>Brak raportu Noriben — analiza mogła się nie uruchomić poprawnie.</div></div>"
fi)

<h2>📄 Log hosta (macOS)</h2>
<pre>$(cat "$LOG_FILE" 2>/dev/null | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' | tail -100)</pre>

<footer>
  Wygenerowano przez noriben_parallels_setup.sh v${VERSION} | macOS → Parallels → Noriben
</footer>
</body>
</html>
HTMLEOF

    log_ok "Raport HTML: $html_out"
    echo "$html_out"
}

# ═════════════════════════════════════════════════════════════
# CLEANUP
# ═════════════════════════════════════════════════════════════

cleanup() {
    stop_spinner
    echo ""
    if [[ -n "$VM_NAME" ]] && vm_exists 2>/dev/null; then
        local status
        status=$(get_vm_status 2>/dev/null || echo "unknown")
        if [[ "$status" == "running" ]]; then
            log "Zatrzymywanie VM po analizie..."
            stop_vm || true
        fi
    fi
}

# ═════════════════════════════════════════════════════════════
# TRYB SETUP (pierwsze uruchomienie)
# ═════════════════════════════════════════════════════════════

run_setup_mode() {
    section "TRYB KONFIGURACJI"
    echo ""
    echo -e "${BOLD}Ten tryb pomoże Ci skonfigurować środowisko Noriben + Parallels.${RESET}"
    echo ""

    mkdir -p "$HOST_TOOLS_DIR" "$HOST_RESULTS_DIR"

    echo -e "${CYAN}${BOLD}Krok 1: Sprawdzenie narzędzi${RESET}"
    LOG_FILE="/tmp/noriben_setup_$$.log"
    touch "$LOG_FILE"
    check_host_tools

    echo ""
    echo -e "${CYAN}${BOLD}Krok 2: Pobieranie Noriben i przygotowanie skryptów${RESET}"
    download_noriben_tools

    echo ""
    echo -e "${CYAN}${BOLD}Krok 3: Dostępne VM w Parallels${RESET}"
    if command -v prlctl &>/dev/null; then
        list_available_vms
    fi

    echo ""
    echo -e "${BOLD}═══ Instrukcja konfiguracji VM ═══${RESET}"
    echo ""
    echo -e "1. Otwórz Parallels Desktop i uruchom VM Windows"
    echo -e "2. W VM uruchom PowerShell jako Administrator i wykonaj:"
    echo -e "   ${CYAN}Set-ExecutionPolicy Bypass -Scope Process -Force${RESET}"
    echo -e "   ${CYAN}# Skopiuj plik vm_setup.ps1 do VM i uruchom:${RESET}"
    echo -e "   ${CYAN}\\$PSVersionTable | Select-Object PSVersion${RESET}"
    echo ""
    echo -e "3. Skopiuj następujące pliki do VM:"
    echo -e "   ${YELLOW}$HOST_TOOLS_DIR/Noriben.py${RESET} → ${CYAN}C:\\Tools\\Noriben.py${RESET}"
    echo -e "   ${YELLOW}procmon64.exe${RESET} → ${CYAN}C:\\Tools\\procmon64.exe${RESET}"
    echo -e "   ${YELLOW}$HOST_TOOLS_DIR/vm_setup.ps1${RESET} → VM i uruchom"
    echo ""
    echo -e "4. Zainstaluj Python 3 w VM (C:\\Python3\\python.exe)"
    echo ""
    echo -e "5. Utwórz snapshot VM:"
    echo -e "   Parallels Desktop → Actions → Take Snapshot"
    echo -e "   Nazwa: ${BOLD}$VM_SNAPSHOT${RESET}"
    echo ""
    echo -e "6. Ustaw VM_NAME w tym skrypcie na: ${BOLD}$(prlctl list --all 2>/dev/null | grep -v UUID | head -2 | tail -1 | awk '{print $NF}' || echo "nazwa_twojej_VM")${RESET}"
    echo ""
    echo -e "${GREEN}${BOLD}Po konfiguracji uruchom analizę:${RESET}"
    echo -e "  ${CYAN}$0 ~/Downloads/podejrzany.exe${RESET}"
    echo ""
    echo -e "Pliki konfiguracyjne zapisane w: ${BOLD}$HOST_TOOLS_DIR${RESET}"

    rm -f "$LOG_FILE"
}

# ═════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════

main() {
    print_banner

    # Parsowanie argumentów
    local setup_mode=false
    local no_revert=false
    local no_cleanup=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --setup)        setup_mode=true ;;
            --no-revert)    no_revert=true ;;
            --no-cleanup)   no_cleanup=true ;;
            --vm)           shift; VM_NAME="$1" ;;
            --snapshot)     shift; VM_SNAPSHOT="$1" ;;
            --timeout)      shift; ANALYSIS_TIMEOUT="$1" ;;
            --list-vms)
                prlctl list --all 2>/dev/null
                exit 0 ;;
            --help|-h)
                echo "Użycie: $0 <próbka.exe> [opcje]"
                echo ""
                echo "  --setup           Tryb konfiguracji (pierwsze uruchomienie)"
                echo "  --vm <nazwa>      Nazwa VM (domyślnie: '$VM_NAME')"
                echo "  --snapshot <n>    Nazwa snapshota (domyślnie: '$VM_SNAPSHOT')"
                echo "  --timeout <s>     Czas analizy w sekundach (domyślnie: $ANALYSIS_TIMEOUT)"
                echo "  --no-revert       Nie przywracaj snapshota przed analizą"
                echo "  --no-cleanup      Nie zatrzymuj VM po analizie"
                echo "  --list-vms        Wylistuj dostępne VM"
                echo ""
                echo "Zmienne środowiskowe:"
                echo "  VM_NAME           Nazwa VM Parallels"
                echo "  VM_SNAPSHOT       Nazwa snapshota"
                echo "  VM_USER           Użytkownik Windows VM"
                echo "  VM_PASS           Hasło Windows VM"
                echo "  ANALYSIS_TIMEOUT  Czas analizy (sekundy)"
                echo ""
                echo "Przykłady:"
                echo "  $0 --setup"
                echo "  $0 ~/Downloads/malware.exe"
                echo "  $0 ~/Downloads/malware.exe --timeout 600 --vm 'Win11 Sandbox'"
                exit 0 ;;
            -*)
                echo -e "${RED}Nieznana opcja: $1${RESET}"; exit 1 ;;
            *)
                SAMPLE_FILE="$1" ;;
        esac
        shift
    done

    # Tryb setup
    if $setup_mode; then
        run_setup_mode
        exit 0
    fi

    # Walidacja próbki
    if [[ -z "$SAMPLE_FILE" ]]; then
        echo -e "${RED}Błąd: podaj plik do analizy${RESET}"
        echo "Użycie: $0 <plik.exe> [--vm <nazwa_vm>] [--timeout <sekundy>]"
        echo "Pierwsze uruchomienie: $0 --setup"
        exit 1
    fi

    [[ ! -f "$SAMPLE_FILE" ]] && { echo -e "${RED}Plik nie istnieje: $SAMPLE_FILE${RESET}"; exit 1; }

    SAMPLE_BASENAME=$(basename "$SAMPLE_FILE")
    SESSION_ID=$(date '+%Y%m%d_%H%M%S')
    SESSION_DIR="$HOST_RESULTS_DIR/${SAMPLE_BASENAME}_${SESSION_ID}"
    LOG_FILE="$SESSION_DIR/host_analysis.log"

    mkdir -p "$SESSION_DIR"
    touch "$LOG_FILE"

    trap cleanup EXIT INT TERM

    {
        echo "═══════════════════════════════════════════"
        echo "  Noriben + Parallels Analysis"
        echo "  Sesja: $SESSION_ID"
        echo "  Próbka: $SAMPLE_FILE"
        echo "  VM: $VM_NAME | Snapshot: $VM_SNAPSHOT"
        echo "  Timeout: ${ANALYSIS_TIMEOUT}s"
        echo "  $(date)"
        echo "═══════════════════════════════════════════"
    } >> "$LOG_FILE"

    log "Sesja: $SESSION_ID"
    log "Wyniki będą w: $SESSION_DIR"

    # ── Wykonaj kroki analizy ──────────────────────────────
    check_host_tools
    download_noriben_tools

    # Sprawdź VM
    if ! vm_exists; then
        log_err "VM '$VM_NAME' nie istnieje w Parallels!"
        list_available_vms
        echo ""
        echo -e "  Zmień VM_NAME lub użyj: ${CYAN}$0 --vm 'Nazwa VM' $SAMPLE_FILE${RESET}"
        echo -e "  Konfiguracja: ${CYAN}$0 --setup${RESET}"
        exit 1
    fi

    # Przywróć snapshot (czyste środowisko)
    $no_revert || revert_to_snapshot

    # Uruchom VM
    start_vm

    # Przygotuj środowisko w VM
    prepare_vm_environment

    # Skopiuj próbkę do VM
    section "KOPIOWANIE PRÓBKI DO VM"
    local sample_vm_path="${VM_MALWARE_DIR}\\${SAMPLE_BASENAME}"
    copy_to_vm "$SAMPLE_FILE" "$sample_vm_path"

    # Uruchom analizę Noriben
    run_noriben_analysis "$sample_vm_path"

    # Pobierz wyniki
    collect_results

    # Analizuj wyniki na hoście
    analyze_noriben_results

    # Generuj raport HTML
    local html_report
    html_report=$(generate_html_report)

    # Finalne podsumowanie
    echo ""
    echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════╗"
    echo -e "║  ✅ Analiza zakończona!                      ║"
    echo -e "╚══════════════════════════════════════════════╝${RESET}"
    echo ""
    echo -e "  📁 Katalog wyników: ${BOLD}$SESSION_DIR${RESET}"
    echo -e "  📄 Log hosta:       ${BOLD}$LOG_FILE${RESET}"
    [[ -n "$html_report" ]] && echo -e "  🌐 Raport HTML:     ${BOLD}$html_report${RESET}"
    echo ""
    echo -e "  Otwórz raport:"
    echo -e "  ${DIM}open '$html_report'${RESET}"
    echo ""

    local sha256
    sha256=$(shasum -a 256 "$SAMPLE_FILE" | awk '{print $1}')
    echo -e "  VirusTotal: ${DIM}https://www.virustotal.com/gui/file/$sha256${RESET}"
    echo ""
}

main "$@"
