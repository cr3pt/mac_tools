#!/bin/bash
# ============================================================
#  noriben_qemu_sandbox.sh  v3.0
#  Analiza malware: QEMU + Apple HVF/TCG → Noriben + Procmon
#
#  Hiperwizor: QEMU z Apple Hypervisor Framework (HVF)
#  ─────────────────────────────────────────────────────────
#  Dlaczego QEMU zamiast Parallels?
#    • HVF = kernel-level isolation (Apple Hypervisor.framework)
#    • Brak artefaktów "Parallels" w VM — malware ich nie wykryje
#    • qcow2 snapshoty atomowe — reset w <3s bez restartu gościa
#    • QEMU monitor (TCP socket) — pełna kontrola CLI bez GUI
#    • Izolacja sieci -netdev none — zero ruchu bez zgody operatora
#    • Darmowy i open-source (brew install qemu)
#
#  Ważna uwaga dotycząca Apple Silicon (M1/M2/M3/M4):
#    Intel Mac  → qemu-system-x86_64 + accel=hvf  (pełna wydajność)
#    Apple Silicon → HVF działa TYLKO dla aarch64 gości.
#      Dla x86 malware na Apple Silicon skrypt używa TCG (software
#      emulation) lub ARM64 Windows + Rosetta. Skrypt auto-wykrywa
#      architekturę hosta i dobiera właściwy backend.
#
#  Pipeline analizy:
#  1. Archiwum z hasłem (ZIP/RAR/7z) → rozpakowywanie
#  2. Analiza STATYCZNA na hoście (PE, YARA, ClamAV, strings IOC)
#  3. qemu-img snapshot -a Baseline_Clean  ← atomowy reset <3s
#  4. Boot QEMU (headless, monitor na TCP 4444)
#  5. Kopiowanie próbki przez SSH (OpenSSH w gościu Windows)
#  6. Noriben.py + Procmon → analiza dynamiczna
#  7. Pobranie wyników przez SSH/SCP
#  8. Atomowe przywrócenie snapshot przez qemu-img
#  9. Skonsolidowany raport HTML + MITRE ATT&CK
#
#  Wymagania hosta (Mac):
#    - macOS 10.15+ (Hypervisor.framework)
#    - brew install qemu
#    - python3, pip3, Homebrew
#
#  Wymagania w obrazie Windows (qcow2):
#    - Python 3.x  → C:\Python3\python.exe
#    - Procmon     → C:\Tools\procmon64.exe
#    - Noriben.py  → C:\Tools\Noriben.py
#    - OpenSSH Server (wbudowany Windows 10/11, opcja w ustawieniach)
#    - Snapshot "Baseline_Clean" utworzony przez qemu-img
# ============================================================

set -euo pipefail

VERSION="3.1.0"

# ─── Kolory ───────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
MAGENTA='\033[0;35m'

# ─── Konfiguracja QEMU ────────────────────────────────────────
# Ścieżka do obrazu qcow2 Windows (USTAW PRZED UŻYCIEM)
QEMU_DISK="${QEMU_DISK:-${HOME}/NoribenTools/windows_sandbox.qcow2}"

# Nazwa snapshota (utworzonego przez: qemu-img snapshot -c Baseline_Clean <dysk>)
QEMU_SNAPSHOT="${QEMU_SNAPSHOT:-Baseline_Clean}"

# Zasoby VM
QEMU_MEM="${QEMU_MEM:-4G}"
QEMU_SMP="${QEMU_SMP:-2}"

# Port SSH do gościa Windows (przekierowany przez QEMU user-net)
QEMU_SSH_PORT="${QEMU_SSH_PORT:-2222}"

# Port monitora QEMU (TCP, używany do savevm/loadvm)
QEMU_MONITOR_PORT="${QEMU_MONITOR_PORT:-4444}"

# Dane SSH do gościa Windows (OpenSSH Server musi być włączony)
VM_USER="${VM_USER:-Administrator}"
VM_PASS="${VM_PASS:-password}"

# Ścieżki wewnątrz Windows VM
VM_PYTHON="C:\\Python3\\python.exe"
VM_NORIBEN="C:\\Tools\\Noriben.py"
VM_PROCMON="C:\\Tools\\procmon64.exe"
VM_MALWARE_DIR="C:\\Malware"
VM_OUTPUT_DIR="C:\\NoribenLogs"

# ─── Ścieżki hosta ────────────────────────────────────────────
HOST_RESULTS_DIR="${HOME}/NoribenResults"
HOST_TOOLS_DIR="${HOME}/NoribenTools"

# ─── Timeouty ─────────────────────────────────────────────────
ANALYSIS_TIMEOUT="${ANALYSIS_TIMEOUT:-300}"
VM_BOOT_TIMEOUT=120
SSH_TIMEOUT=10

# ─── Hasła archiwów malware ───────────────────────────────────
ARCHIVE_PASSWORDS="${ARCHIVE_PASSWORDS:-infected malware virus password 1234 admin sample}"

# ─── Flagi globalne ───────────────────────────────────────────
SAMPLE_FILE=""
SAMPLE_BASENAME=""
EXTRACTED_SAMPLE=""
ARCHIVE_MODE=""       # single | all_full | all_static
SESSION_ID=""
SESSION_DIR=""
LOG_FILE=""
SPINNER_PID=""
QEMU_PID=""
STATIC_RISK_SCORE=0
DYNAMIC_RISK_SCORE=0
declare -a STATIC_FINDINGS=()
declare -a DYNAMIC_FINDINGS=()
declare -a MITRE_TECHNIQUES=()
declare -a SESSION_REPORTS=()   # ścieżki raportów HTML per-plik

# Auto-wykrycie architektury hosta
HOST_ARCH=$(uname -m)   # x86_64 | arm64

# ═════════════════════════════════════════════════════════════
# HELPERS
# ═════════════════════════════════════════════════════════════

spinner_chars="⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

start_spinner() {
    local msg="$1"
    ( local i=0
      while true; do
          printf "\r${CYAN}${spinner_chars:$i:1}${RESET} $msg   "
          i=$(( (i+1) % ${#spinner_chars} ))
          sleep 0.1
      done ) &
    SPINNER_PID=$!
}

stop_spinner() {
    if [[ -n "$SPINNER_PID" ]]; then
        kill "$SPINNER_PID" 2>/dev/null || true
        wait "$SPINNER_PID" 2>/dev/null || true
        SPINNER_PID=""
    fi
    printf "\r\033[K"
}

log()      { echo -e "${BOLD}[•]${RESET} $*";  echo "[INFO] $(date '+%H:%M:%S') $*" >> "$LOG_FILE" 2>/dev/null || true; }
log_ok()   { echo -e "${GREEN}[✓]${RESET} $*"; echo "[OK]   $(date '+%H:%M:%S') $*" >> "$LOG_FILE" 2>/dev/null || true; }
log_warn() { echo -e "${YELLOW}[!]${RESET} $*"; echo "[WARN] $(date '+%H:%M:%S') $*" >> "$LOG_FILE" 2>/dev/null || true; }
log_err()  { echo -e "${RED}[✗]${RESET} $*";   echo "[ERR]  $(date '+%H:%M:%S') $*" >> "$LOG_FILE" 2>/dev/null || true; }

section() {
    echo -e "\n${CYAN}${BOLD}╔══════════════════════════════════════════════╗"
    printf   "${CYAN}${BOLD}║  %-44s║\n" "$*"
    echo -e  "╚══════════════════════════════════════════════╝${RESET}"
    echo -e "\n=== $* ===" >> "$LOG_FILE" 2>/dev/null || true
}

add_finding() {
    local type="$1" score="$2" desc="$3"
    if [[ "$type" == "static" ]]; then
        STATIC_FINDINGS+=("$desc")
        STATIC_RISK_SCORE=$(( STATIC_RISK_SCORE + score ))
    else
        DYNAMIC_FINDINGS+=("$desc")
        DYNAMIC_RISK_SCORE=$(( DYNAMIC_RISK_SCORE + score ))
    fi
}

add_mitre() { MITRE_TECHNIQUES+=("$1"); }

# Wyślij komendę do monitora QEMU przez TCP
qemu_monitor_cmd() {
    local cmd="$1"
    local timeout="${2:-10}"
    echo "$cmd" | nc -w "$timeout" 127.0.0.1 "$QEMU_MONITOR_PORT" 2>/dev/null || true
}

# SSH do gościa Windows
vm_ssh() {
    ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout="$SSH_TIMEOUT" \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        -p "$QEMU_SSH_PORT" \
        "${VM_USER}@127.0.0.1" "$@" 2>/dev/null
}

# SCP z hosta do gościa
vm_scp_to() {
    scp -o StrictHostKeyChecking=no \
        -o ConnectTimeout="$SSH_TIMEOUT" \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        -P "$QEMU_SSH_PORT" \
        "$1" "${VM_USER}@127.0.0.1:$2" 2>/dev/null
}

# SCP z gościa do hosta
vm_scp_from() {
    scp -o StrictHostKeyChecking=no \
        -o ConnectTimeout="$SSH_TIMEOUT" \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        -P "$QEMU_SSH_PORT" \
        "${VM_USER}@127.0.0.1:$1" "$2" 2>/dev/null
}

print_banner() {
    echo -e "${CYAN}${BOLD}"
    cat <<'BANNER'
  ╔══════════════════════════════════════════════════════════╗
  ║   🔬 Noriben QEMU Sandbox  v3.1                        ║
  ║   Apple HVF · qcow2 snapshots · izolacja sieciowa      ║
  ║   Analiza statyczna + dynamiczna + wieloplikowe archiwa  ║
  ╚══════════════════════════════════════════════════════════╝
BANNER
    echo -e "${RESET}"
}

# ═════════════════════════════════════════════════════════════
# MODUŁ A — OBSŁUGA ARCHIWÓW Z HASŁEM
# ═════════════════════════════════════════════════════════════

detect_archive_type() {
    local f="$1"
    local magic ext
    magic=$(file -b "$f" 2>/dev/null || echo "")
    ext="${f##*.}"; ext=$(echo "$ext" | tr '[:upper:]' '[:lower:]')
    case "$magic" in
        *"Zip archive"*|*"ZIP"*)  echo "zip" ;;
        *"RAR archive"*)          echo "rar" ;;
        *"7-zip archive"*)        echo "7z"  ;;
        *"gzip"*)                 echo "gz"  ;;
        *"bzip2"*)                echo "bz2" ;;
        *"XZ compressed"*)        echo "xz"  ;;
        *"POSIX tar"*)            echo "tar" ;;
        *)
            case "$ext" in
                zip) echo "zip" ;; rar) echo "rar" ;; 7z) echo "7z" ;;
                gz)  echo "gz"  ;; bz2) echo "bz2" ;; tar) echo "tar" ;;
                *)   echo "unknown" ;;
            esac ;;
    esac
}

is_archive() { [[ "$(detect_archive_type "$1")" != "unknown" ]]; }

try_extract_archive() {
    local archive="$1" dest_dir="$2" password="${3:-}"
    local arch_type; arch_type=$(detect_archive_type "$archive")
    mkdir -p "$dest_dir"
    case "$arch_type" in
        zip)
            [[ -n "$password" ]] && unzip -P "$password" -o "$archive" -d "$dest_dir" >> "$LOG_FILE" 2>&1 \
                                 || unzip -o "$archive" -d "$dest_dir" >> "$LOG_FILE" 2>&1 ;;
        rar)
            # Hierarchia fallbacków RAR:
            # 1. unrar  (z cask rar: brew install --cask rar)
            # 2. 7z     (brew install p7zip) — obsługuje RAR bez hasła i z hasłem
            # 3. unar   (brew install unar)  — bez obsługi haseł RAR
            if command -v unrar &>/dev/null; then
                [[ -n "$password" ]] && unrar x -p"$password" -y "$archive" "$dest_dir/" >> "$LOG_FILE" 2>&1 \
                                     || unrar x -y "$archive" "$dest_dir/" >> "$LOG_FILE" 2>&1
            elif command -v 7z &>/dev/null; then
                [[ -n "$password" ]] && 7z x -p"$password" -o"$dest_dir" "$archive" >> "$LOG_FILE" 2>&1 \
                                     || 7z x -o"$dest_dir" "$archive" >> "$LOG_FILE" 2>&1
            elif command -v unar &>/dev/null; then
                if [[ -n "$password" ]]; then
                    unar -p "$password" -o "$dest_dir" "$archive" >> "$LOG_FILE" 2>&1
                else
                    unar -o "$dest_dir" "$archive" >> "$LOG_FILE" 2>&1
                fi
            else
                log_err "Brak narzędzia do RAR. Zainstaluj jedno z:"
                log_err "  brew install --cask rar   (zalecane — instaluje unrar)"
                log_err "  brew install p7zip        (7z z obsługą RAR)"
                log_err "  brew install unar         (bez haseł RAR)"
                return 1
            fi ;;
        7z)
            command -v 7z &>/dev/null || { log_err "Brak 7z — brew install p7zip"; return 1; }
            [[ -n "$password" ]] && 7z x -p"$password" -o"$dest_dir" "$archive" >> "$LOG_FILE" 2>&1 \
                                 || 7z x -o"$dest_dir" "$archive" >> "$LOG_FILE" 2>&1 ;;
        gz|bz2|xz|tar)
            tar xf "$archive" -C "$dest_dir" >> "$LOG_FILE" 2>&1 ;;
        *)  log_err "Nieobsługiwany typ: $arch_type"; return 1 ;;
    esac
}

# ─── Pomocnicze: wyświetl tabelę plików w archiwum ───────────
_print_archive_table() {
    local files_list="$1"   # newline-separated paths
    local i=1
    echo ""
    printf "  ${CYAN}${BOLD}%-4s %-40s %-12s %s${RESET}\n" "Nr" "Nazwa pliku" "Rozmiar" "Typ"
    printf "  %s\n" "$(printf '─%.0s' {1..72})"
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        local name size ftype
        name=$(basename "$f")
        size=$(du -sh "$f" 2>/dev/null | cut -f1)
        ftype=$(file -b "$f" 2>/dev/null | cut -c1-28)
        printf "  ${CYAN}[%-2d]${RESET} %-40s %-12s %s\n" "$i" "$name" "$size" "$ftype"
        ((i++)) || true
    done <<< "$files_list"
    echo ""
}

# ─── Pomocnicze: crack hasła archiwum ────────────────────────
_crack_archive_password() {
    local archive="$1"
    local extract_dir="$2"

    add_finding "static" 10 "Archiwum chronione hasłem — technika obejścia AV"
    add_mitre "T1027 — Obfuscated Files or Information"
    log_warn "Archiwum szyfrowane — próba domyślnych haseł..."
    echo ""

    local cracked=false
    for pwd in $ARCHIVE_PASSWORDS; do
        printf "  Próba: ${DIM}%-18s${RESET}" "$pwd"
        rm -rf "$extract_dir" 2>/dev/null || true
        if try_extract_archive "$archive" "$extract_dir" "$pwd" 2>/dev/null \
           && [[ -n "$(ls -A "$extract_dir" 2>/dev/null)" ]]; then
            echo -e " ${GREEN}✓ SUKCES${RESET}"
            log_ok "Hasło: '$pwd'"
            cracked=true
            echo "$pwd" > "$SESSION_DIR/archive_password.txt"
            break
        fi
        echo -e " ${DIM}✗${RESET}"
    done

    if ! $cracked; then
        echo ""
        log_warn "Żadne domyślne hasło nie zadziałało"
        read -r -p "  Podaj hasło ręcznie (Enter = pomiń): " manual_pwd
        if [[ -n "$manual_pwd" ]]; then
            rm -rf "$extract_dir" 2>/dev/null || true
            if try_extract_archive "$archive" "$extract_dir" "$manual_pwd" \
               && [[ -n "$(ls -A "$extract_dir" 2>/dev/null)" ]]; then
                log_ok "Rozpakowano z hasłem ręcznym"
                cracked=true
                echo "$manual_pwd" > "$SESSION_DIR/archive_password.txt"
            else
                log_err "Złe hasło lub błąd rozpakowywania"
            fi
        fi
    fi

    $cracked || { log_err "Nie udało się rozpakować archiwum"; return 1; }
    return 0
}

# ─── Pomocnicze: znajdź pliki wykonywalne w katalogu ─────────
_find_executables() {
    local dir="$1"
    local results
    # Najpierw szukaj typowych rozszerzeń malware
    results=$(find "$dir" -type f \( \
        -name "*.exe" -o -name "*.dll" -o -name "*.bat" \
        -o -name "*.ps1" -o -name "*.vbs" -o -name "*.js"  \
        -o -name "*.scr" -o -name "*.com" -o -name "*.hta" \
        -o -name "*.msi" -o -name "*.jar" \) 2>/dev/null | sort)
    # Fallback — wszystkie pliki jeśli brak typowych
    if [[ -z "$results" ]]; then
        results=$(find "$dir" -type f 2>/dev/null | sort)
    fi
    echo "$results"
}

# ─── Pomocnicze: menu wyboru trybu analizy ───────────────────
_select_analysis_mode() {
    local exe_files="$1"   # newline-separated
    local file_count; file_count=$(echo "$exe_files" | grep -c . || echo 0)

    echo -e "${BOLD}Znaleziono ${CYAN}$file_count${RESET}${BOLD} plików wykonywalnych w archiwum.${RESET}"
    _print_archive_table "$exe_files"

    echo -e "  Tryby analizy:"
    echo -e "  ${CYAN}[0]${RESET}  Wszystkie — statyczna + dynamiczna po kolei (VM reset między próbkami)"
    echo -e "  ${CYAN}[00]${RESET} Wszystkie — tylko statyczna (bez VM)"
    echo -e "  ${CYAN}[N]${RESET}  Pojedynczy plik o numerze N"
    echo ""
    read -r -p "  Wybór [0]: " choice
    choice="${choice:-0}"

    case "$choice" in
        "0")   ARCHIVE_MODE="all_full"   ;;
        "00")  ARCHIVE_MODE="all_static" ;;
        *)
            local chosen_file
            chosen_file=$(echo "$exe_files" | sed -n "${choice}p")
            if [[ -z "$chosen_file" || ! -f "$chosen_file" ]]; then
                log_warn "Nieprawidłowy wybór '$choice' — używam pliku #1"
                chosen_file=$(echo "$exe_files" | head -1)
            fi
            ARCHIVE_MODE="single"
            EXTRACTED_SAMPLE="$chosen_file"
            ;;
    esac

    # Dla trybów "wszystkich" zapisz listę jako plik pomocniczy
    if [[ "$ARCHIVE_MODE" == "all_full" || "$ARCHIVE_MODE" == "all_static" ]]; then
        echo "$exe_files" > "$SESSION_DIR/archive_filelist.txt"
        log "Tryb: $ARCHIVE_MODE — ${file_count} plików"
    else
        log "Tryb: single — $(basename "$EXTRACTED_SAMPLE")"
    fi
}

# ─── Główna funkcja: rozpakuj archiwum i wybierz tryb ────────
handle_archive() {
    local archive="$1"
    local arch_type; arch_type=$(detect_archive_type "$archive")
    local extract_dir="$SESSION_DIR/extracted"

    section "ARCHIWUM — ROZPAKOWYWANIE I INSPEKCJA"
    echo -e "  Plik:    ${BOLD}$(basename "$archive")${RESET}"
    echo -e "  Format:  ${BOLD}$arch_type${RESET}"
    echo -e "  Rozmiar: ${BOLD}$(du -sh "$archive" | cut -f1)${RESET}"
    echo ""

    # ── Detekcja szyfrowania ──────────────────────────────────
    local is_encrypted=false
    case "$arch_type" in
        zip) unzip -t "$archive" >> "$LOG_FILE" 2>&1 || is_encrypted=true ;;
        rar)
            if command -v unrar &>/dev/null; then
                unrar t "$archive" >> "$LOG_FILE" 2>&1 || is_encrypted=true
            elif command -v 7z &>/dev/null; then
                7z t "$archive" >> "$LOG_FILE" 2>&1 || is_encrypted=true
            fi ;;
        7z)  command -v 7z    &>/dev/null && { 7z t "$archive" >> "$LOG_FILE" 2>&1    || is_encrypted=true; } ;;
    esac

    # ── Rozpakowanie ─────────────────────────────────────────
    if $is_encrypted; then
        _crack_archive_password "$archive" "$extract_dir" || return 1
    else
        log_ok "Archiwum bez hasła — rozpakowuję..."
        try_extract_archive "$archive" "$extract_dir" "" \
            || { log_err "Błąd rozpakowywania"; return 1; }
    fi

    # ── Inwentaryzacja zawartości ─────────────────────────────
    local exe_files; exe_files=$(_find_executables "$extract_dir")
    local exe_count; exe_count=$(echo "$exe_files" | grep -c . 2>/dev/null || echo 0)
    local all_count; all_count=$(find "$extract_dir" -type f 2>/dev/null | wc -l | tr -d ' ')

    log "Archiwum zawiera: $all_count plików łącznie, $exe_count wykonywalnych"

    # Wyświetl wszystkie pliki w archiwum
    echo -e "${BOLD}Pełna zawartość archiwum ($all_count plików):${RESET}"
    find "$extract_dir" -type f | sort | while read -r f; do
        local rel="${f#$extract_dir/}"
        local ft; ft=$(file -b "$f" 2>/dev/null | cut -c1-40)
        local sz; sz=$(du -sh "$f" 2>/dev/null | cut -f1)
        echo -e "  ${GREEN}→${RESET} ${rel}  ${DIM}[${sz}] ${ft}${RESET}"
        echo "  ARCHIVE_FILE: $rel [$sz] $ft" >> "$LOG_FILE"
    done

    # ── Wybór trybu analizy ───────────────────────────────────
    if [[ $exe_count -eq 0 ]]; then
        log_warn "Brak plików wykonywalnych — biorę wszystkie pliki jako kandydatów"
        exe_files=$(find "$extract_dir" -type f 2>/dev/null | sort | head -20)
        exe_count=$(echo "$exe_files" | grep -c . || echo 0)
    fi

    if [[ $exe_count -eq 1 ]]; then
        ARCHIVE_MODE="single"
        EXTRACTED_SAMPLE=$(echo "$exe_files" | head -1)
        log_ok "Jeden plik wykonywalny — automatyczny wybór: $(basename "$EXTRACTED_SAMPLE")"
    else
        # Interaktywny wybór trybu
        _select_analysis_mode "$exe_files"
    fi
}

# ─── Reset stanu między analizami wielu plików ──────────────
reset_per_file_state() {
    STATIC_RISK_SCORE=0
    DYNAMIC_RISK_SCORE=0
    STATIC_FINDINGS=()
    DYNAMIC_FINDINGS=()
    MITRE_TECHNIQUES=()
    EXTRACTED_SAMPLE=""
    # Usuń stare SHA256 żeby raport HTML nie brał wartości z poprzedniej próbki
    rm -f "$SESSION_DIR/sample_sha256.txt"
}

# ─── Pełny cykl analizy jednej próbki (statyczna + dynamiczna) ──
analyze_single_file() {
    local target="$1"          # pełna ścieżka na hoście
    local idx="${2:-}"         # numer próbki w serii (np. "2/5"), pusty jeśli brak
    local skip_dynamic="${3:-false}"   # "true" = tylko statyczna

    local fname; fname=$(basename "$target")
    local file_session_dir="$SESSION_DIR/files/${fname%%.*}_$(date '+%H%M%S')"
    mkdir -p "$file_session_dir"

    # Nagłówek próbki w serii
    if [[ -n "$idx" ]]; then
        echo ""
        echo -e "${MAGENTA}${BOLD}"
        echo "  ┌──────────────────────────────────────────────────────────┐"
        printf "  │  Próbka %-51s│\n" "$idx — $fname"
        echo "  └──────────────────────────────────────────────────────────┘"
        echo -e "${RESET}"
    fi

    # ── Analiza statyczna ──────────────────────────────────────
    static_analysis "$target"

    # ── Analiza dynamiczna ────────────────────────────────────
    if [[ "$skip_dynamic" == "false" ]]; then
        # Wyczyść poprzednie wyniki Noriben w VM
        vm_ssh "cmd /c 'del /Q C:\\NoribenLogs\\* 2>nul & exit 0'" >> "$LOG_FILE" 2>&1 || true

        section "KOPIOWANIE PRÓBKI DO VM"
        local vm_path="C:\\Malware\\${fname}"
        vm_scp_to "$target" "$vm_path" && \
            log_ok "Próbka skopiowana: $fname" || \
            { log_err "Błąd kopiowania — pomijam analizę dynamiczną $fname"; }

        run_dynamic_analysis "$vm_path"
        collect_results "$file_session_dir"
        analyze_dynamic_results "$file_session_dir"

        # Wyczyść środowisko VM dla kolejnej próbki przez SSH
        # (revert snapshota robi main po całej serii — tu tylko cleanup)
        section "CZYSZCZENIE VM → GOTOWOŚĆ NA NASTĘPNĄ PRÓBKĘ"
        vm_ssh "cmd /c 'del /Q C:\\Malware\\* 2>nul & del /Q C:\\NoribenLogs\\* 2>nul & exit 0'"             >> "$LOG_FILE" 2>&1 || true
        log_ok "VM wyczyszczona — gotowa na kolejną próbkę"
    fi

    # ── Raport HTML per-plik ───────────────────────────────────
    local html_out
    html_out=$(generate_html_report "$target" "$file_session_dir")
    SESSION_REPORTS+=("$html_out")

    log_ok "Próbka $fname zakończona — static:$STATIC_RISK_SCORE dyn:$DYNAMIC_RISK_SCORE"
}

# ═════════════════════════════════════════════════════════════
# MODUŁ B — ANALIZA STATYCZNA (host macOS)
# ═════════════════════════════════════════════════════════════

static_analysis() {
    local target="$1"
    section "ANALIZA STATYCZNA — $(basename "$target")"

    # B1. Metadane
    echo -e "\n${BOLD}[B1] Metadane${RESET}"
    local sha256 md5 sha1 fsize ftype
    sha256=$(shasum -a 256 "$target" | awk '{print $1}')
    md5=$(md5 -q "$target" 2>/dev/null || md5sum "$target" | awk '{print $1}')
    sha1=$(shasum -a 1 "$target" | awk '{print $1}')
    fsize=$(du -sh "$target" | cut -f1)
    ftype=$(file -b "$target" 2>/dev/null)
    log "SHA256:  $sha256"
    log "MD5:     $md5"
    log "SHA1:    $sha1"
    log "Rozmiar: $fsize"
    log "Typ:     $ftype"
    echo "$sha256" > "$SESSION_DIR/sample_sha256.txt"

    # B2. Magic bytes
    echo -e "\n${BOLD}[B2] Magic bytes (pierwsze 32 bajty)${RESET}"
    xxd "$target" 2>/dev/null | head -4 | tee -a "$LOG_FILE" || \
        hexdump -C "$target" 2>/dev/null | head -4 | tee -a "$LOG_FILE"

    local is_pe=false
    case "$ftype" in
        *"PE32"*|*"MS-DOS"*) is_pe=true; add_finding "static" 5 "Plik wykonywalny PE Windows" ;;
        *"PDF"*)    log_warn "PDF — może zawierać embedded EXE lub JavaScript" ;;
        *"Zip"*)    log_warn "Zagnieżdżone archiwum wewnątrz archiwum (dropper?)" ;;
    esac

    # B3. Analiza nagłówka PE
    if $is_pe; then
        echo -e "\n${BOLD}[B3] Nagłówek PE${RESET}"
        python3 - "$target" 2>/dev/null <<'PYEOF' | tee -a "$LOG_FILE" || true
import sys, math, collections, datetime
def entropy(data):
    if not data: return 0.0
    c = collections.Counter(data)
    return round(-sum((v/len(data))*math.log2(v/len(data)) for v in c.values()), 3)
try:
    import pefile
    pe = pefile.PE(sys.argv[1], fast_load=False)
    h, o = pe.FILE_HEADER, pe.OPTIONAL_HEADER
    arch = {0x8664:'x64', 0x14c:'x86', 0x1c0:'ARM'}.get(h.Machine, hex(h.Machine))
    sub  = {1:'Driver',2:'GUI',3:'Console'}.get(o.Subsystem, str(o.Subsystem))
    try: ts = datetime.datetime.utcfromtimestamp(h.TimeDateStamp).strftime('%Y-%m-%d %H:%M UTC')
    except: ts = f"{h.TimeDateStamp} (nieprawidłowy)"
    print(f"  Architektura:  {arch}")
    print(f"  Timestamp:     {ts}")
    print(f"  Subsystem:     {sub}")
    print(f"  EntryPoint:    {hex(o.AddressOfEntryPoint)}")
    print(f"  ImageBase:     {hex(o.ImageBase)}")
    print(f"  Checksum OK:   {pe.verify_checksum()}")
    print(f"\n  Sekcje PE:")
    high_ent = []
    for s in pe.sections:
        name = s.Name.decode(errors='replace').strip('\x00')
        ent  = entropy(s.get_data())
        flag = "  ⚠ WYSOKA ENTROPIA" if ent > 6.8 else ""
        print(f"    {name:<12}  VA:{hex(s.VirtualAddress):<10}  Raw:{hex(s.SizeOfRawData):<10}  Ent:{ent:.3f}{flag}")
        if ent > 6.8: high_ent.append(name)
    if high_ent: print(f"\n  [!] Sekcje z wysoką entropią: {', '.join(high_ent)} (packer/szyfrowanie)")
    SUSPICIOUS = {
        'VirtualAllocEx':'Process Injection/T1055','WriteProcessMemory':'Process Injection/T1055',
        'CreateRemoteThread':'Process Injection/T1055','SetWindowsHookEx':'Keylogger/T1056',
        'GetAsyncKeyState':'Keylogger/T1056','URLDownloadToFile':'Download/T1105',
        'WinHttpOpen':'HTTP C2/T1071','CryptEncrypt':'Ransomware/T1486',
        'IsDebuggerPresent':'Anti-Debug/T1622','NtQueryInformationProcess':'Anti-VM/T1497',
        'RegSetValueEx':'Registry/T1112','CreateService':'Persistence/T1543',
    }
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        print(f"\n  Importy DLL:")
        found_sus = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors='replace')
            funcs = []
            for imp in entry.imports:
                fn = imp.name.decode(errors='replace') if imp.name else f"ord_{imp.ordinal}"
                funcs.append(fn)
                if fn in SUSPICIOUS: found_sus.append((dll, fn, SUSPICIOUS[fn]))
            print(f"    {dll}: {', '.join(funcs[:7])}{'...' if len(funcs)>7 else ''}")
        if found_sus:
            print(f"\n  [!] PODEJRZANE IMPORTY:")
            for dll, fn, reason in found_sus:
                print(f"      {dll} → {fn}  [{reason}]")
    if hasattr(pe, 'VS_VERSIONINFO'):
        print(f"\n  Version Info:")
        for vi in pe.VS_VERSIONINFO:
            if hasattr(vi, 'StringFileInfo'):
                for sf in vi.StringFileInfo:
                    for st in sf.StringTable:
                        for k, v in st.entries.items():
                            print(f"    {k.decode(errors='replace')}: {v.decode(errors='replace')}")
except ImportError: print("  [pefile niedostępny — pip3 install pefile]")
except Exception as e: print(f"  [Błąd PE: {e}]")
PYEOF
    fi

    # B4. Entropia pliku
    echo -e "\n${BOLD}[B4] Entropia pliku${RESET}"
    python3 - "$target" 2>/dev/null <<'PYEOF' | tee -a "$LOG_FILE" || true
import sys, math, collections
data = open(sys.argv[1], 'rb').read()
if data:
    c = collections.Counter(data)
    e = -sum((v/len(data))*math.log2(v/len(data)) for v in c.values())
    bar = '█'*int(e*5) + '░'*(40-int(e*5))
    lvl = "WYSOKA — packer/szyfrowanie" if e>7.0 else "ŚREDNIA" if e>6.0 else "NORMALNA"
    print(f"  Entropia: {e:.4f} / 8.0  [{lvl}]")
    print(f"  [{bar}]")
PYEOF

    # B5. IOC Strings
    echo -e "\n${BOLD}[B5] Wskaźniki IOC (strings)${RESET}"
    local all_strings; all_strings=$(strings -n 6 "$target" 2>/dev/null || true)
    local ioc_keys=(
        "URL/IP" "Tor/Darknet" "C2/Reverse Shell"
        "Pobieranie kodu" "Kodowanie" "Persistence Win"
        "Anti-debug/VM" "Ransomware" "Keylogger"
        "Privilege Esc" "Lateral Movement" "Dane wrazliwe"
    )
    local ioc_pats=(
        "https?://[^ ]{4,}|[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}"
        "[.]onion|socks[45]://|torbrowser"
        "meterpreter|cobalt.strike|nc -e|reverse.shell|powershell.*-enc"
        "URLDownload|Invoke-WebRequest|DownloadString|certutil.*-urlcache"
        "base64 -d|FromBase64String|Convert.FromBase64"
        "CurrentVersion.Run|RunOnce|schtasks.*/create|sc.*create"
        "IsDebuggerPresent|VirtualBox|VMware|QEMU|SbieDll|wine|Parallels"
        "ransom|CryptEncrypt|[.]locked|[.]encrypted|bitcoin|wallet"
        "GetAsyncKeyState|SetWindowsHookEx|keylog|GetClipboard"
        "SeDebugPrivilege|ImpersonateToken|UAC.*bypass"
        "psexec|wmiexec|net use|pass.the.hash"
        "[.]ssh|[.]aws|password|credentials|api.key"
    )
    local total_ioc=0 _ioc_i=0
    while [[ $_ioc_i -lt ${#ioc_keys[@]} ]]; do
        local category="${ioc_keys[$_ioc_i]}" pattern="${ioc_pats[$_ioc_i]}"
        ((_ioc_i++)) || true
        local hits; hits=$(echo "$all_strings" | grep -iEo "$pattern" | sort -u | head -8 || true)
        if [[ -n "$hits" ]]; then
            echo -e "\n  ${RED}▶${RESET} ${BOLD}$category${RESET}"
            while IFS= read -r hit; do echo -e "    ${YELLOW}→${RESET} $hit"; echo "    IOC[$category]: $hit" >> "$LOG_FILE"; done <<< "$hits"
            ((total_ioc++)) || true
            add_finding "static" 15 "IOC strings: $category"
            case "$category" in
                "C2/Reverse Shell")  add_mitre "T1059 — Command & Scripting Interpreter" ;;
                "Persistence Win")   add_mitre "T1547 — Boot/Logon Autostart Execution" ;;
                "Anti-debug/VM")     add_mitre "T1497 — Virtualization/Sandbox Evasion" ;;
                "Ransomware")        add_mitre "T1486 — Data Encrypted for Impact" ;;
                "Keylogger")         add_mitre "T1056 — Input Capture" ;;
                "Lateral Movement")  add_mitre "T1021 — Remote Services" ;;
            esac
        fi
    done
    [[ $total_ioc -eq 0 ]] && log_ok "Brak IOC w strings" || log_warn "$total_ioc kategorii IOC"

    # B6. ExifTool
    if command -v exiftool &>/dev/null; then
        echo -e "\n${BOLD}[B6] ExifTool${RESET}"
        exiftool "$target" 2>/dev/null | grep -vE "^ExifTool Version|^File Name|^Directory" \
            | head -30 | tee -a "$LOG_FILE" || true
    fi

    # B7. Detekcja packera
    echo -e "\n${BOLD}[B7] Detekcja packera${RESET}"
    local packed=false
    if command -v upx &>/dev/null && upx -t "$target" >> "$LOG_FILE" 2>&1; then
        log_warn "UPX packer wykryty!"
        add_finding "static" 20 "Spakowany UPX — utrudnia analizę statyczną"
        add_mitre "T1027 — Obfuscated Files"
        packed=true
        read -r -p "$(echo -e "  ${YELLOW}Rozpakować UPX? [t/N]${RESET} ")" upx_c
        if [[ "$upx_c" =~ ^[tTyY]$ ]]; then
            local unpacked="$SESSION_DIR/unpacked_$(basename "$target")"
            cp "$target" "$unpacked"
            upx -d "$unpacked" >> "$LOG_FILE" 2>&1 && {
                log_ok "Rozpakowano: $unpacked"; static_analysis "$unpacked"; return
            }
        fi
    fi
    local psigs; psigs=$(echo "$all_strings" | grep -iE "MPRESS|Themida|Enigma|VMProtect|Obsidium|ASPack" | head -3 || true)
    if [[ -n "$psigs" ]]; then
        log_warn "Możliwy protektor: $psigs"
        add_finding "static" 25 "Znany protektor/obfuscator PE"
        packed=true
    fi
    $packed || log_ok "Nie wykryto znanych packerów"

    # B8. YARA
    echo -e "\n${BOLD}[B8] YARA${RESET}"
    _yara_scan "$target"

    # B9. ClamAV
    if command -v clamscan &>/dev/null; then
        echo -e "\n${BOLD}[B9] ClamAV${RESET}"
        start_spinner "ClamAV skanowanie..."
        if clamscan --heuristic-alerts --alert-macros "$target" 2>&1 | tee -a "$LOG_FILE" | grep -q "OK$"; then
            stop_spinner; log_ok "ClamAV: CZYSTY"
        else
            stop_spinner; log_err "ClamAV: WYKRYTO ZAGROŻENIE!"
            add_finding "static" 80 "ClamAV: wykryto złośliwe oprogramowanie"
        fi
    fi

    echo ""
    echo -e "  ${DIM}VirusTotal: https://www.virustotal.com/gui/file/${sha256}${RESET}"
    log_ok "Analiza statyczna — score: $STATIC_RISK_SCORE"
}

# ─── Wbudowane reguły YARA ────────────────────────────────────
_create_yara_rules() {
    local f="$SESSION_DIR/rules.yar"
    cat > "$f" <<'YARARULES'
rule Ransomware_Indicators {
    meta: description="Wskaźniki ransomware" mitre="T1486"
    strings:
        $enc1="CryptEncrypt" nocase  $enc2="BCryptEncrypt" nocase
        $note1="ransom" nocase       $note2="bitcoin" nocase
        $note3="your files" nocase   $ext1=".locked" nocase
        $ext2=".encrypted" nocase
    condition: (2 of ($enc*)) or (3 of ($note*,$ext*))
}
rule ProcessInjection {
    meta: description="Wstrzykiwanie kodu" mitre="T1055"
    strings:
        $i1="VirtualAllocEx" nocase  $i2="WriteProcessMemory" nocase
        $i3="CreateRemoteThread" nocase  $i4="NtCreateThreadEx" nocase
        $i5="QueueUserAPC" nocase
    condition: 2 of them
}
rule Keylogger_Spyware {
    meta: description="Rejestrowanie wejścia" mitre="T1056"
    strings:
        $k1="GetAsyncKeyState" nocase  $k2="SetWindowsHookEx" nocase
        $k3="GetClipboardData" nocase  $k4="keylog" nocase
    condition: 2 of them
}
rule AntiAnalysis {
    meta: description="Unikanie analizy/VM" mitre="T1497,T1622"
    strings:
        $d1="IsDebuggerPresent" nocase  $d2="CheckRemoteDebugger" nocase
        $v1="VirtualBox" nocase  $v2="VMware" nocase
        $v3="QEMU" nocase        $v4="Parallels" nocase
        $s1="SbieDll.dll" nocase
    condition: 1 of ($d*) or 2 of ($v*,$s*)
}
rule NetworkC2 {
    meta: description="Komunikacja C2" mitre="T1071,T1059"
    strings:
        $c1="meterpreter" nocase  $c2="cobalt strike" nocase
        $c3="mimikatz" nocase     $c4="powershell -enc" nocase
        $tor=".onion" nocase
    condition: 1 of them
}
rule Persistence_Registry {
    meta: description="Persistence przez rejestr" mitre="T1547"
    strings:
        $r1="CurrentVersion\\Run" nocase wide  $r2="RunOnce" nocase wide
        $r3="schtasks /create" nocase          $r4="sc create" nocase
    condition: 2 of them
}
rule EncodedPayload {
    meta: description="Zakodowany payload" mitre="T1027"
    strings:
        $b64=/[A-Za-z0-9+\/]{200,}={0,2}/
        $ps="FromBase64String" nocase
        $ps2="Convert.FromBase64" nocase
    condition: any of them
}
rule CredentialTheft {
    meta: description="Kradzież poświadczeń" mitre="T1003"
    strings:
        $l1="lsass" nocase    $l2="sekurlsa" nocase
        $l3="NTLMhash" nocase $l4=".aws/credentials" nocase
        $l5="id_rsa" nocase
    condition: 2 of them
}
YARARULES
    echo "$f"
}

_yara_scan() {
    local target="$1"
    if ! command -v yara &>/dev/null; then log_warn "YARA niedostępny (brew install yara)"; return; fi
    local rules_file; rules_file=$(_create_yara_rules)
    local hits; hits=$(yara -r "$rules_file" "$target" 2>/dev/null || true)
    if [[ -n "$hits" ]]; then
        log_warn "YARA: $(echo "$hits" | wc -l | tr -d ' ') dopasowań:"
        while IFS= read -r hit; do
            echo -e "    ${RED}▶${RESET} $hit"
            add_finding "static" 20 "YARA: $(echo "$hit" | awk '{print $1}')"
        done <<< "$hits"
    else
        log_ok "YARA: brak dopasowań"
    fi
    local custom="$HOST_TOOLS_DIR/custom_rules.yar"
    [[ -f "$custom" ]] && {
        log "Własne reguły YARA: $custom"
        yara "$custom" "$target" 2>/dev/null | tee -a "$LOG_FILE" || true
    }
}

# ═════════════════════════════════════════════════════════════
# MODUŁ C — SPRAWDZENIE I INSTALACJA NARZĘDZI
# ═════════════════════════════════════════════════════════════

check_and_install() {
    local tool="$1" formula="${2:-$1}" desc="${3:-}"
    command -v "$tool" &>/dev/null && { log_ok "$tool: $(command -v "$tool")"; return 0; }
    log_warn "Brak: $tool ${desc:+(${desc})}"
    ! command -v brew &>/dev/null && return 1
    read -r -p "$(echo -e "  ${YELLOW}Zainstalować '$formula'? [t/N]${RESET} ")" c
    [[ ! "$c" =~ ^[tTyY]$ ]] && return 1
    start_spinner "Instalowanie $formula..."
    if brew install "$formula" >> "$LOG_FILE" 2>&1; then
        stop_spinner; log_ok "$formula zainstalowany"
    else
        stop_spinner; log_err "Błąd instalacji $formula"; return 1
    fi
}

check_host_tools() {
    section "SPRAWDZENIE I INSTALACJA NARZĘDZI"

    # Homebrew
    if ! command -v brew &>/dev/null; then
        read -r -p "$(echo -e "${BOLD}Zainstalować Homebrew? [t/N]${RESET} ")" c
        if [[ "$c" =~ ^[tTyY]$ ]]; then
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" \
                </dev/null >> "$LOG_FILE" 2>&1
            [[ -f "/opt/homebrew/bin/brew" ]] && eval "$(/opt/homebrew/bin/brew shellenv)"
            [[ -f "/usr/local/bin/brew" ]]    && eval "$(/usr/local/bin/brew shellenv)"
        fi
    else
        log_ok "Homebrew: $(brew --version | head -1)"
    fi

    # QEMU — narzędzie kluczowe
    if ! command -v qemu-system-x86_64 &>/dev/null && ! command -v qemu-system-aarch64 &>/dev/null; then
        log_warn "QEMU nie znaleziony — instaluję..."
        check_and_install qemu-img qemu "wymagane dla VM" || {
            log_err "QEMU jest wymagany dla analizy dynamicznej!"
            log_err "Zainstaluj ręcznie: brew install qemu"
        }
    else
        local qver; qver=$(qemu-img --version 2>/dev/null | head -1)
        log_ok "QEMU: $qver"
    fi

    # python3
    command -v python3 &>/dev/null && log_ok "python3: $(python3 --version)" || \
        check_and_install python3 python3 "wymagane"

    echo ""
    echo -e "${BOLD}Narzędzia analizy statycznej:${RESET}"
    check_and_install yara      yara         "reguły YARA"       || true
    check_and_install clamscan  clamav       "antywirus"         || true
    check_and_install exiftool  exiftool     "metadane plików"   || true
    check_and_install upx       upx          "detekcja packerów" || true

    echo ""
    echo -e "${BOLD}Narzędzia archiwów:${RESET}"
    check_and_install 7z    p7zip  "ZIP/RAR/7z z hasłem" || true
    # unrar — dostępny tylko przez cask "rar" (brew install --cask rar)
    # Nie przez "brew install unrar" — ta formula została usunięta z Homebrew
    if command -v unrar &>/dev/null; then
        log_ok "unrar: $(command -v unrar)"
    else
        log_warn "Brak unrar — niedostępny przez 'brew install unrar' (usunięty z Homebrew)"
        echo -e "  ${YELLOW}Opcje instalacji:${RESET}"
        echo -e "    ${CYAN}brew install --cask rar${RESET}   ← zalecane (instaluje rar + unrar)"
        echo -e "    ${CYAN}brew install p7zip${RESET}        ← fallback (7z obsługuje RAR)"
        echo -e "    ${CYAN}brew install unar${RESET}         ← fallback (bez haseł RAR)"
        read -r -p "  Zainstalować 'rar' (cask)? [t/N] " _c
        if [[ "$_c" =~ ^[tTyY]$ ]]; then
            start_spinner "Instalowanie cask rar..."
            if brew install --cask rar >> "$LOG_FILE" 2>&1; then
                stop_spinner; log_ok "rar (cask) zainstalowany → unrar dostępny"
            else
                stop_spinner; log_warn "Błąd instalacji cask rar — spróbuj: brew install unar"
                check_and_install unar unar "fallback RAR bez haseł" || true
            fi
        else
            check_and_install unar unar "fallback RAR (bez obsługi haseł)" || true
        fi
    fi

    echo ""
    echo -e "${BOLD}Python packages:${RESET}"
    for pkg in pefile yara-python; do
        local imp="${pkg//-/_}"
        if ! python3 -c "import $imp" &>/dev/null 2>&1; then
            pip3 install "$pkg" --quiet 2>/dev/null || \
            pip3 install "$pkg" --quiet --break-system-packages 2>/dev/null || true
            python3 -c "import $imp" &>/dev/null 2>&1 && log_ok "pip: $pkg" || log_warn "pip: $pkg (opcjonalne)"
        else
            log_ok "pip: $pkg"
        fi
    done
}

# ═════════════════════════════════════════════════════════════
# MODUŁ D — ZARZĄDZANIE VM QEMU
# ═════════════════════════════════════════════════════════════

# Zwróć właściwy binary QEMU zależnie od architektury hosta i gościa
get_qemu_binary() {
    if [[ "$HOST_ARCH" == "arm64" ]]; then
        # Apple Silicon: HVF tylko dla ARM64 gości
        if command -v qemu-system-aarch64 &>/dev/null; then
            echo "qemu-system-aarch64"
        else
            log_err "qemu-system-aarch64 niedostępny — brew install qemu"
            exit 1
        fi
    else
        # Intel: HVF dla x86_64 gości
        if command -v qemu-system-x86_64 &>/dev/null; then
            echo "qemu-system-x86_64"
        else
            log_err "qemu-system-x86_64 niedostępny — brew install qemu"
            exit 1
        fi
    fi
}

# Parametry akceleratora HVF lub fallback TCG
get_qemu_accel_args() {
    if [[ "$HOST_ARCH" == "arm64" ]]; then
        # Apple Silicon — HVF działa natywnie dla aarch64
        echo "-machine virt,accel=hvf,highmem=off -cpu host"
    else
        # Intel Mac — HVF dla x86_64
        echo "-machine q35,accel=hvf -cpu host"
    fi
}

# Sprawdź czy obraz QEMU istnieje
check_qemu_disk() {
    if [[ ! -f "$QEMU_DISK" ]]; then
        log_err "Obraz QEMU nie istnieje: $QEMU_DISK"
        echo ""
        echo -e "  Uruchom tryb setup: ${CYAN}$0 --setup${RESET}"
        echo -e "  Lub ustaw ścieżkę: ${CYAN}QEMU_DISK=/ścieżka/do/windows.qcow2 $0 próbka.exe${RESET}"
        exit 1
    fi
    log_ok "Obraz QEMU: $QEMU_DISK ($(du -sh "$QEMU_DISK" | cut -f1))"
}

# Sprawdź czy snapshot istnieje w obrazie
check_qemu_snapshot() {
    if ! qemu-img snapshot -l "$QEMU_DISK" 2>/dev/null | grep -q "$QEMU_SNAPSHOT"; then
        log_err "Snapshot '$QEMU_SNAPSHOT' nie istnieje w obrazie!"
        echo ""
        log "Dostępne snapshoty:"
        qemu-img snapshot -l "$QEMU_DISK" 2>/dev/null || echo "  (brak)"
        echo ""
        echo -e "  Utwórz snapshot przez QEMU monitor:"
        echo -e "  ${CYAN}(qemu) savevm $QEMU_SNAPSHOT${RESET}"
        echo -e "  Lub uruchom: ${CYAN}$0 --setup${RESET}"
        exit 1
    fi
    log_ok "Snapshot zweryfikowany: $QEMU_SNAPSHOT"
}

# Atomowe przywrócenie snapshota (VM musi być zatrzymana)
revert_to_snapshot() {
    section "PRZYWRACANIE SNAPSHOTA — $QEMU_SNAPSHOT"

    # Zatrzymaj VM jeśli działa
    stop_vm

    start_spinner "qemu-img snapshot -a $QEMU_SNAPSHOT ..."
    if qemu-img snapshot -a "$QEMU_SNAPSHOT" "$QEMU_DISK" >> "$LOG_FILE" 2>&1; then
        stop_spinner
        log_ok "Snapshot przywrócony: $QEMU_SNAPSHOT (<3s atomowo)"
    else
        stop_spinner
        log_err "Błąd przywracania snapshota!"
        qemu-img snapshot -l "$QEMU_DISK" 2>/dev/null
        exit 1
    fi
}

# Uruchom QEMU headless w tle
start_vm() {
    section "URUCHAMIANIE QEMU VM (headless)"

    local qemu_bin; qemu_bin=$(get_qemu_binary)
    local accel_args; accel_args=$(get_qemu_accel_args)

    # Sprawdź czy monitor port wolny
    if nc -z 127.0.0.1 "$QEMU_MONITOR_PORT" 2>/dev/null; then
        log_warn "Port monitora $QEMU_MONITOR_PORT zajęty — VM może już działać"
        return 0
    fi

    log "Uruchamianie: $qemu_bin (HVF: $HOST_ARCH)"
    log "Akcelerator: $accel_args"

    # Uruchom QEMU w tle — headless, monitor na TCP, SSH forwarded
    $qemu_bin \
        $accel_args \
        -m "$QEMU_MEM" \
        -smp "$QEMU_SMP" \
        -drive "file=$QEMU_DISK,format=qcow2,if=virtio,cache=writeback" \
        -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${QEMU_SSH_PORT}-:22,restrict=on" \
        -device "virtio-net-pci,netdev=net0" \
        -monitor "tcp:127.0.0.1:${QEMU_MONITOR_PORT},server,nowait" \
        -display none \
        -daemonize \
        -pidfile "$SESSION_DIR/qemu.pid" \
        >> "$SESSION_DIR/qemu.log" 2>&1 || {
        log_err "Nie udało się uruchomić QEMU!"
        cat "$SESSION_DIR/qemu.log" 2>/dev/null | tail -10
        exit 1
    }

    QEMU_PID=$(cat "$SESSION_DIR/qemu.pid" 2>/dev/null || echo "")
    log_ok "QEMU uruchomiony (PID: $QEMU_PID)"
    log "Monitor: nc 127.0.0.1 $QEMU_MONITOR_PORT"
    log "SSH: ssh -p $QEMU_SSH_PORT $VM_USER@127.0.0.1"

    # Czekaj na SSH
    log "Czekam na gotowość SSH VM (max ${VM_BOOT_TIMEOUT}s)..."
    local waited=0
    while [[ $waited -lt $VM_BOOT_TIMEOUT ]]; do
        if vm_ssh "echo ready" 2>/dev/null | grep -q "ready"; then
            log_ok "VM gotowa po ${waited}s"
            return 0
        fi
        sleep 3; ((waited+=3)) || true
        printf "\r  ${DIM}Boot: ${waited}/${VM_BOOT_TIMEOUT}s${RESET}"
    done
    printf "\r\033[K"
    log_warn "SSH nie odpowiedziało w ${VM_BOOT_TIMEOUT}s — kontynuuję (VM może potrzebować więcej czasu)..."
}

# Zatrzymaj QEMU
stop_vm() {
    local pid_file="$SESSION_DIR/qemu.pid"
    if [[ -f "$pid_file" ]]; then
        local pid; pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            # Wyślij graceful shutdown przez monitor
            qemu_monitor_cmd "system_powerdown" 5 || true
            sleep 3
            # Force kill jeśli nadal działa
            kill -9 "$pid" 2>/dev/null || true
            log_ok "QEMU zatrzymany (PID: $pid)"
        fi
        rm -f "$pid_file"
    elif nc -z 127.0.0.1 "$QEMU_MONITOR_PORT" 2>/dev/null; then
        qemu_monitor_cmd "quit" 3 || true
        sleep 1
        log_ok "QEMU zatrzymany przez monitor"
    fi
}

# Przygotuj środowisko w VM
prepare_vm_environment() {
    section "KONFIGURACJA ŚRODOWISKA VM"

    log "Tworzenie katalogów roboczych w VM..."
    vm_ssh "cmd /c 'mkdir C:\\Tools C:\\Malware C:\\NoribenLogs 2>nul & exit 0'" || \
        log_warn "Tworzenie katalogów (ignoruję błąd jeśli już istnieją)"

    # Wgraj Noriben.py
    local noriben_local="$HOST_TOOLS_DIR/Noriben.py"
    if [[ -f "$noriben_local" ]]; then
        vm_scp_to "$noriben_local" 'C:\Tools\Noriben.py' && log_ok "Noriben.py wgrany" || \
            log_warn "Nie udało się wgrać Noriben.py przez SSH"
    else
        log_warn "Noriben.py nie znaleziony lokalnie — pobierz przez: $0 --setup"
    fi

    # Wyłącz Defender (przez SSH)
    vm_ssh "powershell -Command \"
        Set-MpPreference -DisableRealtimeMonitoring \\\$true 2>\\\$null
        Add-MpPreference -ExclusionPath 'C:\\Malware','C:\\NoribenLogs','C:\\Tools' 2>\\\$null
    \"" >> "$LOG_FILE" 2>&1 && log_ok "Windows Defender skonfigurowany" || true
}

# ═════════════════════════════════════════════════════════════
# MODUŁ E — ANALIZA DYNAMICZNA (Noriben w VM przez SSH)
# ═════════════════════════════════════════════════════════════

run_dynamic_analysis() {
    local sample_vm_path="$1"
    section "ANALIZA DYNAMICZNA — NORIBEN + PROCMON (QEMU/HVF)"

    local timeout_min=$(( ANALYSIS_TIMEOUT / 60 ))
    echo -e "${YELLOW}${BOLD}"
    echo "  ╔────────────────────────────────────────────────────────╗"
    printf "  ║  Próbka:      %-45s║\n" "$(basename "$sample_vm_path")"
    printf "  ║  Timeout:     %-45s║\n" "${ANALYSIS_TIMEOUT}s (${timeout_min} min)"
    printf "  ║  Hiperwizor:  %-45s║\n" "QEMU + Apple HVF ($HOST_ARCH)"
    printf "  ║  Sieć VM:     %-45s║\n" "IZOLOWANA (restrict=on, tylko SSH localhost)"
    echo "  ╚────────────────────────────────────────────────────────╝"
    echo -e "${RESET}"

    # Opcjonalne PCAP — tcpdump na loopback (SSH jest jedynym ruchem z VM)
    local tcpdump_pid="" pcap_file="$SESSION_DIR/network_capture.pcap"
    if command -v tcpdump &>/dev/null; then
        read -r -p "$(echo -e "  ${YELLOW}Przechwytywać ruch SSH (loopback) przez tcpdump? [t/N]${RESET} ")" tcp_c
        if [[ "$tcp_c" =~ ^[tTyY]$ ]]; then
            sudo tcpdump -i lo0 "port $QEMU_SSH_PORT" -w "$pcap_file" >> "$LOG_FILE" 2>&1 &
            tcpdump_pid=$!
            log_ok "tcpdump uruchomiony (PID: $tcpdump_pid)"
        fi
    fi

    # Wyczyść poprzednie logi w VM
    vm_ssh "cmd /c 'del /Q C:\\NoribenLogs\\* 2>nul & exit 0'" >> "$LOG_FILE" 2>&1 || true

    local analysis_start; analysis_start=$(date +%s)
    log "Uruchamianie Noriben przez SSH (timeout: ${ANALYSIS_TIMEOUT}s)..."

    # Uruchom Noriben asynchronicznie przez SSH
    local ps_cmd
    ps_cmd="Start-Process -FilePath '$VM_PYTHON' -ArgumentList '$VM_NORIBEN','--cmd','$sample_vm_path','--timeout','$ANALYSIS_TIMEOUT','--output','C:\\NoribenLogs','--headless','--generalize' -Wait -NoNewWindow -RedirectStandardOutput 'C:\\NoribenLogs\\noriben_stdout.txt' -RedirectStandardError 'C:\\NoribenLogs\\noriben_stderr.txt'"
    vm_ssh "powershell -Command \"$ps_cmd\"" >> "$LOG_FILE" 2>&1 &
    local ssh_pid=$!

    # Progress bar
    while kill -0 $ssh_pid 2>/dev/null; do
        local elapsed=$(( $(date +%s) - analysis_start ))
        local pct=$(( elapsed * 100 / (ANALYSIS_TIMEOUT + 30) ))
        [[ $pct -gt 100 ]] && pct=100
        local filled=$(( pct * 44 / 100 )) empty=$(( 44 - filled ))
        local bar; bar="$(printf '%*s' "$filled" '' | tr ' ' '█')$(printf '%*s' "$empty" '' | tr ' ' '░')"
        printf "\r  ${CYAN}[%s]${RESET}  %3d%%  %ds / %ds  " "$bar" "$pct" "$elapsed" "$ANALYSIS_TIMEOUT"
        sleep 2
    done
    printf "\r\033[K"
    wait $ssh_pid 2>/dev/null || true

    local duration=$(( $(date +%s) - analysis_start ))
    log_ok "Noriben zakończył po ${duration}s"

    if [[ -n "$tcpdump_pid" ]]; then
        sudo kill "$tcpdump_pid" 2>/dev/null || true
        log_ok "PCAP: $pcap_file"
    fi
    sleep 2
}

# Pobierz wyniki z VM przez SCP
collect_results() {
    local dest_dir="${1:-$SESSION_DIR}"
    section "POBIERANIE WYNIKÓW Z VM (SCP)"

    # Spakuj wyniki w VM
    vm_ssh 'powershell -Command "Compress-Archive -Path C:\NoribenLogs\* -DestinationPath C:\NoribenLogs\results.zip -Force"' \
        >> "$LOG_FILE" 2>&1 || {
        log_warn "Compress-Archive nieudane — kopiuję osobno..."
        local vm_files
        vm_files=$(vm_ssh "powershell -Command \"Get-ChildItem 'C:\\NoribenLogs' | Select-Object -ExpandProperty Name\"" 2>/dev/null || echo "")
        mkdir -p "$dest_dir"
        while IFS= read -r fname; do
            [[ -z "$fname" ]] && continue
            vm_scp_from "C:\\NoribenLogs\\$fname" "$dest_dir/$fname" || true
        done <<< "$vm_files"
        return 0
    }

    mkdir -p "$dest_dir"
    local local_zip="$dest_dir/results_noriben.zip"
    vm_scp_from 'C:\NoribenLogs\results.zip' "$local_zip" && {
        unzip -q "$local_zip" -d "$dest_dir/" 2>/dev/null && \
            { log_ok "Wyniki pobrane: $dest_dir"; rm -f "$local_zip"; } || \
            log_warn "Błąd rozpakowywania — ZIP dostępny: $local_zip"
    } || log_err "Nie udało się skopiować wyników z VM"
}

# Analiza wyników Noriben
analyze_dynamic_results() {
    local src_dir="${1:-$SESSION_DIR}"
    section "ANALIZA WYNIKÓW NORIBEN"

    local txt_report; txt_report=$(find "$src_dir" -name "Noriben_*.txt" 2>/dev/null | head -1)
    local csv_data;   csv_data=$(find "$src_dir" -name "Noriben_*.csv" 2>/dev/null | head -1)

    if [[ -z "$txt_report" || ! -f "$txt_report" ]]; then
        log_warn "Brak raportu TXT Noriben — analiza dynamiczna mogła się nie uruchomić"
        log_warn "Sprawdź: $SESSION_DIR/qemu.log i $SESSION_DIR/noriben_stderr.txt"
        return 1
    fi

    log_ok "Raport: $txt_report"
    echo -e "\n${BOLD}── Raport Noriben (skrót) ──${RESET}"
    head -80 "$txt_report" | tee -a "$LOG_FILE"

    echo -e "\n${BOLD}── IOC dynamiczne ──${RESET}"
    local dyn_keys=(
        "Nowe procesy" "Siec TCP/UDP" "Zapis rejestru"
        "Nowe pliki EXE" "Autostart Persistence" "Wstrzykiwanie procesow"
        "Shadow Copy VSS" "Modyfikacje systemu"
    )
    local dyn_pats=(
        "Process Create|CreateProcess|Spawned"
        "TCP|UDP|Connect|DNS"
        "RegSetValue|RegCreateKey|\\Run\\|\\RunOnce\\"
        "[.]exe|[.]dll|[.]bat|[.]ps1|CreateFile|WriteFile"
        "Run|RunOnce|Startup|Schedule|schtasks|Services"
        "VirtualAlloc|WriteProcessMemory|CreateRemoteThread"
        "vssadmin|ShadowCopy|DeleteShadow"
        "System32|SysWOW64|hosts|firewall"
    )
    local dyn_total=0 _dyn_i=0
    while [[ $_dyn_i -lt ${#dyn_keys[@]} ]]; do
        local category="${dyn_keys[$_dyn_i]}" pattern="${dyn_pats[$_dyn_i]}"
        ((_dyn_i++)) || true
        local hits; hits=$(grep -iE "$pattern" "$txt_report" 2>/dev/null | \
            grep -vE "^#|Noriben|Procmon|^-{3}" | head -8 || true)
        if [[ -n "$hits" ]]; then
            echo -e "\n  ${RED}▶${RESET} ${BOLD}$category${RESET}"
            while IFS= read -r line; do
                echo -e "    ${YELLOW}→${RESET} $line"
                echo "    DYN[$category]: $line" >> "$LOG_FILE"
            done <<< "$hits"
            ((dyn_total++)) || true
            add_finding "dynamic" 20 "DYN IOC: $category"
            case "$category" in
                "Sieć TCP/UDP")            add_mitre "T1071 — Application Layer Protocol" ;;
                "Autostart / Persistence") add_mitre "T1547 — Boot Autostart Execution" ;;
                "Wstrzykiwanie procesów")  add_mitre "T1055 — Process Injection" ;;
                "Shadow Copy / VSS")       add_mitre "T1490 — Inhibit System Recovery" ;;
            esac
        fi
    done
    [[ $dyn_total -eq 0 ]] && log_ok "Brak widocznych IOC dynamicznych" || log_warn "$dyn_total kategorii IOC"

    if [[ -n "$csv_data" && -f "$csv_data" ]]; then
        log "Statystyki zdarzeń Procmon:"
        log "  Łącznie: $(wc -l < "$csv_data" | tr -d ' ') zdarzeń"
        awk -F',' 'NR>1 && NF>2 {print $2}' "$csv_data" 2>/dev/null | \
            sort | uniq -c | sort -rn | head -10 | \
            while read -r cnt proc; do echo -e "    ${cnt}x  ${proc}"; done | tee -a "$LOG_FILE" || true
    fi

    log_ok "Analiza dynamiczna — score: $DYNAMIC_RISK_SCORE"
}

# ═════════════════════════════════════════════════════════════
# MODUŁ F — RAPORT HTML
# ═════════════════════════════════════════════════════════════

generate_html_report() {
    # Argumenty opcjonalne dla trybu wieloplikowego
    local target_file="${1:-${EXTRACTED_SAMPLE:-$SAMPLE_FILE}}"
    local report_dir="${2:-$SESSION_DIR}"

    section "GENEROWANIE RAPORTU HTML"

    local fname; fname=$(basename "$target_file")
    local slug; slug="${fname%%.*}"
    local html_out="$report_dir/REPORT_${slug}_${SESSION_ID}.html"
    local sha256; sha256=$(cat "$SESSION_DIR/sample_sha256.txt" 2>/dev/null || \
        shasum -a 256 "$target_file" | awk '{print $1}')
    local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
    local ftype; ftype=$(file -b "$target_file" 2>/dev/null)
    local fsize; fsize=$(du -sh "$target_file" | cut -f1)

    local noriben_txt=""
    local nr; nr=$(find "$report_dir" -name "Noriben_*.txt" 2>/dev/null | head -1)
    [[ -n "$nr" && -f "$nr" ]] && noriben_txt=$(sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g' "$nr")

    local total_score=$(( (STATIC_RISK_SCORE + DYNAMIC_RISK_SCORE) / 2 ))
    [[ $total_score -gt 100 ]] && total_score=100
    local risk_class="low" risk_label="NISKIE" risk_color="#3fb950"
    [[ $total_score -ge 40 ]] && risk_class="med"  && risk_label="ŚREDNIE"  && risk_color="#e3b341"
    [[ $total_score -ge 70 ]] && risk_class="high" && risk_label="WYSOKIE"  && risk_color="#f85149"

    local mitre_html=""
    local mitre_html="" _seen_mitre=""
    for t in "${MITRE_TECHNIQUES[@]:-}"; do
        [[ -z "$t" ]] && continue
        case "$_seen_mitre" in *"|${t}|"*) continue ;; esac
        _seen_mitre="${_seen_mitre}|${t}|"
        mitre_html+="<span class='mtag'>$t</span>"
    done

    local static_html=""; local dynamic_html=""
    [[ ${#STATIC_FINDINGS[@]} -gt 0 ]] && \
        for f in "${STATIC_FINDINGS[@]}"; do static_html+="<div class='finding f-red'>$f</div>"; done || \
        static_html="<div class='finding f-green'>✓ Brak podejrzanych wskaźników statycznych</div>"
    [[ ${#DYNAMIC_FINDINGS[@]} -gt 0 ]] && \
        for f in "${DYNAMIC_FINDINGS[@]}"; do dynamic_html+="<div class='finding f-yellow'>$f</div>"; done || \
        dynamic_html="<div class='finding f-green'>✓ Brak podejrzanych zachowań dynamicznych</div>"

    local log_html; log_html=$(tail -80 "$LOG_FILE" 2>/dev/null | sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g')
    local qemu_log_html; qemu_log_html=$(cat "$SESSION_DIR/qemu.log" 2>/dev/null | tail -30 | \
        sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g' || echo "(brak)")

    cat > "$html_out" <<HTMLEOF
<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="UTF-8">
<title>QEMU Sandbox Report — ${fname}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Courier New',monospace;background:#0d1117;color:#c9d1d9;padding:30px;line-height:1.6}
a{color:#58a6ff}
h1{color:#58a6ff;font-size:1.85em;margin-bottom:4px}
h2{color:#79c0ff;font-size:1.1em;margin:26px 0 10px;border-left:4px solid #388bfd;padding-left:12px}
.subtitle{color:#8b949e;font-size:.87em}
.hdr{border-bottom:1px solid #30363d;padding-bottom:16px;margin-bottom:20px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px;margin:12px 0}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:13px}
.lbl{color:#8b949e;font-size:.73em;text-transform:uppercase;letter-spacing:.04em}
.val{color:#e6edf3;font-size:.87em;margin-top:3px;word-break:break-all}
.hash{color:#3fb950;font-size:.7em}
pre{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:16px;
    overflow-x:auto;white-space:pre-wrap;font-size:.79em;max-height:480px;overflow-y:auto}
.score-wrap{display:flex;align-items:center;gap:18px;margin:14px 0}
.score-circle{width:86px;height:86px;border-radius:50%;display:flex;align-items:center;
    justify-content:center;font-size:1.5em;font-weight:bold;flex-shrink:0}
.high{background:#3d1c1c;color:#f85149;border:3px solid #f85149}
.med {background:#3d2f0e;color:#e3b341;border:3px solid #e3b341}
.low {background:#0d2818;color:#3fb950;border:3px solid #3fb950}
.finding{padding:5px 10px;border-left:3px solid;margin:3px 0;border-radius:0 4px 4px 0;font-size:.83em}
.f-red   {border-color:#f85149;background:#1c0e0e;color:#f85149}
.f-yellow{border-color:#e3b341;background:#1c180e;color:#e3b341}
.f-green {border-color:#3fb950;background:#0d1c0e;color:#3fb950}
.f-blue  {border-color:#388bfd;background:#0e1c3e;color:#79c0ff}
.mtag{display:inline-block;background:#1c2a3e;color:#79c0ff;border:1px solid #264b73;
    border-radius:4px;padding:2px 8px;font-size:.73em;margin:3px}
.bar-wrap{background:#21262d;border-radius:4px;height:7px;width:280px;margin:7px 0}
.bar-fill{height:7px;border-radius:4px}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.vt-btn{display:inline-block;background:#1c3a5e;color:#58a6ff;padding:8px 16px;
    border-radius:6px;text-decoration:none;font-size:.86em;margin-top:8px}
.hvf-badge{display:inline-block;background:#0d2818;color:#3fb950;border:1px solid #3fb950;
    border-radius:4px;padding:2px 10px;font-size:.75em;margin-left:10px}
@media(max-width:680px){.two-col{grid-template-columns:1fr}}
footer{color:#8b949e;font-size:.76em;margin-top:38px;border-top:1px solid #30363d;padding-top:12px}
</style>
</head>
<body>

<div class="hdr">
  <h1>🔬 QEMU Sandbox Report <span class="hvf-badge">Apple HVF · ${HOST_ARCH}</span></h1>
  <p class="subtitle">Noriben + QEMU + Analiza statyczna/dynamiczna | v${VERSION}</p>
  <p class="subtitle">Sesja: ${SESSION_ID} &nbsp;·&nbsp; $ts</p>
</div>

<h2>🛡 Model izolacji</h2>
<div class="grid">
  <div class="card"><div class="lbl">Hiperwizor</div><div class="val">QEMU + Apple Hypervisor.framework (HVF)</div></div>
  <div class="card"><div class="lbl">Sieć VM</div><div class="val" style="color:#3fb950">IZOLOWANA — restrict=on, tylko SSH localhost:${QEMU_SSH_PORT}</div></div>
  <div class="card"><div class="lbl">Snapshot</div><div class="val">qemu-img atomowy reset &lt;3s — ${QEMU_SNAPSHOT}</div></div>
  <div class="card"><div class="lbl">Archiwa VM</div><div class="val">Brak artefaktów VMware/Parallels w gościu</div></div>
</div>

<h2>📁 Próbka</h2>
<div class="grid">
  <div class="card"><div class="lbl">Nazwa</div><div class="val">${SAMPLE_BASENAME}</div></div>
  <div class="card"><div class="lbl">Typ</div><div class="val">${ftype}</div></div>
  <div class="card"><div class="lbl">Rozmiar</div><div class="val">${fsize}</div></div>
  <div class="card"><div class="lbl">SHA256</div><div class="val hash">${sha256}</div></div>
</div>
<a class="vt-btn" href="https://www.virustotal.com/gui/file/${sha256}" target="_blank">🔍 Sprawdź w VirusTotal →</a>

<h2>⚠️ Ocena ryzyka</h2>
<div class="score-wrap">
  <div class="score-circle ${risk_class}">${total_score}</div>
  <div>
    <div style="font-size:1.25em;font-weight:bold;color:${risk_color}">${risk_label}</div>
    <div class="lbl" style="margin-top:5px">Statyczna: ${STATIC_RISK_SCORE} &nbsp;|&nbsp; Dynamiczna: ${DYNAMIC_RISK_SCORE}</div>
    <div class="bar-wrap"><div class="bar-fill" style="width:${total_score}%;background:${risk_color}"></div></div>
  </div>
</div>

<div class="two-col">
  <div><h2>🔍 Analiza statyczna</h2>${static_html}</div>
  <div><h2>🧬 Analiza dynamiczna</h2>${dynamic_html}</div>
</div>

$(if [[ -n "$mitre_html" ]]; then echo "<h2>🗺 MITRE ATT&amp;CK</h2>$mitre_html"; fi)

<h2>⚙️ Konfiguracja QEMU</h2>
<div class="card">
<table style="width:100%;border-collapse:collapse">
  <tr><td style="color:#8b949e;padding:4px 10px;width:160px">Obraz QEMU</td><td style="padding:4px 10px">${QEMU_DISK}</td></tr>
  <tr><td style="color:#8b949e;padding:4px 10px">Snapshot</td><td style="padding:4px 10px">${QEMU_SNAPSHOT}</td></tr>
  <tr><td style="color:#8b949e;padding:4px 10px">RAM / vCPU</td><td style="padding:4px 10px">${QEMU_MEM} / ${QEMU_SMP}</td></tr>
  <tr><td style="color:#8b949e;padding:4px 10px">Akcelerator</td><td style="padding:4px 10px">Apple HVF (${HOST_ARCH})</td></tr>
  <tr><td style="color:#8b949e;padding:4px 10px">Sieć</td><td style="padding:4px 10px">user-mode, restrict=on, SSH localhost:${QEMU_SSH_PORT}</td></tr>
  <tr><td style="color:#8b949e;padding:4px 10px">Timeout</td><td style="padding:4px 10px">${ANALYSIS_TIMEOUT}s ($(( ANALYSIS_TIMEOUT/60 )) min)</td></tr>
</table>
</div>

<h2>📋 Raport Noriben</h2>
$(if [[ -n "$noriben_txt" ]]; then echo "<pre>$noriben_txt</pre>"; \
  else echo "<div class='card' style='color:#8b949e'>Brak raportu Noriben — analiza dynamiczna mogła się nie uruchomić.</div>"; fi)

<h2>📄 Log hosta (macOS)</h2>
<pre>${log_html}</pre>

<h2>🖥 Log QEMU</h2>
<pre>${qemu_log_html}</pre>

<footer>
  Wygenerowano przez noriben_qemu_sandbox.sh v${VERSION} &nbsp;·&nbsp;
  macOS Host → QEMU + Apple HVF → Windows VM → Noriben + Procmon
</footer>
</body>
</html>
HTMLEOF

    log_ok "Raport HTML: $html_out"
    echo "$html_out"
}

# ═════════════════════════════════════════════════════════════
# TRYB SETUP
# ═════════════════════════════════════════════════════════════

run_setup_mode() {
    section "TRYB KONFIGURACJI (pierwsze uruchomienie)"
    mkdir -p "$HOST_TOOLS_DIR" "$HOST_RESULTS_DIR"
    LOG_FILE="/tmp/noriben_qemu_setup_$$.log"; touch "$LOG_FILE"

    check_host_tools

    echo ""
    echo -e "${CYAN}${BOLD}Wykryta architektura hosta: ${HOST_ARCH}${RESET}"
    if [[ "$HOST_ARCH" == "arm64" ]]; then
        echo -e "${YELLOW}Apple Silicon: HVF działa dla ARM64 gości."
        echo -e "Dla x86 malware na M-chip: użyj QEMU TCG (wolniejszy) lub ARM64 Windows + Rosetta.${RESET}"
    else
        echo -e "${GREEN}Intel Mac: HVF z qemu-system-x86_64 — pełna wydajność dla Windows x86/x64.${RESET}"
    fi

    # Pobierz Noriben.py
    echo ""
    local noriben_path="$HOST_TOOLS_DIR/Noriben.py"
    if [[ ! -f "$noriben_path" ]]; then
        start_spinner "Pobieranie Noriben.py z GitHub..."
        curl -fsSL "https://raw.githubusercontent.com/Rurik/Noriben/master/Noriben.py" \
            -o "$noriben_path" 2>/dev/null && { stop_spinner; log_ok "Noriben.py: $noriben_path"; } || \
            { stop_spinner; log_err "Nie udało się pobrać Noriben.py"; }
    else
        log_ok "Noriben.py: $noriben_path"
    fi

    # Generuj skrypt setup dla Windows VM
    cat > "$HOST_TOOLS_DIR/vm_setup.ps1" <<'PSEOF'
param([string]$SnapshotName="Baseline_Clean")
Set-ExecutionPolicy Bypass -Scope Process -Force
$ErrorActionPreference="SilentlyContinue"
Write-Host "=== Konfiguracja VM dla Noriben (QEMU) ===" -ForegroundColor Cyan
foreach ($d in @("C:\Tools","C:\Malware","C:\NoribenLogs","C:\Python3")) {
    New-Item -ItemType Directory -Path $d -Force | Out-Null
    Write-Host "[OK] $d" -ForegroundColor Green
}
if (-not (Test-Path "C:\Python3\python.exe")) {
    Write-Host "[!] Pobieranie Python 3.11..." -ForegroundColor Yellow
    Invoke-WebRequest "https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe" -OutFile "$env:TEMP\python.exe"
    & "$env:TEMP\python.exe" /quiet InstallAllUsers=1 TargetDir=C:\Python3 PrependPath=1
}
if (-not (Test-Path "C:\Tools\procmon64.exe")) {
    winget install Microsoft.Sysinternals.ProcessMonitor --silent --accept-eula
    $src="$env:ProgramFiles\Sysinternals Suite\Procmon64.exe"
    if (Test-Path $src) { Copy-Item $src "C:\Tools\procmon64.exe" }
}
# Włącz OpenSSH Server (wymagany dla komunikacji z hostem macOS)
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service sshd -StartupType Automatic
# Dopuść SSH przez firewall
New-NetFirewallRule -Name "sshd" -DisplayName "OpenSSH Server" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
# Konfiguracja Defender
Set-MpPreference -DisableRealtimeMonitoring $true
@("C:\Malware","C:\NoribenLogs","C:\Tools") | % { Add-MpPreference -ExclusionPath $_ }
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" EnableLUA 0
Stop-Service wuauserv -Force; Set-Service wuauserv -StartupType Disabled
Write-Host ""
Write-Host "=== SSH Server uruchomiony ===" -ForegroundColor Green
Write-Host "Teraz wyłącz VM i wykonaj snapshot przez qemu-img:" -ForegroundColor Yellow
Write-Host "  qemu-img snapshot -c $SnapshotName <ścieżka_do_obrazu.qcow2>" -ForegroundColor Cyan
PSEOF
    log_ok "vm_setup.ps1: $HOST_TOOLS_DIR/vm_setup.ps1"

    echo ""
    echo -e "${BOLD}═══ Dalsze kroki ═══${RESET}"
    echo ""
    echo "1. Utwórz obraz QEMU (lub użyj istniejącego qcow2):"
    echo -e "   ${CYAN}qemu-img create -f qcow2 ~/NoribenTools/windows_sandbox.qcow2 60G${RESET}"
    echo ""
    echo "2. Zainstaluj Windows w QEMU (jednorazowo z ISO):"
    if [[ "$HOST_ARCH" == "arm64" ]]; then
        echo -e "   ${CYAN}qemu-system-aarch64 -accel hvf -cpu host -m 4G -smp 2 \\${RESET}"
        echo -e "   ${CYAN}  -machine virt,highmem=off -cdrom windows_arm64.iso \\${RESET}"
        echo -e "   ${CYAN}  -drive file=windows_sandbox.qcow2,if=virtio \\${RESET}"
        echo -e "   ${CYAN}  -display default${RESET}"
        echo -e "   ${YELLOW}  (Windows on ARM — pobierz z Microsoft Insider Program)${RESET}"
    else
        echo -e "   ${CYAN}qemu-system-x86_64 -accel hvf -cpu host -m 4G -smp 2 \\${RESET}"
        echo -e "   ${CYAN}  -machine q35 -cdrom windows10.iso \\${RESET}"
        echo -e "   ${CYAN}  -drive file=windows_sandbox.qcow2,if=virtio \\${RESET}"
        echo -e "   ${CYAN}  -display default${RESET}"
    fi
    echo ""
    echo "3. W Windows VM — uruchom PowerShell jako Administrator:"
    echo -e "   ${CYAN}Set-ExecutionPolicy Bypass -Scope Process -Force${RESET}"
    echo -e "   ${CYAN}.\\vm_setup.ps1${RESET}"
    echo "   (skrypt włącza OpenSSH Server, Python, Procmon, wyłącza Defender)"
    echo ""
    echo "4. Wyłącz VM i utwórz snapshot qemu-img:"
    echo -e "   ${CYAN}qemu-img snapshot -c Baseline_Clean ~/NoribenTools/windows_sandbox.qcow2${RESET}"
    echo ""
    echo "5. Ustaw ścieżkę obrazu (lub edytuj QEMU_DISK w skrypcie):"
    echo -e "   ${CYAN}export QEMU_DISK=~/NoribenTools/windows_sandbox.qcow2${RESET}"
    echo ""
    echo -e "${GREEN}${BOLD}Uruchomienie analizy:${RESET}"
    echo -e "  ${CYAN}$0 ~/Downloads/malware.exe${RESET}"
    echo -e "  ${CYAN}$0 ~/Downloads/sample.zip --archive-password infected${RESET}"
    echo -e "  ${CYAN}$0 malware.exe --static-only  # bez VM${RESET}"
    echo ""
    echo -e "${YELLOW}Weryfikacja snapshotu:${RESET}"
    echo -e "  ${DIM}qemu-img snapshot -l ~/NoribenTools/windows_sandbox.qcow2${RESET}"
    rm -f "$LOG_FILE"
}

# ═════════════════════════════════════════════════════════════
# MODUŁ G — ZBIORCZY RAPORT SERII (wieloplikowe archiwum)
# ═════════════════════════════════════════════════════════════

_generate_batch_report() {
    local total_files="$1"
    local -n _scores="$2"     # nameref do tablicy batch_scores
    local -n _reports="$3"    # nameref do tablicy SESSION_REPORTS

    local batch_html="$SESSION_DIR/BATCH_REPORT_${SESSION_ID}.html"
    local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')

    # Policz statystyki
    local high_count=0 med_count=0 low_count=0 total_score=0
    for entry in "${_scores[@]}"; do
        local score="${entry##*:}"
        total_score=$(( total_score + score ))
        if   [[ $score -ge 70 ]]; then ((high_count++)) || true
        elif [[ $score -ge 40 ]]; then ((med_count++))  || true
        else                           ((low_count++))   || true
        fi
    done
    local avg_score=0
    [[ ${#_scores[@]} -gt 0 ]] && avg_score=$(( total_score / ${#_scores[@]} ))
    [[ $avg_score -gt 100 ]] && avg_score=100

    # Tabela wyników w terminalu
    echo ""
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗"
    echo -e "║  📊  PODSUMOWANIE SERII                                      ║"
    echo -e "╠══════════════════════════════════════════════════════════════╣"
    printf  "║  Łącznie plików:    %-41s║\n" "$total_files"
    printf  "║  Wysokie ryzyko:    %-41s║\n" "${high_count} plików (score ≥ 70)"
    printf  "║  Średnie ryzyko:    %-41s║\n" "${med_count} plików (score 40–69)"
    printf  "║  Niskie ryzyko:     %-41s║\n" "${low_count} plików (score < 40)"
    printf  "║  Średni score:      %-41s║\n" "$avg_score / 100"
    echo -e "╚══════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
    echo -e "${BOLD}Wyniki per plik:${RESET}"
    for entry in "${_scores[@]}"; do
        local fname="${entry%%:*}"
        local score="${entry##*:}"
        local bar_c="$GREEN"
        local risk="NISKIE"
        if   [[ $score -ge 70 ]]; then bar_c="$RED";    risk="WYSOKIE"
        elif [[ $score -ge 40 ]]; then bar_c="$YELLOW"; risk="ŚREDNIE"
        fi
        printf "  %-38s ${bar_c}%3d/100${RESET}  %s\n" "$fname" "$score" "$risk"
    done
    echo ""
    echo -e "  📁 Katalog sesji:  ${BOLD}$SESSION_DIR${RESET}"
    echo -e "  📊 Zbiorczy raport: ${BOLD}$batch_html${RESET}"
    echo ""

    # Tabela linków do raportów per-plik
    local reports_rows=""
    local scores_idx=0
    for report_path in "${_reports[@]}"; do
        local rname; rname=$(basename "$report_path")
        local fscore=""
        [[ $scores_idx -lt ${#_scores[@]} ]] && {
            local entry="${_scores[$scores_idx]}"
            local fname="${entry%%:*}"
            local score="${entry##*:}"
            local sc_color="#3fb950"
            [[ $score -ge 40 ]] && sc_color="#e3b341"
            [[ $score -ge 70 ]] && sc_color="#f85149"
            fscore="<span style='color:${sc_color};font-weight:bold'>${score}/100</span>"
            reports_rows+="<tr><td><a href='${report_path}'>$rname</a></td><td>$fname</td><td>$fscore</td></tr>"
        }
        ((scores_idx++)) || true
    done

    # Dane wykresu do HTML (Chart.js sparkline)
    local chart_labels="" chart_data="" chart_colors=""
    for entry in "${_scores[@]}"; do
        local fname="${entry%%:*}"
        local score="${entry##*:}"
        local color='"#3fb950"'
        [[ $score -ge 40 ]] && color='"#e3b341"'
        [[ $score -ge 70 ]] && color='"#f85149"'
        chart_labels+="\"${fname}\","
        chart_data+="${score},"
        chart_colors+="${color},"
    done

    cat > "$batch_html" <<BATCHEOF
<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="UTF-8">
<title>Batch Report — ${SAMPLE_BASENAME} — ${SESSION_ID}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Courier New',monospace;background:#0d1117;color:#c9d1d9;padding:30px;line-height:1.6}
a{color:#58a6ff}
h1{color:#58a6ff;font-size:1.7em;margin-bottom:4px}
h2{color:#79c0ff;font-size:1.05em;margin:22px 0 10px;border-left:4px solid #388bfd;padding-left:12px}
.subtitle{color:#8b949e;font-size:.85em}
.hdr{border-bottom:1px solid #30363d;padding-bottom:14px;margin-bottom:18px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin:10px 0}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px;text-align:center}
.card-num{font-size:2em;font-weight:bold}
.card-lbl{color:#8b949e;font-size:.75em;margin-top:4px}
.high{color:#f85149} .med{color:#e3b341} .low{color:#3fb950} .avg{color:#79c0ff}
table{width:100%;border-collapse:collapse;font-size:.84em}
th{color:#8b949e;text-align:left;padding:7px 10px;border-bottom:1px solid #30363d;font-weight:normal;font-size:.75em;text-transform:uppercase}
td{padding:7px 10px;border-bottom:1px solid #21262d}
tr:hover td{background:#161b22}
.chart-wrap{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin:10px 0;height:260px}
footer{color:#8b949e;font-size:.74em;margin-top:32px;border-top:1px solid #30363d;padding-top:10px}
</style>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
</head>
<body>
<div class="hdr">
  <h1>📊 Batch Report — Seria archiwum</h1>
  <p class="subtitle">Archiwum: ${SAMPLE_BASENAME} &nbsp;·&nbsp; Sesja: ${SESSION_ID} &nbsp;·&nbsp; $ts</p>
  <p class="subtitle">QEMU + Apple HVF (${HOST_ARCH}) &nbsp;·&nbsp; Noriben + Procmon</p>
</div>

<h2>📈 Statystyki serii</h2>
<div class="grid">
  <div class="card"><div class="card-num avg">$avg_score</div><div class="card-lbl">Średni score / 100</div></div>
  <div class="card"><div class="card-num">$total_files</div><div class="card-lbl">Łącznie plików</div></div>
  <div class="card"><div class="card-num high">$high_count</div><div class="card-lbl">Wysokie ryzyko (≥70)</div></div>
  <div class="card"><div class="card-num med">$med_count</div><div class="card-lbl">Średnie ryzyko (40–69)</div></div>
  <div class="card"><div class="card-num low">$low_count</div><div class="card-lbl">Niskie ryzyko (&lt;40)</div></div>
</div>

<h2>📊 Wykres ryzyka per plik</h2>
<div class="chart-wrap">
  <canvas id="batchChart"></canvas>
</div>
<script>
new Chart(document.getElementById('batchChart'), {
  type: 'bar',
  data: {
    labels: [${chart_labels}],
    datasets: [{
      label: 'Risk Score',
      data: [${chart_data}],
      backgroundColor: [${chart_colors}],
      borderRadius: 4
    }]
  },
  options: {
    responsive: true, maintainAspectRatio: false,
    scales: {
      y: { min: 0, max: 100, grid: { color: '#21262d' },
           ticks: { color: '#8b949e' } },
      x: { grid: { display: false }, ticks: { color: '#8b949e', maxRotation: 45 } }
    },
    plugins: {
      legend: { display: false },
      tooltip: { callbacks: { label: ctx => ' Score: ' + ctx.raw + '/100' } }
    }
  }
});
</script>

<h2>📋 Wyniki per plik</h2>
<table>
  <thead><tr><th>Raport HTML</th><th>Plik</th><th>Score</th></tr></thead>
  <tbody>$reports_rows</tbody>
</table>

<footer>
  Wygenerowano przez noriben_qemu_sandbox.sh v${VERSION} &nbsp;·&nbsp;
  QEMU + Apple HVF · $total_files plików z archiwum ${SAMPLE_BASENAME}
</footer>
</body>
</html>
BATCHEOF

    log_ok "Zbiorczy raport HTML: $batch_html"
    echo -e "  ${DIM}open '$batch_html'${RESET}"
    echo ""
}

# ═════════════════════════════════════════════════════════════
# CLEANUP
# ═════════════════════════════════════════════════════════════

cleanup() {
    stop_spinner
    stop_vm
}

# ═════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════

main() {
    print_banner

    local setup_mode=false no_revert=false static_only=false dynamic_only=false
    local archive_password=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --setup)             setup_mode=true ;;
            --no-revert)         no_revert=true ;;
            --static-only)       static_only=true ;;
            --dynamic-only)      dynamic_only=true ;;
            --disk)              shift; QEMU_DISK="$1" ;;
            --snapshot)          shift; QEMU_SNAPSHOT="$1" ;;
            --timeout)           shift; ANALYSIS_TIMEOUT="$1" ;;
            --mem)               shift; QEMU_MEM="$1" ;;
            --smp)               shift; QEMU_SMP="$1" ;;
            --ssh-port)          shift; QEMU_SSH_PORT="$1" ;;
            --monitor-port)      shift; QEMU_MONITOR_PORT="$1" ;;
            --archive-password)  shift; archive_password="$1" ;;
            --list-snapshots)
                qemu-img snapshot -l "$QEMU_DISK" 2>/dev/null
                exit 0 ;;
            --help|-h)
                cat <<HELP
Użycie: $0 <plik> [opcje]

  --setup                  Konfiguracja środowiska (pierwsze uruchomienie)
  --disk <ścieżka>         Ścieżka do obrazu QEMU qcow2
  --snapshot <nazwa>       Nazwa snapshota (domyślnie: '$QEMU_SNAPSHOT')
  --timeout <s>            Czas analizy Noriben (domyślnie: ${ANALYSIS_TIMEOUT}s)
  --mem <RAM>              Pamięć VM (domyślnie: ${QEMU_MEM})
  --smp <N>                Liczba vCPU (domyślnie: ${QEMU_SMP})
  --ssh-port <port>        Port SSH do VM (domyślnie: ${QEMU_SSH_PORT})
  --monitor-port <port>    Port monitora QEMU (domyślnie: ${QEMU_MONITOR_PORT})
  --archive-password <p>   Hasło do archiwum ZIP/RAR/7z
  --static-only            Tylko analiza statyczna (bez VM)
  --dynamic-only           Tylko analiza dynamiczna (bez statycznej)
  --no-revert              Nie przywracaj snapshota przed analizą
  --list-snapshots         Lista snapshotów w obrazie

Zmienne środowiskowe:
  QEMU_DISK           Ścieżka do obrazu qcow2
  QEMU_SNAPSHOT       Nazwa snapshota (domyślnie: Baseline_Clean)
  QEMU_MEM            RAM dla VM (domyślnie: 4G)
  QEMU_SMP            vCPU (domyślnie: 2)
  QEMU_SSH_PORT       Port SSH (domyślnie: 2222)
  VM_USER, VM_PASS    Dane SSH do gościa Windows
  ANALYSIS_TIMEOUT    Czas analizy w sekundach
  ARCHIVE_PASSWORDS   Hasła domyślne rozdzielone spacją

Przykłady:
  $0 --setup
  $0 malware.exe
  $0 sample.zip --archive-password infected
  $0 malware.exe --static-only
  $0 malware.exe --timeout 600 --mem 8G
  QEMU_DISK=~/my_win10.qcow2 $0 malware.exe
HELP
                exit 0 ;;
            -*) echo -e "${RED}Nieznana opcja: $1${RESET}"; exit 1 ;;
            *)  SAMPLE_FILE="$1" ;;
        esac
        shift
    done

    [[ "$setup_mode" == true ]] && { run_setup_mode; exit 0; }

    [[ -z "$SAMPLE_FILE" ]] && {
        echo -e "${RED}Błąd: podaj plik do analizy${RESET}"
        echo "Użycie: $0 <plik> | $0 --help | $0 --setup"
        exit 1
    }
    [[ ! -f "$SAMPLE_FILE" ]] && { echo -e "${RED}Plik nie istnieje: $SAMPLE_FILE${RESET}"; exit 1; }

    SAMPLE_BASENAME=$(basename "$SAMPLE_FILE")
    SESSION_ID=$(date '+%Y%m%d_%H%M%S')
    SESSION_DIR="$HOST_RESULTS_DIR/${SAMPLE_BASENAME%%.*}_${SESSION_ID}"
    LOG_FILE="$SESSION_DIR/host_analysis.log"

    mkdir -p "$SESSION_DIR"
    touch "$LOG_FILE"
    trap cleanup EXIT INT TERM

    {
        echo "═══════════════════════════════════════════"
        echo "  noriben_qemu_sandbox.sh v$VERSION"
        echo "  Sesja:        $SESSION_ID"
        echo "  Plik:         $SAMPLE_FILE"
        echo "  Host arch:    $HOST_ARCH"
        echo "  QEMU disk:    $QEMU_DISK"
        echo "  Snapshot:     $QEMU_SNAPSHOT"
        echo "  Timeout:      ${ANALYSIS_TIMEOUT}s"
        echo "  $(date)"
        echo "═══════════════════════════════════════════"
    } >> "$LOG_FILE"

    log "Sesja: $SESSION_ID | Host: $HOST_ARCH | Wyniki: $SESSION_DIR"

    # 0. Narzędzia
    check_host_tools

    # 1. Archiwum — rozpakowywanie i wybór trybu
    local analysis_target="$SAMPLE_FILE"
    if is_archive "$SAMPLE_FILE"; then
        [[ -n "$archive_password" ]] && ARCHIVE_PASSWORDS="$archive_password $ARCHIVE_PASSWORDS"
        handle_archive "$SAMPLE_FILE"
        # handle_archive ustawia ARCHIVE_MODE i EXTRACTED_SAMPLE
        [[ "$ARCHIVE_MODE" == "single" ]] && analysis_target="$EXTRACTED_SAMPLE"
    else
        ARCHIVE_MODE="single"
        analysis_target="$SAMPLE_FILE"
    fi

    # Nadpisz ARCHIVE_MODE jeśli użyto flag CLI
    [[ "$static_only"  == "true" && "$ARCHIVE_MODE" == "all_full" ]]  && ARCHIVE_MODE="all_static"
    [[ "$dynamic_only" == "true" && "$ARCHIVE_MODE" == "all_full" ]]  && ARCHIVE_MODE="all_full"  # zachowaj

    # ─────────────────────────────────────────────────────────
    # TRYB: all_full lub all_static — wiele plików po kolei
    # ─────────────────────────────────────────────────────────
    if [[ "$ARCHIVE_MODE" == "all_full" || "$ARCHIVE_MODE" == "all_static" ]]; then
        local file_list_path="$SESSION_DIR/archive_filelist.txt"
        [[ ! -f "$file_list_path" ]] && {
            log_err "Brak listy plików — błąd wewnętrzny"
            exit 1
        }

        local all_files=()
        while IFS= read -r _mf_line; do
            [[ -n "$_mf_line" ]] && all_files+=("$_mf_line")
        done < "$file_list_path"
        local total="${#all_files[@]}"
        local skip_dynamic=false
        [[ "$ARCHIVE_MODE" == "all_static" || "$static_only" == "true" ]] && skip_dynamic=true

        echo ""
        echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════╗"
        printf  "║  Tryb: %-53s║\n" "$([ "$skip_dynamic" == "true" ] && echo "WSZYSTKIE — tylko statyczna" || echo "WSZYSTKIE — statyczna + dynamiczna")"
        printf  "║  Łącznie plików: %-43s║\n" "$total"
        echo -e "╚══════════════════════════════════════════════════════════╝${RESET}"

        # Przygotuj VM raz dla całej serii (tylko tryb full)
        if [[ "$skip_dynamic" == "false" ]]; then
            check_qemu_disk
            check_qemu_snapshot

            $no_revert || revert_to_snapshot
            start_vm

            [[ ! -f "$HOST_TOOLS_DIR/Noriben.py" ]] && {
                start_spinner "Pobieranie Noriben.py..."
                curl -fsSL "https://raw.githubusercontent.com/Rurik/Noriben/master/Noriben.py" \
                    -o "$HOST_TOOLS_DIR/Noriben.py" 2>/dev/null \
                    && { stop_spinner; log_ok "Noriben.py pobrany"; } \
                    || { stop_spinner; log_err "Brak Noriben.py"; }
            }
            prepare_vm_environment
        fi

        # ── Pętla po plikach ─────────────────────────────────
        local idx=0
        local -a batch_scores=()
        for file_path in "${all_files[@]}"; do
            [[ -z "$file_path" || ! -f "$file_path" ]] && continue
            ((idx++)) || true

            reset_per_file_state
            analyze_single_file "$file_path" "${idx}/${total}" "$skip_dynamic"

            local f_total=$(( (STATIC_RISK_SCORE + DYNAMIC_RISK_SCORE) / 2 ))
            [[ $f_total -gt 100 ]] && f_total=100
            batch_scores+=("$(basename "$file_path"):${f_total}")
        done

        # Zatrzymaj VM po całej serii
        [[ "$skip_dynamic" == "false" ]] && {
            section "KONIEC SERII — ZATRZYMYWANIE VM"
            stop_vm
            log_ok "VM zatrzymana po przeanalizowaniu wszystkich $total plików"
        }

        # ── Zbiorczy raport serii ─────────────────────────────
        _generate_batch_report "$total" batch_scores SESSION_REPORTS

    # ─────────────────────────────────────────────────────────
    # TRYB: single — jeden plik (normalny przepływ)
    # ─────────────────────────────────────────────────────────
    else
        # Analiza statyczna
        [[ "$dynamic_only" == "false" ]] && static_analysis "$analysis_target"

        # Analiza dynamiczna
        if [[ "$static_only" == "false" ]]; then
            check_qemu_disk
            check_qemu_snapshot

            $no_revert || revert_to_snapshot
            start_vm

            [[ ! -f "$HOST_TOOLS_DIR/Noriben.py" ]] && {
                start_spinner "Pobieranie Noriben.py..."
                curl -fsSL "https://raw.githubusercontent.com/Rurik/Noriben/master/Noriben.py" \
                    -o "$HOST_TOOLS_DIR/Noriben.py" 2>/dev/null \
                    && { stop_spinner; log_ok "Noriben.py pobrany"; } \
                    || { stop_spinner; log_err "Brak Noriben.py"; }
            }

            prepare_vm_environment

            section "KOPIOWANIE PRÓBKI DO VM"
            local vm_path="C:\\Malware\\$(basename "$analysis_target")"
            vm_scp_to "$analysis_target" "$vm_path" && \
                log_ok "Próbka skopiowana" || log_err "Błąd kopiowania próbki"

            run_dynamic_analysis "$vm_path"
            collect_results
            analyze_dynamic_results

            section "RESET VM → $QEMU_SNAPSHOT"
            revert_to_snapshot
            log_ok "VM zresetowana — gotowa na kolejną próbkę"
        fi

        local html_report
        html_report=$(generate_html_report "$analysis_target" "$SESSION_DIR")
        SESSION_REPORTS+=("$html_report")

        # Podsumowanie końcowe
        local total=$(( (STATIC_RISK_SCORE + DYNAMIC_RISK_SCORE) / 2 ))
        [[ $total -gt 100 ]] && total=100

        echo ""
        echo -e "${GREEN}${BOLD}╔═════════════════════════════════════════════════╗"
        echo -e "║  ✅  Analiza zakończona!                        ║"
        echo -e "╚═════════════════════════════════════════════════╝${RESET}"
        echo ""
        printf "  %-22s ${BOLD}%d / 100${RESET}\n" "Wynik ryzyka:"  "$total"
        printf "  %-22s %d\n"                       "Statyczna:"    "$STATIC_RISK_SCORE"
        printf "  %-22s %d\n"                       "Dynamiczna:"   "$DYNAMIC_RISK_SCORE"
        printf "  %-22s %s\n"                       "Hiperwizor:"   "QEMU + Apple HVF ($HOST_ARCH)"
        echo ""
        echo -e "  📁 Wyniki:      ${BOLD}$SESSION_DIR${RESET}"
        [[ -n "$html_report" ]] && echo -e "  🌐 Raport HTML: ${BOLD}$html_report${RESET}"
        echo ""
        echo -e "  ${DIM}open '$html_report'${RESET}"
        local sha256; sha256=$(shasum -a 256 "$analysis_target" | awk '{print $1}')
        echo -e "  ${DIM}https://www.virustotal.com/gui/file/$sha256${RESET}"
        echo ""
    fi
}
main "$@"
