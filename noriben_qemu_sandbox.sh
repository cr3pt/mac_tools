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
# Wykryj wersje QEMU (major.minor)
_qemu_version_ge() {
    local bin="$1" need_maj="$2" need_min="$3"
    local ver_str maj min
    ver_str=$("$bin" --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
    maj="${ver_str%%.*}"; min="${ver_str##*.}"
    [[ -z "$maj" ]] && return 1
    if   [[ $maj -gt $need_maj ]]; then return 0
    elif [[ $maj -eq $need_maj && $min -ge $need_min ]]; then return 0
    else return 1
    fi
}

# Wykryj wersje macOS
_macos_version_ge() {
    local need="$1"
    local ver; ver=$(sw_vers -productVersion 2>/dev/null | cut -d. -f1)
    [[ -n "$ver" && $ver -ge $need ]]
}

get_qemu_accel_args() {
    if [[ "$HOST_ARCH" == "arm64" ]]; then
        local qemu_bin; qemu_bin=$(get_qemu_binary 2>/dev/null || echo "qemu-system-aarch64")
        # QEMU 9.2+ na macOS 15+: automatyczna negocjacja 40-bit IPA przez HVF API
        # (patch Danny Canter, QEMU 9.2, sierpien 2024)
        # Na starszych kombinacjach wymagane highmem=off (domyslny IPA = 36 bitow)
        if _qemu_version_ge "$qemu_bin" 9 2 && _macos_version_ge 15; then
            echo "-machine virt,accel=hvf -cpu host"
        else
            echo "-machine virt,accel=hvf,highmem=off -cpu host"
        fi
    else
        echo "-machine q35,accel=hvf -cpu host"
    fi
}

# Sprawdz i przytnij RAM jesli stara konfiguracja HVF (36-bit IPA)
_guard_mem_for_hvf() {
    [[ "$HOST_ARCH" != "arm64" ]] && return
    local qemu_bin; qemu_bin=$(get_qemu_binary 2>/dev/null || echo "qemu-system-aarch64")
    if _qemu_version_ge "$qemu_bin" 9 2 && _macos_version_ge 15; then
        log "HVF 40-bit IPA (QEMU 9.2+ / macOS 15+) bez ograniczen RAM"
        return
    fi
    local mem_val mem_mb
    mem_val="${QEMU_MEM%[GgMm]}"
    case "${QEMU_MEM: -1}" in
        G|g) mem_mb=$(( mem_val * 1024 )) ;;
        M|m) mem_mb=$mem_val ;;
        *)   mem_mb=4096 ;;
    esac
    if [[ $mem_mb -gt 12288 ]]; then
        log_warn "Apple Silicon HVF 36-bit IPA: $QEMU_MEM za duzy, przycinamy do 12G"
        log_warn "Zaktualizuj QEMU do 9.2+ i macOS do 15+ aby usunac limit"
        QEMU_MEM="12G"
    fi
}
