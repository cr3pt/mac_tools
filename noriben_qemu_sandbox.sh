#!/bin/bash
# ============================================================
#  noriben_qemu_sandbox.sh  v3.2
#  Analiza malware: QEMU + Apple HVF/TCG → Noriben + Procmon
#
#  Nowości v3.2:
#  ✦ Dual-VM mode: ARM64 (HVF, szybka) + x86_64 (TCG) równolegle
#  ✦ Poprawna obsługa M4 / macOS 15+ (40-bit IPA, brak limitu RAM)
#  ✦ Automatyczna detekcja QEMU 9.2+ i dobór parametrów HVF
#  ✦ bash 3.2 compatible (macOS /bin/bash)
#  ✦ unrar przez cask rar (brew install --cask rar)
#  ✦ Wieloplikowe archiwa: single / all_full / all_static
#
#  Dual-VM mode:
#    VM1 (ARM): qemu-system-aarch64 -accel hvf  → Windows on ARM
#    VM2 (x86): qemu-system-x86_64  -accel tcg  → Windows x86/x64
#    Obie działają równolegle na różnych portach SSH/monitor.
#    Każda próbka trafia do obu VM i analizowana jest niezależnie.
#    Wyniki scalane w jednym raporcie HTML.
#
#  IPA / RAM na Apple Silicon:
#    QEMU <9.2  lub macOS <15: highmem=off, max ~12 GB
#    QEMU 9.2+ i macOS 15+:   40-bit IPA, brak ograniczeń RAM
#    M4 z macOS 15 i QEMU 9.2+: pełna wydajność bez limitów
#
#  Wymagania hosta:
#    - macOS 12+ (Hypervisor.framework)
#    - brew install qemu
#    - python3, Homebrew
#
#  Wymagania w obrazach Windows (qcow2):
#    VM1 (ARM): Windows on ARM, Python3, Procmon, Noriben, OpenSSH
#    VM2 (x86): Windows 10/11 x64, Python3, Procmon, Noriben, OpenSSH
#    Snapshot "Baseline_Clean" w każdym obrazie
# ============================================================

set -euo pipefail
VERSION="3.2.0"

# ─── Kolory ───────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'
DIM='\033[2m'; RESET='\033[0m'

# ─── Konfiguracja VM1 (ARM64 / HVF) ──────────────────────────
QEMU_DISK="${QEMU_DISK:-${HOME}/NoribenTools/windows_arm_sandbox.qcow2}"
QEMU_SNAPSHOT="${QEMU_SNAPSHOT:-Baseline_Clean}"
QEMU_MEM="${QEMU_MEM:-16G}"
QEMU_SMP="${QEMU_SMP:-4}"
QEMU_SSH_PORT="${QEMU_SSH_PORT:-2222}"
QEMU_MONITOR_PORT="${QEMU_MONITOR_PORT:-4444}"

# ─── Konfiguracja VM2 (x86_64 / TCG) ─────────────────────────
QEMU_DISK_X86="${QEMU_DISK_X86:-${HOME}/NoribenTools/windows_x86_sandbox.qcow2}"
QEMU_SNAPSHOT_X86="${QEMU_SNAPSHOT_X86:-Baseline_Clean}"
QEMU_MEM_X86="${QEMU_MEM_X86:-8G}"
QEMU_SMP_X86="${QEMU_SMP_X86:-4}"
QEMU_SSH_PORT_X86="${QEMU_SSH_PORT_X86:-2223}"
QEMU_MONITOR_PORT_X86="${QEMU_MONITOR_PORT_X86:-4445}"

# ─── Dane SSH ─────────────────────────────────────────────────
VM_USER="${VM_USER:-Administrator}"
VM_PASS="${VM_PASS:-password}"

# ─── Ścieżki wewnątrz VM ─────────────────────────────────────
VM_PYTHON="C:\\Python3\\python.exe"
VM_NORIBEN="C:\\Tools\\Noriben.py"
VM_PROCMON="C:\\Tools\\procmon64.exe"
VM_MALWARE_DIR="C:\\Malware"
VM_OUTPUT_DIR="C:\\NoribenLogs"

# ─── Ścieżki hosta ───────────────────────────────────────────
HOST_RESULTS_DIR="${HOME}/NoribenResults"
HOST_TOOLS_DIR="${HOME}/NoribenTools"

# ─── Timeouty ────────────────────────────────────────────────
ANALYSIS_TIMEOUT="${ANALYSIS_TIMEOUT:-300}"
VM_BOOT_TIMEOUT=120
SSH_TIMEOUT=10

# ─── Hasła archiwów ──────────────────────────────────────────
ARCHIVE_PASSWORDS="${ARCHIVE_PASSWORDS:-infected malware virus password 1234 admin sample}"

# ─── Flagi globalne ──────────────────────────────────────────
SAMPLE_FILE=""
SAMPLE_BASENAME=""
EXTRACTED_SAMPLE=""
ARCHIVE_MODE=""
SESSION_ID=""
SESSION_DIR=""
LOG_FILE=""
SPINNER_PID=""
QEMU_PID=""
QEMU_PID_X86=""
STATIC_RISK_SCORE=0
DYNAMIC_RISK_SCORE=0
STATIC_FINDINGS=()
DYNAMIC_FINDINGS=()
MITRE_TECHNIQUES=()
SESSION_REPORTS=()
batch_scores=()

# ─── Tryb dual-VM ────────────────────────────────────────────
DUAL_VM_MODE="${DUAL_VM_MODE:-false}"

HOST_ARCH=$(uname -m)

# ═══════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════

spinner_chars="⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

start_spinner() {
    local msg="$1"
    ( local i=0
      while true; do
          printf "\r${CYAN}${spinner_chars:$i:1}${RESET} $msg   "
          i=$(( (i+1) % 10 ))
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
    echo "=== $* ===" >> "$LOG_FILE" 2>/dev/null || true
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

# ─── SSH/SCP helpers (przyjmują port jako argument) ──────────
_vm_ssh() {
    local port="$1"; shift
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout="$SSH_TIMEOUT" \
        -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
        -p "$port" "${VM_USER}@127.0.0.1" "$@" 2>/dev/null
}
_vm_scp_to() {
    local port="$1" src="$2" dst="$3"
    scp -o StrictHostKeyChecking=no -o ConnectTimeout="$SSH_TIMEOUT" \
        -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
        -P "$port" "$src" "${VM_USER}@127.0.0.1:$dst" 2>/dev/null
}
_vm_scp_from() {
    local port="$1" src="$2" dst="$3"
    scp -o StrictHostKeyChecking=no -o ConnectTimeout="$SSH_TIMEOUT" \
        -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
        -P "$port" "${VM_USER}@127.0.0.1:$src" "$dst" 2>/dev/null
}

# Skróty dla VM1 (ARM) i VM2 (x86)
vm_ssh()      { _vm_ssh      "$QEMU_SSH_PORT"     "$@"; }
vm_scp_to()   { _vm_scp_to   "$QEMU_SSH_PORT"     "$1" "$2"; }
vm_scp_from() { _vm_scp_from "$QEMU_SSH_PORT"     "$1" "$2"; }
vm2_ssh()     { _vm_ssh      "$QEMU_SSH_PORT_X86" "$@"; }
vm2_scp_to()  { _vm_scp_to   "$QEMU_SSH_PORT_X86" "$1" "$2"; }
vm2_scp_from(){ _vm_scp_from "$QEMU_SSH_PORT_X86" "$1" "$2"; }

qemu_monitor_cmd() {
    local port="${2:-$QEMU_MONITOR_PORT}"
    echo "$1" | nc -w 5 127.0.0.1 "$port" 2>/dev/null || true
}

print_banner() {
    echo -e "${CYAN}${BOLD}"
    cat << 'BANNER'
  ╔══════════════════════════════════════════════════════════╗
  ║   🔬 Noriben QEMU Sandbox  v3.2                        ║
  ║   Apple HVF (ARM64) + TCG (x86)  ·  Dual-VM mode       ║
  ║   qcow2 snapshots · izolacja sieciowa · MITRE ATT&CK   ║
  ╚══════════════════════════════════════════════════════════╝
BANNER
    echo -e "${RESET}"
}

# ═══════════════════════════════════════════════════════════════
# MODUŁ A — ARCHIWA
# ═══════════════════════════════════════════════════════════════

detect_archive_type() {
    local f="$1" magic ext
    magic=$(file -b "$f" 2>/dev/null || echo "")
    ext=$(echo "${f##*.}" | tr '[:upper:]' '[:lower:]')
    case "$magic" in
        *"Zip archive"*|*"ZIP"*) echo "zip" ;;
        *"RAR archive"*)         echo "rar" ;;
        *"7-zip archive"*)       echo "7z"  ;;
        *"gzip"*)                echo "gz"  ;;
        *"bzip2"*)               echo "bz2" ;;
        *"XZ compressed"*)       echo "xz"  ;;
        *"POSIX tar"*)           echo "tar" ;;
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
            [[ -n "$password" ]] \
                && unzip -P "$password" -o "$archive" -d "$dest_dir" >> "$LOG_FILE" 2>&1 \
                || unzip -o "$archive" -d "$dest_dir" >> "$LOG_FILE" 2>&1 ;;
        rar)
            if command -v unrar &>/dev/null; then
                [[ -n "$password" ]] \
                    && unrar x -p"$password" -y "$archive" "$dest_dir/" >> "$LOG_FILE" 2>&1 \
                    || unrar x -y "$archive" "$dest_dir/" >> "$LOG_FILE" 2>&1
            elif command -v 7z &>/dev/null; then
                [[ -n "$password" ]] \
                    && 7z x -p"$password" -o"$dest_dir" "$archive" >> "$LOG_FILE" 2>&1 \
                    || 7z x -o"$dest_dir" "$archive" >> "$LOG_FILE" 2>&1
            elif command -v unar &>/dev/null; then
                [[ -n "$password" ]] \
                    && unar -p "$password" -o "$dest_dir" "$archive" >> "$LOG_FILE" 2>&1 \
                    || unar -o "$dest_dir" "$archive" >> "$LOG_FILE" 2>&1
            else
                log_err "Brak narzędzia RAR. Zainstaluj: brew install --cask rar  LUB  brew install p7zip"
                return 1
            fi ;;
        7z)
            command -v 7z &>/dev/null || { log_err "Brak 7z — brew install p7zip"; return 1; }
            [[ -n "$password" ]] \
                && 7z x -p"$password" -o"$dest_dir" "$archive" >> "$LOG_FILE" 2>&1 \
                || 7z x -o"$dest_dir" "$archive" >> "$LOG_FILE" 2>&1 ;;
        gz|bz2|xz|tar)
            tar xf "$archive" -C "$dest_dir" >> "$LOG_FILE" 2>&1 ;;
        *) log_err "Nieobsługiwany typ: $arch_type"; return 1 ;;
    esac
}

_crack_archive_password() {
    local archive="$1" extract_dir="$2"
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
        echo ""; log_warn "Żadne domyślne hasło nie zadziałało"
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
}

_find_executables() {
    local dir="$1"
    local results
    results=$(find "$dir" -type f \( \
        -name "*.exe" -o -name "*.dll" -o -name "*.bat" \
        -o -name "*.ps1" -o -name "*.vbs" -o -name "*.js"  \
        -o -name "*.scr" -o -name "*.com" -o -name "*.hta" \
        -o -name "*.msi" -o -name "*.jar" \) 2>/dev/null | sort)
    [[ -z "$results" ]] && results=$(find "$dir" -type f 2>/dev/null | sort)
    echo "$results"
}

_print_archive_table() {
    local files_list="$1"
    local i=1
    echo ""
    printf "  ${CYAN}${BOLD}%-4s %-40s %-10s %s${RESET}\n" "Nr" "Nazwa pliku" "Rozmiar" "Typ"
    printf "  %s\n" "$(printf '─%.0s' {1..72})"
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        local name size ftype
        name=$(basename "$f")
        size=$(du -sh "$f" 2>/dev/null | cut -f1)
        ftype=$(file -b "$f" 2>/dev/null | cut -c1-28)
        printf "  ${CYAN}[%-2d]${RESET} %-40s %-10s %s\n" "$i" "$name" "$size" "$ftype"
        ((i++)) || true
    done <<< "$files_list"
    echo ""
}

_select_analysis_mode() {
    local exe_files="$1"
    local file_count; file_count=$(echo "$exe_files" | grep -c . || echo 0)
    echo -e "${BOLD}Znaleziono ${CYAN}$file_count${RESET}${BOLD} plików wykonywalnych w archiwum.${RESET}"
    _print_archive_table "$exe_files"
    echo -e "  Tryby analizy:"
    echo -e "  ${CYAN}[0]${RESET}  Wszystkie — statyczna + dynamiczna po kolei"
    echo -e "  ${CYAN}[00]${RESET} Wszystkie — tylko statyczna (bez VM)"
    echo -e "  ${CYAN}[N]${RESET}  Pojedynczy plik o numerze N"
    echo ""
    read -r -p "  Wybór [0]: " choice; choice="${choice:-0}"
    case "$choice" in
        "0")  ARCHIVE_MODE="all_full"   ;;
        "00") ARCHIVE_MODE="all_static" ;;
        *)
            local chosen_file
            chosen_file=$(echo "$exe_files" | sed -n "${choice}p")
            if [[ -z "$chosen_file" || ! -f "$chosen_file" ]]; then
                log_warn "Nieprawidłowy wybór — plik #1"
                chosen_file=$(echo "$exe_files" | head -1)
            fi
            ARCHIVE_MODE="single"
            EXTRACTED_SAMPLE="$chosen_file"
            ;;
    esac
    if [[ "$ARCHIVE_MODE" == "all_full" || "$ARCHIVE_MODE" == "all_static" ]]; then
        echo "$exe_files" > "$SESSION_DIR/archive_filelist.txt"
    fi
    log "Tryb: $ARCHIVE_MODE"
}

handle_archive() {
    local archive="$1"
    local arch_type; arch_type=$(detect_archive_type "$archive")
    local extract_dir="$SESSION_DIR/extracted"
    section "ARCHIWUM — ROZPAKOWYWANIE I INSPEKCJA"
    echo -e "  Plik:    ${BOLD}$(basename "$archive")${RESET}"
    echo -e "  Format:  ${BOLD}$arch_type${RESET}  Rozmiar: ${BOLD}$(du -sh "$archive" | cut -f1)${RESET}"
    echo ""
    local is_encrypted=false
    case "$arch_type" in
        zip) unzip -t "$archive" >> "$LOG_FILE" 2>&1 || is_encrypted=true ;;
        rar)
            if command -v unrar &>/dev/null; then
                unrar t "$archive" >> "$LOG_FILE" 2>&1 || is_encrypted=true
            elif command -v 7z &>/dev/null; then
                7z t "$archive" >> "$LOG_FILE" 2>&1 || is_encrypted=true
            fi ;;
        7z) command -v 7z &>/dev/null && { 7z t "$archive" >> "$LOG_FILE" 2>&1 || is_encrypted=true; } ;;
    esac
    if $is_encrypted; then
        _crack_archive_password "$archive" "$extract_dir" || return 1
    else
        log_ok "Archiwum bez hasła — rozpakowuję..."
        try_extract_archive "$archive" "$extract_dir" "" || { log_err "Błąd rozpakowywania"; return 1; }
    fi
    local exe_files; exe_files=$(_find_executables "$extract_dir")
    local exe_count; exe_count=$(echo "$exe_files" | grep -c . 2>/dev/null || echo 0)
    local all_count; all_count=$(find "$extract_dir" -type f 2>/dev/null | wc -l | tr -d ' ')
    log "Zawartość: $all_count plików łącznie, $exe_count wykonywalnych"
    find "$extract_dir" -type f | sort | while read -r f; do
        echo -e "  ${GREEN}→${RESET} ${f#$extract_dir/}  ${DIM}[$(du -sh "$f"|cut -f1)] $(file -b "$f"|cut -c1-40)${RESET}"
    done
    [[ $exe_count -eq 0 ]] && { exe_files=$(find "$extract_dir" -type f 2>/dev/null | sort | head -20); exe_count=$(echo "$exe_files" | grep -c . || echo 0); }
    if [[ $exe_count -eq 1 ]]; then
        ARCHIVE_MODE="single"
        EXTRACTED_SAMPLE=$(echo "$exe_files" | head -1)
        log_ok "Jeden plik — automatyczny wybór: $(basename "$EXTRACTED_SAMPLE")"
    else
        _select_analysis_mode "$exe_files"
    fi
}

reset_per_file_state() {
    STATIC_RISK_SCORE=0; DYNAMIC_RISK_SCORE=0
    STATIC_FINDINGS=(); DYNAMIC_FINDINGS=(); MITRE_TECHNIQUES=()
    EXTRACTED_SAMPLE=""
    rm -f "$SESSION_DIR/sample_sha256.txt"
}

# ═══════════════════════════════════════════════════════════════
# MODUŁ B — ANALIZA STATYCZNA
# ═══════════════════════════════════════════════════════════════

static_analysis() {
    local target="$1"
    section "ANALIZA STATYCZNA — $(basename "$target")"

    echo -e "\n${BOLD}[B1] Metadane${RESET}"
    local sha256 md5 sha1 fsize ftype
    sha256=$(shasum -a 256 "$target" | awk '{print $1}')
    md5=$(md5 -q "$target" 2>/dev/null || md5sum "$target" | awk '{print $1}')
    sha1=$(shasum -a 1 "$target" | awk '{print $1}')
    fsize=$(du -sh "$target" | cut -f1)
    ftype=$(file -b "$target" 2>/dev/null)
    log "SHA256:  $sha256"; log "MD5:     $md5"
    log "Rozmiar: $fsize";  log "Typ:     $ftype"
    echo "$sha256" > "$SESSION_DIR/sample_sha256.txt"

    echo -e "\n${BOLD}[B2] Magic bytes${RESET}"
    xxd "$target" 2>/dev/null | head -4 | tee -a "$LOG_FILE" || \
        hexdump -C "$target" 2>/dev/null | head -4 | tee -a "$LOG_FILE"

    local is_pe=false
    case "$ftype" in
        *"PE32"*|*"MS-DOS"*) is_pe=true; add_finding "static" 5 "Plik wykonywalny PE Windows" ;;
        *"PDF"*)   log_warn "PDF — może zawierać embedded EXE lub JavaScript" ;;
        *"Zip"*)   log_warn "Zagnieżdżone archiwum wewnątrz archiwum (dropper?)" ;;
    esac

    if $is_pe; then
        echo -e "\n${BOLD}[B3] Nagłówek PE${RESET}"
        python3 - "$target" 2>/dev/null << 'PYEOF' | tee -a "$LOG_FILE" || true
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
    print(f"\n  Sekcje PE:")
    for s in pe.sections:
        name = s.Name.decode(errors='replace').strip('\x00')
        ent  = entropy(s.get_data())
        flag = "  ⚠ WYSOKA ENTROPIA" if ent > 6.8 else ""
        print(f"    {name:<12}  Ent:{ent:.3f}{flag}")
    SUSPICIOUS = {
        'VirtualAllocEx':'T1055','WriteProcessMemory':'T1055','CreateRemoteThread':'T1055',
        'SetWindowsHookEx':'T1056','GetAsyncKeyState':'T1056',
        'URLDownloadToFile':'T1105','CryptEncrypt':'T1486',
        'IsDebuggerPresent':'T1622','RegSetValueEx':'T1112','CreateService':'T1543',
    }
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        found_sus = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors='replace')
            for imp in entry.imports:
                fn = imp.name.decode(errors='replace') if imp.name else f"ord_{imp.ordinal}"
                if fn in SUSPICIOUS: found_sus.append((dll, fn, SUSPICIOUS[fn]))
        if found_sus:
            print(f"\n  [!] PODEJRZANE IMPORTY:")
            for dll, fn, t in found_sus:
                print(f"      {dll} → {fn}  [{t}]")
    if hasattr(pe, 'VS_VERSIONINFO'):
        print(f"\n  Version Info:")
        for vi in pe.VS_VERSIONINFO:
            if hasattr(vi, 'StringFileInfo'):
                for sf in vi.StringFileInfo:
                    for st in sf.StringTable:
                        for k, v in st.entries.items():
                            k2 = k.decode(errors='replace')
                            v2 = v.decode(errors='replace').strip()
                            if v2: print(f"    {k2}: {v2}")
except ImportError: print("  [pefile niedostępny — pip3 install pefile]")
except Exception as e: print(f"  [Błąd PE: {e}]")
PYEOF
    fi

    echo -e "\n${BOLD}[B4] Entropia pliku${RESET}"
    python3 - "$target" 2>/dev/null << 'PYEOF' | tee -a "$LOG_FILE" || true
import sys, math, collections
data = open(sys.argv[1], 'rb').read()
if data:
    c = collections.Counter(data)
    e = -sum((v/len(data))*math.log2(v/len(data)) for v in c.values())
    lvl = "WYSOKA — packer/szyfrowanie" if e>7.0 else "SREDNIA" if e>6.0 else "NORMALNA"
    print(f"  Entropia: {e:.4f} / 8.0  [{lvl}]")
PYEOF

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
            while IFS= read -r hit; do
                echo -e "    ${YELLOW}→${RESET} $hit"
                echo "    IOC[$category]: $hit" >> "$LOG_FILE"
            done <<< "$hits"
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

    if command -v exiftool &>/dev/null; then
        echo -e "\n${BOLD}[B6] ExifTool${RESET}"
        exiftool "$target" 2>/dev/null | grep -vE "^ExifTool Version|^File Name|^Directory" | head -20 | tee -a "$LOG_FILE" || true
    fi

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
                log_ok "Rozpakowano: $unpacked"
                static_analysis "$unpacked"; return
            }
        fi
    fi
    local psigs; psigs=$(strings -n 4 "$target" 2>/dev/null | \
        grep -iE "MPRESS|Themida|Enigma|VMProtect|Obsidium|ASPack|PECompact|PESpin|nPack|WinUpack|Molebox" | head -3 || true)
    if [[ -n "$psigs" ]]; then
        log_warn "Możliwy protektor/packer: $(echo "$psigs" | head -1)"
        add_finding "static" 25 "Znany protektor PE: $(echo "$psigs" | head -1)"
        add_mitre "T1027 — Obfuscated Files"
        packed=true
    fi
    $packed || log_ok "Nie wykryto znanych packerów"

    echo -e "\n${BOLD}[B8] YARA${RESET}"
    _yara_scan "$target"

    if command -v clamscan &>/dev/null; then
        echo -e "\n${BOLD}[B9] ClamAV${RESET}"
        start_spinner "ClamAV skanowanie..."
        if clamscan --heuristic-alerts "$target" 2>&1 | tee -a "$LOG_FILE" | grep -q "OK$"; then
            stop_spinner; log_ok "ClamAV: CZYSTY"
        else
            stop_spinner; log_err "ClamAV: WYKRYTO ZAGROŻENIE!"
            add_finding "static" 80 "ClamAV: wykryto złośliwe oprogramowanie"
        fi
    fi

    local sha256b; sha256b=$(shasum -a 256 "$target" | awk '{print $1}')
    echo -e "\n  ${DIM}VirusTotal: https://www.virustotal.com/gui/file/${sha256b}${RESET}"
    log_ok "Analiza statyczna zakończona — score: $STATIC_RISK_SCORE"
}

_create_yara_rules() {
    local f="$SESSION_DIR/rules.yar"
    cat > "$f" << 'YARARULES'
rule Ransomware_Indicators {
    meta: mitre="T1486"
    strings:
        $e1="CryptEncrypt" nocase $e2="BCryptEncrypt" nocase
        $n1="ransom" nocase $n2="bitcoin" nocase $n3=".locked" nocase
    condition: (2 of ($e*)) or (2 of ($n*))
}
rule ProcessInjection {
    meta: mitre="T1055"
    strings:
        $i1="VirtualAllocEx" nocase $i2="WriteProcessMemory" nocase
        $i3="CreateRemoteThread" nocase $i4="NtCreateThreadEx" nocase
    condition: 2 of them
}
rule Keylogger_Spyware {
    meta: mitre="T1056"
    strings:
        $k1="GetAsyncKeyState" nocase $k2="SetWindowsHookEx" nocase
        $k3="GetClipboardData" nocase
    condition: 2 of them
}
rule AntiAnalysis {
    meta: mitre="T1497,T1622"
    strings:
        $d1="IsDebuggerPresent" nocase $v1="VirtualBox" nocase
        $v2="VMware" nocase $v3="QEMU" nocase $v4="Parallels" nocase
    condition: 1 of ($d*) or 2 of ($v*)
}
rule NetworkC2 {
    meta: mitre="T1071"
    strings:
        $c1="meterpreter" nocase $c2="cobalt strike" nocase
        $c3="mimikatz" nocase $tor=".onion" nocase
    condition: 1 of them
}
rule Persistence_Registry {
    meta: mitre="T1547"
    strings:
        $r1="CurrentVersion\\Run" nocase wide $r2="RunOnce" nocase wide
        $r3="schtasks /create" nocase
    condition: 2 of them
}
rule EncodedPayload {
    meta: mitre="T1027"
    strings:
        $b64=/[A-Za-z0-9+\/]{200,}={0,2}/
        $ps="FromBase64String" nocase
    condition: any of them
}
rule CredentialTheft {
    meta: mitre="T1003"
    strings:
        $l1="lsass" nocase $l2="sekurlsa" nocase $l3=".aws/credentials" nocase
    condition: 2 of them
}
YARARULES
    echo "$f"
}

_yara_scan() {
    local target="$1"
    command -v yara &>/dev/null || { log_warn "YARA niedostępny (brew install yara)"; return; }
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
    [[ -f "$custom" ]] && yara "$custom" "$target" 2>/dev/null | tee -a "$LOG_FILE" || true
}

# ═══════════════════════════════════════════════════════════════
# MODUŁ C — NARZĘDZIA
# ═══════════════════════════════════════════════════════════════

check_and_install() {
    local tool="$1" formula="${2:-$1}" desc="${3:-}"
    command -v "$tool" &>/dev/null && { log_ok "$tool: $(command -v "$tool")"; return 0; }
    log_warn "Brak: $tool ${desc:+(${desc})}"
    command -v brew &>/dev/null || return 1
    read -r -p "$(echo -e "  ${YELLOW}Zainstalować '$formula'? [t/N]${RESET} ")" c
    [[ ! "$c" =~ ^[tTyY]$ ]] && return 1
    start_spinner "Instalowanie $formula..."
    brew install "$formula" >> "$LOG_FILE" 2>&1 \
        && { stop_spinner; log_ok "$formula zainstalowany"; } \
        || { stop_spinner; log_err "Błąd instalacji $formula"; return 1; }
}

check_host_tools() {
    section "SPRAWDZENIE NARZĘDZI"
    command -v brew &>/dev/null || {
        read -r -p "Zainstalować Homebrew? [t/N] " c
        [[ "$c" =~ ^[tTyY]$ ]] && /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" </dev/null >> "$LOG_FILE" 2>&1
        [[ -f "/opt/homebrew/bin/brew" ]] && eval "$(/opt/homebrew/bin/brew shellenv)"
    }
    command -v qemu-system-aarch64 &>/dev/null || command -v qemu-system-x86_64 &>/dev/null \
        || check_and_install qemu-img qemu "wymagane dla VM" || true
    command -v qemu-system-aarch64 &>/dev/null && log_ok "QEMU (aarch64): OK"
    command -v qemu-system-x86_64 &>/dev/null  && log_ok "QEMU (x86_64):  OK"
    check_and_install yara     yara     "YARA"      || true
    check_and_install clamscan clamav   "antywirus"  || true
    check_and_install exiftool exiftool "metadane"  || true
    check_and_install 7z       p7zip    "archiwa"   || true
    if command -v unrar &>/dev/null; then
        log_ok "unrar: $(command -v unrar)"
    else
        log_warn "Brak unrar. Zainstaluj: brew install --cask rar  (instaluje rar + unrar)"
        read -r -p "  Zainstalować cask 'rar'? [t/N] " _c
        if [[ "$_c" =~ ^[tTyY]$ ]]; then
            start_spinner "brew install --cask rar..."
            brew install --cask rar >> "$LOG_FILE" 2>&1 \
                && { stop_spinner; log_ok "rar (cask) — unrar dostępny"; } \
                || { stop_spinner; check_and_install unar unar "fallback RAR" || true; }
        else
            check_and_install unar unar "fallback RAR (bez haseł)" || true
        fi
    fi
    for pkg in pefile yara-python; do
        local imp="${pkg//-/_}"
        python3 -c "import $imp" &>/dev/null 2>&1 && log_ok "pip: $pkg" || {
            pip3 install "$pkg" --quiet 2>/dev/null \
                || pip3 install "$pkg" --quiet --break-system-packages 2>/dev/null || true
            python3 -c "import $imp" &>/dev/null 2>&1 && log_ok "pip: $pkg" || log_warn "pip: $pkg (opcjonalne)"
        }
    done
}

# ═══════════════════════════════════════════════════════════════
# MODUŁ D — ZARZĄDZANIE VM QEMU
# ═══════════════════════════════════════════════════════════════

_qemu_version_ge() {
    local bin="$1" need_maj="$2" need_min="$3"
    local ver_str maj min
    ver_str=$("$bin" --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
    maj="${ver_str%%.*}"; min="${ver_str##*.}"
    [[ -z "$maj" ]] && return 1
    if   [[ $maj -gt $need_maj ]]; then return 0
    elif [[ $maj -eq $need_maj && $min -ge $need_min ]]; then return 0
    else return 1; fi
}

_macos_version_ge() {
    local need="$1"
    local ver; ver=$(sw_vers -productVersion 2>/dev/null | cut -d. -f1)
    [[ -n "$ver" && $ver -ge $need ]]
}

# VM1: ARM64 / HVF
get_qemu_binary()     { echo "qemu-system-aarch64"; }
get_qemu_accel_args() {
    if [[ "$HOST_ARCH" == "arm64" ]]; then
        # M4 + macOS 15 + QEMU 9.2+: 40-bit IPA, bez ograniczeń RAM, bez highmem=off
        # Starsze kombinacje: highmem=off wymagane (36-bit IPA)
        if _qemu_version_ge "qemu-system-aarch64" 9 2 && _macos_version_ge 15; then
            log "HVF: 40-bit IPA (QEMU 9.2+ / macOS 15+) — brak limitów RAM"
            echo "-machine virt,accel=hvf -cpu host"
        else
            log "HVF: 36-bit IPA (stara wersja QEMU/macOS) — highmem=off"
            echo "-machine virt,accel=hvf,highmem=off -cpu host"
        fi
    else
        echo "-machine q35,accel=hvf -cpu host"
    fi
}

# VM2: x86_64 / TCG (emulacja software, HVF niedostępne dla x86 na Apple Silicon)
get_qemu_binary_x86()     { echo "qemu-system-x86_64"; }
get_qemu_accel_args_x86() {
    # Na Apple Silicon: wyłącznie TCG (software emulation) — HVF nie obsługuje x86 na arm64
    # Na Intel Mac: można użyć HVF dla x86
    if [[ "$HOST_ARCH" == "arm64" ]]; then
        echo "-machine q35,accel=tcg -cpu qemu64"
    else
        echo "-machine q35,accel=hvf -cpu host"
    fi
}

check_qemu_disk() {
    [[ -f "$QEMU_DISK" ]] && log_ok "Obraz VM1 (ARM): $QEMU_DISK ($(du -sh "$QEMU_DISK"|cut -f1))" \
        || { log_err "Brak obrazu VM1: $QEMU_DISK"; echo "Uruchom: $0 --setup"; exit 1; }
}

check_qemu_disk_x86() {
    [[ -f "$QEMU_DISK_X86" ]] && log_ok "Obraz VM2 (x86): $QEMU_DISK_X86 ($(du -sh "$QEMU_DISK_X86"|cut -f1))" \
        || { log_err "Brak obrazu VM2 (x86): $QEMU_DISK_X86"; echo "Ustaw: QEMU_DISK_X86=/ścieżka/do/win_x86.qcow2"; return 1; }
}

check_qemu_snapshot() {
    qemu-img snapshot -l "$QEMU_DISK" 2>/dev/null | grep -q "$QEMU_SNAPSHOT" \
        && log_ok "Snapshot VM1: $QEMU_SNAPSHOT" \
        || { log_err "Brak snapshota '$QEMU_SNAPSHOT' w $QEMU_DISK"; exit 1; }
}

check_qemu_snapshot_x86() {
    qemu-img snapshot -l "$QEMU_DISK_X86" 2>/dev/null | grep -q "$QEMU_SNAPSHOT_X86" \
        && log_ok "Snapshot VM2: $QEMU_SNAPSHOT_X86" \
        || { log_err "Brak snapshota '$QEMU_SNAPSHOT_X86' w $QEMU_DISK_X86"; return 1; }
}

revert_to_snapshot() {
    section "RESET VM1 → $QEMU_SNAPSHOT"
    stop_vm
    start_spinner "qemu-img snapshot -a $QEMU_SNAPSHOT ..."
    qemu-img snapshot -a "$QEMU_SNAPSHOT" "$QEMU_DISK" >> "$LOG_FILE" 2>&1 \
        && { stop_spinner; log_ok "VM1 reset (<3s)"; } \
        || { stop_spinner; log_err "Błąd resetu VM1!"; exit 1; }
}

revert_to_snapshot_x86() {
    section "RESET VM2 (x86) → $QEMU_SNAPSHOT_X86"
    stop_vm_x86
    start_spinner "qemu-img snapshot -a $QEMU_SNAPSHOT_X86 ..."
    qemu-img snapshot -a "$QEMU_SNAPSHOT_X86" "$QEMU_DISK_X86" >> "$LOG_FILE" 2>&1 \
        && { stop_spinner; log_ok "VM2 reset (<3s)"; } \
        || { stop_spinner; log_err "Błąd resetu VM2!"; return 1; }
}

start_vm() {
    section "URUCHAMIANIE VM1 — ARM64 / HVF (headless)"
    nc -z 127.0.0.1 "$QEMU_MONITOR_PORT" 2>/dev/null && { log_warn "VM1 już działa"; return 0; }
    local qemu_bin; qemu_bin=$(get_qemu_binary)
    command -v "$qemu_bin" &>/dev/null || { log_err "Brak $qemu_bin — brew install qemu"; exit 1; }
    local accel_args; accel_args=$(get_qemu_accel_args)
    local _net_dev
    [[ "$HOST_ARCH" == "arm64" ]] && _net_dev="virtio-net-device" || _net_dev="virtio-net-pci"
    log "Uruchamianie: $qemu_bin $accel_args"
    $qemu_bin \
        $accel_args \
        -m "$QEMU_MEM" -smp "$QEMU_SMP" \
        -drive "file=$QEMU_DISK,format=qcow2,if=virtio,cache=writeback" \
        -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${QEMU_SSH_PORT}-:22,restrict=on" \
        -device "$_net_dev,netdev=net0" \
        -monitor "tcp:127.0.0.1:${QEMU_MONITOR_PORT},server,nowait" \
        -display none -daemonize \
        -pidfile "$SESSION_DIR/qemu.pid" \
        >> "$SESSION_DIR/qemu.log" 2>&1 \
        || { log_err "Nie udało się uruchomić VM1!"; tail -5 "$SESSION_DIR/qemu.log" 2>/dev/null; exit 1; }
    QEMU_PID=$(cat "$SESSION_DIR/qemu.pid" 2>/dev/null || echo "")
    log_ok "VM1 uruchomiona (PID: $QEMU_PID) — SSH: localhost:$QEMU_SSH_PORT"
    _wait_for_ssh "$QEMU_SSH_PORT" "VM1"
}

start_vm_x86() {
    section "URUCHAMIANIE VM2 — x86_64 / TCG (headless)"
    nc -z 127.0.0.1 "$QEMU_MONITOR_PORT_X86" 2>/dev/null && { log_warn "VM2 już działa"; return 0; }
    local qemu_bin; qemu_bin=$(get_qemu_binary_x86)
    command -v "$qemu_bin" &>/dev/null || { log_err "Brak $qemu_bin — brew install qemu"; return 1; }
    local accel_args; accel_args=$(get_qemu_accel_args_x86)
    if [[ "$HOST_ARCH" == "arm64" ]]; then
        log_warn "VM2 (x86): TCG software emulation na Apple Silicon — wolniejsza niż HVF"
        log_warn "Emulacja x86 przez TCG: oczekuj ~3-10x wolniej niż natywna VM ARM"
    fi
    log "Uruchamianie: $qemu_bin $accel_args"
    $qemu_bin \
        $accel_args \
        -m "$QEMU_MEM_X86" -smp "$QEMU_SMP_X86" \
        -drive "file=$QEMU_DISK_X86,format=qcow2,if=virtio,cache=writeback" \
        -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${QEMU_SSH_PORT_X86}-:22,restrict=on" \
        -device "virtio-net-pci,netdev=net0" \
        -monitor "tcp:127.0.0.1:${QEMU_MONITOR_PORT_X86},server,nowait" \
        -display none -daemonize \
        -pidfile "$SESSION_DIR/qemu2.pid" \
        >> "$SESSION_DIR/qemu2.log" 2>&1 \
        || { log_err "Nie udało się uruchomić VM2 (x86)!"; tail -5 "$SESSION_DIR/qemu2.log" 2>/dev/null; return 1; }
    QEMU_PID_X86=$(cat "$SESSION_DIR/qemu2.pid" 2>/dev/null || echo "")
    log_ok "VM2 uruchomiona (PID: $QEMU_PID_X86) — SSH: localhost:$QEMU_SSH_PORT_X86"
    _wait_for_ssh "$QEMU_SSH_PORT_X86" "VM2 (x86)"
}

_wait_for_ssh() {
    local port="$1" label="${2:-VM}"
    log "Czekam na SSH $label (max ${VM_BOOT_TIMEOUT}s)..."
    local waited=0
    while [[ $waited -lt $VM_BOOT_TIMEOUT ]]; do
        if _vm_ssh "$port" "echo ready" 2>/dev/null | grep -q "ready"; then
            log_ok "$label gotowa po ${waited}s"
            return 0
        fi
        sleep 3; ((waited+=3)) || true
        printf "\r  ${DIM}Boot $label: ${waited}/${VM_BOOT_TIMEOUT}s${RESET}"
    done
    printf "\r\033[K"
    log_warn "$label — SSH nie odpowiedziało w ${VM_BOOT_TIMEOUT}s (kontynuuję)"
}

stop_vm() {
    local pid_file="$SESSION_DIR/qemu.pid"
    if [[ -f "$pid_file" ]]; then
        local pid; pid=$(cat "$pid_file")
        kill -0 "$pid" 2>/dev/null && {
            qemu_monitor_cmd "system_powerdown" "$QEMU_MONITOR_PORT" || true
            sleep 3; kill -9 "$pid" 2>/dev/null || true
            log_ok "VM1 zatrzymana"
        }
        rm -f "$pid_file"
    fi
}

stop_vm_x86() {
    local pid_file="$SESSION_DIR/qemu2.pid"
    if [[ -f "$pid_file" ]]; then
        local pid; pid=$(cat "$pid_file")
        kill -0 "$pid" 2>/dev/null && {
            qemu_monitor_cmd "system_powerdown" "$QEMU_MONITOR_PORT_X86" || true
            sleep 3; kill -9 "$pid" 2>/dev/null || true
            log_ok "VM2 (x86) zatrzymana"
        }
        rm -f "$pid_file"
    fi
}

stop_all_vms() { stop_vm; stop_vm_x86; }

prepare_vm_environment() {
    local ssh_port="${1:-$QEMU_SSH_PORT}" label="${2:-VM1}"
    log "Konfiguracja $label..."
    _vm_ssh "$ssh_port" "cmd /c 'mkdir C:\\Tools C:\\Malware C:\\NoribenLogs 2>nul & exit 0'" \
        >> "$LOG_FILE" 2>&1 || true
    local noriben_local="$HOST_TOOLS_DIR/Noriben.py"
    [[ -f "$noriben_local" ]] && {
        _vm_scp_to "$ssh_port" "$noriben_local" 'C:\Tools\Noriben.py' \
            && log_ok "Noriben.py → $label" || log_warn "Nie udało się wgrać Noriben.py do $label"
    }
    _vm_ssh "$ssh_port" "powershell -Command \"
        Set-MpPreference -DisableRealtimeMonitoring \\\$true 2>\\\$null
        Add-MpPreference -ExclusionPath 'C:\\Malware','C:\\NoribenLogs','C:\\Tools' 2>\\\$null
    \"" >> "$LOG_FILE" 2>&1 || true
    log_ok "$label skonfigurowana"
}

# ═══════════════════════════════════════════════════════════════
# MODUŁ E — ANALIZA DYNAMICZNA
# ═══════════════════════════════════════════════════════════════

run_dynamic_analysis() {
    local sample_vm_path="$1"
    local ssh_port="${2:-$QEMU_SSH_PORT}"
    local monitor_port="${3:-$QEMU_MONITOR_PORT}"
    local label="${4:-VM1}"
    local results_dir="${5:-$SESSION_DIR}"

    section "ANALIZA DYNAMICZNA — NORIBEN ($label)"
    local timeout_min=$(( ANALYSIS_TIMEOUT / 60 ))
    echo -e "  ${BOLD}Próbka:${RESET}  $(basename "$sample_vm_path")"
    echo -e "  ${BOLD}Timeout:${RESET} ${ANALYSIS_TIMEOUT}s (${timeout_min} min)"
    echo -e "  ${BOLD}VM:${RESET}      $label  SSH:localhost:${ssh_port}"
    [[ "$HOST_ARCH" == "arm64" && "$label" == *"x86"* ]] && \
        echo -e "  ${YELLOW}⚠ TCG software emulation — wolniejsza analiza${RESET}"
    echo ""

    _vm_ssh "$ssh_port" "cmd /c 'del /Q C:\\NoribenLogs\\* 2>nul & exit 0'" >> "$LOG_FILE" 2>&1 || true

    # Opcjonalne przechwytywanie ruchu sieciowego przez tcpdump (loopback)
    local tcpdump_pid="" pcap_file="$SESSION_DIR/${label}_network_capture.pcap"
    if command -v tcpdump &>/dev/null; then
        read -r -p "$(echo -e "  ${YELLOW}Przechwytywać ruch $label przez tcpdump? [t/N]${RESET} ")" tcp_c
        if [[ "$tcp_c" =~ ^[tTyY]$ ]]; then
            sudo tcpdump -i lo0 "port $ssh_port" -w "$pcap_file" >> "$LOG_FILE" 2>&1 &
            tcpdump_pid=$!
            log_ok "tcpdump uruchomiony (PID: $tcpdump_pid) → $pcap_file"
        fi
    fi

    local analysis_start; analysis_start=$(date +%s)
    local ps_cmd
    ps_cmd="Start-Process -FilePath '$VM_PYTHON' -ArgumentList '$VM_NORIBEN','--cmd','$sample_vm_path','--timeout','$ANALYSIS_TIMEOUT','--output','C:\\NoribenLogs','--headless','--generalize' -Wait -NoNewWindow -RedirectStandardOutput 'C:\\NoribenLogs\\noriben_stdout.txt' -RedirectStandardError 'C:\\NoribenLogs\\noriben_stderr.txt'"
    _vm_ssh "$ssh_port" "powershell -Command \"$ps_cmd\"" >> "$LOG_FILE" 2>&1 &
    local ssh_pid=$!

    while kill -0 $ssh_pid 2>/dev/null; do
        local elapsed=$(( $(date +%s) - analysis_start ))
        local pct=$(( elapsed * 100 / (ANALYSIS_TIMEOUT + 30) ))
        [[ $pct -gt 100 ]] && pct=100
        local filled=$(( pct * 40 / 100 )) empty=$(( 40 - filled ))
        local bar
        bar="$(printf '%*s' "$filled" '' | tr ' ' '█')$(printf '%*s' "$empty" '' | tr ' ' '░')"
        printf "\r  ${CYAN}[$bar]${RESET}  %3d%%  %ds " "$pct" "$elapsed"
        sleep 2
    done
    printf "\r\033[K"
    wait $ssh_pid 2>/dev/null || true
    log_ok "$label — Noriben zakończył po $(( $(date +%s) - analysis_start ))s"
    [[ -n "$tcpdump_pid" ]] && { sudo kill "$tcpdump_pid" 2>/dev/null || true; log_ok "PCAP: $pcap_file"; }
    sleep 2
}

collect_results() {
    local ssh_port="${1:-$QEMU_SSH_PORT}"
    local dest_dir="${2:-$SESSION_DIR}"
    mkdir -p "$dest_dir"
    _vm_ssh "$ssh_port" 'powershell -Command "Compress-Archive -Path C:\NoribenLogs\* -DestinationPath C:\NoribenLogs\results.zip -Force"' \
        >> "$LOG_FILE" 2>&1 || {
        log_warn "Compress-Archive nieudane — kopiuję osobno..."
        local vm_files
        vm_files=$(_vm_ssh "$ssh_port" "powershell -Command \"Get-ChildItem 'C:\\NoribenLogs' | Select-Object -ExpandProperty Name\"" 2>/dev/null || echo "")
        while IFS= read -r fname; do
            [[ -z "$fname" ]] && continue
            _vm_scp_from "$ssh_port" "C:\\NoribenLogs\\$fname" "$dest_dir/$fname" || true
        done <<< "$vm_files"
        return 0
    }
    local local_zip="$dest_dir/results_noriben.zip"
    _vm_scp_from "$ssh_port" 'C:\NoribenLogs\results.zip' "$local_zip" && {
        unzip -q "$local_zip" -d "$dest_dir/" 2>/dev/null \
            && { log_ok "Wyniki pobrane: $dest_dir"; rm -f "$local_zip"; } \
            || log_warn "Błąd rozpakowywania — ZIP: $local_zip"
    } || log_err "Nie udało się skopiować wyników"
}

analyze_dynamic_results() {
    local src_dir="${1:-$SESSION_DIR}"
    section "ANALIZA WYNIKÓW NORIBEN"
    local txt_report; txt_report=$(find "$src_dir" -name "Noriben_*.txt" 2>/dev/null | head -1)
    [[ -z "$txt_report" || ! -f "$txt_report" ]] && {
        log_warn "Brak raportu Noriben TXT w $src_dir"
        return 1
    }
    log_ok "Raport: $txt_report"
    head -60 "$txt_report" | tee -a "$LOG_FILE"

    local dyn_keys=(
        "Nowe procesy" "Siec TCP/UDP" "Zapis rejestru"
        "Nowe pliki EXE" "Autostart Persistence" "Wstrzykiwanie procesow"
        "Shadow Copy VSS" "Modyfikacje systemu"
    )
    local dyn_pats=(
        "Process Create|CreateProcess|Spawned"
        "TCP|UDP|Connect|DNS"
        "RegSetValue|RegCreateKey|\\\\Run\\\\|\\\\RunOnce\\\\"
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
                "Siec TCP/UDP")            add_mitre "T1071 — Application Layer Protocol" ;;
                "Autostart Persistence")   add_mitre "T1547 — Boot Autostart Execution" ;;
                "Wstrzykiwanie procesow")  add_mitre "T1055 — Process Injection" ;;
                "Shadow Copy VSS")         add_mitre "T1490 — Inhibit System Recovery" ;;
            esac
        fi
    done
    [[ $dyn_total -eq 0 ]] && log_ok "Brak IOC dynamicznych" || log_warn "$dyn_total kategorii IOC"
    log_ok "Analiza dynamiczna — score: $DYNAMIC_RISK_SCORE"
}

# ═══════════════════════════════════════════════════════════════
# MODUŁ E2 — ANALIZA DUAL-VM (ARM + x86 równolegle)
# ═══════════════════════════════════════════════════════════════

run_dual_vm_analysis() {
    local target="$1"
    local fname; fname=$(basename "$target")
    local file_dir="$SESSION_DIR/files/${fname%%.*}_$(date '+%H%M%S')"
    local arm_dir="$file_dir/arm64"
    local x86_dir="$file_dir/x86_64"
    mkdir -p "$arm_dir" "$x86_dir"

    section "DUAL-VM — $fname"
    echo -e "  ${BOLD}${CYAN}VM1 (ARM64 / HVF):${RESET}  Windows on ARM  →  SSH localhost:$QEMU_SSH_PORT"
    echo -e "  ${BOLD}${YELLOW}VM2 (x86_64 / TCG):${RESET} Windows x86/x64 →  SSH localhost:$QEMU_SSH_PORT_X86"
    echo ""

    # Skopiuj próbkę do obu VM
    section "KOPIOWANIE PRÓBKI → OBU VM"
    local vm1_path="C:\\Malware\\${fname}" vm2_path="C:\\Malware\\${fname}"
    _vm_ssh  "$QEMU_SSH_PORT"     "cmd /c 'del /Q C:\\NoribenLogs\\* 2>nul & exit 0'" >> "$LOG_FILE" 2>&1 || true
    _vm_ssh  "$QEMU_SSH_PORT_X86" "cmd /c 'del /Q C:\\NoribenLogs\\* 2>nul & exit 0'" >> "$LOG_FILE" 2>&1 || true
    _vm_scp_to "$QEMU_SSH_PORT"     "$target" "$vm1_path" && log_ok "→ VM1 (ARM)" || log_err "Błąd kopiowania do VM1"
    _vm_scp_to "$QEMU_SSH_PORT_X86" "$target" "$vm2_path" && log_ok "→ VM2 (x86)" || log_err "Błąd kopiowania do VM2"

    # Uruchom Noriben w obu VM RÓWNOLEGLE (w tle)
    section "NORIBEN — ANALIZA RÓWNOLEGŁA"
    echo -e "  ${CYAN}VM1 (ARM):${RESET} uruchamianie Noriben w tle..."
    local ps_cmd
    ps_cmd="Start-Process -FilePath '$VM_PYTHON' -ArgumentList '$VM_NORIBEN','--cmd','$vm1_path','--timeout','$ANALYSIS_TIMEOUT','--output','C:\\NoribenLogs','--headless','--generalize' -Wait -NoNewWindow -RedirectStandardOutput 'C:\\NoribenLogs\\noriben_stdout.txt' -RedirectStandardError 'C:\\NoribenLogs\\noriben_stderr.txt'"
    _vm_ssh "$QEMU_SSH_PORT" "powershell -Command \"$ps_cmd\"" >> "$LOG_FILE" 2>&1 &
    local pid_arm=$!

    echo -e "  ${YELLOW}VM2 (x86):${RESET} uruchamianie Noriben w tle..."
    _vm_ssh "$QEMU_SSH_PORT_X86" "powershell -Command \"$ps_cmd\"" >> "$LOG_FILE" 2>&1 &
    local pid_x86=$!

    # Progress bar podczas gdy obie VM pracują równolegle
    local analysis_start; analysis_start=$(date +%s)
    echo ""
    while kill -0 $pid_arm 2>/dev/null || kill -0 $pid_x86 2>/dev/null; do
        local elapsed=$(( $(date +%s) - analysis_start ))
        local pct=$(( elapsed * 100 / (ANALYSIS_TIMEOUT + 30) ))
        [[ $pct -gt 100 ]] && pct=100
        local filled=$(( pct * 35 / 100 )) empty=$(( 35 - filled ))
        local bar
        bar="$(printf '%*s' "$filled" '' | tr ' ' '█')$(printf '%*s' "$empty" '' | tr ' ' '░')"
        local arm_status="●" x86_status="●"
        kill -0 $pid_arm 2>/dev/null || arm_status="${GREEN}✓${RESET}"
        kill -0 $pid_x86 2>/dev/null || x86_status="${GREEN}✓${RESET}"
        printf "\r  ${CYAN}[$bar]${RESET} %3d%%  ARM:%b  x86:%b  %ds" \
            "$pct" "$arm_status" "$x86_status" "$elapsed"
        sleep 2
    done
    printf "\r\033[K"
    wait $pid_arm 2>/dev/null || true
    wait $pid_x86 2>/dev/null || true
    log_ok "Obie VM zakończyły analizę po $(( $(date +%s) - analysis_start ))s"
    sleep 2

    # Pobierz wyniki z obu VM
    section "POBIERANIE WYNIKÓW"
    log "← VM1 (ARM)..."
    collect_results "$QEMU_SSH_PORT" "$arm_dir"
    log "← VM2 (x86)..."
    collect_results "$QEMU_SSH_PORT_X86" "$x86_dir"

    # Analizuj wyniki (scalaj scoring)
    section "ANALIZA WYNIKÓW — VM1 (ARM)"
    analyze_dynamic_results "$arm_dir"
    local arm_dyn_score=$DYNAMIC_RISK_SCORE

    section "ANALIZA WYNIKÓW — VM2 (x86)"
    # Nie resetuj statycznych wyników — tylko dynamiczne z x86
    local x86_start_dyn=$DYNAMIC_RISK_SCORE
    analyze_dynamic_results "$x86_dir"
    local x86_dyn_score=$(( DYNAMIC_RISK_SCORE - x86_start_dyn ))

    # Reset VM po analizie
    section "CZYSZCZENIE VM PO ANALIZIE"
    _vm_ssh "$QEMU_SSH_PORT"     "cmd /c 'del /Q C:\\Malware\\* C:\\NoribenLogs\\* 2>nul & exit 0'" >> "$LOG_FILE" 2>&1 || true
    _vm_ssh "$QEMU_SSH_PORT_X86" "cmd /c 'del /Q C:\\Malware\\* C:\\NoribenLogs\\* 2>nul & exit 0'" >> "$LOG_FILE" 2>&1 || true
    log_ok "Obie VM wyczyszczone"

    # Raport HTML z wynikami obu VM
    generate_html_report "$target" "$file_dir" "$arm_dir" "$x86_dir"
}

# ═══════════════════════════════════════════════════════════════
# MODUŁ F — RAPORT HTML
# ═══════════════════════════════════════════════════════════════

generate_html_report() {
    local target_file="${1:-${EXTRACTED_SAMPLE:-$SAMPLE_FILE}}"
    local report_dir="${2:-$SESSION_DIR}"
    local arm_dir="${3:-}"
    local x86_dir="${4:-}"
    section "GENEROWANIE RAPORTU HTML"

    local fname; fname=$(basename "$target_file")
    local slug="${fname%%.*}"
    local html_out="$report_dir/REPORT_${slug}_${SESSION_ID}.html"
    local sha256; sha256=$(cat "$SESSION_DIR/sample_sha256.txt" 2>/dev/null || \
        shasum -a 256 "$target_file" | awk '{print $1}')
    local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
    local ftype; ftype=$(file -b "$target_file" 2>/dev/null)
    local fsize; fsize=$(du -sh "$target_file" | cut -f1)

    local total_score=$(( (STATIC_RISK_SCORE + DYNAMIC_RISK_SCORE) / 2 ))
    [[ $total_score -gt 100 ]] && total_score=100
    local risk_class="low" risk_label="NISKIE" risk_color="#3fb950"
    [[ $total_score -ge 40 ]] && risk_class="med"  risk_label="ŚREDNIE"  risk_color="#e3b341"
    [[ $total_score -ge 70 ]] && risk_class="high" risk_label="WYSOKIE"  risk_color="#f85149"

    local mitre_html="" _seen_mitre=""
    for t in "${MITRE_TECHNIQUES[@]:-}"; do
        [[ -z "$t" ]] && continue
        case "$_seen_mitre" in *"|${t}|"*) continue ;; esac
        _seen_mitre="${_seen_mitre}|${t}|"
        mitre_html+="<span class='mtag'>$t</span>"
    done

    local static_html="" dynamic_html=""
    for f in "${STATIC_FINDINGS[@]:-}";  do static_html+="<div class='finding f-red'>$f</div>"; done
    for f in "${DYNAMIC_FINDINGS[@]:-}"; do dynamic_html+="<div class='finding f-yellow'>$f</div>"; done
    [[ -z "$static_html" ]]  && static_html="<div class='finding f-green'>✓ Brak wskaźników statycznych</div>"
    [[ -z "$dynamic_html" ]] && dynamic_html="<div class='finding f-green'>✓ Brak zachowań dynamicznych</div>"

    local arm_noriben_html="" x86_noriben_html=""
    if [[ -n "$arm_dir" ]]; then
        local nr; nr=$(find "$arm_dir" -name "Noriben_*.txt" 2>/dev/null | head -1)
        [[ -n "$nr" && -f "$nr" ]] && arm_noriben_html=$(sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g' "$nr")
    fi
    if [[ -n "$x86_dir" ]]; then
        local nr2; nr2=$(find "$x86_dir" -name "Noriben_*.txt" 2>/dev/null | head -1)
        [[ -n "$nr2" && -f "$nr2" ]] && x86_noriben_html=$(sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g' "$nr2")
    fi
    [[ -z "$arm_noriben_html" && -z "$x86_noriben_html" ]] && {
        local nr3; nr3=$(find "$report_dir" -name "Noriben_*.txt" 2>/dev/null | head -1)
        [[ -n "$nr3" && -f "$nr3" ]] && arm_noriben_html=$(sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g' "$nr3")
    }

    local log_html; log_html=$(tail -80 "$LOG_FILE" 2>/dev/null | sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g')
    local qemu_log_html; qemu_log_html=$(cat "$SESSION_DIR/qemu.log" 2>/dev/null | tail -30 | \
        sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g' || echo "(brak)")
    local qemu2_log_html; qemu2_log_html=$(cat "$SESSION_DIR/qemu2.log" 2>/dev/null | tail -20 | \
        sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g' || echo "(brak)")

    local dual_section=""
    if [[ -n "$arm_dir" || -n "$x86_dir" ]]; then
        dual_section="<h2>🔀 Dual-VM — Porównanie wyników</h2>
<div class='two-col'>
  <div>
    <h3 style='color:#79c0ff;margin-bottom:8px'>🦾 VM1 — ARM64 / HVF</h3>
    $(if [[ -n "$arm_noriben_html" ]]; then echo "<pre>${arm_noriben_html}</pre>"; \
      else echo "<div class='card' style='color:#8b949e'>Brak raportu Noriben (VM1)</div>"; fi)
  </div>
  <div>
    <h3 style='color:#e3b341;margin-bottom:8px'>🖥 VM2 — x86_64 / TCG</h3>
    $(if [[ -n "$x86_noriben_html" ]]; then echo "<pre>${x86_noriben_html}</pre>"; \
      else echo "<div class='card' style='color:#8b949e'>Brak raportu Noriben (VM2)</div>"; fi)
  </div>
</div>"
    fi

    mkdir -p "$report_dir"
    cat > "$html_out" << HTMLEOF
<!DOCTYPE html><html lang="pl"><head><meta charset="UTF-8">
<title>QEMU Sandbox v3.2 — ${fname}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Courier New',monospace;background:#0d1117;color:#c9d1d9;padding:28px;line-height:1.6}
a{color:#58a6ff} h1{color:#58a6ff;font-size:1.7em;margin-bottom:4px}
h2{color:#79c0ff;font-size:1.05em;margin:22px 0 10px;border-left:4px solid #388bfd;padding-left:12px}
h3{color:#79c0ff;font-size:.95em;margin:12px 0 6px}
.subtitle{color:#8b949e;font-size:.84em}
.hdr{border-bottom:1px solid #30363d;padding-bottom:14px;margin-bottom:18px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;margin:10px 0}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px}
.lbl{color:#8b949e;font-size:.72em;text-transform:uppercase;letter-spacing:.04em}
.val{color:#e6edf3;font-size:.85em;margin-top:3px;word-break:break-all}
.hash{color:#3fb950;font-size:.68em}
pre{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:14px;
    overflow-x:auto;white-space:pre-wrap;font-size:.77em;max-height:380px;overflow-y:auto}
.score-wrap{display:flex;align-items:center;gap:16px;margin:12px 0}
.score-circle{width:80px;height:80px;border-radius:50%;display:flex;align-items:center;
    justify-content:center;font-size:1.4em;font-weight:bold;flex-shrink:0}
.high{background:#3d1c1c;color:#f85149;border:3px solid #f85149}
.med {background:#3d2f0e;color:#e3b341;border:3px solid #e3b341}
.low {background:#0d2818;color:#3fb950;border:3px solid #3fb950}
.finding{padding:4px 10px;border-left:3px solid;margin:2px 0;border-radius:0 4px 4px 0;font-size:.82em}
.f-red   {border-color:#f85149;background:#1c0e0e;color:#f85149}
.f-yellow{border-color:#e3b341;background:#1c180e;color:#e3b341}
.f-green {border-color:#3fb950;background:#0d1c0e;color:#3fb950}
.mtag{display:inline-block;background:#1c2a3e;color:#79c0ff;border:1px solid #264b73;
    border-radius:4px;padding:2px 8px;font-size:.72em;margin:2px}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.bar-wrap{background:#21262d;border-radius:4px;height:6px;width:240px;margin:6px 0}
.bar-fill{height:6px;border-radius:4px}
.vt-btn{display:inline-block;background:#1c3a5e;color:#58a6ff;padding:7px 14px;
    border-radius:6px;text-decoration:none;font-size:.84em;margin-top:7px}
.dual-badge{display:inline-block;background:#1c2a1c;color:#3fb950;border:1px solid #3fb950;
    border-radius:4px;padding:2px 10px;font-size:.74em;margin-left:8px}
footer{color:#8b949e;font-size:.73em;margin-top:32px;border-top:1px solid #30363d;padding-top:10px}
@media(max-width:700px){.two-col{grid-template-columns:1fr}}
</style></head><body>

<div class="hdr">
  <h1>🔬 QEMU Sandbox Report <span class="dual-badge">Dual-VM: HVF + TCG</span></h1>
  <p class="subtitle">v${VERSION} · ${ts} · Sesja: ${SESSION_ID}</p>
  <p class="subtitle">Host: macOS ${HOST_ARCH} · VM1: aarch64/HVF · VM2: x86_64/TCG</p>
</div>

<h2>🛡 Model izolacji</h2>
<div class="grid">
  <div class="card"><div class="lbl">VM1 hiperwizor</div><div class="val">QEMU + Apple HVF (${HOST_ARCH}) — kernel-level isolation</div></div>
  <div class="card"><div class="lbl">VM2 hiperwizor</div><div class="val">QEMU TCG (software emulation x86_64)</div></div>
  <div class="card"><div class="lbl">Sieć VM</div><div class="val" style="color:#3fb950">IZOLOWANA — user-mode restrict=on, tylko SSH localhost</div></div>
  <div class="card"><div class="lbl">Snapshot reset</div><div class="val">qemu-img atomowy &lt;3s — ${QEMU_SNAPSHOT}</div></div>
</div>

<h2>📁 Próbka</h2>
<div class="grid">
  <div class="card"><div class="lbl">Nazwa</div><div class="val">${fname}</div></div>
  <div class="card"><div class="lbl">Typ</div><div class="val">${ftype}</div></div>
  <div class="card"><div class="lbl">Rozmiar</div><div class="val">${fsize}</div></div>
  <div class="card"><div class="lbl">SHA256</div><div class="val hash">${sha256}</div></div>
</div>
<a class="vt-btn" href="https://www.virustotal.com/gui/file/${sha256}" target="_blank">🔍 VirusTotal →</a>

<h2>⚠️ Ocena ryzyka</h2>
<div class="score-wrap">
  <div class="score-circle ${risk_class}">${total_score}</div>
  <div>
    <div style="font-size:1.2em;font-weight:bold;color:${risk_color}">${risk_label}</div>
    <div class="lbl" style="margin-top:4px">Statyczna: ${STATIC_RISK_SCORE} &nbsp;|&nbsp; Dynamiczna: ${DYNAMIC_RISK_SCORE}</div>
    <div class="bar-wrap"><div class="bar-fill" style="width:${total_score}%;background:${risk_color}"></div></div>
  </div>
</div>

<div class="two-col">
  <div><h2>🔍 Analiza statyczna</h2>${static_html}</div>
  <div><h2>🧬 Analiza dynamiczna</h2>${dynamic_html}</div>
</div>

$(if [[ -n "$mitre_html" ]]; then echo "<h2>🗺 MITRE ATT&amp;CK</h2>$mitre_html"; fi)

${dual_section}

$(if [[ -z "$arm_dir" && -z "$x86_dir" && -n "$arm_noriben_html" ]]; then
    echo "<h2>📋 Raport Noriben</h2><pre>${arm_noriben_html}</pre>"
fi)

<h2>⚙️ Konfiguracja</h2>
<div class="card">
<table style="width:100%;border-collapse:collapse;font-size:.83em">
  <tr><td style="color:#8b949e;padding:3px 10px;width:180px">VM1 obraz (ARM)</td><td style="padding:3px 10px">${QEMU_DISK}</td></tr>
  <tr><td style="color:#8b949e;padding:3px 10px">VM1 snapshot</td><td style="padding:3px 10px">${QEMU_SNAPSHOT} · RAM: ${QEMU_MEM} · vCPU: ${QEMU_SMP}</td></tr>
  <tr><td style="color:#8b949e;padding:3px 10px">VM2 obraz (x86)</td><td style="padding:3px 10px">${QEMU_DISK_X86}</td></tr>
  <tr><td style="color:#8b949e;padding:3px 10px">VM2 snapshot</td><td style="padding:3px 10px">${QEMU_SNAPSHOT_X86} · RAM: ${QEMU_MEM_X86} · vCPU: ${QEMU_SMP_X86}</td></tr>
  <tr><td style="color:#8b949e;padding:3px 10px">Timeout</td><td style="padding:3px 10px">${ANALYSIS_TIMEOUT}s ($(( ANALYSIS_TIMEOUT/60 )) min)</td></tr>
  <tr><td style="color:#8b949e;padding:3px 10px">Host</td><td style="padding:3px 10px">macOS ${HOST_ARCH} · $(sw_vers -productVersion 2>/dev/null)</td></tr>
</table>
</div>

<h2>📄 Log hosta</h2>
<pre>${log_html}</pre>

<h2>🖥 Log QEMU — VM1 (ARM/HVF)</h2>
<pre>${qemu_log_html}</pre>

$(if [[ -n "$qemu2_log_html" && "$qemu2_log_html" != "(brak)" ]]; then
    echo "<h2>🖥 Log QEMU — VM2 (x86/TCG)</h2><pre>${qemu2_log_html}</pre>"
fi)

<footer>noriben_qemu_sandbox.sh v${VERSION} · QEMU/HVF (ARM64) + QEMU/TCG (x86_64) · Noriben + Procmon</footer>
</body></html>
HTMLEOF

    log_ok "Raport HTML: $html_out"
    SESSION_REPORTS+=("$html_out")
    echo "$html_out"
}

# ═══════════════════════════════════════════════════════════════
# MODUŁ G — ZBIORCZY RAPORT SERII
# ═══════════════════════════════════════════════════════════════

_generate_batch_report() {
    # Argumenty: total_files scores_array_name reports_array_name
    # Zamiast nameref (bash 4.3+) używamy globalnych tablic bezpośrednio
    local total_files="$1"
    # batch_scores i SESSION_REPORTS są globalne — używamy ich bezpośrednio
    local batch_html="$SESSION_DIR/BATCH_REPORT_${SESSION_ID}.html"
    local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
    local high_count=0 med_count=0 low_count=0 total_score_sum=0 avg_score=0

    for entry in "${batch_scores[@]:-}"; do
        [[ -z "$entry" ]] && continue
        local score="${entry##*:}"
        total_score_sum=$(( total_score_sum + score ))
        if   [[ $score -ge 70 ]]; then ((high_count++)) || true
        elif [[ $score -ge 40 ]]; then ((med_count++))  || true
        else                           ((low_count++))  || true
        fi
    done
    [[ ${#batch_scores[@]} -gt 0 ]] && avg_score=$(( total_score_sum / ${#batch_scores[@]} ))
    [[ $avg_score -gt 100 ]] && avg_score=100

    echo ""
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════╗"
    echo -e "║  📊  PODSUMOWANIE SERII                                  ║"
    printf  "║  Pliki: %-49s║\n" "$total_files  |  Avg score: $avg_score/100"
    printf  "║  ${RED}Wysokie: %-3s${CYAN}  ${YELLOW}Średnie: %-3s${CYAN}  ${GREEN}Niskie: %-3s${CYAN}                  ║\n" \
        "$high_count" "$med_count" "$low_count"
    echo -e "╚══════════════════════════════════════════════════════════╝${RESET}"
    echo ""
    for entry in "${batch_scores[@]:-}"; do
        [[ -z "$entry" ]] && continue
        local fname="${entry%%:*}" score="${entry##*:}"
        local bar_c="$GREEN" risk="NISKIE"
        [[ $score -ge 40 ]] && bar_c="$YELLOW" && risk="SREDNIE"
        [[ $score -ge 70 ]] && bar_c="$RED"    && risk="WYSOKIE"
        printf "  %-40s ${bar_c}%3d/100${RESET}  %s\n" "$fname" "$score" "$risk"
    done
    echo ""

    local reports_rows="" chart_labels="" chart_data="" chart_colors=""
    local si=0
    for report_path in "${SESSION_REPORTS[@]:-}"; do
        [[ -z "$report_path" ]] && { ((si++)) || true; continue; }
        local rname; rname=$(basename "$report_path")
        if [[ $si -lt ${#batch_scores[@]} ]]; then
            local bentry="${batch_scores[$si]}"
            local bfname="${bentry%%:*}" bscore="${bentry##*:}"
            local sc_c='"#3fb950"'
            [[ $bscore -ge 40 ]] && sc_c='"#e3b341"'
            [[ $bscore -ge 70 ]] && sc_c='"#f85149"'
            local sc_cv="${sc_c//\"/}"
            reports_rows+="<tr><td><a href='${report_path}'>$rname</a></td><td>$bfname</td><td style='color:${sc_cv};font-weight:bold'>${bscore}/100</td></tr>"
            chart_labels+="\"${bfname}\","
            chart_data+="${bscore},"
            chart_colors+="${sc_c},"
        fi
        ((si++)) || true
    done

    cat > "$batch_html" << BATCHEOF
<!DOCTYPE html><html lang="pl"><head><meta charset="UTF-8">
<title>Batch Report — ${SAMPLE_BASENAME}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Courier New',monospace;background:#0d1117;color:#c9d1d9;padding:28px;line-height:1.6}
a{color:#58a6ff} h1{color:#58a6ff;font-size:1.6em;margin-bottom:4px}
h2{color:#79c0ff;font-size:1.05em;margin:20px 0 10px;border-left:4px solid #388bfd;padding-left:12px}
.subtitle{color:#8b949e;font-size:.84em}
.hdr{border-bottom:1px solid #30363d;padding-bottom:14px;margin-bottom:18px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;margin:10px 0}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px;text-align:center}
.card-num{font-size:2em;font-weight:bold} .card-lbl{color:#8b949e;font-size:.73em;margin-top:4px}
.high{color:#f85149} .med{color:#e3b341} .low{color:#3fb950} .avg{color:#79c0ff}
table{width:100%;border-collapse:collapse;font-size:.83em}
th{color:#8b949e;text-align:left;padding:6px 10px;border-bottom:1px solid #30363d;font-weight:normal;font-size:.73em;text-transform:uppercase}
td{padding:6px 10px;border-bottom:1px solid #21262d}
.chart-wrap{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px;height:240px;margin:10px 0}
footer{color:#8b949e;font-size:.72em;margin-top:28px;border-top:1px solid #30363d;padding-top:10px}
</style>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
</head><body>
<div class="hdr">
  <h1>📊 Batch Report</h1>
  <p class="subtitle">Archiwum: ${SAMPLE_BASENAME} · Sesja: ${SESSION_ID} · ${ts}</p>
  <p class="subtitle">QEMU/HVF (ARM64) + QEMU/TCG (x86_64) · Dual-VM mode</p>
</div>
<h2>📈 Statystyki</h2>
<div class="grid">
  <div class="card"><div class="card-num avg">$avg_score</div><div class="card-lbl">Avg score/100</div></div>
  <div class="card"><div class="card-num">$total_files</div><div class="card-lbl">Pliki łącznie</div></div>
  <div class="card"><div class="card-num high">$high_count</div><div class="card-lbl">Wysokie (≥70)</div></div>
  <div class="card"><div class="card-num med">$med_count</div><div class="card-lbl">Średnie (40-69)</div></div>
  <div class="card"><div class="card-num low">$low_count</div><div class="card-lbl">Niskie (&lt;40)</div></div>
</div>
<h2>📊 Wykres ryzyka</h2>
<div class="chart-wrap"><canvas id="batchChart"></canvas></div>
<script>new Chart(document.getElementById('batchChart'),{type:'bar',data:{labels:[${chart_labels}],datasets:[{label:'Score',data:[${chart_data}],backgroundColor:[${chart_colors}],borderRadius:4}]},options:{responsive:true,maintainAspectRatio:false,scales:{y:{min:0,max:100,grid:{color:'#21262d'},ticks:{color:'#8b949e'}},x:{grid:{display:false},ticks:{color:'#8b949e',maxRotation:45}}},plugins:{legend:{display:false}}}});</script>
<h2>📋 Wyniki per plik</h2>
<table><thead><tr><th>Raport</th><th>Plik</th><th>Score</th></tr></thead>
<tbody>${reports_rows}</tbody></table>
<footer>noriben_qemu_sandbox.sh v${VERSION} · $total_files plików · Dual-VM: HVF + TCG</footer>
</body></html>
BATCHEOF

    log_ok "Zbiorczy raport: $batch_html"
    echo -e "  ${DIM}open '$batch_html'${RESET}"
    echo ""
}

# ═══════════════════════════════════════════════════════════════
# TRYB SETUP
# ═══════════════════════════════════════════════════════════════

run_setup_mode() {
    section "SETUP — KONFIGURACJA ŚRODOWISKA"
    mkdir -p "$HOST_TOOLS_DIR" "$HOST_RESULTS_DIR"
    LOG_FILE="/tmp/noriben_qemu_setup_$$.log"; touch "$LOG_FILE"
    check_host_tools

    echo ""
    echo -e "${BOLD}${CYAN}Wykryta architektura: ${HOST_ARCH}${RESET}"
    if [[ "$HOST_ARCH" == "arm64" ]]; then
        echo -e "${GREEN}Apple Silicon:"
        echo -e "  VM1 (ARM):  qemu-system-aarch64 + HVF  → Windows on ARM (szybka)"
        echo -e "  VM2 (x86):  qemu-system-x86_64  + TCG  → Windows x86/x64 (emulacja SW)${RESET}"
        if _qemu_version_ge "qemu-system-aarch64" 9 2 2>/dev/null && _macos_version_ge 15; then
            echo -e "${GREEN}  ✓ QEMU 9.2+ + macOS 15: 40-bit IPA — brak limitu RAM${RESET}"
        else
            echo -e "${YELLOW}  ⚠ Stara wersja QEMU lub macOS <15: highmem=off, max ~12 GB dla VM${RESET}"
            echo -e "${DIM}  Zaktualizuj: brew upgrade qemu  |  Upgrade do macOS 15+${RESET}"
        fi
    else
        echo -e "${GREEN}Intel Mac: HVF dla obu VM${RESET}"
    fi

    # Pobierz Noriben.py
    echo ""
    local noriben_path="$HOST_TOOLS_DIR/Noriben.py"
    if [[ ! -f "$noriben_path" ]]; then
        start_spinner "Pobieranie Noriben.py z GitHub..."
        curl -fsSL "https://raw.githubusercontent.com/Rurik/Noriben/master/Noriben.py" \
            -o "$noriben_path" 2>/dev/null \
            && { stop_spinner; log_ok "Noriben.py: $noriben_path"; } \
            || { stop_spinner; log_err "Błąd pobierania Noriben.py"; }
    else
        log_ok "Noriben.py: $noriben_path (już istnieje)"
    fi

    # Skrypt konfiguracyjny Windows VM
    cat > "$HOST_TOOLS_DIR/vm_setup.ps1" << 'PSEOF'
Set-ExecutionPolicy Bypass -Scope Process -Force
$ErrorActionPreference="SilentlyContinue"
Write-Host "=== Konfiguracja VM dla Noriben (QEMU) ===" -ForegroundColor Cyan
foreach ($d in @("C:\Tools","C:\Malware","C:\NoribenLogs","C:\Python3")) {
    New-Item -ItemType Directory -Path $d -Force | Out-Null
    Write-Host "[OK] $d" -ForegroundColor Green
}
if (-not (Test-Path "C:\Python3\python.exe")) {
    Write-Host "[!] Instaluję Python 3..." -ForegroundColor Yellow
    Invoke-WebRequest "https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe" -OutFile "$env:TEMP\python.exe"
    & "$env:TEMP\python.exe" /quiet InstallAllUsers=1 TargetDir=C:\Python3 PrependPath=1
}
if (-not (Test-Path "C:\Tools\procmon64.exe")) {
    winget install Microsoft.Sysinternals.ProcessMonitor --silent --accept-eula
    $src="$env:ProgramFiles\Sysinternals Suite\Procmon64.exe"
    if (Test-Path $src) { Copy-Item $src "C:\Tools\procmon64.exe" }
}
# OpenSSH Server (wymagany dla komunikacji z hostem macOS)
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd; Set-Service sshd -StartupType Automatic
New-NetFirewallRule -Name "sshd" -DisplayName "OpenSSH Server" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
# Defender
Set-MpPreference -DisableRealtimeMonitoring $true
@("C:\Malware","C:\NoribenLogs","C:\Tools") | % { Add-MpPreference -ExclusionPath $_ }
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" EnableLUA 0
Stop-Service wuauserv -Force; Set-Service wuauserv -StartupType Disabled
Write-Host "=== Gotowe! ===" -ForegroundColor Green
Write-Host "Zamknij VM i wykonaj snapshot:" -ForegroundColor Yellow
Write-Host "  qemu-img snapshot -c Baseline_Clean <ścieżka_obrazu.qcow2>" -ForegroundColor Cyan
PSEOF
    log_ok "vm_setup.ps1: $HOST_TOOLS_DIR/vm_setup.ps1"

    echo ""
    echo -e "${BOLD}═══ Dalsze kroki ═══${RESET}"
    echo ""
    echo "1. Utwórz obrazy qcow2:"
    echo -e "   ${CYAN}# VM1 — Windows on ARM (dla Apple Silicon)"
    echo -e "   qemu-img create -f qcow2 ~/NoribenTools/windows_arm_sandbox.qcow2 60G"
    echo -e "   # VM2 — Windows x86/x64"
    echo -e "   qemu-img create -f qcow2 ~/NoribenTools/windows_x86_sandbox.qcow2 60G${RESET}"
    echo ""
    echo "2. Zainstaluj Windows w każdym obrazie (z ISO)"
    echo "3. W każdej VM: PowerShell jako Admin → .\\vm_setup.ps1"
    echo "4. Zamknij każdą VM i utwórz snapshot:"
    echo -e "   ${CYAN}qemu-img snapshot -c Baseline_Clean ~/NoribenTools/windows_arm_sandbox.qcow2"
    echo -e "   qemu-img snapshot -c Baseline_Clean ~/NoribenTools/windows_x86_sandbox.qcow2${RESET}"
    echo ""
    echo -e "${GREEN}${BOLD}Uruchomienie:${RESET}"
    echo -e "  ${CYAN}$0 malware.exe               ${DIM}# single VM (ARM)"
    echo -e "  $0 malware.exe --dual-vm     ${DIM}# ARM + x86 równolegle"
    echo -e "  $0 sample.zip --dual-vm --archive-password infected${RESET}"
    rm -f "$LOG_FILE"
}

# ═══════════════════════════════════════════════════════════════
# CLEANUP
# ═══════════════════════════════════════════════════════════════

cleanup() {
    stop_spinner
    stop_all_vms
}

# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

main() {
    print_banner

    local setup_mode=false no_revert=false static_only=false dynamic_only=false
    local archive_password="" dual_vm=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --setup)             setup_mode=true ;;
            --dual-vm)           dual_vm=true ;;
            --no-revert)         no_revert=true ;;
            --static-only)       static_only=true ;;
            --dynamic-only)      dynamic_only=true ;;
            --disk)              shift; QEMU_DISK="$1" ;;
            --disk-x86)          shift; QEMU_DISK_X86="$1" ;;
            --snapshot)          shift; QEMU_SNAPSHOT="$1" ;;
            --timeout)           shift; ANALYSIS_TIMEOUT="$1" ;;
            --mem)               shift; QEMU_MEM="$1" ;;
            --mem-x86)           shift; QEMU_MEM_X86="$1" ;;
            --smp)               shift; QEMU_SMP="$1" ;;
            --ssh-port)          shift; QEMU_SSH_PORT="$1" ;;
            --ssh-port-x86)      shift; QEMU_SSH_PORT_X86="$1" ;;
            --archive-password)  shift; archive_password="$1" ;;
            --list-snapshots)
                echo "VM1 (ARM):"; qemu-img snapshot -l "$QEMU_DISK" 2>/dev/null || true
                echo "VM2 (x86):"; qemu-img snapshot -l "$QEMU_DISK_X86" 2>/dev/null || true
                exit 0 ;;
            --help|-h)
                cat << HELP
Użycie: $0 <plik> [opcje]

  --setup                  Konfiguracja środowiska (pierwsze uruchomienie)
  --dual-vm                Uruchom obie VM: ARM64/HVF + x86_64/TCG równolegle
  --disk <ścieżka>         Obraz VM1 (ARM64)  [domyślnie: \$QEMU_DISK]
  --disk-x86 <ścieżka>    Obraz VM2 (x86_64) [domyślnie: \$QEMU_DISK_X86]
  --snapshot <nazwa>       Snapshot VM1 (domyślnie: $QEMU_SNAPSHOT)
  --timeout <s>            Czas analizy Noriben (domyślnie: ${ANALYSIS_TIMEOUT}s)
  --mem <RAM>              RAM VM1 (domyślnie: ${QEMU_MEM})
  --mem-x86 <RAM>          RAM VM2 (domyślnie: ${QEMU_MEM_X86})
  --smp <N>                vCPU (domyślnie: ${QEMU_SMP})
  --ssh-port <port>        SSH VM1 (domyślnie: ${QEMU_SSH_PORT})
  --ssh-port-x86 <port>    SSH VM2 (domyślnie: ${QEMU_SSH_PORT_X86})
  --archive-password <p>   Hasło do archiwum ZIP/RAR/7z
  --static-only            Tylko analiza statyczna (bez VM)
  --dynamic-only           Tylko analiza dynamiczna (bez statycznej)
  --no-revert              Nie przywracaj snapshota przed analizą
  --list-snapshots         Lista snapshotów w obu obrazach

Zmienne środowiskowe:
  QEMU_DISK, QEMU_DISK_X86      Ścieżki do obrazów qcow2
  QEMU_MEM, QEMU_MEM_X86        RAM dla VM (np. 16G, 8G)
  QEMU_SMP, QEMU_SMP_X86        Liczba vCPU
  QEMU_SSH_PORT / _X86           Porty SSH (domyślnie: 2222, 2223)
  QEMU_MONITOR_PORT / _X86       Porty monitora (domyślnie: 4444, 4445)
  VM_USER, VM_PASS               Dane SSH do VM
  ANALYSIS_TIMEOUT               Czas analizy w sekundach
  ARCHIVE_PASSWORDS              Domyślne hasła archiwów
  DUAL_VM_MODE=true              Aktywuj dual-VM globalnie

Przykłady:
  $0 --setup
  $0 malware.exe
  $0 malware.exe --dual-vm
  $0 sample.zip --dual-vm --archive-password infected
  $0 malware.exe --static-only
  $0 malware.exe --timeout 600 --mem 32G
  DUAL_VM_MODE=true $0 malware.exe
HELP
                exit 0 ;;
            -*) echo -e "${RED}Nieznana opcja: $1${RESET}"; exit 1 ;;
            *)  SAMPLE_FILE="$1" ;;
        esac
        shift
    done

    [[ "$setup_mode" == "true" ]] && { run_setup_mode; exit 0; }
    [[ "$DUAL_VM_MODE" == "true" ]] && dual_vm=true

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
        echo "═══════════════════════════════════════"
        echo "  noriben_qemu_sandbox.sh v$VERSION"
        echo "  Sesja:    $SESSION_ID"
        echo "  Plik:     $SAMPLE_FILE"
        echo "  Host:     $HOST_ARCH"
        echo "  Dual-VM:  $dual_vm"
        echo "  VM1 disk: $QEMU_DISK"
        echo "  VM2 disk: $QEMU_DISK_X86"
        echo "  Timeout:  ${ANALYSIS_TIMEOUT}s"
        echo "  $(date)"
        echo "═══════════════════════════════════════"
    } >> "$LOG_FILE"

    log "Sesja: $SESSION_ID | Host: $HOST_ARCH | Dual-VM: $dual_vm"

    check_host_tools

    # 1. Archiwum
    local analysis_target="$SAMPLE_FILE"
    if is_archive "$SAMPLE_FILE"; then
        [[ -n "$archive_password" ]] && ARCHIVE_PASSWORDS="$archive_password $ARCHIVE_PASSWORDS"
        handle_archive "$SAMPLE_FILE"
        [[ "$ARCHIVE_MODE" == "single" ]] && analysis_target="$EXTRACTED_SAMPLE"
    else
        ARCHIVE_MODE="single"
    fi

    [[ "$static_only" == "true" && "$ARCHIVE_MODE" == "all_full" ]] && ARCHIVE_MODE="all_static"

    # ─── TRYB WIELOPLIKOWY ────────────────────────────────────
    if [[ "$ARCHIVE_MODE" == "all_full" || "$ARCHIVE_MODE" == "all_static" ]]; then
        local file_list_path="$SESSION_DIR/archive_filelist.txt"
        [[ ! -f "$file_list_path" ]] && { log_err "Brak listy plików"; exit 1; }
        local all_files=()
        while IFS= read -r _mf_line; do
            [[ -n "$_mf_line" ]] && all_files+=("$_mf_line")
        done < "$file_list_path"
        local total="${#all_files[@]}"
        local skip_dynamic=false
        [[ "$ARCHIVE_MODE" == "all_static" || "$static_only" == "true" ]] && skip_dynamic=true

        echo -e "${BOLD}${CYAN}Tryb: $([ "$skip_dynamic" == "true" ] && echo "WSZYSTKIE — tylko statyczna" || echo "WSZYSTKIE — statyczna + dynamiczna (dual-VM: $dual_vm)")${RESET}"
        echo -e "Łącznie plików: ${BOLD}$total${RESET}"
        echo ""

        # Uruchom VM(y) raz dla całej serii
        if [[ "$skip_dynamic" == "false" ]]; then
            check_qemu_disk; check_qemu_snapshot
            $no_revert || revert_to_snapshot
            start_vm
            [[ ! -f "$HOST_TOOLS_DIR/Noriben.py" ]] && {
                curl -fsSL "https://raw.githubusercontent.com/Rurik/Noriben/master/Noriben.py" \
                    -o "$HOST_TOOLS_DIR/Noriben.py" 2>/dev/null && log_ok "Noriben.py pobrany" || log_err "Brak Noriben.py"
            }
            prepare_vm_environment "$QEMU_SSH_PORT" "VM1 (ARM)"
            if $dual_vm; then
                if check_qemu_disk_x86 2>/dev/null && check_qemu_snapshot_x86 2>/dev/null; then
                    $no_revert || revert_to_snapshot_x86
                    start_vm_x86
                    prepare_vm_environment "$QEMU_SSH_PORT_X86" "VM2 (x86)"
                else
                    log_warn "VM2 (x86) niedostępna — kontynuuję bez dual-VM"
                    dual_vm=false
                fi
            fi
        fi

        local idx=0
        batch_scores=()
        for file_path in "${all_files[@]}"; do
            [[ -z "$file_path" || ! -f "$file_path" ]] && continue
            ((idx++)) || true
            local fname_p; fname_p=$(basename "$file_path")
            echo ""
            echo -e "${MAGENTA}${BOLD}  ┌── Próbka ${idx}/${total} — ${fname_p} ──${RESET}"

            reset_per_file_state
            [[ "$skip_dynamic" == "false" ]] && static_analysis "$file_path" || static_analysis "$file_path"

            if [[ "$skip_dynamic" == "false" ]]; then
                if $dual_vm; then
                    run_dual_vm_analysis "$file_path"
                else
                    local file_dir="$SESSION_DIR/files/${fname_p%%.*}_$(date '+%H%M%S')"
                    mkdir -p "$file_dir"
                    local vm1_path="C:\\Malware\\${fname_p}"
                    _vm_ssh "$QEMU_SSH_PORT" "cmd /c 'del /Q C:\\NoribenLogs\\* 2>nul & exit 0'" >> "$LOG_FILE" 2>&1 || true
                    _vm_scp_to "$QEMU_SSH_PORT" "$file_path" "$vm1_path" && log_ok "→ VM1" || log_err "Błąd kopiowania"
                    run_dynamic_analysis "$vm1_path" "$QEMU_SSH_PORT" "$QEMU_MONITOR_PORT" "VM1" "$file_dir"
                    collect_results "$QEMU_SSH_PORT" "$file_dir"
                    analyze_dynamic_results "$file_dir"
                    generate_html_report "$file_path" "$file_dir"
                    _vm_ssh "$QEMU_SSH_PORT" "cmd /c 'del /Q C:\\Malware\\* C:\\NoribenLogs\\* 2>nul & exit 0'" >> "$LOG_FILE" 2>&1 || true
                fi
            else
                generate_html_report "$file_path" "$SESSION_DIR"
            fi

            local f_total=$(( (STATIC_RISK_SCORE + DYNAMIC_RISK_SCORE) / 2 ))
            [[ $f_total -gt 100 ]] && f_total=100
            batch_scores+=("${fname_p}:${f_total}")
        done

        [[ "$skip_dynamic" == "false" ]] && {
            section "KONIEC SERII — ZATRZYMYWANIE VM"
            stop_all_vms
            log_ok "Wszystkie VM zatrzymane"
        }
        _generate_batch_report "$total"
        echo -e "  📁 Wyniki: ${BOLD}$SESSION_DIR${RESET}"

    # ─── TRYB SINGLE ─────────────────────────────────────────
    else
        [[ "$dynamic_only" == "false" ]] && static_analysis "$analysis_target"

        if [[ "$static_only" == "false" ]]; then
            if $dual_vm; then
                # Dual-VM: uruchom obie VM
                section "DUAL-VM MODE — ARM64/HVF + x86_64/TCG"
                check_qemu_disk; check_qemu_snapshot
                $no_revert || revert_to_snapshot
                start_vm
                [[ ! -f "$HOST_TOOLS_DIR/Noriben.py" ]] && {
                    curl -fsSL "https://raw.githubusercontent.com/Rurik/Noriben/master/Noriben.py" \
                        -o "$HOST_TOOLS_DIR/Noriben.py" 2>/dev/null && log_ok "Noriben.py pobrany" || log_err "Brak Noriben.py"
                }
                prepare_vm_environment "$QEMU_SSH_PORT" "VM1 (ARM)"
                local dual_active=false
                if check_qemu_disk_x86 2>/dev/null && check_qemu_snapshot_x86 2>/dev/null; then
                    $no_revert || revert_to_snapshot_x86
                    start_vm_x86
                    prepare_vm_environment "$QEMU_SSH_PORT_X86" "VM2 (x86)"
                    dual_active=true
                else
                    log_warn "VM2 (x86) niedostępna — tryb single VM"
                fi
                if $dual_active; then
                    run_dual_vm_analysis "$analysis_target"
                else
                    local fdir="$SESSION_DIR"
                    local vm1p="C:\\Malware\\$(basename "$analysis_target")"
                    _vm_scp_to "$QEMU_SSH_PORT" "$analysis_target" "$vm1p"
                    run_dynamic_analysis "$vm1p" "$QEMU_SSH_PORT" "$QEMU_MONITOR_PORT" "VM1" "$fdir"
                    collect_results "$QEMU_SSH_PORT" "$fdir"
                    analyze_dynamic_results "$fdir"
                    generate_html_report "$analysis_target" "$fdir"
                fi
                stop_all_vms
            else
                # Single VM (VM1 ARM)
                check_qemu_disk; check_qemu_snapshot
                $no_revert || revert_to_snapshot
                start_vm
                [[ ! -f "$HOST_TOOLS_DIR/Noriben.py" ]] && {
                    curl -fsSL "https://raw.githubusercontent.com/Rurik/Noriben/master/Noriben.py" \
                        -o "$HOST_TOOLS_DIR/Noriben.py" 2>/dev/null && log_ok "Noriben.py pobrany" || log_err "Brak Noriben.py"
                }
                prepare_vm_environment "$QEMU_SSH_PORT" "VM1 (ARM)"
                section "KOPIOWANIE PRÓBKI → VM1"
                local vm_path="C:\\Malware\\$(basename "$analysis_target")"
                _vm_scp_to "$QEMU_SSH_PORT" "$analysis_target" "$vm_path" && log_ok "Próbka skopiowana" || log_err "Błąd kopiowania"
                run_dynamic_analysis "$vm_path" "$QEMU_SSH_PORT" "$QEMU_MONITOR_PORT" "VM1" "$SESSION_DIR"
                collect_results "$QEMU_SSH_PORT" "$SESSION_DIR"
                analyze_dynamic_results "$SESSION_DIR"
                stop_vm
                generate_html_report "$analysis_target" "$SESSION_DIR"
            fi
        else
            generate_html_report "$analysis_target" "$SESSION_DIR"
        fi

        local total=$(( (STATIC_RISK_SCORE + DYNAMIC_RISK_SCORE) / 2 ))
        [[ $total -gt 100 ]] && total=100
        echo ""
        echo -e "${GREEN}${BOLD}╔══════════════════════════════════════╗"
        echo -e "║  ✅  Analiza zakończona!              ║"
        echo -e "╚══════════════════════════════════════╝${RESET}"
        echo ""
        printf "  %-22s ${BOLD}%d / 100${RESET}\n" "Wynik ryzyka:"   "$total"
        printf "  %-22s %d\n"                       "Statyczna:"     "$STATIC_RISK_SCORE"
        printf "  %-22s %d\n"                       "Dynamiczna:"    "$DYNAMIC_RISK_SCORE"
        printf "  %-22s %s\n"                       "Dual-VM:"       "$dual_vm"
        echo ""
        echo -e "  📁 Wyniki: ${BOLD}$SESSION_DIR${RESET}"
        [[ ${#SESSION_REPORTS[@]} -gt 0 ]] && echo -e "  🌐 Raport:  ${BOLD}${SESSION_REPORTS[0]}${RESET}"
        echo -e "  ${DIM}open '${SESSION_REPORTS[0]:-$SESSION_DIR}'${RESET}"
        echo ""
    fi
}

main "$@"
