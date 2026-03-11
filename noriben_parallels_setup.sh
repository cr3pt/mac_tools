#!/bin/bash
# ============================================================
#  noriben_parallels_setup.sh  v2.0
#  Automatyzacja środowiska Noriben + Parallels na macOS
#
#  Nowości v2.0:
#  ✦ Obsługa archiwów z hasłem (ZIP/RAR/7z — typowe dla malware)
#  ✦ Analiza STATYCZNA na hoście przed wysłaniem do VM
#      - Magic bytes, PE headers, entropia sekcji
#      - YARA (wbudowane reguły + własne)
#      - ClamAV, strings IOC, pefile (Python)
#      - Identyfikacja packera, anty-debug, anty-VM
#  ✦ Analiza DYNAMICZNA w VM Windows (Noriben + Procmon)
#      - Monitoring procesów, rejestru, plików, sieci
#      - Opcjonalny tcpdump/Wireshark na hoście (ruch VM)
#      - Timeout konfigurowalny (domyślnie 5 min)
#  ✦ Skonsolidowany raport HTML łączący obie analizy
#  ✦ Ocena ryzyka z tagami MITRE ATT&CK
#
#  Wymagania hosta (Mac):
#    - Parallels Desktop 18+  (prlctl w PATH)
#    - python3 + pip3
#    - Homebrew (auto-instalowany)
#
#  Wymagania wewnątrz Windows VM:
#    - Python 3.x         → C:\Python3\python.exe
#    - Sysinternals Procmon → C:\Tools\procmon64.exe
#    - Noriben.py         → C:\Tools\Noriben.py
#    - Parallels Guest Tools
# ============================================================

set -euo pipefail

VERSION="2.0.0"

# ─── Kolory terminala ─────────────────────────────────────────
RED='\033[0;31m';    YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m';   BOLD='\033[1m';      DIM='\033[2m'
RESET='\033[0m'

# ─── Konfiguracja VM — DOSTOSUJ DO SWOJEGO ŚRODOWISKA ─────────
VM_NAME="${VM_NAME:-Windows 11 Malware}"
VM_SNAPSHOT="${VM_SNAPSHOT:-Baseline_Clean}"
VM_USER="${VM_USER:-Administrator}"
VM_PASS="${VM_PASS:-password}"

VM_PYTHON="C:\\Python3\\python.exe"
VM_NORIBEN="C:\\Tools\\Noriben.py"
VM_PROCMON="C:\\Tools\\procmon64.exe"
VM_MALWARE_DIR="C:\\Malware"
VM_OUTPUT_DIR="C:\\NoribenLogs"

# ─── Ścieżki hosta ────────────────────────────────────────────
HOST_RESULTS_DIR="${HOME}/NoribenResults"
HOST_TOOLS_DIR="${HOME}/NoribenTools"

# ─── Timeouty ─────────────────────────────────────────────────
ANALYSIS_TIMEOUT="${ANALYSIS_TIMEOUT:-300}"   # 5 min analizy Noriben
VM_BOOT_TIMEOUT=120
VM_COPY_TIMEOUT=60

# ─── Domyślne hasła archiwów (typowe dla sampli malware) ──────
ARCHIVE_PASSWORDS="${ARCHIVE_PASSWORDS:-infected malware virus password 1234 admin sample}"

# ─── Flagi globalne ───────────────────────────────────────────
SAMPLE_FILE=""
SAMPLE_BASENAME=""
EXTRACTED_SAMPLE=""
SESSION_ID=""
SESSION_DIR=""
LOG_FILE=""
SPINNER_PID=""
STATIC_RISK_SCORE=0
DYNAMIC_RISK_SCORE=0
declare -a STATIC_FINDINGS=()
declare -a DYNAMIC_FINDINGS=()
declare -a MITRE_TECHNIQUES=()

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
log_warn() { echo -e "${YELLOW}[!]${RESET} $*";echo "[WARN] $(date '+%H:%M:%S') $*" >> "$LOG_FILE" 2>/dev/null || true; }
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

print_banner() {
    echo -e "${CYAN}${BOLD}"
    cat <<'BANNER'
  ╔════════════════════════════════════════════════════════╗
  ║   🧪 Noriben + Parallels Sandbox  v2.0               ║
  ║   Analiza statyczna + dynamiczna + archiwa z hasłem   ║
  ╚════════════════════════════════════════════════════════╝
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
    ext="${f##*.}"; ext="${ext,,}"
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
                zip)  echo "zip" ;;
                rar)  echo "rar" ;;
                7z)   echo "7z"  ;;
                gz)   echo "gz"  ;;
                bz2)  echo "bz2" ;;
                tar)  echo "tar" ;;
                *)    echo "unknown" ;;
            esac ;;
    esac
}

is_archive() {
    [[ "$(detect_archive_type "$1")" != "unknown" ]]
}

try_extract_archive() {
    local archive="$1" dest_dir="$2" password="${3:-}"
    local arch_type
    arch_type=$(detect_archive_type "$archive")
    mkdir -p "$dest_dir"

    case "$arch_type" in
        zip)
            if [[ -n "$password" ]]; then
                unzip -P "$password" -o "$archive" -d "$dest_dir" >> "$LOG_FILE" 2>&1
            else
                unzip -o "$archive" -d "$dest_dir" >> "$LOG_FILE" 2>&1
            fi ;;
        rar)
            if command -v unrar &>/dev/null; then
                if [[ -n "$password" ]]; then
                    unrar x -p"$password" -y "$archive" "$dest_dir/" >> "$LOG_FILE" 2>&1
                else
                    unrar x -y "$archive" "$dest_dir/" >> "$LOG_FILE" 2>&1
                fi
            elif command -v 7z &>/dev/null; then
                if [[ -n "$password" ]]; then
                    7z x -p"$password" -o"$dest_dir" "$archive" >> "$LOG_FILE" 2>&1
                else
                    7z x -o"$dest_dir" "$archive" >> "$LOG_FILE" 2>&1
                fi
            else
                log_err "Brak unrar i 7z — zainstaluj: brew install unrar p7zip"
                return 1
            fi ;;
        7z)
            if command -v 7z &>/dev/null; then
                if [[ -n "$password" ]]; then
                    7z x -p"$password" -o"$dest_dir" "$archive" >> "$LOG_FILE" 2>&1
                else
                    7z x -o"$dest_dir" "$archive" >> "$LOG_FILE" 2>&1
                fi
            else
                log_err "Brak 7z — zainstaluj: brew install p7zip"
                return 1
            fi ;;
        gz|bz2|xz|tar)
            tar xf "$archive" -C "$dest_dir" >> "$LOG_FILE" 2>&1 ;;
        *)
            log_err "Nieobsługiwany typ archiwum: $arch_type"
            return 1 ;;
    esac
}

handle_archive() {
    local archive="$1"
    local arch_type
    arch_type=$(detect_archive_type "$archive")
    local extract_dir="$SESSION_DIR/extracted"

    section "ARCHIWUM Z HASŁEM — ROZPAKOWYWANIE"
    log "Wykryto archiwum: $(basename "$archive") (typ: $arch_type)"

    # Sprawdź szyfrowanie
    local is_encrypted=false
    case "$arch_type" in
        zip)
            unzip -t "$archive" >> "$LOG_FILE" 2>&1 || is_encrypted=true ;;
        rar)
            command -v unrar &>/dev/null && \
                { unrar t "$archive" >> "$LOG_FILE" 2>&1 || is_encrypted=true; } ;;
        7z)
            command -v 7z &>/dev/null && \
                { 7z t "$archive" >> "$LOG_FILE" 2>&1 || is_encrypted=true; } ;;
    esac

    if $is_encrypted; then
        add_finding "static" 10 "Archiwum chronione hasłem (technika obejścia AV)"
        add_mitre "T1027 — Obfuscated Files or Information"
        log_warn "Archiwum chronione hasłem — próba domyślnych haseł..."

        local cracked=false
        echo ""
        for pwd in $ARCHIVE_PASSWORDS; do
            printf "  Próba: ${DIM}%-15s${RESET}" "$pwd"
            rm -rf "$extract_dir" 2>/dev/null || true
            if try_extract_archive "$archive" "$extract_dir" "$pwd" 2>/dev/null; then
                if [[ -n "$(ls -A "$extract_dir" 2>/dev/null)" ]]; then
                    echo -e " ${GREEN}✓ SUKCES${RESET}"
                    log_ok "Hasło: '$pwd'"
                    cracked=true
                    echo "$pwd" > "$SESSION_DIR/archive_password.txt"
                    break
                fi
            fi
            echo -e " ${DIM}✗${RESET}"
        done

        if ! $cracked; then
            echo ""
            log_warn "Domyślne hasła nie zadziałały"
            read -r -p "  Podaj hasło ręcznie (Enter = pomiń): " manual_pwd
            if [[ -n "$manual_pwd" ]]; then
                rm -rf "$extract_dir" 2>/dev/null || true
                try_extract_archive "$archive" "$extract_dir" "$manual_pwd" && \
                [[ -n "$(ls -A "$extract_dir" 2>/dev/null)" ]] && {
                    log_ok "Rozpakowano z hasłem podanym ręcznie"
                    cracked=true
                    echo "$manual_pwd" > "$SESSION_DIR/archive_password.txt"
                } || log_err "Złe hasło lub błąd rozpakowywania"
            fi
        fi

        $cracked || { log_err "Nie udało się rozpakować archiwum"; return 1; }
    else
        log_ok "Archiwum bez hasła — rozpakowuję..."
        try_extract_archive "$archive" "$extract_dir" "" || \
            { log_err "Błąd rozpakowywania"; return 1; }
    fi

    echo ""
    log "Zawartość archiwum:"
    find "$extract_dir" -type f | while read -r f; do
        local ft; ft=$(file -b "$f" 2>/dev/null | cut -c1-55)
        echo -e "  ${GREEN}→${RESET} $(basename "$f")  ${DIM}($ft)${RESET}"
        echo "  → $f ($ft)" >> "$LOG_FILE"
    done

    # Wybierz plik wykonywalny
    local exe_files
    exe_files=$(find "$extract_dir" -type f \
        \( -name "*.exe" -o -name "*.dll" -o -name "*.bat" \
           -o -name "*.ps1" -o -name "*.vbs" -o -name "*.js" \
           -o -name "*.scr" -o -name "*.com" \) 2>/dev/null)

    [[ -z "$exe_files" ]] && exe_files=$(find "$extract_dir" -type f | head -3)

    local file_count
    file_count=$(echo "$exe_files" | grep -c . || echo 0)

    if [[ $file_count -gt 1 ]]; then
        echo ""
        echo -e "${BOLD}Znaleziono $file_count plików — wybierz do analizy:${RESET}"
        local i=1
        while IFS= read -r f; do
            echo -e "  ${CYAN}[$i]${RESET} $(basename "$f")"
            ((i++)) || true
        done <<< "$exe_files"
        echo -e "  ${CYAN}[0]${RESET} Analizuj wszystkie"
        echo ""
        read -r -p "  Wybór [1]: " choice
        choice="${choice:-1}"
        if [[ "$choice" == "0" ]]; then
            EXTRACTED_SAMPLE="ALL:$extract_dir"
        else
            EXTRACTED_SAMPLE=$(echo "$exe_files" | sed -n "${choice}p")
        fi
    else
        EXTRACTED_SAMPLE="$exe_files"
    fi

    log_ok "Plik do analizy: $(basename "${EXTRACTED_SAMPLE#ALL:}")"
}

# ═════════════════════════════════════════════════════════════
# MODUŁ B — ANALIZA STATYCZNA (na hoście macOS)
# ═════════════════════════════════════════════════════════════

static_analysis() {
    local target="$1"
    section "ANALIZA STATYCZNA — $(basename "$target")"

    # ── B1. Metadane ──────────────────────────────────────────
    echo -e "\n${BOLD}[B1] Metadane${RESET}"
    local sha256 md5 sha1 fsize ftype
    sha256=$(shasum -a 256 "$target" | awk '{print $1}')
    md5=$(md5 -q "$target" 2>/dev/null || md5sum "$target" | awk '{print $1}')
    sha1=$(shasum -a 1 "$target" | awk '{print $1}')
    fsize=$(du -sh "$target" | cut -f1)
    ftype=$(file -b "$target" 2>/dev/null)

    log "SHA256:   $sha256"
    log "MD5:      $md5"
    log "SHA1:     $sha1"
    log "Rozmiar:  $fsize"
    log "Typ:      $ftype"
    echo "$sha256" > "$SESSION_DIR/sample_sha256.txt"

    # ── B2. Magic bytes ───────────────────────────────────────
    echo -e "\n${BOLD}[B2] Magic bytes (pierwsze 32 bajty)${RESET}"
    xxd "$target" 2>/dev/null | head -4 | tee -a "$LOG_FILE" || \
        hexdump -C "$target" 2>/dev/null | head -4 | tee -a "$LOG_FILE"

    local is_pe=false
    case "$ftype" in
        *"PE32"*|*"MS-DOS"*)
            is_pe=true
            log_warn "Plik wykonywalny Windows (PE)"
            add_finding "static" 5 "Plik wykonywalny PE Windows" ;;
        *"shell script"*|*"Python"*|*"Ruby"*|*"Perl"*)
            log_warn "Skrypt — sprawdź zawartość" ;;
        *"PDF"*)    log_warn "PDF — może zawierać JS lub embedded EXE" ;;
        *"Zip"*)    log_warn "Zagnieżdżone archiwum (dropper?)" ;;
    esac

    # ── B3. Analiza nagłówka PE ───────────────────────────────
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
    h  = pe.FILE_HEADER
    o  = pe.OPTIONAL_HEADER
    arch = {0x8664:'x64', 0x14c:'x86', 0x1c0:'ARM'}.get(h.Machine, hex(h.Machine))
    sub  = {1:'Driver', 2:'GUI', 3:'Console'}.get(o.Subsystem, str(o.Subsystem))
    try:
        ts_str = datetime.datetime.utcfromtimestamp(h.TimeDateStamp).strftime('%Y-%m-%d %H:%M UTC')
    except Exception:
        ts_str = f"{h.TimeDateStamp} (nieprawidłowy)"

    print(f"  Architektura:   {arch}")
    print(f"  Timestamp:      {ts_str}")
    print(f"  Subsystem:      {sub}")
    print(f"  EntryPoint:     {hex(o.AddressOfEntryPoint)}")
    print(f"  ImageBase:      {hex(o.ImageBase)}")
    print(f"  Checksum OK:    {pe.verify_checksum()}")

    print(f"\n  Sekcje PE:")
    high_ent = []
    for s in pe.sections:
        name = s.Name.decode(errors='replace').strip('\x00')
        ent  = entropy(s.get_data())
        flag = "  ⚠ WYSOKA ENTROPIA (packing/szyfrowanie)" if ent > 6.8 else ""
        print(f"    {name:<12}  VA:{hex(s.VirtualAddress):<10}  Raw:{hex(s.SizeOfRawData):<10}  Ent:{ent:.3f}{flag}")
        if ent > 6.8: high_ent.append(name)
    if high_ent:
        print(f"\n  [!] Sekcje z wysoką entropią: {', '.join(high_ent)}")

    SUSPICIOUS = {
        'VirtualAllocEx':       'Process Injection / T1055',
        'WriteProcessMemory':   'Process Injection / T1055',
        'CreateRemoteThread':   'Process Injection / T1055',
        'SetWindowsHookEx':     'Keylogger / T1056',
        'GetAsyncKeyState':     'Keylogger / T1056',
        'URLDownloadToFile':    'Download / T1105',
        'WinHttpOpen':          'HTTP C2 / T1071',
        'CryptEncrypt':         'Ransomware / T1486',
        'IsDebuggerPresent':    'Anti-Debug / T1622',
        'NtQueryInformationProcess': 'Anti-VM / T1497',
        'RegSetValueEx':        'Registry / T1112',
        'CreateService':        'Persistence / T1543',
        'ShellExecuteEx':       'Execution / T1059',
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
                if fn in SUSPICIOUS:
                    found_sus.append((dll, fn, SUSPICIOUS[fn]))
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

except ImportError:
    print("  [pefile niedostępny — pip3 install pefile]")
except Exception as e:
    print(f"  [Błąd PE: {e}]")
PYEOF
    fi

    # ── B4. Entropia pliku ────────────────────────────────────
    echo -e "\n${BOLD}[B4] Entropia pliku${RESET}"
    python3 - "$target" 2>/dev/null <<'PYEOF' | tee -a "$LOG_FILE" || true
import sys, math, collections
data = open(sys.argv[1], 'rb').read()
if data:
    c = collections.Counter(data)
    e = -sum((v/len(data))*math.log2(v/len(data)) for v in c.values())
    filled = int(e * 5)
    bar = '█' * filled + '░' * (40 - filled)
    lvl = "WYSOKA — packer/szyfrowanie" if e>7.0 else "ŚREDNIA" if e>6.0 else "NORMALNA"
    print(f"  Entropia: {e:.4f} / 8.0  [{lvl}]")
    print(f"  [{bar}]")
PYEOF

    # ── B5. IOC Strings ───────────────────────────────────────
    echo -e "\n${BOLD}[B5] Wskaźniki IOC (strings)${RESET}"
    local all_strings
    all_strings=$(strings -n 6 "$target" 2>/dev/null || true)

    declare -A IOC_MAP=(
        ["URL/IP"]="https?://[^ ]{4,}|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
        ["Tor/Darknet"]="\.onion|socks[45]://|torbrowser"
        ["C2/Reverse Shell"]="meterpreter|cobalt.?strike|nc -e|bind.shell|reverse.shell|powershell.*-enc"
        ["Pobieranie kodu"]="URLDownload|Invoke-WebRequest|DownloadString|bitsadmin.*transfer|certutil.*-urlcache"
        ["Kodowanie"]="base64 -d|base64.*decode|FromBase64String|certutil.*-decode"
        ["Persistence Win"]="CurrentVersion.Run|RunOnce|Startup|schtasks.*/create|sc.*create"
        ["Anti-debug/VM"]="IsDebuggerPresent|VirtualBox|VMware|QEMU|Parallels|SbieDll|wine"
        ["Ransomware"]="ransom|CryptEncrypt|\.locked|\.encrypted|bitcoin|wallet"
        ["Keylogger"]="GetAsyncKeyState|SetWindowsHookEx|keylog|GetClipboard"
        ["Privilege Esc"]="SeDebugPrivilege|ImpersonateToken|runas|UAC.*bypass"
        ["Lateral Movement"]="psexec|wmiexec|net use|\\\\\\\\.*\\\\admin\$|pass.the.hash"
        ["Dane wrażliwe"]="\.ssh|\.aws|password|credentials|token|api.?key"
    )

    local total_ioc=0
    for category in "${!IOC_MAP[@]}"; do
        local pattern="${IOC_MAP[$category]}"
        local hits
        hits=$(echo "$all_strings" | grep -iEo "$pattern" | sort -u | head -8 || true)
        if [[ -n "$hits" ]]; then
            echo -e "\n  ${RED}▶${RESET} ${BOLD}$category${RESET}"
            while IFS= read -r hit; do
                echo -e "    ${YELLOW}→${RESET} $hit"
                echo "    IOC[$category]: $hit" >> "$LOG_FILE"
            done <<< "$hits"
            ((total_ioc++)) || true
            add_finding "static" 15 "IOC strings: $category"
            case "$category" in
                "C2/Reverse Shell")   add_mitre "T1059 — Command & Scripting Interpreter" ;;
                "Persistence Win")    add_mitre "T1547 — Boot/Logon Autostart Execution" ;;
                "Anti-debug/VM")      add_mitre "T1497 — Virtualization/Sandbox Evasion" ;;
                "Ransomware")         add_mitre "T1486 — Data Encrypted for Impact" ;;
                "Keylogger")          add_mitre "T1056 — Input Capture" ;;
                "Lateral Movement")   add_mitre "T1021 — Remote Services" ;;
            esac
        fi
    done
    [[ $total_ioc -eq 0 ]] && log_ok "Brak IOC w strings" || log_warn "$total_ioc kategorii IOC"

    # ── B6. ExifTool ──────────────────────────────────────────
    if command -v exiftool &>/dev/null; then
        echo -e "\n${BOLD}[B6] Metadane ExifTool${RESET}"
        exiftool "$target" 2>/dev/null | grep -vE "^ExifTool Version|^File Name|^Directory" \
            | head -30 | tee -a "$LOG_FILE" || true
    fi

    # ── B7. Detekcja packera ──────────────────────────────────
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
                static_analysis "$unpacked"
                return
            }
        fi
    fi

    local packer_hits
    packer_hits=$(echo "$all_strings" | grep -iE \
        "MPRESS|Themida|Enigma|VMProtect|Obsidium|ExeCryptor|PECompact|ASPack|nSPack" \
        | head -3 || true)
    if [[ -n "$packer_hits" ]]; then
        log_warn "Możliwy protektor PE: $packer_hits"
        add_finding "static" 25 "Znany protektor/obfuscator PE"
        packed=true
    fi

    $packed || log_ok "Nie wykryto znanych packerów"

    # ── B8. YARA ──────────────────────────────────────────────
    echo -e "\n${BOLD}[B8] Skanowanie YARA${RESET}"
    _yara_scan "$target"

    # ── B9. ClamAV ────────────────────────────────────────────
    if command -v clamscan &>/dev/null; then
        echo -e "\n${BOLD}[B9] ClamAV${RESET}"
        start_spinner "Skanowanie ClamAV..."
        local clam_out
        if clam_out=$(clamscan --heuristic-alerts --alert-macros "$target" 2>&1); then
            stop_spinner; log_ok "ClamAV: CZYSTY"
        else
            stop_spinner
            log_err "ClamAV: WYKRYTO ZAGROŻENIE!"
            echo "$clam_out" | grep -v "^$" | tee -a "$LOG_FILE"
            add_finding "static" 80 "ClamAV: wykryto złośliwe oprogramowanie"
        fi
    fi

    echo ""
    echo -e "  ${DIM}VirusTotal: https://www.virustotal.com/gui/file/${sha256}${RESET}"
    log_ok "Analiza statyczna zakończona — score: $STATIC_RISK_SCORE"
}

# ─── Wbudowane reguły YARA ────────────────────────────────────
_create_yara_rules() {
    local f="$SESSION_DIR/rules.yar"
    cat > "$f" <<'YARARULES'
rule Ransomware_Indicators {
    meta: description="Wskaźniki ransomware" mitre="T1486"
    strings:
        $enc1="CryptEncrypt"       nocase
        $enc2="BCryptEncrypt"      nocase
        $note1="ransom"            nocase
        $note2="bitcoin"           nocase
        $note3="your files"        nocase
        $ext1=".locked"            nocase
        $ext2=".encrypted"         nocase
    condition: (2 of ($enc*)) or (3 of ($note*,$ext*))
}
rule ProcessInjection {
    meta: description="Wstrzykiwanie kodu" mitre="T1055"
    strings:
        $i1="VirtualAllocEx"       nocase
        $i2="WriteProcessMemory"   nocase
        $i3="CreateRemoteThread"   nocase
        $i4="NtCreateThreadEx"     nocase
        $i5="QueueUserAPC"         nocase
    condition: 2 of them
}
rule Keylogger_Spyware {
    meta: description="Rejestrowanie wejścia" mitre="T1056"
    strings:
        $k1="GetAsyncKeyState"     nocase
        $k2="SetWindowsHookEx"     nocase
        $k3="GetClipboardData"     nocase
        $k4="keylog"               nocase
    condition: 2 of them
}
rule AntiAnalysis {
    meta: description="Unikanie analizy/sandbox" mitre="T1497,T1622"
    strings:
        $d1="IsDebuggerPresent"    nocase
        $d2="CheckRemoteDebugger"  nocase
        $v1="VirtualBox"           nocase
        $v2="VMware"               nocase
        $v3="QEMU"                 nocase
        $v4="Parallels"            nocase
        $s1="SbieDll.dll"          nocase
    condition: 1 of ($d*) or 2 of ($v*,$s*)
}
rule NetworkC2 {
    meta: description="Komunikacja C2" mitre="T1071,T1059"
    strings:
        $c1="meterpreter"          nocase
        $c2="cobalt strike"        nocase
        $c3="mimikatz"             nocase
        $c4="powershell -enc"      nocase
        $c5="nc -e /bin/sh"        nocase
        $tor=".onion"              nocase
    condition: 1 of them
}
rule Persistence_Registry {
    meta: description="Persistence przez rejestr" mitre="T1547"
    strings:
        $r1="CurrentVersion\\Run"  nocase wide
        $r2="RunOnce"              nocase wide
        $r3="schtasks /create"     nocase
        $r4="sc create"            nocase
    condition: 2 of them
}
rule EncodedPayload {
    meta: description="Zakodowany payload" mitre="T1027"
    strings:
        $b64=/[A-Za-z0-9+\/]{200,}={0,2}/
        $ps="FromBase64String"     nocase
        $ps2="Convert.FromBase64"  nocase
    condition: any of them
}
rule CredentialTheft {
    meta: description="Kradzież poświadczeń" mitre="T1003"
    strings:
        $l1="lsass"                nocase
        $l2="sekurlsa"             nocase
        $l3="NTLMhash"             nocase
        $l4=".aws/credentials"     nocase
        $l5="id_rsa"               nocase
    condition: 2 of them
}
YARARULES
    echo "$f"
}

_yara_scan() {
    local target="$1"
    if ! command -v yara &>/dev/null; then
        log_warn "YARA niedostępny (brew install yara)"
        return
    fi

    local rules_file
    rules_file=$(_create_yara_rules)
    local hits
    hits=$(yara -r "$rules_file" "$target" 2>/dev/null || true)

    if [[ -n "$hits" ]]; then
        log_warn "YARA wykryła $(echo "$hits" | wc -l | tr -d ' ') dopasowań:"
        while IFS= read -r hit; do
            echo -e "    ${RED}▶${RESET} $hit"
            add_finding "static" 20 "YARA: $(echo "$hit" | awk '{print $1}')"
        done <<< "$hits"
    else
        log_ok "YARA: brak dopasowań"
    fi

    local custom="$HOST_TOOLS_DIR/custom_rules.yar"
    if [[ -f "$custom" ]]; then
        log "Własne reguły YARA: $custom"
        yara "$custom" "$target" 2>/dev/null | tee -a "$LOG_FILE" || true
    else
        log "${DIM}Własne reguły: $custom (brak — możesz dodać)${RESET}"
    fi
}

# ═════════════════════════════════════════════════════════════
# MODUŁ C — NARZĘDZIA HOSTA
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
        [[ "$tool" == "clamscan" ]] && { start_spinner "Aktualizacja bazy ClamAV..."; freshclam >> "$LOG_FILE" 2>&1 || true; stop_spinner; }
    else
        stop_spinner; log_err "Błąd instalacji $formula"; return 1
    fi
}

check_host_tools() {
    section "SPRAWDZENIE I INSTALACJA NARZĘDZI (macOS HOST)"

    # Homebrew
    if ! command -v brew &>/dev/null; then
        read -r -p "$(echo -e "${BOLD}Zainstalować Homebrew? [t/N]${RESET} ")" c
        if [[ "$c" =~ ^[tTyY]$ ]]; then
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" \
                </dev/null >> "$LOG_FILE" 2>&1
            [[ -f "/opt/homebrew/bin/brew" ]] && eval "$(/opt/homebrew/bin/brew shellenv)"
            [[ -f "/usr/local/bin/brew" ]]    && eval "$(/usr/local/bin/brew shellenv)"
            log_ok "Homebrew zainstalowany"
        fi
    else
        log_ok "Homebrew: $(brew --version | head -1)"
    fi

    # prlctl
    if ! command -v prlctl &>/dev/null; then
        log_err "prlctl nie znaleziony!"
        echo -e "  ${DIM}export PATH=\"\$PATH:/Applications/Parallels Desktop.app/Contents/MacOS\"${RESET}"
    else
        log_ok "Parallels: $(prlctl --version 2>/dev/null | head -1)"
    fi

    # python3
    command -v python3 &>/dev/null && log_ok "python3: $(python3 --version)" || \
        check_and_install python3 python3 "wymagane"

    echo ""
    echo -e "${BOLD}Narzędzia analizy:${RESET}"
    check_and_install yara      yara         "reguły YARA"       || true
    check_and_install clamscan  clamav       "antywirus"         || true
    check_and_install exiftool  exiftool     "metadane"          || true
    check_and_install upx       upx          "detekcja packerów" || true

    echo ""
    echo -e "${BOLD}Narzędzia archiwów:${RESET}"
    check_and_install 7z        p7zip        "ZIP/RAR/7z"        || true
    check_and_install unrar     unrar        "RAR"               || true

    echo ""
    echo -e "${BOLD}Pakiety Python:${RESET}"
    for pkg in pefile yara-python; do
        local imp="${pkg//-/_}"
        if ! python3 -c "import $imp" &>/dev/null 2>&1; then
            pip3 install "$pkg" --quiet 2>/dev/null || \
            pip3 install "$pkg" --quiet --break-system-packages 2>/dev/null || true
            python3 -c "import $imp" &>/dev/null 2>&1 && log_ok "pip: $pkg" || log_warn "pip: $pkg (nieudane — opcjonalne)"
        else
            log_ok "pip: $pkg"
        fi
    done
}

# ═════════════════════════════════════════════════════════════
# MODUŁ D — ZARZĄDZANIE VM PARALLELS
# ═════════════════════════════════════════════════════════════

download_noriben_tools() {
    section "PRZYGOTOWANIE NARZĘDZI NORIBEN"
    mkdir -p "$HOST_TOOLS_DIR"

    local npath="$HOST_TOOLS_DIR/Noriben.py"
    if [[ ! -f "$npath" ]]; then
        start_spinner "Pobieranie Noriben.py..."
        curl -fsSL "https://raw.githubusercontent.com/Rurik/Noriben/master/Noriben.py" \
            -o "$npath" 2>/dev/null && { stop_spinner; log_ok "Noriben.py: $npath"; } || \
            { stop_spinner; log_err "Nie udało się pobrać Noriben.py"; }
    else
        log_ok "Noriben.py: $npath"
    fi

    cat > "$HOST_TOOLS_DIR/vm_setup.ps1" <<'PSEOF'
param([string]$SnapshotName="Baseline_Clean")
Set-ExecutionPolicy Bypass -Scope Process -Force
$ErrorActionPreference="SilentlyContinue"
Write-Host "=== Konfiguracja VM dla Noriben ===" -ForegroundColor Cyan
foreach ($d in @("C:\Tools","C:\Malware","C:\NoribenLogs","C:\Python3")) {
    New-Item -ItemType Directory -Path $d -Force | Out-Null
    Write-Host "[OK] $d" -ForegroundColor Green
}
if (-not (Test-Path "C:\Python3\python.exe")) {
    $url="https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe"
    Invoke-WebRequest $url -OutFile "$env:TEMP\python.exe"
    & "$env:TEMP\python.exe" /quiet InstallAllUsers=1 TargetDir=C:\Python3 PrependPath=1
}
if (-not (Test-Path "C:\Tools\procmon64.exe")) {
    winget install Microsoft.Sysinternals.ProcessMonitor --silent --accept-eula
    $src="$env:ProgramFiles\Sysinternals Suite\Procmon64.exe"
    if (Test-Path $src) { Copy-Item $src "C:\Tools\procmon64.exe" }
}
Set-MpPreference -DisableRealtimeMonitoring $true
@("C:\Malware","C:\NoribenLogs","C:\Tools") | % { Add-MpPreference -ExclusionPath $_ }
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" EnableLUA 0
Stop-Service wuauserv -Force; Set-Service wuauserv -StartupType Disabled
Write-Host "=== Gotowe! Wykonaj snapshot: '$SnapshotName' ===" -ForegroundColor Green
PSEOF
    log_ok "vm_setup.ps1: $HOST_TOOLS_DIR/vm_setup.ps1"
}

vm_exists()     { prlctl list --all 2>/dev/null | grep -q "$VM_NAME"; }
get_vm_status() { prlctl status "$VM_NAME" 2>/dev/null | awk '{print $NF}' || echo "unknown"; }

list_available_vms() {
    echo -e "\n${BOLD}Dostępne VM:${RESET}"
    prlctl list --all 2>/dev/null || echo "  (brak VM)"
}

revert_to_snapshot() {
    section "PRZYWRACANIE SNAPSHOTA '$VM_SNAPSHOT'"
    local snap_id
    snap_id=$(prlctl snapshot-list "$VM_NAME" 2>/dev/null | \
        grep -i "$VM_SNAPSHOT" | awk '{print $1}' | head -1)
    if [[ -z "$snap_id" ]]; then
        log_err "Snapshot '$VM_SNAPSHOT' nie znaleziony!"
        prlctl snapshot-list "$VM_NAME" 2>/dev/null
        exit 1
    fi
    start_spinner "Przywracanie $VM_SNAPSHOT..."
    prlctl snapshot-switch "$VM_NAME" --id "$snap_id" >> "$LOG_FILE" 2>&1
    stop_spinner
    log_ok "Snapshot przywrócony"
}

start_vm() {
    section "URUCHAMIANIE WINDOWS VM"
    [[ "$(get_vm_status)" == "running" ]] && { log_ok "VM już działa"; return; }
    start_spinner "Uruchamianie VM '$VM_NAME'..."
    prlctl start "$VM_NAME" >> "$LOG_FILE" 2>&1
    stop_spinner
    log "Czekam na gotowość (max ${VM_BOOT_TIMEOUT}s)..."
    local waited=0
    while [[ $waited -lt $VM_BOOT_TIMEOUT ]]; do
        prlctl exec "$VM_NAME" cmd /c "echo ready" &>/dev/null 2>&1 && \
            { log_ok "VM gotowa po ${waited}s"; sleep 5; return; }
        sleep 3; ((waited+=3)) || true
        printf "\r  ${DIM}Boot: ${waited}/${VM_BOOT_TIMEOUT}s${RESET}"
    done
    printf "\r\033[K"
    log_warn "Timeout bootu — kontynuuję..."
}

stop_vm() {
    prlctl stop "$VM_NAME" --kill >> "$LOG_FILE" 2>&1 || true
    log_ok "VM zatrzymana"
}

copy_to_vm() {
    local src="$1" dst="$2"
    log "Host → VM: $(basename "$src") → $dst"
    prlctl exec "$VM_NAME" cmd /c "mkdir ${dst%\\*} 2>nul & exit 0" >> "$LOG_FILE" 2>&1 || true
    prlctl copy "$VM_NAME" "$src" "$dst" >> "$LOG_FILE" 2>&1 && \
        { log_ok "Skopiowano: $(basename "$src")"; return 0; }
    log_warn "prlctl copy nieudane — próba base64..."
    local b64; b64=$(base64 -i "$src")
    prlctl exec "$VM_NAME" powershell -Command \
        "[IO.File]::WriteAllBytes('$dst', [Convert]::FromBase64String('$b64'))" \
        >> "$LOG_FILE" 2>&1 && log_ok "Skopiowano (base64)" || \
        { log_err "Nie udało się skopiować $src"; return 1; }
}

copy_from_vm() {
    local src="$1" dst="$2"
    log "VM → Host: $(basename "$src")"
    prlctl copy "$VM_NAME" "$src" "$dst" --from-guest >> "$LOG_FILE" 2>&1 && \
        { log_ok "Pobrano: $(basename "$src")"; return 0; }
    log_warn "Fallback base64..."
    local tmp="$dst.b64"
    prlctl exec "$VM_NAME" powershell -Command \
        "[Convert]::ToBase64String([IO.File]::ReadAllBytes('$src'))" > "$tmp" 2>/dev/null && \
    base64 -d "$tmp" > "$dst" && rm -f "$tmp" && log_ok "Pobrano (base64)" || \
    log_err "Nie udało się pobrać: $src"
}

prepare_vm_environment() {
    section "KONFIGURACJA ŚRODOWISKA VM"
    for dir in "C:\\Tools" "C:\\Malware" "C:\\NoribenLogs"; do
        prlctl exec "$VM_NAME" cmd /c "mkdir $dir 2>nul & exit 0" >> "$LOG_FILE" 2>&1 || true
        log_ok "VM: $dir"
    done

    [[ -f "$HOST_TOOLS_DIR/Noriben.py" ]] && copy_to_vm "$HOST_TOOLS_DIR/Noriben.py" "C:\\Tools\\Noriben.py" || {
        prlctl exec "$VM_NAME" powershell -Command \
            "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/Rurik/Noriben/master/Noriben.py' -OutFile 'C:\Tools\Noriben.py'" \
            >> "$LOG_FILE" 2>&1 && log_ok "Noriben.py pobrany w VM" || log_err "Brak Noriben.py"
    }

    [[ -f "$HOST_TOOLS_DIR/procmon64.exe" ]] && copy_to_vm "$HOST_TOOLS_DIR/procmon64.exe" "C:\\Tools\\procmon64.exe" || {
        prlctl exec "$VM_NAME" powershell -Command \
            "winget install Microsoft.Sysinternals.ProcessMonitor --silent --accept-eula" \
            >> "$LOG_FILE" 2>&1 || true
    }

    prlctl exec "$VM_NAME" powershell -Command \
        "Set-MpPreference -DisableRealtimeMonitoring \$true 2>\$null; \
         Add-MpPreference -ExclusionPath 'C:\Malware','C:\NoribenLogs','C:\Tools' 2>\$null" \
        >> "$LOG_FILE" 2>&1 && log_ok "Defender skonfigurowany" || true
}

# ═════════════════════════════════════════════════════════════
# MODUŁ E — ANALIZA DYNAMICZNA (Noriben w VM)
# ═════════════════════════════════════════════════════════════

run_dynamic_analysis() {
    local sample_vm_path="$1"
    section "ANALIZA DYNAMICZNA — NORIBEN + PROCMON"

    local timeout_min=$(( ANALYSIS_TIMEOUT / 60 ))
    echo -e "${YELLOW}${BOLD}"
    echo "  ╔────────────────────────────────────────────────────────╗"
    printf "  ║  Próbka:  %-48s║\n" "$(basename "$sample_vm_path")"
    printf "  ║  Timeout: %-48s║\n" "${ANALYSIS_TIMEOUT}s (${timeout_min} min)"
    echo "  ║  Monitor: procesy · rejestr · pliki · sieć              ║"
    echo "  ╚────────────────────────────────────────────────────────╝"
    echo -e "${RESET}"

    # Opcjonalny tcpdump
    local tcpdump_pid="" pcap_file="$SESSION_DIR/network_capture.pcap"
    if command -v tcpdump &>/dev/null; then
        read -r -p "$(echo -e "  ${YELLOW}Przechwytywać ruch sieciowy VM przez tcpdump? [t/N]${RESET} ")" tcp_c
        if [[ "$tcp_c" =~ ^[tTyY]$ ]]; then
            local prl_iface
            prl_iface=$(ifconfig 2>/dev/null | grep -E "^vnic|^prl" | awk -F: '{print $1}' | head -1 || echo "en0")
            sudo tcpdump -i "$prl_iface" -w "$pcap_file" >> "$LOG_FILE" 2>&1 &
            tcpdump_pid=$!
            log_ok "tcpdump: interfejs $prl_iface → $pcap_file"
        fi
    fi

    prlctl exec "$VM_NAME" cmd /c "del /Q C:\\NoribenLogs\\* 2>nul & exit 0" >> "$LOG_FILE" 2>&1 || true

    local analysis_start; analysis_start=$(date +%s)
    log "Uruchamianie Noriben (timeout: ${ANALYSIS_TIMEOUT}s)..."

    prlctl exec "$VM_NAME" powershell -Command \
        "Start-Process -FilePath '$VM_PYTHON' \
         -ArgumentList '$VM_NORIBEN','--cmd','$sample_vm_path', \
             '--timeout','$ANALYSIS_TIMEOUT', \
             '--output','C:\NoribenLogs', \
             '--headless','--generalize' \
         -Wait -NoNewWindow \
         -RedirectStandardOutput 'C:\NoribenLogs\noriben_stdout.txt' \
         -RedirectStandardError  'C:\NoribenLogs\noriben_stderr.txt'" \
        >> "$LOG_FILE" 2>&1 &
    local prlctl_pid=$!

    while kill -0 $prlctl_pid 2>/dev/null; do
        local elapsed=$(( $(date +%s) - analysis_start ))
        local pct=$(( elapsed * 100 / (ANALYSIS_TIMEOUT + 30) ))
        [[ $pct -gt 100 ]] && pct=100
        local filled=$(( pct * 44 / 100 )) empty=$(( 44 - filled ))
        local bar
        bar="$(printf '%*s' "$filled" '' | tr ' ' '█')$(printf '%*s' "$empty" '' | tr ' ' '░')"
        printf "\r  ${CYAN}[%s]${RESET}  %3d%%  %ds / %ds  " "$bar" "$pct" "$elapsed" "$ANALYSIS_TIMEOUT"
        sleep 2
    done
    printf "\r\033[K"
    wait $prlctl_pid 2>/dev/null || true

    local duration=$(( $(date +%s) - analysis_start ))
    log_ok "Noriben zakończył po ${duration}s"

    if [[ -n "$tcpdump_pid" ]]; then
        sudo kill "$tcpdump_pid" 2>/dev/null || true
        log_ok "PCAP: $pcap_file ($(du -sh "$pcap_file" 2>/dev/null | cut -f1))"
        command -v tshark &>/dev/null && \
            tshark -r "$pcap_file" -q -z conv,ip 2>/dev/null | head -15 | tee -a "$LOG_FILE" || true
    fi

    sleep 3
}

collect_results() {
    section "POBIERANIE WYNIKÓW Z VM"

    local vm_files
    vm_files=$(prlctl exec "$VM_NAME" powershell -Command \
        "Get-ChildItem 'C:\NoribenLogs' | Select-Object -ExpandProperty Name" 2>/dev/null || echo "")

    if [[ -z "$vm_files" ]]; then
        log_warn "Brak plików w C:\\NoribenLogs"
        return 1
    fi

    log "Pliki wyników:"
    echo "$vm_files" | while read -r f; do
        [[ -z "$f" ]] && continue
        echo -e "  ${GREEN}→${RESET} $f"
    done

    local zip_vm="C:\\NoribenLogs\\results_${SESSION_ID}.zip"
    prlctl exec "$VM_NAME" powershell -Command \
        "Compress-Archive -Path 'C:\NoribenLogs\*' -DestinationPath '$zip_vm' -Force" \
        >> "$LOG_FILE" 2>&1 || {
        log_warn "Compress-Archive nieudane — kopiuję osobno..."
        echo "$vm_files" | while IFS= read -r fname; do
            [[ -z "$fname" ]] && continue
            copy_from_vm "C:\\NoribenLogs\\$fname" "$SESSION_DIR/$fname" || true
        done
        return 0
    }

    local local_zip="$SESSION_DIR/results_${SESSION_ID}.zip"
    copy_from_vm "$zip_vm" "$local_zip"
    if [[ -f "$local_zip" && -s "$local_zip" ]]; then
        unzip -q "$local_zip" -d "$SESSION_DIR/" 2>/dev/null && \
            { log_ok "Wyniki: $SESSION_DIR"; rm -f "$local_zip"; } || \
            log_warn "Błąd rozpakowywania — ZIP: $local_zip"
    fi
}

analyze_dynamic_results() {
    section "ANALIZA WYNIKÓW NORIBEN (DYNAMICZNA)"

    local txt_report csv_data
    txt_report=$(find "$SESSION_DIR" -name "Noriben_*.txt" 2>/dev/null | head -1)
    csv_data=$(find "$SESSION_DIR" -name "Noriben_*.csv" 2>/dev/null | head -1)

    if [[ -z "$txt_report" || ! -f "$txt_report" ]]; then
        log_warn "Brak raportu TXT Noriben"
        return 1
    fi

    log_ok "Raport: $txt_report"
    echo ""
    echo -e "${BOLD}── Raport Noriben (skrót) ──${RESET}"
    head -80 "$txt_report" | tee -a "$LOG_FILE"

    echo -e "\n${BOLD}── Wykryte zachowania (IOC dynamiczne) ──${RESET}"
    declare -A DYN_IOC=(
        ["Nowe procesy"]="Process Create|CreateProcess|Spawned"
        ["Sieć TCP/UDP"]="TCP|UDP|Connect|DNS"
        ["Zapis rejestru"]="RegSetValue|RegCreateKey|\\\\Run\\\\|\\\\RunOnce\\\\"
        ["Nowe pliki EXE/DLL"]="\.exe|\.dll|\.bat|\.ps1 CreateFile|WriteFile"
        ["Autostart / Persistence"]="Run|RunOnce|Startup|Schedule|schtasks|Services"
        ["Wstrzykiwanie procesów"]="VirtualAlloc|WriteProcessMemory|CreateRemoteThread|Inject"
        ["Shadow Copy / VSS"]="vssadmin|ShadowCopy|DeleteShadow"
        ["Modyfikacje systemu"]="System32|SysWOW64|drivers\\\\etc\\\\hosts|firewall"
    )

    local dyn_total=0
    for category in "${!DYN_IOC[@]}"; do
        local hits
        hits=$(grep -iE "${DYN_IOC[$category]}" "$txt_report" 2>/dev/null | \
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

    [[ $dyn_total -eq 0 ]] && log_ok "Brak IOC dynamicznych" || log_warn "$dyn_total kategorii IOC"

    if [[ -n "$csv_data" && -f "$csv_data" ]]; then
        echo ""
        log "Statystyki zdarzeń Procmon:"
        local total_events; total_events=$(wc -l < "$csv_data" | tr -d ' ')
        log "  Łącznie: $total_events zdarzeń"
        log "  Top procesów:"
        awk -F',' 'NR>1 && NF>2 {print $2}' "$csv_data" 2>/dev/null | \
            sort | uniq -c | sort -rn | head -10 | \
            while read -r cnt proc; do echo -e "    ${cnt}x  ${proc}"; done | tee -a "$LOG_FILE" || true
    fi

    log_ok "Analiza dynamiczna zakończona — score: $DYNAMIC_RISK_SCORE"
}

# ═════════════════════════════════════════════════════════════
# MODUŁ F — RAPORT HTML
# ═════════════════════════════════════════════════════════════

generate_html_report() {
    section "GENEROWANIE RAPORTU HTML"

    local html_out="$SESSION_DIR/REPORT_${SESSION_ID}.html"
    local sha256; sha256=$(cat "$SESSION_DIR/sample_sha256.txt" 2>/dev/null || \
        shasum -a 256 "${EXTRACTED_SAMPLE:-$SAMPLE_FILE}" | awk '{print $1}')
    local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
    local ftype; ftype=$(file -b "${EXTRACTED_SAMPLE:-$SAMPLE_FILE}" 2>/dev/null)
    local fsize; fsize=$(du -sh "${EXTRACTED_SAMPLE:-$SAMPLE_FILE}" | cut -f1)

    local noriben_txt=""
    local nr; nr=$(find "$SESSION_DIR" -name "Noriben_*.txt" 2>/dev/null | head -1)
    [[ -n "$nr" && -f "$nr" ]] && noriben_txt=$(sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g' "$nr")

    local total_score=$(( (STATIC_RISK_SCORE + DYNAMIC_RISK_SCORE) / 2 ))
    [[ $total_score -gt 100 ]] && total_score=100
    local risk_class="low" risk_label="NISKIE" risk_color="#3fb950"
    [[ $total_score -ge 40 ]] && risk_class="med"  && risk_label="ŚREDNIE"  && risk_color="#e3b341"
    [[ $total_score -ge 70 ]] && risk_class="high" && risk_label="WYSOKIE"  && risk_color="#f85149"

    local mitre_html=""
    if [[ ${#MITRE_TECHNIQUES[@]} -gt 0 ]]; then
        local seen_tags=()
        for t in "${MITRE_TECHNIQUES[@]}"; do
            local already=false
            for s in "${seen_tags[@]:-}"; do [[ "$s" == "$t" ]] && already=true; done
            $already && continue
            seen_tags+=("$t")
            mitre_html+="<span class='mtag'>$t</span>"
        done
    fi

    local static_html=""
    if [[ ${#STATIC_FINDINGS[@]} -gt 0 ]]; then
        for f in "${STATIC_FINDINGS[@]}"; do
            static_html+="<div class='finding f-red'>$f</div>"
        done
    else
        static_html="<div class='finding f-green'>✓ Brak podejrzanych wskaźników statycznych</div>"
    fi

    local dynamic_html=""
    if [[ ${#DYNAMIC_FINDINGS[@]} -gt 0 ]]; then
        for f in "${DYNAMIC_FINDINGS[@]}"; do
            dynamic_html+="<div class='finding f-yellow'>$f</div>"
        done
    else
        dynamic_html="<div class='finding f-green'>✓ Brak podejrzanych zachowań dynamicznych</div>"
    fi

    local log_html=""
    log_html=$(tail -80 "$LOG_FILE" 2>/dev/null | sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g')

    cat > "$html_out" <<HTMLEOF
<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="UTF-8">
<title>Sandbox Report — ${SAMPLE_BASENAME}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Courier New',monospace;background:#0d1117;color:#c9d1d9;padding:30px;line-height:1.6}
a{color:#58a6ff}
h1{color:#58a6ff;font-size:1.85em;margin-bottom:4px}
h2{color:#79c0ff;font-size:1.1em;margin:26px 0 10px;border-left:4px solid #388bfd;padding-left:12px}
.subtitle{color:#8b949e;font-size:.87em}
.hdr{border-bottom:1px solid #30363d;padding-bottom:16px;margin-bottom:20px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:13px;margin:13px 0}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:13px}
.lbl{color:#8b949e;font-size:.73em;text-transform:uppercase;letter-spacing:.04em}
.val{color:#e6edf3;font-size:.88em;margin-top:3px;word-break:break-all}
.hash{color:#3fb950;font-size:.71em}
pre{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:16px;overflow-x:auto;
    white-space:pre-wrap;font-size:.8em;max-height:500px;overflow-y:auto}
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
.mtag{display:inline-block;background:#1c2a3e;color:#79c0ff;border:1px solid #264b73;
    border-radius:4px;padding:2px 8px;font-size:.73em;margin:3px}
.bar-wrap{background:#21262d;border-radius:4px;height:7px;width:280px;margin:7px 0}
.bar-fill{height:7px;border-radius:4px}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.vt-btn{display:inline-block;background:#1c3a5e;color:#58a6ff;padding:8px 16px;
    border-radius:6px;text-decoration:none;font-size:.86em;margin-top:8px}
@media(max-width:680px){.two-col{grid-template-columns:1fr}}
footer{color:#8b949e;font-size:.76em;margin-top:38px;border-top:1px solid #30363d;padding-top:12px}
</style>
</head>
<body>

<div class="hdr">
  <h1>🔬 Sandbox Analysis Report</h1>
  <p class="subtitle">Noriben + Parallels + Analiza statyczna/dynamiczna | v${VERSION}</p>
  <p class="subtitle">Sesja: ${SESSION_ID} &nbsp;·&nbsp; $ts</p>
</div>

<h2>📁 Próbka</h2>
<div class="grid">
  <div class="card"><div class="lbl">Nazwa pliku</div><div class="val">${SAMPLE_BASENAME}</div></div>
  <div class="card"><div class="lbl">Typ pliku</div><div class="val">${ftype}</div></div>
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

$(if [[ -n "$mitre_html" ]]; then echo "<h2>🗺 MITRE ATT&CK</h2>$mitre_html"; fi)

<h2>⚙️ Konfiguracja analizy</h2>
<div class="card">
<table style="width:100%;border-collapse:collapse">
  <tr><td style="color:#8b949e;padding:4px 10px;width:150px">VM</td><td style="padding:4px 10px">${VM_NAME}</td></tr>
  <tr><td style="color:#8b949e;padding:4px 10px">Snapshot</td><td style="padding:4px 10px">${VM_SNAPSHOT}</td></tr>
  <tr><td style="color:#8b949e;padding:4px 10px">Timeout</td><td style="padding:4px 10px">${ANALYSIS_TIMEOUT}s ($(( ANALYSIS_TIMEOUT/60 )) min)</td></tr>
  <tr><td style="color:#8b949e;padding:4px 10px">Noriben</td><td style="padding:4px 10px">${VM_NORIBEN}</td></tr>
  <tr><td style="color:#8b949e;padding:4px 10px">Procmon</td><td style="padding:4px 10px">${VM_PROCMON}</td></tr>
</table>
</div>

<h2>📋 Raport Noriben</h2>
$(if [[ -n "$noriben_txt" ]]; then echo "<pre>$noriben_txt</pre>"; \
  else echo "<div class='card' style='color:#f85149'>Brak raportu Noriben.</div>"; fi)

<h2>📄 Log hosta (macOS)</h2>
<pre>${log_html}</pre>

<footer>
  Wygenerowano przez noriben_parallels_setup.sh v${VERSION} &nbsp;·&nbsp;
  macOS Host → Parallels → Windows VM → Noriben + Procmon
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
    LOG_FILE="/tmp/noriben_setup_$$.log"; touch "$LOG_FILE"

    check_host_tools
    download_noriben_tools

    echo ""
    echo -e "${CYAN}${BOLD}Dostępne VM w Parallels:${RESET}"
    command -v prlctl &>/dev/null && list_available_vms

    echo ""
    echo -e "${BOLD}═══ Dalsze kroki ═══${RESET}"
    echo "1. Uruchom VM Windows w Parallels"
    echo "2. Skopiuj $HOST_TOOLS_DIR/vm_setup.ps1 do VM"
    echo "3. W VM — PowerShell jako Administrator:"
    echo -e "   ${CYAN}Set-ExecutionPolicy Bypass -Scope Process -Force${RESET}"
    echo -e "   ${CYAN}.\\vm_setup.ps1${RESET}"
    echo "4. Snapshot: Parallels → Actions → Take Snapshot"
    echo -e "   Nazwa: ${BOLD}$VM_SNAPSHOT${RESET}"
    echo ""
    echo -e "${GREEN}${BOLD}Uruchomienie analizy:${RESET}"
    echo -e "  ${CYAN}$0 ~/Downloads/malware.exe${RESET}"
    echo -e "  ${CYAN}$0 ~/Downloads/sample.zip --archive-password infected${RESET}"
    rm -f "$LOG_FILE"
}

# ═════════════════════════════════════════════════════════════
# CLEANUP
# ═════════════════════════════════════════════════════════════

cleanup() {
    stop_spinner
    command -v prlctl &>/dev/null && vm_exists 2>/dev/null && \
        [[ "$(get_vm_status 2>/dev/null)" == "running" ]] && stop_vm || true
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
            --vm)                shift; VM_NAME="$1" ;;
            --snapshot)          shift; VM_SNAPSHOT="$1" ;;
            --timeout)           shift; ANALYSIS_TIMEOUT="$1" ;;
            --archive-password)  shift; archive_password="$1" ;;
            --list-vms)          prlctl list --all 2>/dev/null; exit 0 ;;
            --help|-h)
                cat <<HELP
Użycie: $0 <plik> [opcje]

  --setup                  Konfiguracja (pierwsze uruchomienie)
  --vm <nazwa>             Nazwa VM Parallels (domyślnie: '$VM_NAME')
  --snapshot <n>           Nazwa snapshota (domyślnie: '$VM_SNAPSHOT')
  --timeout <s>            Czas analizy (domyślnie: ${ANALYSIS_TIMEOUT}s)
  --archive-password <p>   Hasło do archiwum ZIP/RAR/7z
  --static-only            Tylko analiza statyczna (bez VM)
  --dynamic-only           Tylko analiza dynamiczna (bez statycznej)
  --no-revert              Nie przywracaj snapshota
  --list-vms               Lista dostępnych VM

Zmienne środowiskowe:
  VM_NAME, VM_SNAPSHOT, VM_USER, VM_PASS
  ANALYSIS_TIMEOUT         Czas analizy w sekundach
  ARCHIVE_PASSWORDS        Hasła domyślne (rozdzielone spacją)

Przykłady:
  $0 --setup
  $0 malware.exe
  $0 sample.zip --archive-password infected
  $0 sample.rar --archive-password "secret pass" --timeout 600
  $0 malware.exe --static-only
  $0 malware.exe --vm "Win10 Sandbox" --snapshot Clean_Baseline
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
        echo "  noriben_parallels_setup.sh v$VERSION"
        echo "  Sesja:   $SESSION_ID"
        echo "  Plik:    $SAMPLE_FILE"
        echo "  VM:      $VM_NAME  |  Snapshot: $VM_SNAPSHOT"
        echo "  Timeout: ${ANALYSIS_TIMEOUT}s"
        echo "  $(date)"
        echo "═══════════════════════════════════════════"
    } >> "$LOG_FILE"

    log "Sesja: $SESSION_ID | Wyniki: $SESSION_DIR"

    # 0. Narzędzia
    check_host_tools
    download_noriben_tools

    # 1. Archiwum
    local analysis_target="$SAMPLE_FILE"
    if is_archive "$SAMPLE_FILE"; then
        [[ -n "$archive_password" ]] && ARCHIVE_PASSWORDS="$archive_password $ARCHIVE_PASSWORDS"
        handle_archive "$SAMPLE_FILE"
        [[ -n "$EXTRACTED_SAMPLE" && "$EXTRACTED_SAMPLE" != ALL:* ]] && \
            analysis_target="$EXTRACTED_SAMPLE"
    fi

    # 2. Analiza statyczna
    [[ "$dynamic_only" == false ]] && static_analysis "$analysis_target"

    # 3. Analiza dynamiczna
    if [[ "$static_only" == false ]]; then
        if ! vm_exists 2>/dev/null; then
            log_err "VM '$VM_NAME' nie istnieje!"
            list_available_vms
            exit 1
        fi
        $no_revert || revert_to_snapshot
        start_vm
        prepare_vm_environment

        section "KOPIOWANIE PRÓBKI DO VM"
        local vm_path="${VM_MALWARE_DIR}\\$(basename "$analysis_target")"
        copy_to_vm "$analysis_target" "$vm_path"

        run_dynamic_analysis "$vm_path"
        collect_results
        analyze_dynamic_results
    fi

    # 4. Raport HTML
    local html_report
    html_report=$(generate_html_report)

    # Podsumowanie
    local total=$(( (STATIC_RISK_SCORE + DYNAMIC_RISK_SCORE) / 2 ))
    [[ $total -gt 100 ]] && total=100

    echo ""
    echo -e "${GREEN}${BOLD}╔═════════════════════════════════════════════════╗"
    echo -e "║  ✅  Analiza zakończona!                        ║"
    echo -e "╚═════════════════════════════════════════════════╝${RESET}"
    echo ""
    printf "  %-22s ${BOLD}%d / 100${RESET}\n" "Wynik ryzyka:"   "$total"
    printf "  %-22s %d\n"                       "Statyczna:"     "$STATIC_RISK_SCORE"
    printf "  %-22s %d\n"                       "Dynamiczna:"    "$DYNAMIC_RISK_SCORE"
    echo ""
    echo -e "  📁 Wyniki:      ${BOLD}$SESSION_DIR${RESET}"
    [[ -n "$html_report" ]] && echo -e "  🌐 Raport HTML: ${BOLD}$html_report${RESET}"
    echo ""
    echo -e "  ${DIM}open '$html_report'${RESET}"
    local sha256; sha256=$(shasum -a 256 "$analysis_target" | awk '{print $1}')
    echo -e "  ${DIM}https://www.virustotal.com/gui/file/$sha256${RESET}"
    echo ""
}

main "$@"
