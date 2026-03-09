#!/bin/bash
# ============================================================
#  sandbox_analyzer_v2.sh — Zaawansowana analiza plików
#  Obsługa: macOS (natywne + Wine dla Windows .exe/.dll)
#  Funkcje: auto-instalacja narzędzi, długi timeout, raport HTML
#
#  Wymagania: macOS 12+, Homebrew (auto-instalowany jeśli brak)
# ============================================================

set -euo pipefail

# ─── Wersja ──────────────────────────────────────────────────
VERSION="2.0.0"

# ─── Kolory terminala ─────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'
DIM='\033[2m'; RESET='\033[0m'

# ─── Konfiguracja ────────────────────────────────────────────
SANDBOX_DIR="/tmp/sandbox_analysis_$$"
REPORT_TXT="$SANDBOX_DIR/report.txt"
REPORT_HTML="$SANDBOX_DIR/report.html"
PROFILE_FILE="$SANDBOX_DIR/sandbox.sb"
WINE_PROFILE="$SANDBOX_DIR/wine_sandbox.sb"

TIMEOUT_SECS=300          # 5 minut (dla wolnych aplikacji Windows)
WINE_TIMEOUT=600          # 10 minut dla Wine (Windows apps)
MAX_FILE_SIZE_MB=500
LOG_LEVEL="${LOG_LEVEL:-INFO}"  # DEBUG | INFO | WARN | ERROR

# ─── Wymagane narzędzia i skąd je pobrać ─────────────────────
# Format: "narzędzie:brew_formula:pip_package:opis"
declare -A TOOLS_BREW=(
    ["strings"]="binutils:Analiza ciągów znaków w binarnych"
    ["xxd"]="vim:Podgląd hex"
    ["yara"]="yara:Skanowanie regułami YARA (malware)"
    ["exiftool"]="exiftool:Metadane EXIF/ID3/PDF"
    ["clamav"]="clamav:Skaner antywirusowy open-source"
    ["wine"]="wine:Emulator Windows (uruchamianie .exe)"
    ["winetricks"]="winetricks:Pomocnik konfiguracji Wine"
    ["oletools"]="python-oletools:Analiza dokumentów Office/VBA"
    ["pefile"]="":""
    ["binwalk"]="binwalk:Analiza firmware / embedded"
    ["upx"]="upx:Detekcja i rozpakowanie UPX packerów"
    ["radare2"]="radare2:Inżynieria wsteczna / deasembler"
)

# ─── Spinner / Progress ───────────────────────────────────────
SPINNER_PID=""
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
    if [[ -n "$SPINNER_PID" ]]; then
        kill "$SPINNER_PID" 2>/dev/null || true
        wait "$SPINNER_PID" 2>/dev/null || true
        SPINNER_PID=""
        printf "\r\033[K"
    fi
}

# ─── Logowanie ────────────────────────────────────────────────
log()      { echo -e "${BOLD}[•]${RESET} $*";             echo "[INFO] $(date '+%H:%M:%S') $*" >> "$REPORT_TXT"; }
log_ok()   { echo -e "${GREEN}[✓]${RESET} $*";            echo "[OK]   $(date '+%H:%M:%S') $*" >> "$REPORT_TXT"; }
log_warn() { echo -e "${YELLOW}[!]${RESET} $*";           echo "[WARN] $(date '+%H:%M:%S') $*" >> "$REPORT_TXT"; }
log_err()  { echo -e "${RED}[✗]${RESET} $*";              echo "[ERR]  $(date '+%H:%M:%S') $*" >> "$REPORT_TXT"; }
log_dbg()  { [[ "$LOG_LEVEL" == "DEBUG" ]] && echo -e "${DIM}[D] $*${RESET}" || true; }
section()  {
    echo -e "\n${CYAN}${BOLD}╔══════════════════════════════════════╗"
    printf "${CYAN}${BOLD}║  %-36s║\n" "$*"
    echo -e "╚══════════════════════════════════════╝${RESET}"
    echo -e "\n=== $* ===" >> "$REPORT_TXT"
}

# ─── Banner ───────────────────────────────────────────────────
print_banner() {
    echo -e "${CYAN}${BOLD}"
    cat <<'BANNER'
  ╔════════════════════════════════════════════════════╗
  ║   🔬 macOS Sandbox File Analyzer  v2.0            ║
  ║   Analiza plików macOS & Windows (Wine)           ║
  ║   Auto-install · YARA · ClamAV · Radare2          ║
  ╚════════════════════════════════════════════════════╝
BANNER
    echo -e "${RESET}"
}

# ════════════════════════════════════════════════════════════════
# MODUŁ 0 — AUTO-INSTALACJA NARZĘDZI
# ════════════════════════════════════════════════════════════════

install_homebrew() {
    if command -v brew &>/dev/null; then
        log_ok "Homebrew już zainstalowany: $(brew --version | head -1)"
        return 0
    fi

    log_warn "Homebrew nie znaleziony — instaluję..."
    echo -e "${YELLOW}Homebrew jest wymagany do instalacji narzędzi analitycznych.${RESET}"
    read -r -p "$(echo -e "${BOLD}Czy zainstalować Homebrew? [t/N]${RESET} ")" confirm
    if [[ ! "$confirm" =~ ^[tTyY]$ ]]; then
        log_err "Homebrew wymagany — przerywam"
        exit 1
    fi

    start_spinner "Instalowanie Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" \
        </dev/null >> "$REPORT_TXT" 2>&1
    stop_spinner

    # Dodaj brew do PATH (Apple Silicon / Intel)
    if [[ -f "/opt/homebrew/bin/brew" ]]; then
        eval "$(/opt/homebrew/bin/brew shellenv)"
    elif [[ -f "/usr/local/bin/brew" ]]; then
        eval "$(/usr/local/bin/brew shellenv)"
    fi

    log_ok "Homebrew zainstalowany pomyślnie"
}

check_and_install_tool() {
    local tool="$1"
    local formula="${2:-$tool}"
    local description="${3:-}"

    if command -v "$tool" &>/dev/null; then
        log_ok "${tool}: $(command -v "$tool")"
        return 0
    fi

    log_warn "Brak: $tool ${description:+(${description})}"
    read -r -p "$(echo -e "  ${YELLOW}Zainstalować '$formula' przez Homebrew? [t/N]${RESET} ")" confirm
    if [[ ! "$confirm" =~ ^[tTyY]$ ]]; then
        log_warn "Pominięto instalację: $tool"
        return 1
    fi

    start_spinner "Instalowanie $formula..."
    if brew install "$formula" >> "$REPORT_TXT" 2>&1; then
        stop_spinner
        log_ok "$formula zainstalowany"

        # Specjalna konfiguracja po instalacji
        case "$tool" in
            clamav)
                log "Aktualizacja bazy wirusów ClamAV..."
                start_spinner "Pobieranie bazy sygnatur ClamAV..."
                sudo freshclam >> "$REPORT_TXT" 2>&1 || freshclam >> "$REPORT_TXT" 2>&1 || true
                stop_spinner
                log_ok "Baza ClamAV zaktualizowana"
                ;;
            wine)
                log "Wine zainstalowany — konfiguracja WINEPREFIX..."
                export WINEPREFIX="$SANDBOX_DIR/wine_prefix"
                mkdir -p "$WINEPREFIX"
                # Inicjalizacja Wine (cicha)
                start_spinner "Inicjalizacja środowiska Wine..."
                WINEDEBUG=-all wineboot --init >> "$REPORT_TXT" 2>&1 || true
                stop_spinner
                log_ok "Wine skonfigurowany w: $WINEPREFIX"
                ;;
        esac
        return 0
    else
        stop_spinner
        log_err "Nie udało się zainstalować: $formula"
        return 1
    fi
}

install_python_tools() {
    log "Sprawdzanie narzędzi Python..."
    if ! command -v pip3 &>/dev/null && ! command -v pip &>/dev/null; then
        log_warn "pip nie znaleziony — pomijam narzędzia Python"
        return
    fi

    local pip_cmd
    pip_cmd=$(command -v pip3 || command -v pip)

    # oletools (analiza makr VBA, OLE documents)
    if ! command -v olevba &>/dev/null; then
        log_warn "oletools nie znaleziony (analiza makr VBA/Office)"
        read -r -p "$(echo -e "  ${YELLOW}Zainstalować oletools? [t/N]${RESET} ")" confirm
        if [[ "$confirm" =~ ^[tTyY]$ ]]; then
            start_spinner "Instalowanie oletools..."
            "$pip_cmd" install oletools --quiet >> "$REPORT_TXT" 2>&1 && \
                { stop_spinner; log_ok "oletools zainstalowany"; } || \
                { stop_spinner; log_warn "Błąd instalacji oletools"; }
        fi
    else
        log_ok "oletools: $(command -v olevba)"
    fi

    # pefile (analiza PE plików Windows)
    if ! "$pip_cmd" show pefile &>/dev/null 2>&1; then
        log_warn "pefile nie znaleziony (analiza PE/Windows executables)"
        read -r -p "$(echo -e "  ${YELLOW}Zainstalować pefile? [t/N]${RESET} ")" confirm
        if [[ "$confirm" =~ ^[tTyY]$ ]]; then
            start_spinner "Instalowanie pefile..."
            "$pip_cmd" install pefile --quiet >> "$REPORT_TXT" 2>&1 && \
                { stop_spinner; log_ok "pefile zainstalowany"; } || \
                { stop_spinner; log_warn "Błąd instalacji pefile"; }
        fi
    else
        log_ok "pefile: dostępny przez Python"
    fi
}

# Główna funkcja instalacji — sprawdź wszystko na starcie
setup_tools() {
    section "SPRAWDZANIE I INSTALACJA NARZĘDZI"
    echo ""
    echo -e "${BOLD}Narzędzia wymagane do analizy:${RESET}"
    echo ""
    printf "  %-20s %-30s %s\n" "NARZĘDZIE" "BREW FORMULA" "OPIS"
    printf "  %-20s %-30s %s\n" "─────────────────" "───────────────────────────" "──────────────────────────"

    declare -A tool_map=(
        ["xxd"]="vim|Podgląd hex pliku"
        ["exiftool"]="exiftool|Metadane (EXIF, ID3, PDF)"
        ["yara"]="yara|Skanowanie regułami YARA"
        ["clamscan"]="clamav|Antywirus ClamAV"
        ["upx"]="upx|Detekcja packerów UPX"
        ["r2"]="radare2|Deasembler / RE"
        ["binwalk"]="binwalk|Analiza embedded/firmware"
        ["wine"]="wine|Emulator Windows (.exe/.dll)"
        ["winetricks"]="winetricks|Konfiguracja Wine"
    )

    for tool in "${!tool_map[@]}"; do
        IFS='|' read -r formula desc <<< "${tool_map[$tool]}"
        if command -v "$tool" &>/dev/null; then
            printf "  ${GREEN}✓${RESET} %-19s %-30s %s\n" "$tool" "$formula" "$desc"
        else
            printf "  ${RED}✗${RESET} %-19s %-30s %s\n" "$tool" "$formula" "$desc"
        fi
    done

    echo ""
    read -r -p "$(echo -e "${BOLD}Zainstalować brakujące narzędzia automatycznie? [t/N]${RESET} ")" auto_install

    install_homebrew

    if [[ "$auto_install" =~ ^[tTyY]$ ]]; then
        log "Instalowanie brakujących narzędzi..."
        for tool in "${!tool_map[@]}"; do
            IFS='|' read -r formula desc <<< "${tool_map[$tool]}"
            check_and_install_tool "$tool" "$formula" "$desc" || true
        done
        install_python_tools
    else
        log "Pomijam auto-instalację — używam dostępnych narzędzi"
    fi
}

# ════════════════════════════════════════════════════════════════
# PROFIL SANDBOX
# ════════════════════════════════════════════════════════════════

create_sandbox_profiles() {
    # Profil dla plików macOS (ścisły)
    cat > "$PROFILE_FILE" <<'SBPROFILE'
(version 1)
(deny default)
(allow file-read*
    (literal "/")
    (subpath "/usr/lib")
    (subpath "/usr/share")
    (subpath "/System/Library")
    (subpath "/Library/Frameworks")
    (literal "/dev/null")
    (literal "/dev/random")
    (literal "/dev/urandom")
    (subpath "/tmp/sandbox_analysis")
    (subpath "/private/tmp/sandbox_analysis")
)
(allow file-write* (subpath "/tmp/sandbox_analysis"))
(allow process-fork)
(allow process-exec)
(deny network*)
(deny mach-lookup
    (global-name "com.apple.SecurityServer")
    (global-name "com.apple.securityd")
    (global-name "com.apple.lsd.xpc")
)
(deny ipc-posix*)
(deny system-socket)
(allow signal (target self))
(allow sysctl-read)
SBPROFILE

    # Profil Wine (nieco mniej restrykcyjny — Wine wymaga więcej uprawnień IPC)
    cat > "$WINE_PROFILE" <<'WINEPROFILE'
(version 1)
(deny default)
(allow file-read*
    (literal "/")
    (subpath "/usr/lib")
    (subpath "/usr/share")
    (subpath "/System/Library")
    (subpath "/Library/Frameworks")
    (literal "/dev/null")
    (literal "/dev/random")
    (literal "/dev/urandom")
    (subpath "/tmp/sandbox_analysis")
    (subpath "/private/tmp/sandbox_analysis")
    (subpath "/usr/local/lib")
    (subpath "/opt/homebrew/lib")
    (subpath "/opt/homebrew/share/wine")
    (subpath "/usr/local/share/wine")
)
(allow file-write* (subpath "/tmp/sandbox_analysis"))
(allow process-fork)
(allow process-exec)
(allow process-exec-interpreter)
(deny network*)
(allow mach-lookup
    (global-name "com.apple.fonts")
    (global-name "com.apple.FontServer")
)
(allow ipc-posix-shm-read*)
(allow ipc-posix-shm-write-data)
(allow signal (target self))
(allow sysctl-read)
(allow iokit-open (iokit-user-client-class "IOHIDLibUserClient"))
WINEPROFILE
}

# ════════════════════════════════════════════════════════════════
# MODUŁ 1 — METADANE
# ════════════════════════════════════════════════════════════════

analyze_metadata() {
    section "METADANE PLIKU"
    local f="$1"

    log "Ścieżka:     $f"
    log "Rozmiar:     $(du -sh "$f" | cut -f1) ($(wc -c < "$f") bajtów)"
    log "Typ (file):  $(file -b "$f")"
    log "Właściciel:  $(ls -la "$f" | awk '{print $3"/"$4}')"
    log "Uprawnienia: $(ls -la "$f" | awk '{print $1}')"
    log "Utworzono:   $(GetFileInfo -d "$f" 2>/dev/null || stat -f "%SB" "$f" 2>/dev/null || echo "nieznana")"
    log "Modyfikacja: $(GetFileInfo -m "$f" 2>/dev/null || stat -f "%Sm" "$f")"

    log "MD5:         $(md5 -q "$f" 2>/dev/null || md5sum "$f" | awk '{print $1}')"
    log "SHA1:        $(shasum -a 1 "$f" | awk '{print $1}')"
    log "SHA256:      $(shasum -a 256 "$f" | awk '{print $1}')"
    log "SHA512:      $(shasum -a 512 "$f" | awk '{print $1}')"

    if command -v exiftool &>/dev/null; then
        log "=== ExifTool Metadata ==="
        exiftool "$f" 2>/dev/null | grep -v "^ExifTool Version" | head -40 | tee -a "$REPORT_TXT"
    fi
}

# ════════════════════════════════════════════════════════════════
# MODUŁ 2 — DETEKCJA TYPU I MAGIC BYTES
# ════════════════════════════════════════════════════════════════

analyze_magic() {
    section "MAGIC BYTES I TYP PLIKU"
    local f="$1"

    echo "Pierwsze 16 bajtów (hex):"
    xxd "$f" 2>/dev/null | head -8 | tee -a "$REPORT_TXT" || \
        hexdump -C "$f" 2>/dev/null | head -8 | tee -a "$REPORT_TXT"

    local ext="${f##*.}"
    local detected
    detected=$(file -b --mime-type "$f" 2>/dev/null || echo "nieznany")

    log "Rozszerzenie:    .${ext,,}"
    log "Wykryty MIME:    $detected"

    # Detekcja typów
    local file_desc
    file_desc=$(file -b "$f" 2>/dev/null)

    local is_windows=false
    local is_macho=false
    local is_office=false
    local is_script=false

    case "$file_desc" in
        *"PE32"*|*"MS-DOS"*|*"Windows"*)
            log_warn "Plik wykonywalny Windows (PE/EXE/DLL)"
            is_windows=true ;;
        *"Mach-O"*)
            log_warn "Plik wykonywalny macOS (Mach-O)"
            is_macho=true ;;
        *"Composite Document File"*|*"CDFV2"*|*"Microsoft"*)
            log_warn "Dokument Office (potencjalnie z makrami VBA)"
            is_office=true ;;
        *"shell script"*|*"Python"*|*"Ruby"*|*"Perl"*)
            log_warn "Skrypt — sprawdź zawartość"
            is_script=true ;;
        *"PDF"*)
            log_warn "PDF — może zawierać skrypty JS lub embedded EXE" ;;
        *"Zip"*|*"RAR"*|*"7-zip"*)
            log_warn "Archiwum — może zawierać ukryte pliki" ;;
        *) log "Typ: $file_desc" ;;
    esac

    # Eksportuj zmienne globalne
    export FILE_IS_WINDOWS="$is_windows"
    export FILE_IS_MACHO="$is_macho"
    export FILE_IS_OFFICE="$is_office"
    export FILE_IS_SCRIPT="$is_script"

    # Ostrzeżenie o rozbieżności rozszerzenia
    local expected_ext=""
    case "$detected" in
        application/x-mach-binary)      expected_ext="(brak/.app)" ;;
        application/x-dosexec)          expected_ext=".exe/.dll/.com" ;;
        application/pdf)                expected_ext=".pdf" ;;
        application/zip)                expected_ext=".zip/.jar/.apk" ;;
        text/x-shellscript)             expected_ext=".sh" ;;
    esac

    if [[ -n "$expected_ext" && "${ext,,}" != "${expected_ext//[().\/]/}" ]]; then
        log_warn "Możliwa rozbieżność: rozszerzenie .${ext,,} ale typ sugeruje $expected_ext"
    fi
}

# ════════════════════════════════════════════════════════════════
# MODUŁ 3 — ANALIZA PE (pliki Windows)
# ════════════════════════════════════════════════════════════════

analyze_pe_windows() {
    local f="$1"
    [[ "$FILE_IS_WINDOWS" != "true" ]] && return

    section "ANALIZA PE / WINDOWS EXECUTABLE"

    log "Szczegóły struktury PE:"
    file "$f" | tee -a "$REPORT_TXT"

    # Strings w pliku PE
    log "Ciągi znaków z binarnego PE:"
    strings -n 6 "$f" 2>/dev/null | head -100 | tee -a "$REPORT_TXT" || true

    # Sekcje PE przez strings (heurystycznie)
    log "Podejrzane sekcje i importy:"
    strings -n 4 "$f" 2>/dev/null | grep -iE \
        "kernel32|ntdll|CreateProcess|VirtualAlloc|WriteProcessMemory|SetWindowsHook|\
        RegSetValue|URLDownload|WinExec|ShellExecute|IsDebuggerPresent|\
        FindWindow|GetAsyncKeyState|keylog|screenshot|inject|hook" \
        | sort -u | head -50 | tee -a "$REPORT_TXT" || true

    # Analiza przez pefile (Python)
    if command -v python3 &>/dev/null; then
        python3 - "$f" >> "$REPORT_TXT" 2>/dev/null <<'PYEOF' || true
import sys, os
try:
    import pefile
    pe = pefile.PE(sys.argv[1])
    print("\n[PE INFO]")
    print(f"  Machine:       {hex(pe.FILE_HEADER.Machine)}")
    print(f"  TimeDateStamp: {pe.FILE_HEADER.TimeDateStamp}")
    print(f"  Subsystem:     {pe.OPTIONAL_HEADER.Subsystem}")
    print(f"  Entry Point:   {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
    print(f"\n[SECTIONS]")
    for s in pe.sections:
        name = s.Name.decode(errors='replace').strip('\x00')
        print(f"  {name:<12} VSize:{hex(s.Misc_VirtualSize)} RawSize:{hex(s.SizeOfRawData)} Entropy:{s.get_entropy():.2f}")
        if s.get_entropy() > 7.0:
            print(f"    ⚠ WYSOKA ENTROPIA — możliwe pakowanie/szyfrowanie!")
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        print(f"\n[IMPORTY DLL]")
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode(errors='replace')
            funcs = [imp.name.decode(errors='replace') if imp.name else f"ord_{imp.ordinal}"
                     for imp in entry.imports[:10]]
            print(f"  {dll_name}: {', '.join(funcs)}")
except ImportError:
    print("  [pefile niedostępny — pomiń lub zainstaluj: pip3 install pefile]")
except Exception as e:
    print(f"  [Błąd analizy PE: {e}]")
PYEOF
        python3 - "$f" 2>/dev/null <<'PYEOF' || true
import sys
try:
    import pefile
    pe = pefile.PE(sys.argv[1])
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors='replace')
            for imp in entry.imports:
                fname = imp.name.decode(errors='replace') if imp.name else ""
                if any(kw in fname.lower() for kw in ['virtualalloc','writeprocess','createremote',
                    'loadlibrary','getprocaddr','urldownload','winhttp','winexec','shellexec']):
                    print(f"  [PODEJRZANE IMPORTY] {dll} -> {fname}")
except: pass
PYEOF
    fi

    # Sprawdź packer UPX
    if command -v upx &>/dev/null; then
        log "Sprawdzanie pakera UPX:"
        if upx -t "$f" >> "$REPORT_TXT" 2>&1; then
            log_warn "Plik spakowany UPX — utrudnia analizę statyczną"
            read -r -p "$(echo -e "  ${YELLOW}Rozpakować UPX do katalogu sandbox? [t/N]${RESET} ")" upx_confirm
            if [[ "$upx_confirm" =~ ^[tTyY]$ ]]; then
                cp "$f" "$SANDBOX_DIR/unpacked_$(basename "$f")"
                upx -d "$SANDBOX_DIR/unpacked_$(basename "$f")" >> "$REPORT_TXT" 2>&1 && \
                    log_ok "Rozpakowano do: $SANDBOX_DIR/unpacked_$(basename "$f")" || \
                    log_err "Nie udało się rozpakować"
            fi
        else
            log_ok "Plik nie jest spakowany UPX"
        fi
    fi
}

# ════════════════════════════════════════════════════════════════
# MODUŁ 4 — URUCHOMIENIE W WINE (Windows .exe/.dll)
# ════════════════════════════════════════════════════════════════

run_windows_in_wine() {
    local f="$1"
    [[ "$FILE_IS_WINDOWS" != "true" ]] && return
    [[ ! -f "$f" ]] && return

    section "URUCHOMIENIE WINDOWS W WINE (SANDBOX)"

    if ! command -v wine &>/dev/null; then
        log_warn "Wine nie zainstalowany — pomiń tę sekcję"
        log_warn "Zainstaluj: brew install --cask wine-stable"
        return
    fi

    local wine_ver
    wine_ver=$(wine --version 2>/dev/null || echo "nieznana")
    log_ok "Wine: $wine_ver"

    echo ""
    echo -e "${RED}${BOLD}╔═══════════════════════════════════════════════════════╗"
    echo -e "║  ⚠️  OSTRZEŻENIE — URUCHAMIASZ PLIK WINDOWS W WINE   ║"
    echo -e "║                                                       ║"
    echo -e "║  Sandbox ogranicza: sieć, zapis poza /tmp             ║"
    echo -e "║  Timeout: ${WINE_TIMEOUT}s ($(( WINE_TIMEOUT/60 )) minut)                       ║"
    echo -e "║  Środowisko Wine jest izolowane od systemu            ║"
    echo -e "║                                                       ║"
    echo -e "║  Nie ma 100% gwarancji izolacji dla złośl. kodu!     ║"
    echo -e "╚═══════════════════════════════════════════════════════╝${RESET}"
    echo ""

    read -r -p "$(echo -e "${BOLD}Uruchomić .exe w Wine? [t/N]${RESET} ")" wine_confirm
    [[ ! "$wine_confirm" =~ ^[tTyY]$ ]] && { log "Pominięto uruchomienie Wine"; return; }

    # Przygotuj izolowany WINEPREFIX
    export WINEPREFIX="$SANDBOX_DIR/wine_prefix"
    export WINEDEBUG="warn+heap,err+all"
    export WINEARCH="win64"

    mkdir -p "$WINEPREFIX"

    local wine_copy="$SANDBOX_DIR/target_$(basename "$f")"
    cp "$f" "$wine_copy"

    local wine_stdout="$SANDBOX_DIR/wine_stdout.txt"
    local wine_stderr="$SANDBOX_DIR/wine_stderr.txt"
    local wine_debug="$SANDBOX_DIR/wine_debug.txt"

    log "Inicjalizacja Wine (WINEPREFIX=$WINEPREFIX)..."
    start_spinner "Inicjalizacja środowiska Wine..."
    WINEDEBUG=-all wineboot --init >> "$REPORT_TXT" 2>&1 || true
    stop_spinner

    log "Uruchamianie pliku: $(basename "$f")"
    log "Timeout: ${WINE_TIMEOUT}s"
    log "Sandbox: $WINE_PROFILE"
    echo ""

    # Monitor systemu plików (co Wine próbuje zapisać/czytać)
    local monitor_out="$SANDBOX_DIR/fs_monitor.txt"

    # Uruchom Wine przez sandbox-exec z timeoutem
    log "Monitorowanie aktywności..."
    if timeout "$WINE_TIMEOUT" sandbox-exec -f "$WINE_PROFILE" \
        /usr/bin/env \
            WINEPREFIX="$WINEPREFIX" \
            WINEDEBUG="warn+heap,warn+loaddll,err+all,warn+reg,warn+file" \
            WINEARCH="$WINEARCH" \
            HOME="$SANDBOX_DIR" \
            PATH="/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin" \
        wine "$wine_copy" \
        > "$wine_stdout" 2> "$wine_stderr"; then
        log_ok "Proces Wine zakończył się normalnie"
    else
        local ec=$?
        if [[ $ec -eq 124 ]]; then
            log_warn "Timeout — Wine działał ${WINE_TIMEOUT}s ($(( WINE_TIMEOUT/60 )) min)"
        else
            log_warn "Wine zakończył się z kodem: $ec"
        fi
    fi

    # Analiza wyjścia Wine
    if [[ -s "$wine_stdout" ]]; then
        log "=== Stdout Wine (pierwsze 100 linii) ==="
        head -100 "$wine_stdout" | tee -a "$REPORT_TXT"
    fi

    if [[ -s "$wine_stderr" ]]; then
        log_warn "=== Stderr / Debug Wine (istotne wpisy) ==="
        # Filtruj tylko istotne błędy
        grep -iE "err:|fixme:|warn:reg|warn:file|loaddll|CreateProcess|ShellExecute|URLDownload|WinExec" \
            "$wine_stderr" | head -100 | tee -a "$REPORT_TXT" || true
    fi

    # Sprawdź co zostało zapisane w WINEPREFIX (nowe pliki)
    log "Pliki utworzone przez aplikację w WINEPREFIX:"
    find "$WINEPREFIX" -newer "$wine_copy" -type f 2>/dev/null | head -30 | tee -a "$REPORT_TXT" || true

    # Sprawdź modyfikacje rejestru Wine
    log "Modyfikacje rejestru Wine (NTUSER.DAT, SYSTEM.reg):"
    find "$WINEPREFIX" -name "*.reg" -newer "$wine_copy" 2>/dev/null | \
        while read -r reg; do
            log_warn "Zmieniony rejestr: $reg"
        done

    # Naruszenia sandbox z logów systemowych
    log "Naruszenia piaskownicy (sandboxd):"
    log2 show --predicate 'process == "sandboxd"' --last 2m 2>/dev/null \
        | grep -iE "deny|violation|wine" | tail -30 | tee -a "$REPORT_TXT" \
        || log "  (brak dostępu do logów systemowych)"
}

# ════════════════════════════════════════════════════════════════
# MODUŁ 5 — ANALIZA MAKR VBA (Office)
# ════════════════════════════════════════════════════════════════

analyze_office_macros() {
    local f="$1"
    [[ "$FILE_IS_OFFICE" != "true" ]] && return

    section "ANALIZA MAKR VBA / OFFICE"

    if command -v olevba &>/dev/null; then
        log "Skanowanie makr VBA przez oletools..."
        olevba --decode "$f" 2>/dev/null | tee -a "$REPORT_TXT" | head -100 || \
            log_warn "olevba nie mogło przeanalizować pliku"

        log "Wyodrębnianie IOC z makr:"
        olevba "$f" 2>/dev/null | grep -iE \
            "Shell|AutoOpen|Auto_Open|Document_Open|Workbook_Open|\
            WScript|CreateObject|URLDownload|PowerShell|cmd.exe|\
            http|ftp|base64|Chr\(|Shell\(" | \
            head -40 | tee -a "$REPORT_TXT" || true
    else
        log_warn "oletools nie zainstalowane — pomiń analizę VBA"
        log_warn "Zainstaluj: pip3 install oletools"
    fi
}

# ════════════════════════════════════════════════════════════════
# MODUŁ 6 — SKANOWANIE YARA
# ════════════════════════════════════════════════════════════════

analyze_yara() {
    section "SKANOWANIE YARA"

    if ! command -v yara &>/dev/null; then
        log_warn "YARA nie zainstalowane — pomiń"
        return
    fi

    local f="$1"
    local yara_rules="$SANDBOX_DIR/rules.yar"

    # Wbudowane reguły YARA (przykładowe — w produkcji użyj YARA-Rules lub Malpedia)
    cat > "$yara_rules" <<'YARAEOF'
rule SuspiciousShellCommands {
    meta: description = "Podejrzane polecenia powłoki"
    strings:
        $s1 = "curl" nocase
        $s2 = "wget" nocase
        $s3 = "base64 -d" nocase
        $s4 = "eval $(" nocase
        $s5 = "chmod +x" nocase
        $s6 = "/tmp/" nocase
        $s7 = "LaunchAgent" nocase
        $s8 = "LaunchDaemon" nocase
    condition: 3 of them
}

rule WindowsMalwarePatterns {
    meta: description = "Wzorce złośliwego kodu Windows"
    strings:
        $inject1 = "VirtualAllocEx" nocase
        $inject2 = "WriteProcessMemory" nocase
        $inject3 = "CreateRemoteThread" nocase
        $inject4 = "SetWindowsHookEx" nocase
        $download1 = "URLDownloadToFile" nocase
        $download2 = "WinHttpOpen" nocase
        $ransom1 = "CryptEncrypt" nocase
        $ransom2 = "CryptGenRandom" nocase
        $ransom3 = "ransom" nocase
        $keylog1 = "GetAsyncKeyState" nocase
        $keylog2 = "SetWindowsHookEx" nocase
    condition: 2 of them
}

rule AntiDebugAntiVM {
    meta: description = "Techniki anty-debugowania i anty-VM"
    strings:
        $ad1 = "IsDebuggerPresent" nocase
        $ad2 = "CheckRemoteDebugger" nocase
        $vm1 = "VBoxGuest" nocase
        $vm2 = "VMware" nocase
        $vm3 = "QEMU" nocase
        $vm4 = "Parallels" nocase
        $vm5 = "VirtualBox" nocase
    condition: 1 of ($ad*) or 2 of ($vm*)
}

rule SuspiciousNetworkActivity {
    meta: description = "Wskaźniki aktywności sieciowej C2"
    strings:
        $tor = ".onion" nocase
        $c2_1 = "reverse_shell" nocase
        $c2_2 = "bind_shell" nocase
        $c2_3 = "meterpreter" nocase
        $c2_4 = "nc -e" nocase
        $c2_5 = "bash -i >& /dev/tcp" nocase
    condition: 1 of them
}

rule MacOSPersistence {
    meta: description = "Mechanizmy persistence na macOS"
    strings:
        $p1 = "com.apple.launchd" nocase
        $p2 = "~/Library/LaunchAgents" nocase
        $p3 = "/Library/LaunchDaemons" nocase
        $p4 = "osascript" nocase
        $p5 = "defaults write" nocase
        $p6 = "crontab -l" nocase
    condition: 2 of them
}

rule EncodedPayload {
    meta: description = "Zakodowany/zaszyfrowany payload"
    strings:
        $b64_1 = /[A-Za-z0-9+\/]{100,}={0,2}/
        $hex1 = /\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){15,}/
        $xor1 = "xor" nocase
    condition: any of them
}
YARAEOF

    log "Uruchamianie YARA z regułami..."
    local yara_results
    if yara_results=$(yara "$yara_rules" "$f" 2>&1); then
        if [[ -n "$yara_results" ]]; then
            log_warn "YARA wykryła dopasowania:"
            echo "$yara_results" | tee -a "$REPORT_TXT"
        else
            log_ok "Brak dopasowań YARA"
        fi
    else
        log_warn "YARA: błąd skanowania (może być normalny dla niektórych typów plików)"
    fi
}

# ════════════════════════════════════════════════════════════════
# MODUŁ 7 — CLAMAV
# ════════════════════════════════════════════════════════════════

analyze_clamav() {
    section "SKANOWANIE ANTYWIRUSOWE (ClamAV)"

    if ! command -v clamscan &>/dev/null; then
        log_warn "ClamAV nie zainstalowany — pomiń"
        log_warn "Zainstaluj: brew install clamav && freshclam"
        return
    fi

    local f="$1"
    log "Skanowanie ClamAV..."
    local clam_ver
    clam_ver=$(clamscan --version 2>/dev/null | head -1)
    log "Wersja: $clam_ver"

    start_spinner "Skanowanie ClamAV..."
    local clam_out
    if clam_out=$(clamscan --alert-encrypted --alert-encrypted-archive \
        --alert-macros --heuristic-alerts \
        "$f" 2>&1); then
        stop_spinner
        log_ok "ClamAV: CZYSTY"
        echo "$clam_out" >> "$REPORT_TXT"
    else
        stop_spinner
        log_err "ClamAV: WYKRYTO ZAGROŻENIE!"
        echo "$clam_out" | tee -a "$REPORT_TXT"
    fi
}

# ════════════════════════════════════════════════════════════════
# MODUŁ 8 — WERYFIKACJA PODPISU (macOS)
# ════════════════════════════════════════════════════════════════

analyze_signature() {
    section "PODPIS KODU I KWARANTANNA"
    local f="$1"

    # Tylko dla plików macOS
    if [[ "$FILE_IS_WINDOWS" == "true" ]]; then
        log "Plik Windows — Gatekeeper/codesign nie dotyczy"
        log "Sprawdź podpis Authenticode (signtool) w środowisku Windows"
        # Można sprawdzić przez osslsigncode jeśli dostępny
        if command -v osslsigncode &>/dev/null; then
            osslsigncode verify "$f" 2>&1 | tee -a "$REPORT_TXT" || true
        fi
        return
    fi

    log "Gatekeeper (spctl):"
    spctl --assess --type exec "$f" 2>&1 | tee -a "$REPORT_TXT" || true

    log "Podpis cyfrowy (codesign):"
    codesign -dv --verbose=4 "$f" 2>&1 | tee -a "$REPORT_TXT" || true

    log "Weryfikacja podpisu:"
    codesign --verify --verbose=2 "$f" 2>&1 | tee -a "$REPORT_TXT" && \
        log_ok "Podpis prawidłowy" || log_warn "Brak lub nieprawidłowy podpis"

    log "Atrybut kwarantanny:"
    local qattr
    qattr=$(xattr -p com.apple.quarantine "$f" 2>/dev/null || echo "brak")
    [[ "$qattr" == "brak" ]] && \
        log_warn "Brak com.apple.quarantine — plik mógł ominąć Gatekeeper" || \
        log_ok "Quarantine: $qattr"

    log "Wszystkie atrybuty rozszerzone (xattr):"
    xattr -l "$f" 2>/dev/null | tee -a "$REPORT_TXT" || echo "  brak" | tee -a "$REPORT_TXT"
}

# ════════════════════════════════════════════════════════════════
# MODUŁ 9 — PODEJRZANE CIĄGI (IOC)
# ════════════════════════════════════════════════════════════════

analyze_strings_ioc() {
    section "WSKAŹNIKI KOMPROMITACJI (IOC) — STRINGS"
    local f="$1"

    declare -A IOC_CATEGORIES=(
        ["Sieć/URL"]="https?://[^ ]{4,}|ftp://[^ ]{4,}|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]+"
        ["Tor/Darknet"]="\.onion|socks[45]?://|torbrowser"
        ["Narzędzia ataku"]="meterpreter|cobalt.?strike|mimikatz|empire|metasploit|nc -e|ncat|socat"
        ["Persistence macOS"]="LaunchAgent|LaunchDaemon|crontab|loginitem|osascript|applescript"
        ["Persistence Win"]="HKEY_LOCAL_MACHINE|HKCU\\\\Run|SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run|schtasks|sc create"
        ["Pobieranie kodu"]="curl.*-[sSo]|wget.*-O|URLDownloadToFile|WinHttpOpen|Invoke-WebRequest|DownloadString"
        ["Kodowanie"]="base64.*decode|base64 -d|FromBase64String|certutil.*-decode"
        ["Eskalacja uprawnień"]="sudo |su -|runas|UAC|SeDebugPrivilege|token.impersonat"
        ["Anti-analiza"]="IsDebuggerPresent|VirtualBox|VMware|QEMU|Parallels|sandbox|wine|virtualenv"
        ["Crypto/Ransomware"]="ransom|bitcoin|\.onion|CryptEncrypt|CryptGenRandom|wallet|decrypt.*files"
        ["Keylogger/Surveillance"]="GetAsyncKeyState|SetWindowsHookEx|screencapture|keylog|screenshot"
        ["Niszczenie danych"]="rm -rf|shred|format|cipher /w|wipe"
    )

    local total_hits=0
    for category in "${!IOC_CATEGORIES[@]}"; do
        local pattern="${IOC_CATEGORIES[$category]}"
        local matches
        matches=$(strings -n 5 "$f" 2>/dev/null | grep -iE "$pattern" | sort -u | head -10 || true)
        if [[ -n "$matches" ]]; then
            echo -e "\n  ${RED}[IOC]${RESET} ${BOLD}$category${RESET}"
            echo "  [IOC] $category" >> "$REPORT_TXT"
            while IFS= read -r line; do
                echo -e "    ${YELLOW}→${RESET} $line"
                echo "    → $line" >> "$REPORT_TXT"
            done <<< "$matches"
            ((total_hits++)) || true
        fi
    done

    echo ""
    if [[ $total_hits -eq 0 ]]; then
        log_ok "Nie wykryto podejrzanych wzorców IOC"
    else
        log_warn "Wykryto $total_hits kategorii IOC — szczegóły powyżej"
    fi
}

# ════════════════════════════════════════════════════════════════
# MODUŁ 10 — URUCHOMIENIE macOS W SANDBOX
# ════════════════════════════════════════════════════════════════

run_macos_in_sandbox() {
    local f="$1"

    # Tylko dla plików macOS lub skryptów
    local file_type
    file_type=$(file -b "$f")
    local runnable=false
    echo "$file_type" | grep -qiE "mach-o|shell script|python|executable" && runnable=true
    [[ "$FILE_IS_SCRIPT" == "true" ]] && runnable=true

    [[ "$runnable" != "true" ]] && return
    [[ "$FILE_IS_WINDOWS" == "true" ]] && return  # Windows obsługiwany przez Wine

    section "URUCHOMIENIE macOS W SANDBOX"

    echo -e "${YELLOW}${BOLD}Ograniczenia sandbox:${RESET}"
    echo "  • Brak dostępu do sieci (TCP/UDP/Unix)"
    echo "  • Zapis tylko do /tmp/sandbox_analysis"
    echo "  • Brak dostępu do Keychain"
    echo "  • Brak IPC / shared memory"
    echo "  • Timeout: ${TIMEOUT_SECS}s ($(( TIMEOUT_SECS/60 )) min)"
    echo ""

    read -r -p "$(echo -e "${BOLD}Uruchomić w sandboxie? [t/N]${RESET} ")" confirm
    [[ ! "$confirm" =~ ^[tTyY]$ ]] && { log "Pominięto wykonanie"; return; }

    local sandbox_copy="$SANDBOX_DIR/exec_$(basename "$f")"
    cp "$f" "$sandbox_copy"
    chmod +x "$sandbox_copy" 2>/dev/null || true

    local out="$SANDBOX_DIR/exec_stdout.txt"
    local err_f="$SANDBOX_DIR/exec_stderr.txt"

    log "Uruchamianie przez sandbox-exec (timeout: ${TIMEOUT_SECS}s)..."

    if timeout "$TIMEOUT_SECS" sandbox-exec -f "$PROFILE_FILE" \
        /usr/bin/env -i \
            HOME="$SANDBOX_DIR" \
            PATH="/usr/bin:/bin:/usr/local/bin" \
            TMPDIR="$SANDBOX_DIR" \
        "$sandbox_copy" > "$out" 2> "$err_f"; then
        log_ok "Proces zakończył się normalnie"
    else
        local ec=$?
        [[ $ec -eq 124 ]] && log_warn "Timeout — $(( TIMEOUT_SECS/60 )) minuty upłynęły" || \
                              log_warn "Kod wyjścia: $ec"
    fi

    [[ -s "$out" ]] && { log "Stdout:"; head -100 "$out" | tee -a "$REPORT_TXT"; }
    [[ -s "$err_f" ]] && { log_warn "Stderr:"; head -50 "$err_f" | tee -a "$REPORT_TXT"; }

    log "Naruszenia sandbox:"
    log2 show --predicate 'process == "sandboxd"' --last 2m 2>/dev/null \
        | grep -i "deny" | tail -30 | tee -a "$REPORT_TXT" \
        || log "  (brak dostępu do logów lub brak naruszeń)"
}

# ════════════════════════════════════════════════════════════════
# MODUŁ 11 — OCENA RYZYKA
# ════════════════════════════════════════════════════════════════

risk_assessment() {
    section "OCENA RYZYKA"
    local f="$1"
    local score=0
    declare -a reasons=()

    # ClamAV wykrycie
    if command -v clamscan &>/dev/null; then
        if ! clamscan -q "$f" 2>/dev/null; then
            ((score+=80)) || true
            reasons+=("🔴 ClamAV: wykryto złośliwe oprogramowanie")
        fi
    fi

    # YARA dopasowania
    if command -v yara &>/dev/null && [[ -f "$SANDBOX_DIR/rules.yar" ]]; then
        local yara_hits
        yara_hits=$(yara "$SANDBOX_DIR/rules.yar" "$f" 2>/dev/null | wc -l | tr -d ' ')
        if [[ $yara_hits -gt 0 ]]; then
            score=$((score + yara_hits * 15))
            reasons+=("🟠 YARA: $yara_hits dopasowań reguł")
        fi
    fi

    # Binarny bez podpisu
    if [[ "$FILE_IS_MACHO" == "true" ]] && ! codesign -v "$f" &>/dev/null 2>&1; then
        ((score+=25)) || true
        reasons+=("🟠 Binarny macOS bez ważnego podpisu codesign")
    fi

    # Skrypt z pobieraniem
    if [[ "$FILE_IS_SCRIPT" == "true" ]]; then
        ((score+=10)) || true; reasons+=("🟡 Plik skryptu powłoki")
        strings "$f" 2>/dev/null | grep -qiE "curl|wget|URLDownload|Invoke-WebRequest" && \
            { ((score+=20)) || true; reasons+=("🟠 Skrypt pobiera zewnętrzny kod"); }
        strings "$f" 2>/dev/null | grep -qiE "base64 -d|base64.*decode|FromBase64" && \
            { ((score+=25)) || true; reasons+=("🟠 Dekodowanie base64 w skrypcie"); }
    fi

    # Persistence
    strings "$f" 2>/dev/null | grep -qiE "LaunchAgent|LaunchDaemon|HKCU.Run|schtasks|crontab" && \
        { ((score+=35)) || true; reasons+=("🔴 Wskaźniki mechanizmu persistence"); }

    # C2 / Sieć
    strings "$f" 2>/dev/null | grep -qiE "\.onion|reverse.shell|meterpreter|cobalt.strike" && \
        { ((score+=50)) || true; reasons+=("🔴 Wskaźniki C2 / Reverse Shell / Tor"); }

    # Anti-debug
    strings "$f" 2>/dev/null | grep -qiE "IsDebuggerPresent|CheckRemoteDebug|VirtualBox|VMware" && \
        { ((score+=30)) || true; reasons+=("🟠 Techniki anty-debugowania / anty-VM"); }

    # Brak kwarantanny (macOS)
    if [[ "$FILE_IS_WINDOWS" != "true" ]]; then
        ! xattr "$f" 2>/dev/null | grep -q "quarantine" && \
            { ((score+=15)) || true; reasons+=("🟡 Brak atrybutu kwarantanny macOS"); }
    fi

    # Packer UPX
    if command -v upx &>/dev/null && upx -t "$f" &>/dev/null 2>&1; then
        ((score+=20)) || true
        reasons+=("🟠 Plik spakowany UPX — utrudnia analizę")
    fi

    # Cap score
    [[ $score -gt 100 ]] && score=100

    echo ""
    echo -e "┌─────────────────────────────────────────┐"
    printf  "│  Wynik ryzyka: ${BOLD}%3d / 100${RESET}" "$score"

    if   [[ $score -ge 70 ]]; then printf "   ${RED}${BOLD}WYSOKIE${RESET}   │\n"
    elif [[ $score -ge 40 ]]; then printf "   ${YELLOW}${BOLD}ŚREDNIE${RESET}   │\n"
    elif [[ $score -ge 20 ]]; then printf "   ${YELLOW}NISKIE-MED${RESET} │\n"
    else                            printf "   ${GREEN}${BOLD}NISKIE${RESET}    │\n"
    fi

    echo "└─────────────────────────────────────────┘"

    echo "Wynik ryzyka: $score/100" >> "$REPORT_TXT"
    echo ""
    for r in "${reasons[@]}"; do
        echo -e "  $r"
        echo "  $r" >> "$REPORT_TXT"
    done

    # Rekomendacje
    echo ""
    echo -e "${BOLD}Rekomendacje:${RESET}"
    if [[ $score -ge 70 ]]; then
        echo -e "  ${RED}• NIE otwieraj i NIE uruchamiaj tego pliku w normalnym systemie${RESET}"
        echo -e "  ${RED}• Prześlij do VirusTotal: https://virustotal.com${RESET}"
        echo -e "  ${RED}• Zgłoś do administratora / działu bezpieczeństwa${RESET}"
        echo -e "  ${RED}• Rozważ przeskanowanie systemu pod kątem infekcji${RESET}"
    elif [[ $score -ge 40 ]]; then
        echo -e "  ${YELLOW}• Zachowaj ostrożność — sprawdź źródło pliku${RESET}"
        echo -e "  ${YELLOW}• Zweryfikuj hash na: https://virustotal.com${RESET}"
        echo -e "  ${YELLOW}• Nie otwieraj jeśli nie ufasz źródłu${RESET}"
    else
        echo -e "  ${GREEN}• Plik wydaje się bezpieczny, ale zachowaj ostrożność${RESET}"
        echo -e "  ${GREEN}• Zawsze sprawdzaj źródło przed uruchomieniem${RESET}"
    fi

    local sha256
    sha256=$(shasum -a 256 "$f" | awk '{print $1}')
    echo ""
    echo -e "  ${DIM}VirusTotal: https://www.virustotal.com/gui/file/$sha256${RESET}"
}

# ════════════════════════════════════════════════════════════════
# RAPORT HTML
# ════════════════════════════════════════════════════════════════

generate_html_report() {
    local f="$1"
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')

    cat > "$REPORT_HTML" <<HTMLEOF
<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="UTF-8">
<title>Sandbox Analysis Report</title>
<style>
  body { font-family: 'Courier New', monospace; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }
  h1 { color: #58a6ff; border-bottom: 2px solid #30363d; padding-bottom: 10px; }
  h2 { color: #79c0ff; margin-top: 30px; }
  .ok    { color: #3fb950; }
  .warn  { color: #e3b341; }
  .err   { color: #f85149; }
  .info  { color: #8b949e; }
  pre { background: #161b22; padding: 15px; border-radius: 6px; overflow-x: auto; border: 1px solid #30363d; white-space: pre-wrap; }
  .meta { background: #161b22; padding: 15px; border-radius: 6px; margin: 10px 0; }
  .score-box { display: inline-block; padding: 10px 20px; border-radius: 8px; font-size: 1.4em; font-weight: bold; margin: 10px 0; }
  .high { background: #3d1c1c; color: #f85149; border: 2px solid #f85149; }
  .med  { background: #3d2f0e; color: #e3b341; border: 2px solid #e3b341; }
  .low  { background: #0d2818; color: #3fb950; border: 2px solid #3fb950; }
  footer { color: #8b949e; font-size: 0.8em; margin-top: 40px; border-top: 1px solid #30363d; padding-top: 10px; }
</style>
</head>
<body>
<h1>🔬 Sandbox Analysis Report</h1>
<div class="meta">
  <strong>Plik:</strong> $(basename "$f")<br>
  <strong>Data:</strong> $ts<br>
  <strong>SHA256:</strong> $(shasum -a 256 "$f" | awk '{print $1}')<br>
  <strong>Rozmiar:</strong> $(du -sh "$f" | cut -f1)<br>
  <strong>Typ:</strong> $(file -b "$f")<br>
</div>
<h2>📋 Pełny Raport</h2>
<pre>$(cat "$REPORT_TXT" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')</pre>
<footer>Wygenerowano przez sandbox_analyzer_v2.sh v${VERSION} na macOS</footer>
</body>
</html>
HTMLEOF
    log_ok "Raport HTML: $REPORT_HTML"
}

# ════════════════════════════════════════════════════════════════
# CLEANUP
# ════════════════════════════════════════════════════════════════

cleanup() {
    stop_spinner
    if [[ "${KEEP_SANDBOX:-false}" != "true" ]]; then
        rm -rf "$SANDBOX_DIR"
    else
        log "Sandbox zachowany (KEEP_SANDBOX=true): $SANDBOX_DIR"
    fi
}

# ════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════

main() {
    print_banner

    # Argumenty
    local target_file=""
    local no_exec=false
    local skip_install=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --no-exec)       no_exec=true ;;
            --skip-install)  skip_install=true ;;
            --keep-sandbox)  export KEEP_SANDBOX=true ;;
            --timeout)       shift; TIMEOUT_SECS="$1"; WINE_TIMEOUT=$(( TIMEOUT_SECS * 2 )) ;;
            --help|-h)
                echo "Użycie: $0 <plik> [opcje]"
                echo ""
                echo "  --no-exec        Nie uruchamiaj pliku w sandboxie"
                echo "  --skip-install   Pomiń sprawdzanie/instalację narzędzi"
                echo "  --keep-sandbox   Zachowaj katalog sandbox po zakończeniu"
                echo "  --timeout <s>    Ustaw timeout (domyślnie: ${TIMEOUT_SECS}s)"
                echo "  LOG_LEVEL=DEBUG  Włącz debugowanie"
                exit 0 ;;
            *)  target_file="$1" ;;
        esac
        shift
    done

    if [[ -z "$target_file" ]]; then
        echo -e "${RED}Błąd: podaj ścieżkę do pliku${RESET}"
        echo "Użycie: $0 <plik> [--no-exec] [--skip-install] [--timeout 300]"
        exit 1
    fi

    [[ ! -f "$target_file" ]] && { echo -e "${RED}Plik nie istnieje: $target_file${RESET}"; exit 1; }

    local size_mb
    size_mb=$(du -sm "$target_file" | awk '{print $1}')
    if [[ $size_mb -gt $MAX_FILE_SIZE_MB ]]; then
        echo -e "${RED}Plik za duży: ${size_mb}MB (limit: ${MAX_FILE_SIZE_MB}MB)${RESET}"
        exit 1
    fi

    # Przygotowanie środowiska
    mkdir -p "$SANDBOX_DIR"
    trap cleanup EXIT INT TERM

    {
        echo "════════════════════════════════════════"
        echo "  SANDBOX ANALYSIS REPORT v$VERSION"
        echo "  $(date)"
        echo "  Plik: $target_file"
        echo "════════════════════════════════════════"
    } > "$REPORT_TXT"

    # Ustawienia
    log "Timeout macOS: ${TIMEOUT_SECS}s ($(( TIMEOUT_SECS/60 ))min)"
    log "Timeout Wine:  ${WINE_TIMEOUT}s ($(( WINE_TIMEOUT/60 ))min)"

    # 0. Instalacja narzędzi
    [[ "$skip_install" == "false" ]] && setup_tools

    # Tworzenie profili sandbox
    create_sandbox_profiles

    # 1–11. Analiza
    analyze_metadata       "$target_file"
    analyze_magic          "$target_file"
    analyze_strings_ioc    "$target_file"
    analyze_signature      "$target_file"
    analyze_pe_windows     "$target_file"
    analyze_office_macros  "$target_file"
    analyze_yara           "$target_file"
    analyze_clamav         "$target_file"

    if [[ "$no_exec" == "false" ]]; then
        if [[ "$FILE_IS_WINDOWS" == "true" ]]; then
            run_windows_in_wine   "$target_file"
        else
            run_macos_in_sandbox  "$target_file"
        fi
    fi

    risk_assessment "$target_file"
    generate_html_report "$target_file"

    # Zapisz raporty
    local base_name
    base_name="sandbox_report_$(basename "$target_file")_$(date +%Y%m%d_%H%M%S)"
    local final_txt
    local final_html
    final_txt="$(pwd)/${base_name}.txt"
    final_html="$(pwd)/${base_name}.html"

    cp "$REPORT_TXT"  "$final_txt"
    cp "$REPORT_HTML" "$final_html"

    echo ""
    echo -e "${GREEN}${BOLD}╔═══════════════════════════════════╗"
    echo -e "║  Analiza zakończona!              ║"
    echo -e "╚═══════════════════════════════════╝${RESET}"
    echo -e "  📄 Raport TXT:  ${BOLD}$final_txt${RESET}"
    echo -e "  🌐 Raport HTML: ${BOLD}$final_html${RESET}"
    echo ""
    echo -e "  Otwórz raport HTML:"
    echo -e "  ${DIM}open '$final_html'${RESET}"
}

main "$@"
