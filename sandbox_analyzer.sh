#!/bin/bash
# ============================================================
#  sandbox_analyzer.sh — Analiza podejrzanych plików na macOS
#  Autor: skrypt demonstracyjny (bezpieczne środowisko)
#  Wymaga: macOS 10.15+, narzędzi: sandbox-exec, file, strings,
#           codesign, spctl, mdls, lsof (wbudowane w macOS)
# ============================================================

set -euo pipefail

# ─── Kolory terminala ────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ─── Konfiguracja ────────────────────────────────────────────
SANDBOX_DIR="/tmp/sandbox_analysis_$$"
REPORT_FILE="$SANDBOX_DIR/report.txt"
PROFILE_FILE="$SANDBOX_DIR/sandbox.sb"
TIMEOUT_SECS=30          # Limit czasu wykonania w sandboxie
MAX_FILE_SIZE_MB=100     # Maksymalny rozmiar analizowanego pliku

# ─── Profil sandbox-exec (Apple Sandbox Profile Language) ────
# Blokuje: sieć, zapis do systemu, dostęp do prywatnych katalogów
create_sandbox_profile() {
cat > "$PROFILE_FILE" <<'SBPROFILE'
(version 1)

;; Domyślnie odmawiaj wszystkiego
(deny default)

;; Zezwól na odczyt tylko wybranych lokalizacji
(allow file-read*
    (literal "/")
    (literal "/usr")
    (subpath "/usr/lib")
    (subpath "/usr/share")
    (subpath "/System/Library/Frameworks")
    (subpath "/System/Library/PrivateFrameworks")
    (subpath "/Library/Frameworks")
    (literal "/dev/null")
    (literal "/dev/random")
    (literal "/dev/urandom")
    (subpath "/tmp/sandbox_analysis")
)

;; Zezwól na zapis TYLKO do katalogu sandbox
(allow file-write*
    (subpath "/tmp/sandbox_analysis")
)

;; Zezwól na podstawowe operacje procesów (fork, exec)
(allow process-fork)
(allow process-exec)

;; Blokuj całą sieć (TCP, UDP, Unix sockets poza tmp)
(deny network*)

;; Blokuj dostęp do kluczy systemowych (Keychain)
(deny mach-lookup
    (global-name "com.apple.SecurityServer")
    (global-name "com.apple.securityd")
)

;; Blokuj IPC i shared memory
(deny ipc-posix*)
(deny system-socket)

;; Zezwól na sygnały wewnątrz procesu
(allow signal (target self))
SBPROFILE
}

# ─── Banner ──────────────────────────────────────────────────
print_banner() {
echo -e "${CYAN}${BOLD}"
cat <<'BANNER'
  ┌─────────────────────────────────────────────┐
  │   🔬 macOS Sandbox File Analyzer            │
  │   Bezpieczna analiza podejrzanych plików    │
  └─────────────────────────────────────────────┘
BANNER
echo -e "${RESET}"
}

# ─── Logowanie ───────────────────────────────────────────────
log()      { echo -e "${BOLD}[•]${RESET} $*"; echo "[INFO] $*" >> "$REPORT_FILE"; }
log_ok()   { echo -e "${GREEN}[✓]${RESET} $*"; echo "[OK]   $*" >> "$REPORT_FILE"; }
log_warn() { echo -e "${YELLOW}[!]${RESET} $*"; echo "[WARN] $*" >> "$REPORT_FILE"; }
log_err()  { echo -e "${RED}[✗]${RESET} $*"; echo "[ERR]  $*" >> "$REPORT_FILE"; }
section()  { echo -e "\n${CYAN}${BOLD}═══ $* ═══${RESET}"; echo -e "\n=== $* ===" >> "$REPORT_FILE"; }

# ─── Sprawdzenie zależności ───────────────────────────────────
check_deps() {
    local missing=0
    for cmd in file strings codesign spctl mdls xxd; do
        if ! command -v "$cmd" &>/dev/null; then
            log_warn "Brak narzędzia: $cmd"
            ((missing++)) || true
        fi
    done
    [[ $missing -gt 0 ]] && log_warn "$missing narzędzi niedostępnych — niektóre testy zostaną pominięte"
}

# ─── 1. Metadane pliku ────────────────────────────────────────
analyze_metadata() {
    section "METADANE PLIKU"
    local f="$1"

    log "Ścieżka:     $f"
    log "Rozmiar:     $(du -sh "$f" | cut -f1)"
    log "Typ (file):  $(file -b "$f")"
    log "Właściciel:  $(ls -la "$f" | awk '{print $3, $4}')"
    log "Uprawnienia: $(ls -la "$f" | awk '{print $1}')"
    log "Modyfikacja: $(GetFileInfo -m "$f" 2>/dev/null || stat -f "%Sm" "$f")"

    # Hasha kryptograficzne
    log "MD5:    $(md5 -q "$f" 2>/dev/null || md5sum "$f" | awk '{print $1}')"
    log "SHA256: $(shasum -a 256 "$f" | awk '{print $1}')"
}

# ─── 2. Analiza nagłówków magic bytes ────────────────────────
analyze_magic() {
    section "MAGIC BYTES / NAGŁÓWEK"
    local f="$1"
    local header
    header=$(xxd "$f" 2>/dev/null | head -4 || hexdump -C "$f" 2>/dev/null | head -4)
    echo "$header"
    echo "$header" >> "$REPORT_FILE"

    # Sprawdź ukryte rozszerzenie (rozbieżność między nazwą a typem)
    local ext="${f##*.}"
    local detected
    detected=$(file -b --mime-type "$f" 2>/dev/null || echo "nieznany")
    log "Deklarowane rozszerzenie: .$ext"
    log "Wykryty MIME:             $detected"

    case "$detected" in
        application/x-mach-binary) log_warn "Plik wykonywalny Mach-O (binarny macOS)" ;;
        application/zip)           log_warn "Archiwum ZIP — może zawierać ukryte pliki" ;;
        text/x-shellscript)        log_warn "Skrypt powłoki — sprawdź zawartość" ;;
        application/x-sh)         log_warn "Skrypt powłoki" ;;
        application/pdf)          log_ok  "PDF — sprawdź wbudowane skrypty JS" ;;
        *)                        log "Typ: $detected" ;;
    esac
}

# ─── 3. Analiza stringów ──────────────────────────────────────
analyze_strings() {
    section "PODEJRZANE CIĄGI ZNAKÓW"
    local f="$1"

    # Wzorce IOC (Indicators of Compromise)
    local -a patterns=(
        "http[s]?://"              # URL
        "curl|wget|nc |ncat"       # Narzędzia sieciowe
        "/etc/passwd|/etc/shadow"  # Pliki systemowe
        "chmod \+x|chmod 777"      # Zmiana uprawnień
        "base64 --decode\|base64 -d" # Dekodowanie base64
        "eval\|exec\|system("      # Funkcje wykonywania kodu
        "LaunchAgent\|LaunchDaemon" # Persistence macOS
        "sudo\|su -"               # Eskalacja uprawnień
        "rm -rf\|shred"            # Niszczenie plików
        "/Library/Application Support" # Katalogi systemowe
        "osascript\|AppleScript"   # Skrypty macOS
        "Terminal\|bash\|zsh\|sh -c" # Powłoki
        "keylogger\|screenshot\|screencapture" # Surveillance
        "\.onion\|tor\|socks"      # Sieć Tor
        "crypto\|bitcoin\|wallet\|ransom" # Ransomware
    )

    local found=0
    local all_strings
    all_strings=$(strings -n 6 "$f" 2>/dev/null || true)

    for pattern in "${patterns[@]}"; do
        local matches
        matches=$(echo "$all_strings" | grep -iE "$pattern" | head -5 || true)
        if [[ -n "$matches" ]]; then
            log_warn "Wzorzec: ${BOLD}$pattern${RESET}"
            echo "$matches" | while read -r line; do
                echo -e "    ${RED}→${RESET} $line"
                echo "    → $line" >> "$REPORT_FILE"
            done
            ((found++)) || true
        fi
    done

    [[ $found -eq 0 ]] && log_ok "Nie wykryto podejrzanych ciągów" \
                       || log_warn "Wykryto $found kategorii podejrzanych wzorców"
}

# ─── 4. Weryfikacja podpisu kodu ──────────────────────────────
analyze_signature() {
    section "PODPIS KODU I KWARANTANNA"
    local f="$1"

    # Gatekeeper / spctl
    log "Weryfikacja Gatekeeper:"
    if spctl --assess --type exec "$f" 2>&1 | tee -a "$REPORT_FILE" | grep -q "accepted"; then
        log_ok "Plik zaakceptowany przez Gatekeeper"
    else
        log_warn "Gatekeeper odrzucił lub plik nie jest podpisany"
    fi

    # codesign
    log "Weryfikacja codesign:"
    if codesign -dv "$f" 2>&1 | tee -a "$REPORT_FILE" | grep -q "Identifier"; then
        log_ok "Plik ma podpis cyfrowy"
        codesign --verify --verbose=2 "$f" 2>&1 | tee -a "$REPORT_FILE" || log_warn "Podpis nieprawidłowy lub uszkodzony"
    else
        log_warn "Brak podpisu cyfrowego (unsigned binary)"
    fi

    # Quarantine xattr
    log "Atrybut kwarantanny (quarantine):"
    local qattr
    qattr=$(xattr -p com.apple.quarantine "$f" 2>/dev/null || echo "brak")
    if [[ "$qattr" == "brak" ]]; then
        log_warn "Brak atrybutu kwarantanny — plik mógł ominąć Gatekeeper"
    else
        log_ok "Atrybut kwarantanny: $qattr"
    fi

    # Wszystkie xattrs
    log "Wszystkie atrybuty rozszerzone:"
    xattr -l "$f" 2>/dev/null | tee -a "$REPORT_FILE" || echo "  brak" | tee -a "$REPORT_FILE"
}

# ─── 5. Analiza Mach-O (jeśli binarny) ───────────────────────
analyze_macho() {
    local f="$1"
    if ! file "$f" | grep -qi "mach-o\|executable"; then return; fi

    section "ANALIZA MACH-O (BINARNY)"
    log "Architektura:"
    lipo -info "$f" 2>/dev/null | tee -a "$REPORT_FILE" || true

    log "Biblioteki dynamiczne (otool -L):"
    otool -L "$f" 2>/dev/null | tee -a "$REPORT_FILE" || true

    log "Sekcje i segmenty:"
    otool -l "$f" 2>/dev/null | grep -E "sectname|segname|cmd LC_" | tee -a "$REPORT_FILE" || true

    # Sprawdź ładowanie adresów URL (hardcoded C2?)
    log "Potencjalne hardcoded URL:"
    strings "$f" 2>/dev/null | grep -E "https?://[^ ]{4,}" | head -20 | tee -a "$REPORT_FILE" || true
}

# ─── 6. Wykonanie w sandboxie ────────────────────────────────
run_in_sandbox() {
    local f="$1"
    if ! file "$f" | grep -qi "script\|shell\|python\|executable"; then
        log "Pominięto wykonanie — plik nie jest wykonywalny/skryptem"
        return
    fi

    section "WYKONANIE W SANDBOXIE (ograniczone środowisko)"
    log_warn "Uruchamianie w izolowanym sandboxie przez ${TIMEOUT_SECS}s..."
    log_warn "Sandbox blokuje: sieć, zapis poza /tmp, dostęp do Keychain"

    local sandbox_out="$SANDBOX_DIR/execution_output.txt"
    local sandbox_err="$SANDBOX_DIR/execution_error.txt"

    # Kopiuj plik do sandbox dir
    local sandbox_copy="$SANDBOX_DIR/$(basename "$f")"
    cp "$f" "$sandbox_copy"
    chmod +x "$sandbox_copy" 2>/dev/null || true

    # Uruchom przez sandbox-exec z timeoutem
    if timeout "$TIMEOUT_SECS" sandbox-exec -f "$PROFILE_FILE" \
        /usr/bin/env -i HOME="$SANDBOX_DIR" PATH="/usr/bin:/bin" \
        "$sandbox_copy" > "$sandbox_out" 2> "$sandbox_err"; then
        log_ok "Proces zakończył się normalnie"
    else
        local exit_code=$?
        if [[ $exit_code -eq 124 ]]; then
            log_warn "Timeout — proces przekroczył ${TIMEOUT_SECS}s"
        else
            log_warn "Proces zakończył się z kodem: $exit_code"
        fi
    fi

    if [[ -s "$sandbox_out" ]]; then
        log "Stdout (pierwsze 50 linii):"
        head -50 "$sandbox_out" | tee -a "$REPORT_FILE"
    fi
    if [[ -s "$sandbox_err" ]]; then
        log_warn "Stderr:"
        head -50 "$sandbox_err" | tee -a "$REPORT_FILE"
    fi

    # Sprawdź co sandbox zablokował (przez log systemowy)
    log "Sprawdzanie naruszeń sandbox w logu systemowym:"
    log2 show --predicate 'process == "sandboxd"' --last 1m 2>/dev/null \
        | grep -i "deny\|violation" | tail -20 | tee -a "$REPORT_FILE" \
        || log "  (brak danych lub brak uprawnień do logów)"
}

# ─── 7. Sprawdzenie znanych złośliwych hashów (offline) ───────
check_known_hashes() {
    section "SPRAWDZENIE HASHÓW (baza offline)"
    local f="$1"
    local sha256
    sha256=$(shasum -a 256 "$f" | awk '{print $1}')

    # Mini-baza przykładowych złośliwych hashów (demonstracyjna)
    local -A KNOWN_MALICIOUS=(
        ["44d88612fea8a8f36de82e1278abb02f"]="EICAR test file"
        ["3395856ce81f2b7382dee72602f798b642f14d6"]="EICAR SHA1"
        ["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"]="EICAR SHA256"
    )

    if [[ -v KNOWN_MALICIOUS[$sha256] ]]; then
        log_err "⚠️  ZNANY ZŁOŚLIWY HASH: ${KNOWN_MALICIOUS[$sha256]}"
    else
        log_ok "Hash $sha256 nie figuruje w lokalnej bazie"
        log "Sprawdź ręcznie: https://www.virustotal.com/gui/file/$sha256"
    fi
}

# ─── 8. Ocena ryzyka ─────────────────────────────────────────
risk_assessment() {
    section "OCENA RYZYKA"
    local f="$1"
    local score=0
    local -a reasons=()

    # Binarny bez podpisu
    if file "$f" | grep -qi "mach-o" && ! codesign -v "$f" &>/dev/null; then
        ((score+=30)) || true; reasons+=("Binarny Mach-O bez ważnego podpisu")
    fi

    # Skrypt powłoki z podejrzanymi wywołaniami
    if file "$f" | grep -qi "shell\|script"; then
        ((score+=10)) || true; reasons+=("Plik skryptu powłoki")
        if strings "$f" | grep -qiE "curl|wget|nc |base64 -d|eval"; then
            ((score+=25)) || true; reasons+=("Skrypt zawiera pobranie/dekodowanie kodu")
        fi
    fi

    # Brak atrybutu kwarantanny
    if ! xattr "$f" 2>/dev/null | grep -q "quarantine"; then
        ((score+=15)) || true; reasons+=("Brak atrybutu kwarantanny")
    fi

    # Znaki persistence
    if strings "$f" | grep -qiE "LaunchAgent|LaunchDaemon|crontab"; then
        ((score+=35)) || true; reasons+=("Potencjalny mechanizm persistence")
    fi

    # Podejrzane sieć
    if strings "$f" | grep -qiE "\.onion|socks5?://|reverse.shell|bind.*shell"; then
        ((score+=40)) || true; reasons+=("Wskaźniki C2/Reverse Shell/Tor")
    fi

    echo ""
    echo -e "${BOLD}Wynik ryzyka: $score / 100${RESET}"
    echo "Wynik ryzyka: $score / 100" >> "$REPORT_FILE"

    for r in "${reasons[@]}"; do
        echo -e "  ${YELLOW}→${RESET} $r"
        echo "  → $r" >> "$REPORT_FILE"
    done

    if   [[ $score -ge 70 ]]; then echo -e "\n${RED}${BOLD}⚠️  RYZYKO WYSOKIE${RESET}"; echo "RYZYKO: WYSOKIE" >> "$REPORT_FILE"
    elif [[ $score -ge 40 ]]; then echo -e "\n${YELLOW}${BOLD}⚠️  RYZYKO ŚREDNIE${RESET}"; echo "RYZYKO: ŚREDNIE" >> "$REPORT_FILE"
    else                            echo -e "\n${GREEN}${BOLD}✓  RYZYKO NISKIE${RESET}";  echo "RYZYKO: NISKIE"  >> "$REPORT_FILE"
    fi
}

# ─── Cleanup ──────────────────────────────────────────────────
cleanup() {
    log "Czyszczenie środowiska sandbox..."
    rm -rf "$SANDBOX_DIR"
}

# ─── MAIN ─────────────────────────────────────────────────────
main() {
    print_banner

    if [[ $# -lt 1 ]]; then
        echo -e "Użycie: ${BOLD}$0 <plik_do_analizy> [--no-exec]${RESET}"
        echo ""
        echo "  <plik>     Ścieżka do pliku do analizy"
        echo "  --no-exec  Pomiń wykonanie w sandboxie"
        echo ""
        echo "Przykład: $0 ~/Downloads/podejrzany.sh"
        exit 1
    fi

    local target_file="$1"
    local no_exec=false
    [[ "${2:-}" == "--no-exec" ]] && no_exec=true

    # Walidacja
    [[ ! -f "$target_file" ]] && { echo -e "${RED}Plik nie istnieje: $target_file${RESET}"; exit 1; }

    local size_mb
    size_mb=$(du -sm "$target_file" | awk '{print $1}')
    if [[ $size_mb -gt $MAX_FILE_SIZE_MB ]]; then
        echo -e "${RED}Plik za duży (${size_mb}MB > ${MAX_FILE_SIZE_MB}MB)${RESET}"
        exit 1
    fi

    # Przygotowanie środowiska
    mkdir -p "$SANDBOX_DIR"
    trap cleanup EXIT

    echo "Raport analizy - $(date)" > "$REPORT_FILE"
    echo "Plik: $target_file"       >> "$REPORT_FILE"
    echo "=================================" >> "$REPORT_FILE"

    create_sandbox_profile
    check_deps

    # Uruchom analizy
    analyze_metadata   "$target_file"
    analyze_magic      "$target_file"
    analyze_strings    "$target_file"
    analyze_signature  "$target_file"
    analyze_macho      "$target_file"
    check_known_hashes "$target_file"

    if [[ "$no_exec" == false ]]; then
        echo ""
        read -r -p "$(echo -e "${YELLOW}Czy uruchomić plik w sandboxie? [t/N]${RESET} ")" confirm
        [[ "$confirm" =~ ^[tTyY]$ ]] && run_in_sandbox "$target_file"
    fi

    risk_assessment "$target_file"

    # Zapisz raport
    local final_report="$(pwd)/sandbox_report_$(basename "$target_file")_$(date +%Y%m%d_%H%M%S).txt"
    cp "$REPORT_FILE" "$final_report"

    echo ""
    echo -e "${GREEN}${BOLD}Raport zapisany:${RESET} $final_report"
    echo -e "${CYAN}Sandbox wyczyszczony automatycznie.${RESET}"
}

main "$@"
