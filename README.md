# 🔬 macOS Malware Sandbox Toolkit

Zestaw skryptów do **bezpiecznej, offline'owej analizy podejrzanych plików** na macOS. Obsługuje pliki natywne macOS (Mach-O, skrypty) oraz pliki Windows (`.exe`, `.dll`) — przez Wine lub izolowaną maszynę wirtualną Parallels + Noriben.

> ⚠️ **Zastrzeżenie:** Narzędzia przeznaczone wyłącznie do celów edukacyjnych, badań bezpieczeństwa i analizy własnych środowisk. Nie używaj do analizy plików, do których nie masz praw.

---

## 📦 Zawartość repozytorium

| Plik | Opis |
|---|---|
| `sandbox_analyzer.sh` | Szybka analiza statyczna + uruchomienie w `sandbox-exec` (macOS) |
| `sandbox_analyzer_v2.sh` | Rozszerzona analiza: YARA, ClamAV, PE, VBA, Wine, auto-install |
| `noriben_parallels_setup.sh` | Pełna automatyzacja: Parallels VM + Noriben + Procmon + raport HTML |

---

## 🚀 Szybki start

```bash
# Sklonuj repozytorium
git clone https://github.com/TWOJ_LOGIN/macos-sandbox-toolkit
cd macos-sandbox-toolkit
chmod +x *.sh

# Szybka analiza pliku
./sandbox_analyzer_v2.sh ~/Downloads/podejrzany.exe

# Pełna analiza w VM Windows (pierwsze uruchomienie)
./noriben_parallels_setup.sh --setup
./noriben_parallels_setup.sh ~/Downloads/malware.exe
```

---

## 🛠 Wymagania

### Minimalne (sandbox_analyzer.sh / v2)
- macOS 12 Monterey lub nowszy
- [Homebrew](https://brew.sh) (auto-instalowany przez skrypt)
- Python 3.x

### Dla analizy Windows przez Wine (sandbox_analyzer_v2.sh)
- `brew install --cask wine-stable`

### Dla pełnej analizy VM (noriben_parallels_setup.sh)
- [Parallels Desktop 18+](https://www.parallels.com/products/desktop/)
- Windows VM z zainstalowanymi:
  - Python 3 w `C:\Python3\`
  - [Sysinternals Procmon](https://learn.microsoft.com/sysinternals/downloads/procmon) w `C:\Tools\procmon64.exe`
  - [Noriben.py](https://github.com/Rurik/Noriben) w `C:\Tools\Noriben.py`
  - Snapshot o nazwie `Baseline_Clean`

---

## 📋 Szczegółowy opis skryptów

### 1. `sandbox_analyzer.sh` — Analiza podstawowa

Szybka analiza statyczna i dynamiczna pliku bez zewnętrznych zależności.

```bash
./sandbox_analyzer.sh <plik>
./sandbox_analyzer.sh <plik> --no-exec    # tylko statyczna analiza
```

**Co sprawdza:**
- Metadane, magic bytes, SHA256/MD5
- Podejrzane ciągi znaków (IOC): URL, narzędzia sieciowe, `eval`, `base64`
- Podpis kodu (`codesign`, Gatekeeper, atrybut kwarantanny)
- Uruchomienie w izolowanym `sandbox-exec` (blokada sieci, zapisu, Keychain)
- Ocena ryzyka 0–100 z uzasadnieniem

---

### 2. `sandbox_analyzer_v2.sh` — Analiza zaawansowana

Rozszerzona wersja z auto-instalacją narzędzi i obsługą plików Windows przez Wine.

```bash
./sandbox_analyzer_v2.sh <plik>
./sandbox_analyzer_v2.sh <plik> --no-exec          # bez uruchamiania
./sandbox_analyzer_v2.sh <plik> --timeout 600       # własny timeout (sekundy)
./sandbox_analyzer_v2.sh <plik> --skip-install      # pomiń instalację narzędzi
./sandbox_analyzer_v2.sh <plik> --keep-sandbox      # zachowaj katalog sandbox

LOG_LEVEL=DEBUG ./sandbox_analyzer_v2.sh <plik>     # tryb debugowania
```

**Moduły analizy:**

| Moduł | Opis |
|---|---|
| Auto-install | Sprawdza i instaluje brakujące narzędzia przez Homebrew / pip |
| Magic bytes | Detekcja ukrytego rozszerzenia, analiza nagłówka hex |
| IOC Strings | 12 kategorii wskaźników: C2, persistence, ransomware, Tor, keylogger… |
| Podpis kodu | `codesign`, Gatekeeper, `spctl`, atrybuty `xattr` |
| Analiza PE | Struktura sekcji, entropia, importy DLL, detekcja packera UPX |
| VBA/Office | Makra Word/Excel przez `oletools` + `olevba` |
| YARA | 6 wbudowanych reguł (C2, anty-VM, persistence, ransomware, encoded payload) |
| ClamAV | Skanowanie antywirusowe open-source |
| Wine sandbox | Izolowane uruchomienie `.exe`/`.dll` z monitoringiem rejestru i systemu plików |
| Ocena ryzyka | Wynik 0–100 z kategorią LOW / MEDIUM / HIGH |

**Narzędzia instalowane automatycznie:**
`yara` · `clamav` · `exiftool` · `upx` · `radare2` · `binwalk` · `wine` · `oletools` · `pefile`

---

### 3. `noriben_parallels_setup.sh` — Pełna analiza w VM

Automatyzuje cały cykl analizy dynamicznej w izolowanej maszynie wirtualnej Windows: od przywrócenia snapshota, przez uruchomienie próbki pod nadzorem Noriben + Procmon, aż po pobranie wyników i wygenerowanie raportu HTML.

```bash
# Konfiguracja (raz)
./noriben_parallels_setup.sh --setup

# Analiza
./noriben_parallels_setup.sh <plik.exe>
./noriben_parallels_setup.sh <plik.exe> --vm "Win11 Sandbox" --timeout 600
./noriben_parallels_setup.sh <plik.exe> --no-revert     # bez przywracania snapshota
./noriben_parallels_setup.sh --list-vms                 # lista dostępnych VM
```

**Zmienne środowiskowe:**
```bash
VM_NAME="Windows 11 Malware"     # Nazwa VM w Parallels
VM_SNAPSHOT="Baseline_Clean"      # Nazwa snapshota (czyste środowisko)
VM_USER="Administrator"           # Użytkownik Windows
ANALYSIS_TIMEOUT=300              # Czas analizy (sekundy)
```

**Flow analizy:**

```
Mac (host)                           Windows VM (Parallels)
─────────────────────────────────────────────────────────────
1. Sprawdź narzędzia hosta
2. Przywróć snapshot ───────────────→ Czyste Windows
3. Uruchom VM             ←→ boot
4. Skonfiguruj środowisko ──────────→ Defender off, katalogi
5. Skopiuj próbkę ──────────────────→ C:\Malware\plik.exe
6. Uruchom Noriben ─────────────────→ Procmon + próbka
7. Czekaj (domyślnie 5 min)  ←→ monitoring
8. Pobierz wyniki ←─────────────────  C:\NoribenLogs\*
9. Zatrzymaj VM
10. Analiza IOC + raport HTML
```

**Co Noriben monitoruje:**
- Tworzenie i kończenie procesów (process injection, spawning)
- Operacje na rejestrze (persistence: `Run`, `RunOnce`, `Startup`)
- System plików (dropped EXE/DLL/BAT, modyfikacje plików systemowych)
- Aktywność sieciową (TCP/UDP connections, DNS queries)

---

## 🔒 Model izolacji

### sandbox-exec (skrypty v1/v2)
Wbudowany mechanizm macOS, profil DENY-ALL z wyjątkami:
- ❌ Brak dostępu do sieci (TCP, UDP, Unix sockets)
- ❌ Brak zapisu poza `/tmp/sandbox_analysis`
- ❌ Brak dostępu do Keychain / SecurityServer
- ❌ Brak IPC i shared memory
- ✅ Timeout (domyślnie 5 min, konfigurowalny)

### Parallels VM (noriben_parallels_setup.sh)
- Izolacja na poziomie hypervisora
- Snapshot przywracany przed każdą analizą → zawsze czyste środowisko
- Sieć VM może być odcięta przez ustawienia Parallels (zalecane)
- Po analizie VM jest zatrzymywana automatycznie

> **Uwaga:** Żaden sandbox nie daje 100% gwarancji izolacji dla wyrafinowanego malware. Do analizy próbek wysokiego ryzyka zalecane jest fizycznie odizolowane środowisko (air-gap).

---

## 📊 Format wyników

Każda sesja tworzy katalog `~/NoribenResults/<plik>_<timestamp>/` zawierający:

```
session_dir/
├── host_analysis.log        # Pełny log z hosta
├── Noriben_<timestamp>.txt  # Raport tekstowy Noriben
├── Noriben_<timestamp>.csv  # Surowe dane zdarzeń (do dalszej analizy)
├── analysis_report_*.html   # Raport HTML (otwórz w przeglądarce)
└── wine_prefix/             # (opcjonalnie) środowisko Wine
```

---

## 🔗 Powiązane projekty

- [Noriben](https://github.com/Rurik/Noriben) — lekki sandbox oparty na Procmon
- [Sysinternals Procmon](https://learn.microsoft.com/sysinternals/downloads/procmon) — monitor procesów/rejestru/plików
- [YARA](https://github.com/VirusTotal/yara) — silnik reguł do klasyfikacji malware
- [ClamAV](https://www.clamav.net) — open-source antywirus
- [oletools](https://github.com/decalage2/oletools) — analiza dokumentów Office/VBA
- [ANY.RUN](https://any.run) — alternatywa online (darmowy plan z publicznymi sesjami)

---

## ⚖️ Licencja

MIT License — szczegóły w pliku `LICENSE`.

---

## 🤝 Wkład

Pull requesty mile widziane. Przed większymi zmianami otwórz Issue z opisem proponowanej funkcjonalności.
