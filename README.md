# 🧪 Noriben + Parallels Sandbox

> Automatyczna analiza złośliwego oprogramowania na macOS — statyczna i dynamiczna — przy użyciu izolowanej maszyny wirtualnej Windows (Parallels Desktop) i narzędzia [Noriben](https://github.com/Rurik/Noriben).

---

## Spis treści

- [O projekcie](#o-projekcie)
- [Architektura](#architektura)
- [Wymagania](#wymagania)
- [Instalacja](#instalacja)
- [Pierwsze uruchomienie — konfiguracja VM](#pierwsze-uruchomienie--konfiguracja-vm)
- [Użycie](#użycie)
- [Opcje i flagi](#opcje-i-flagi)
- [Obsługa archiwów z hasłem](#obsługa-archiwów-z-hasłem)
- [Analiza statyczna](#analiza-statyczna)
- [Analiza dynamiczna](#analiza-dynamiczna)
- [Wyniki i raporty](#wyniki-i-raporty)
- [Zmienne środowiskowe](#zmienne-środowiskowe)
- [Model izolacji](#model-izolacji)
- [Struktura katalogów](#struktura-katalogów)
- [O Noriben.py](#o-noribenpyy)
- [Znane ograniczenia](#znane-ograniczenia)
- [Licencja](#licencja)

---

## O projekcie

`noriben_parallels_setup.sh` to skrypt bashowy dla macOS, który automatyzuje pełny cykl analizy podejrzanych plików:

1. **Analiza statyczna** — przeprowadzana lokalnie na Macu (bez uruchamiania próbki)
2. **Analiza dynamiczna** — próbka uruchamiana w izolowanej maszynie wirtualnej Windows pod nadzorem Noriben + Sysinternals Procmon
3. **Raport HTML** — skonsolidowany wynik obu analiz z tagami MITRE ATT&CK i oceną ryzyka

Skrypt obsługuje pliki wykonywalne Windows (`.exe`, `.dll`), skrypty (`.bat`, `.ps1`, `.vbs`) oraz **archiwa z hasłem** (ZIP, RAR, 7z) — powszechnie stosowane przez dystrybutorów malware do omijania skanerów antywirusowych.

---

## Architektura

```
macOS (host)                              Windows VM (Parallels)
─────────────────────────────────────────────────────────────────
 noriben_parallels_setup.sh
  │
  ├─ [A] Archiwum z hasłem
  │       └─ Rozpakowanie ZIP/RAR/7z
  │
  ├─ [B] Analiza statyczna (lokalnie)
  │       ├─ Magic bytes / nagłówek PE
  │       ├─ Entropia sekcji (detekcja packera)
  │       ├─ IOC strings (12 kategorii)
  │       ├─ YARA (8 reguł wbudowanych + własne)
  │       ├─ ClamAV
  │       └─ pefile (Python)
  │
  ├─ Przywróć snapshot ──────────────────→ Czyste Windows
  ├─ Uruchom VM             ←→ boot
  ├─ Skonfiguruj środowisko ─────────────→ Defender off, katalogi
  ├─ Skopiuj próbkę ─────────────────────→ C:\Malware\plik.exe
  │
  ├─ [C] Analiza dynamiczna
  │       └─ Uruchom Noriben ────────────→ Procmon + próbka
  │              ←─ monitoring ──────────  procesy · rejestr
  │              ←─ monitoring ──────────  pliki · sieć
  │       └─ [opcja] tcpdump PCAP
  │
  ├─ Pobierz wyniki ←────────────────────  C:\NoribenLogs\*
  ├─ Zatrzymaj VM
  │
  └─ [D] Raport HTML
          ├─ Wyniki statyczne + dynamiczne
          ├─ Tagi MITRE ATT&CK
          ├─ Ocena ryzyka (0–100)
          └─ Link VirusTotal
```

---

## Wymagania

### macOS (host)

| Wymaganie | Minimalna wersja | Uwagi |
|---|---|---|
| macOS | 12 Monterey | |
| [Parallels Desktop](https://www.parallels.com/products/desktop/) | 18 | `prlctl` musi być w `PATH` |
| Python 3 | 3.9+ | auto-instalowany przez Homebrew |
| [Homebrew](https://brew.sh) | dowolna | auto-instalowany przez skrypt |

### Narzędzia opcjonalne (instalowane automatycznie)

| Narzędzie | Homebrew formula | Zastosowanie |
|---|---|---|
| `yara` | `yara` | Skanowanie regułami YARA |
| `clamscan` | `clamav` | Antywirus open-source |
| `exiftool` | `exiftool` | Metadane plików |
| `upx` | `upx` | Detekcja i rozpakowywanie packera UPX |
| `7z` | `p7zip` | Archiwa ZIP/RAR/7z z hasłem |
| `unrar` | `unrar` | Archiwa RAR |
| `pefile` | pip | Analiza nagłówka PE (Python) |
| `yara-python` | pip | Reguły YARA z Pythona |

### Windows VM (gość)

| Wymaganie | Ścieżka domyślna | Uwagi |
|---|---|---|
| Python 3.x | `C:\Python3\python.exe` | instalowany przez `vm_setup.ps1` |
| Sysinternals Procmon | `C:\Tools\procmon64.exe` | instalowany przez `vm_setup.ps1` |
| Noriben.py | `C:\Tools\Noriben.py` | pobierany automatycznie |
| Parallels Guest Tools | — | wymagane do kopiowania plików |
| Snapshot `Baseline_Clean` | — | czyste środowisko przed każdą analizą |

---

## Instalacja

```bash
# Sklonuj repozytorium
git clone https://github.com/cr3pt/mac_tools
cd mac_tools

# Nadaj uprawnienia
chmod +x noriben_parallels_setup.sh
```

Upewnij się, że `prlctl` jest dostępny w terminalu:

```bash
which prlctl
# Jeśli brak — dodaj do PATH:
export PATH="$PATH:/Applications/Parallels Desktop.app/Contents/MacOS"
```

---

## Pierwsze uruchomienie — konfiguracja VM

Wykonaj raz przed pierwszą analizą:

```bash
./noriben_parallels_setup.sh --setup
```

Skrypt przeprowadzi przez następujące kroki:

**1. Sprawdzenie i instalacja narzędzi** na hoście (Homebrew, YARA, ClamAV, p7zip itp.)

**2. Pobranie Noriben.py** z oficjalnego repozytorium GitHub

**3. Wygenerowanie `vm_setup.ps1`** — skrypt PowerShell do konfiguracji Windows VM

**4. Konfiguracja Windows VM** — wykonaj ręcznie w VM:
```powershell
# W Windows VM — PowerShell jako Administrator
Set-ExecutionPolicy Bypass -Scope Process -Force
.\vm_setup.ps1
```

Skrypt `vm_setup.ps1` automatycznie:
- tworzy katalogi `C:\Tools`, `C:\Malware`, `C:\NoribenLogs`
- instaluje Python 3 (`C:\Python3`)
- instaluje Procmon przez `winget`
- wyłącza Windows Defender Real-Time (wymagane dla analizy malware)
- wyłącza UAC i Windows Update
- dodaje wykluczenia Defender dla katalogów roboczych

**5. Utwórz snapshot** w Parallels Desktop:
```
Parallels Desktop → Actions → Take Snapshot
Nazwa snapshota: Baseline_Clean
```

> ⚠️ Snapshot musi powstać **po** konfiguracji VM. Jest przywracany automatycznie przed każdą analizą, gwarantując czyste środowisko.

---

## Użycie

### Podstawowa analiza

```bash
./noriben_parallels_setup.sh ~/Downloads/podejrzany.exe
```

### Analiza archiwum z hasłem

```bash
./noriben_parallels_setup.sh ~/Downloads/sample.zip --archive-password infected
./noriben_parallels_setup.sh ~/Downloads/sample.rar --archive-password "tajne haslo"
```

### Tylko analiza statyczna (bez VM)

```bash
./noriben_parallels_setup.sh ~/Downloads/malware.exe --static-only
```

### Tylko analiza dynamiczna (bez statycznej)

```bash
./noriben_parallels_setup.sh ~/Downloads/malware.exe --dynamic-only
```

### Własna VM i dłuższy timeout

```bash
./noriben_parallels_setup.sh ~/Downloads/malware.exe \
  --vm "Win10 Sandbox" \
  --snapshot "Clean_Baseline" \
  --timeout 600
```

### Lista dostępnych VM

```bash
./noriben_parallels_setup.sh --list-vms
```

---

## Opcje i flagi

```
Użycie: noriben_parallels_setup.sh <plik> [opcje]

  --setup                  Konfiguracja środowiska (pierwsze uruchomienie)
  --vm <nazwa>             Nazwa VM w Parallels Desktop
  --snapshot <nazwa>       Nazwa snapshota do przywrócenia
  --timeout <sekundy>      Czas analizy Noriben (domyślnie: 300s / 5 min)
  --archive-password <p>   Hasło do archiwum ZIP/RAR/7z
  --static-only            Tylko analiza statyczna — bez uruchamiania VM
  --dynamic-only           Tylko analiza dynamiczna — bez analizy statycznej
  --no-revert              Nie przywracaj snapshota przed analizą
  --list-vms               Wylistuj wszystkie VM dostępne w Parallels
  --help                   Wyświetl pomoc
```

---

## Obsługa archiwów z hasłem

Dystrybutorzy malware często pakują próbki w archiwa chronione hasłem, aby ominąć skaner antywirusowy na bramce pocztowej lub w usłudze wymiany plików. Skrypt obsługuje ten scenariusz automatycznie.

**Obsługiwane formaty:** ZIP · RAR · 7z · tar.gz · tar.bz2 · tar.xz

**Automatyczna próba domyślnych haseł:**

```
infected · malware · virus · password · 1234 · admin · sample
```

**Własna lista haseł (zmienna środowiskowa):**

```bash
ARCHIVE_PASSWORDS="moje_haslo inne_haslo infected" \
  ./noriben_parallels_setup.sh sample.zip
```

**Jeśli żadne hasło nie zadziała** — skrypt pyta interaktywnie o hasło ręczne.

**Wybór pliku z archiwum:** jeśli archiwum zawiera wiele plików, skrypt wyświetla menu wyboru lub opcję analizy wszystkich plików po kolei.

---

## Analiza statyczna

Przeprowadzana lokalnie na macOS **przed** wysłaniem próbki do VM. Nie wymaga uruchamiania podejrzanego kodu.

| Moduł | Opis |
|---|---|
| **B1 — Metadane** | SHA256, MD5, SHA1, rozmiar, typ pliku |
| **B2 — Magic bytes** | Pierwsze 32 bajty w hex, detekcja ukrytego rozszerzenia |
| **B3 — Nagłówek PE** | Architektura, timestamp, subsystem, sekcje PE, entropia, importy DLL, version info |
| **B4 — Entropia** | Entropia całego pliku (wskaźnik szyfrowania / packowania) |
| **B5 — IOC Strings** | 12 kategorii wskaźników: URL/IP, Tor, C2, pobieranie kodu, kodowanie base64, persistence, anty-debug, ransomware, keylogger, privilege escalation, lateral movement, dane wrażliwe |
| **B6 — ExifTool** | Metadane osadzone w pliku (kompilator, wersja, autor) |
| **B7 — Packer** | Detekcja UPX + znanych protektorów (Themida, VMProtect, ASPack, PECompact…) z opcją automatycznego rozpakowania UPX |
| **B8 — YARA** | 8 wbudowanych reguł + opcjonalne własne (`~/NoribenTools/custom_rules.yar`) |
| **B9 — ClamAV** | Skanowanie antywirusowe open-source |

**Wbudowane reguły YARA:**

| Reguła | Wykrywa | MITRE |
|---|---|---|
| `Ransomware_Indicators` | CryptEncrypt, żądanie okupu, rozszerzenia `.locked` | T1486 |
| `ProcessInjection` | VirtualAllocEx, WriteProcessMemory, CreateRemoteThread | T1055 |
| `Keylogger_Spyware` | GetAsyncKeyState, SetWindowsHookEx, GetClipboardData | T1056 |
| `AntiAnalysis` | IsDebuggerPresent, VirtualBox, VMware, QEMU, SbieDll | T1497, T1622 |
| `NetworkC2` | meterpreter, cobalt strike, mimikatz, `.onion` | T1071, T1059 |
| `Persistence_Registry` | CurrentVersion\Run, RunOnce, schtasks, sc create | T1547 |
| `EncodedPayload` | base64 (200+ znaków), FromBase64String | T1027 |
| `CredentialTheft` | lsass, sekurlsa, NTLMhash, `.aws/credentials` | T1003 |

**Własne reguły YARA:**

Umieść plik `custom_rules.yar` w katalogu `~/NoribenTools/` — zostanie automatycznie załadowany podczas każdej analizy.

---

## Analiza dynamiczna

Przeprowadzana wewnątrz izolowanej maszyny wirtualnej Windows przez narzędzie **Noriben.py** wspomagane **Sysinternals Procmon**.

**Co Noriben monitoruje:**

| Kategoria | Przykłady |
|---|---|
| Procesy | tworzenie, kończenie, wstrzykiwanie (CreateProcess, Spawned) |
| Rejestr | zapisy do Run/RunOnce, HKCU/HKLM (persistence) |
| System plików | nowe `.exe`/`.dll`/`.bat`, dropped payloads, modyfikacje plików systemowych |
| Sieć | TCP/UDP connections, zapytania DNS |
| Usługi | tworzenie usług Windows, zadania harmonogramu |

**Opcjonalne przechwytywanie ruchu sieciowego:**

Na początku analizy dynamicznej skrypt pyta czy uruchomić `tcpdump` na interfejsie sieciowym VM. Plik PCAP jest zapisywany razem z wynikami i można go otworzyć w Wireshark.

```bash
# Jeśli tshark jest zainstalowany — skrypt automatycznie wyświetla top połączeń:
brew install wireshark  # zawiera tshark
```

**Wykrywane zachowania dynamiczne:**

| Kategoria IOC | MITRE |
|---|---|
| Sieć TCP/UDP | T1071 — Application Layer Protocol |
| Autostart / Persistence | T1547 — Boot/Logon Autostart Execution |
| Wstrzykiwanie procesów | T1055 — Process Injection |
| Shadow Copy / VSS | T1490 — Inhibit System Recovery |
| Modyfikacje systemu | T1112 — Modify Registry |

---

## Wyniki i raporty

Każda sesja tworzy unikalny katalog w `~/NoribenResults/`:

```
~/NoribenResults/<nazwa_pliku>_<timestamp>/
│
├── REPORT_<timestamp>.html     ← Główny raport HTML (otwórz w przeglądarce)
├── host_analysis.log           ← Pełny log z hosta macOS
├── sample_sha256.txt           ← Hash SHA256 próbki
│
├── Noriben_<timestamp>.txt     ← Raport tekstowy Noriben
├── Noriben_<timestamp>.csv     ← Surowe zdarzenia Procmon (do dalszej analizy)
├── noriben_stdout.txt          ← Stdout Noriben z VM
├── noriben_stderr.txt          ← Stderr / błędy Noriben z VM
│
├── network_capture.pcap        ← Przechwycony ruch sieciowy VM (opcjonalnie)
├── extracted/                  ← Pliki wypakowane z archiwum (jeśli dotyczy)
└── archive_password.txt        ← Użyte hasło archiwum (jeśli dotyczy)
```

**Raport HTML zawiera:**
- metadane próbki + link do VirusTotal
- pasek ryzyka (0–100) z podziałem na statyczny i dynamiczny
- wyniki analizy statycznej i dynamicznej w dwóch kolumnach
- tagi MITRE ATT&CK
- konfigurację sesji (VM, snapshot, timeout)
- pełny raport Noriben
- log hosta (ostatnie 80 linii)

**Otwieranie raportu:**

```bash
open ~/NoribenResults/malware_20250311_143022/REPORT_20250311_143022.html
```

---

## Zmienne środowiskowe

Wszystkie parametry można ustawić przez zmienne środowiskowe bez modyfikowania skryptu:

```bash
# Podstawowe
export VM_NAME="Windows 10 Malware Lab"
export VM_SNAPSHOT="Clean_Baseline"
export VM_USER="Administrator"
export VM_PASS="haslo_vm"

# Timeout analizy (sekundy)
export ANALYSIS_TIMEOUT=600   # 10 minut

# Domyślne hasła archiwów (rozdzielone spacją)
export ARCHIVE_PASSWORDS="infected malware virus moje_haslo"

# Uruchomienie
./noriben_parallels_setup.sh ~/Downloads/sample.exe
```

Lub jednorazowo przed komendą:

```bash
ANALYSIS_TIMEOUT=600 VM_NAME="Win10 Lab" \
  ./noriben_parallels_setup.sh ~/Downloads/malware.exe
```

---

## Model izolacji

### Snapshot VM (główna ochrona)

Przed każdą analizą skrypt automatycznie przywraca VM do czystego snapshota `Baseline_Clean`. Gwarantuje to, że każda próbka jest analizowana w identycznym, niezainfekowanym środowisku.

```
Analiza 1: snapshot → uruchomienie → zainfekowane Windows → STOP
Analiza 2: snapshot → czyste Windows → uruchomienie → zainfekowane Windows → STOP
```

### Izolacja sieciowa (zalecana konfiguracja)

Dla maksymalnej izolacji zaleca się odcięcie sieci VM w ustawieniach Parallels:

```
Parallels Desktop → VM → Configure → Hardware → Network
→ Zmień na: "Host-only" lub "Disconnected"
```

> ⚠️ **Ważne:** Jeśli VM ma dostęp do internetu, malware może pobrać dodatkowe komponenty, skontaktować się z serwerem C2 lub zmodyfikować hosty docelowe. Zależy od celu analizy — połączenie sieciowe może być celowo włączone dla obserwacji ruchu C2.

### Tcpdump na hoście (monitorowanie sieci)

Opcjonalny `tcpdump` na interfejsie sieciowym Parallels rejestruje **cały ruch** generowany przez VM bez konieczności instalowania czegokolwiek w gościu.

### Ograniczenia sandboxingu

Parallels nie jest hiperwizorem klasy security (jak Xen/KVM z DRAKVUF). Wyrafinowany malware może:
- wykryć środowisko wirtualne (VMware/Parallels artifacts)
- próbować ucieczki z VM przez podatności hiperwizora
- opóźnić złośliwe zachowanie wykraczające poza ustawiony timeout

**Do analizy próbek najwyższego ryzyka** zalecane jest fizycznie odizolowane środowisko (air-gap) lub dedykowane rozwiązanie jak CAPE Sandbox / DRAKVUF.

---

## Struktura katalogów projektu

```
.
├── noriben_parallels_setup.sh   ← Główny skrypt (macOS host)
├── Noriben.py                   ← Pobierany automatycznie do ~/NoribenTools/
└── README.md
```

Po pierwszym uruchomieniu `--setup` tworzone są:

```
~/NoribenTools/
├── Noriben.py                   ← Pobrane z GitHub
├── vm_setup.ps1                 ← Skrypt konfiguracyjny Windows VM
└── custom_rules.yar             ← (opcjonalny) własne reguły YARA

~/NoribenResults/
└── <próbka>_<timestamp>/        ← Wyniki każdej sesji
```

---

## O Noriben.py

[Noriben](https://github.com/Rurik/Noriben) to lekkie narzędzie do analizy malware napisane przez Briana Lenziego. Działa jako wrapper wokół **Sysinternals Process Monitor (Procmon)** — zbiera i filtruje zdarzenia systemowe generowane przez analizowaną próbkę, a następnie eksportuje je do czytelnych raportów TXT i CSV.

**Zalety Noriben:**
- minimalna ingerencja w system gościa (nie wymaga sterownika kernel-mode)
- prosta konfiguracja (jeden plik `.py`)
- działa na każdym Windows z Pythonem i Procmon
- filtruje szum systemowy, wyświetlając tylko zdarzenia istotne dla próbki

**Ograniczenia:**
- opiera się na Procmon — widoczny dla malware sprawdzającego listę procesów
- nie analizuje ruchu sieciowego na poziomie pakietów (stąd opcjonalny tcpdump na hoście)
- nie przechwytuje wywołań systemowych na poziomie kernela (w przeciwieństwie do DRAKVUF)

Oficjalne repozytorium: [github.com/Rurik/Noriben](https://github.com/Rurik/Noriben)

---

## Znane ograniczenia

| Ograniczenie | Opis |
|---|---|
| Wyłącznie macOS | Skrypt wymaga `bash` z macOS i narzędzi `prlctl` (Parallels) |
| Parallels płatny | Parallels Desktop nie jest darmowy — alternatywą jest UTM (darmowy, wolniejszy) |
| Timeout | Malware opóźniające działanie (sleep, trigger) może nie aktywować się w oknie analizy |
| Anty-VM | Próbki sprawdzające środowisko wirtualne mogą nie wykazać złośliwego zachowania |
| Jeden plik na raz | Analiza dynamiczna obsługuje jedną próbkę na sesję (archiwum może zawierać wiele) |
| Sieć VM | Domyślnie VM ma dostęp do sieci — zalecane odcięcie dla pełnej izolacji |

---

## Licencja

MIT License — szczegóły w pliku `LICENSE`.

Noriben.py objęty licencją Apache 2.0 — szczegóły w [repozytorium Noriben](https://github.com/Rurik/Noriben/blob/master/LICENSE).

---

## Zastrzeżenie

Narzędzie przeznaczone wyłącznie do celów **edukacyjnych i badań bezpieczeństwa** we własnym, kontrolowanym środowisku. Autor nie ponosi odpowiedzialności za użycie niezgodne z prawem lub szkody wynikłe z analizy złośliwego oprogramowania. Analizuj wyłącznie pliki, do których masz prawo i w środowisku, za które odpowiadasz.
