# 🔬 Noriben QEMU Sandbox

> Automatyczna analiza złośliwego oprogramowania na macOS — statyczna i dynamiczna — przy użyciu **QEMU z Apple Hypervisor Framework** jako izolowanego hiperwizora klasy security oraz narzędzia [Noriben](https://github.com/Rurik/Noriben) do monitorowania zachowania próbki w Windows VM.

---

## Spis treści

- [O projekcie](#o-projekcie)
- [Dlaczego QEMU zamiast Parallels](#dlaczego-qemu-zamiast-parallels)
- [Architektura](#architektura)
- [Wymagania](#wymagania)
- [Instalacja](#instalacja)
- [Pierwsze uruchomienie — konfiguracja VM](#pierwsze-uruchomienie--konfiguracja-vm)
- [Użycie](#użycie)
- [Opcje i flagi](#opcje-i-flagi)
- [Zmienne środowiskowe](#zmienne-środowiskowe)
- [Obsługa archiwów z hasłem](#obsługa-archiwów-z-hasłem)
- [Analiza statyczna](#analiza-statyczna)
- [Analiza dynamiczna](#analiza-dynamiczna)
- [Model izolacji](#model-izolacji)
- [Wyniki i raporty](#wyniki-i-raporty)
- [Struktura katalogów](#struktura-katalogów)
- [O Noriben.py](#o-noribenpyy)
- [Znane ograniczenia](#znane-ograniczenia)
- [Licencja](#licencja)

---

## O projekcie

`noriben_qemu_sandbox.sh` to skrypt bashowy dla macOS automatyzujący pełny cykl analizy podejrzanych plików w bezpiecznym, odtwarzalnym środowisku:

1. **Analiza statyczna** — lokalnie na Macu, bez uruchamiania próbki (PE headers, YARA, ClamAV, IOC strings)
2. **Analiza dynamiczna** — próbka uruchamiana w izolowanej maszynie wirtualnej Windows pod nadzorem **Noriben.py + Sysinternals Procmon**
3. **Raport HTML** — skonsolidowany wynik obu analiz z tagami MITRE ATT&CK i oceną ryzyka 0–100

Skrypt obsługuje pliki wykonywalne Windows (`.exe`, `.dll`, `.bat`, `.ps1`, `.vbs`, `.scr`) oraz **archiwa chronione hasłem** (ZIP, RAR, 7z) — powszechnie stosowane przez dystrybutorów malware do omijania skanerów antywirusowych.

---

## Dlaczego QEMU zamiast Parallels

Parallels Desktop nie jest hiperwizorem klasy security. Instaluje własne sterowniki kernel-extension, pozostawia rozpoznawalne artefakty w systemie gościa (ciągi `prl_*`, procesy Parallels Tools) i nie oferuje atomowych snapshotów przez CLI. Wyrafinowany malware może te artefakty wykryć i zmienić swoje zachowanie.

**QEMU z Apple Hypervisor Framework (HVF)** eliminuje te problemy:

| Kryterium | Parallels Desktop | QEMU + Apple HVF |
|---|---|---|
| Poziom izolacji | kext Parallels w kernel space | Apple Hypervisor.framework (kernel-level, bez kext) |
| Artefakty w VM | strings `prl_*`, procesy Parallels | brak — QEMU można ukryć przed gościem |
| Snapshoty przez CLI | `prlctl snapshot-switch` (~30s) | `qemu-img snapshot -a` (atomowe, <3s) |
| Izolacja sieciowa | domyślnie otwarta | `restrict=on` — zero ruchu bez zgody operatora |
| Monitor VM | GUI Parallels | TCP socket — `nc 127.0.0.1:4444` |
| Komunikacja host↔gość | Parallels Guest Tools | OpenSSH Server (wbudowany w Windows 10/11) |
| Koszt | ~$100/rok | darmowy — `brew install qemu` |
| Źródło | zamknięte | open-source |

### Uwaga dotycząca Apple Silicon (M1/M2/M3/M4)

HVF na Apple Silicon działa **wyłącznie dla gości o tej samej architekturze co host** (aarch64). Dla próbek x86 skrypt automatycznie dobiera właściwy backend:

| Chip hosta | Binary QEMU | Akcelerator | Gość Windows | Wydajność |
|---|---|---|---|---|
| Intel Mac | `qemu-system-x86_64` | `-machine q35,accel=hvf` | Windows 10/11 x64 | pełna (HVF natywnie) |
| Apple Silicon | `qemu-system-aarch64` | `-machine virt,accel=hvf` | Windows on ARM (WoA) | pełna (HVF natywnie) |
| Apple Silicon + x86 malware | `qemu-system-x86_64` | TCG (software) | Windows 10/11 x64 | wolniejsza (emulacja SW) |

---

## Architektura

```
macOS (host)                                    Windows VM (QEMU/HVF)
───────────────────────────────────────────────────────────────────────
 noriben_qemu_sandbox.sh
  │
  ├─ [A] Archiwum z hasłem
  │       └─ ZIP/RAR/7z → auto-próba haseł → rozpakowanie
  │
  ├─ [B] Analiza statyczna (na hoście, bez uruchamiania próbki)
  │       ├─ Magic bytes / nagłówek PE
  │       ├─ Entropia sekcji (detekcja packera/szyfrowania)
  │       ├─ IOC strings (12 kategorii)
  │       ├─ YARA (8 reguł wbudowanych + własne)
  │       ├─ ClamAV + ExifTool
  │       └─ pefile Python (importy, timestamp, version info)
  │
  ├─ qemu-img snapshot -a Baseline_Clean  ← atomowy reset <3s
  ├─ Boot QEMU headless ─────────────────→ Windows startuje
  │     monitor: nc 127.0.0.1:4444
  │     SSH:     localhost:2222
  ├─ Konfiguruj VM (SSH) ────────────────→ Defender off, katalogi
  ├─ Skopiuj próbkę (SCP) ───────────────→ C:\Malware\plik.exe
  │
  ├─ [C] Analiza dynamiczna (Noriben + Procmon)
  │       └─ SSH → Start-Process Noriben ─→ procmon64.exe startuje
  │              ←─ monitoring ────────────  procesy · rejestr
  │              ←─ monitoring ────────────  pliki · usługi
  │       └─ [opcja] tcpdump na loopback (ruch SSH)
  │
  ├─ Pobierz wyniki (SCP) ←──────────────  C:\NoribenLogs\*
  ├─ qemu-img snapshot -a Baseline_Clean  ← reset po analizie
  │
  └─ [D] Raport HTML
          ├─ Karta: model izolacji QEMU/HVF
          ├─ Wyniki statyczne + dynamiczne
          ├─ Tagi MITRE ATT&CK
          ├─ Ocena ryzyka (0–100)
          └─ Link VirusTotal
```

---

## Wymagania

### macOS (host)

| Wymaganie | Wersja | Uwagi |
|---|---|---|
| macOS | 10.15 Catalina+ | Hypervisor.framework dostępny od Catalina |
| [Homebrew](https://brew.sh) | dowolna | auto-instalowany przez skrypt |
| Python 3 | 3.9+ | auto-instalowany przez Homebrew |
| QEMU | 8.0+ | `brew install qemu` |

### Narzędzia opcjonalne — instalowane automatycznie przez skrypt

| Narzędzie | Homebrew formula | Zastosowanie |
|---|---|---|
| `yara` | `yara` | Skanowanie regułami YARA |
| `clamscan` | `clamav` | Antywirus open-source |
| `exiftool` | `exiftool` | Metadane plików |
| `upx` | `upx` | Detekcja i rozpakowywanie packera UPX |
| `7z` | `p7zip` | Archiwa 7z/ZIP z hasłem |
| `unrar` | `unrar` | Archiwa RAR |
| `pefile` | pip | Analiza nagłówka PE (Python) |
| `yara-python` | pip | Reguły YARA z Pythona |

### Windows VM — obraz qcow2

| Wymaganie | Ścieżka domyślna | Uwagi |
|---|---|---|
| Python 3.x | `C:\Python3\python.exe` | instalowany przez `vm_setup.ps1` |
| Sysinternals Procmon | `C:\Tools\procmon64.exe` | instalowany przez `vm_setup.ps1` |
| Noriben.py | `C:\Tools\Noriben.py` | wgrywany przez skrypt przez SCP |
| **OpenSSH Server** | port 22 | wymagany — wbudowany w Windows 10/11 |
| Snapshot `Baseline_Clean` | obraz qcow2 | tworzony przez `qemu-img snapshot -c` |

> ⚠️ **OpenSSH Server** zastępuje Parallels Guest Tools jako mechanizm komunikacji host↔gość. Jest wbudowany w Windows 10/11 — wystarczy go włączyć.

---

## Instalacja

```bash
# Sklonuj repozytorium
git clone https://github.com/TWOJ_LOGIN/noriben-qemu-sandbox
cd noriben-qemu-sandbox

# Nadaj uprawnienia
chmod +x noriben_qemu_sandbox.sh

# Zainstaluj QEMU (jeśli nie ma)
brew install qemu
```

---

## Pierwsze uruchomienie — konfiguracja VM

Wykonaj **raz** przed pierwszą analizą:

```bash
./noriben_qemu_sandbox.sh --setup
```

Skrypt przeprowadzi przez następujące kroki i wyświetli instrukcje dostosowane do architektury Twojego Maca (Intel lub Apple Silicon).

### Krok 1 — Utwórz obraz qcow2

```bash
qemu-img create -f qcow2 ~/NoribenTools/windows_sandbox.qcow2 60G
```

### Krok 2 — Zainstaluj Windows z ISO

**Intel Mac:**
```bash
qemu-system-x86_64 \
  -machine q35,accel=hvf \
  -cpu host \
  -m 4G -smp 2 \
  -drive file=~/NoribenTools/windows_sandbox.qcow2,if=virtio \
  -cdrom ~/Downloads/windows10.iso \
  -boot d \
  -display default
```

**Apple Silicon (Windows on ARM):**
```bash
qemu-system-aarch64 \
  -machine virt,accel=hvf,highmem=off \
  -cpu host \
  -m 4G -smp 2 \
  -drive file=~/NoribenTools/windows_sandbox.qcow2,if=virtio \
  -cdrom ~/Downloads/windows_arm64.iso \
  -boot d \
  -display default
```

> Obraz ARM Windows pobierz z [Microsoft Windows Insider Program](https://www.microsoft.com/en-us/software-download/windowsinsiderpreviewARM64).

### Krok 3 — Skonfiguruj Windows VM

Po instalacji Windows, w VM uruchom PowerShell jako Administrator i wykonaj skrypt wygenerowany przez `--setup`:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\vm_setup.ps1
```

Skrypt `vm_setup.ps1` automatycznie:
- tworzy katalogi `C:\Tools`, `C:\Malware`, `C:\NoribenLogs`, `C:\Python3`
- instaluje Python 3 (`C:\Python3\python.exe`)
- instaluje Procmon przez `winget`
- **włącza OpenSSH Server** i otwiera port 22 w firewallu
- wyłącza Windows Defender Real-Time Protection
- wyłącza UAC i Windows Update
- dodaje wykluczenia Defender dla katalogów roboczych

### Krok 4 — Utwórz snapshot

Wyłącz VM, a następnie utwórz atomowy snapshot:

```bash
qemu-img snapshot -c Baseline_Clean ~/NoribenTools/windows_sandbox.qcow2
```

Weryfikacja:
```bash
qemu-img snapshot -l ~/NoribenTools/windows_sandbox.qcow2
```

> Snapshot jest przywracany automatycznie **przed każdą analizą** (reset <3s) i ponownie **po zakończeniu** — VM jest zawsze gotowa na kolejną próbkę.

---

## Użycie

### Podstawowa analiza (statyczna + dynamiczna)

```bash
./noriben_qemu_sandbox.sh ~/Downloads/podejrzany.exe
```

### Archiwum z hasłem

```bash
./noriben_qemu_sandbox.sh ~/Downloads/sample.zip --archive-password infected
./noriben_qemu_sandbox.sh ~/Downloads/sample.rar --archive-password "tajne haslo"
```

### Tylko analiza statyczna (bez uruchamiania VM)

```bash
./noriben_qemu_sandbox.sh ~/Downloads/malware.exe --static-only
```

### Tylko analiza dynamiczna (bez statycznej)

```bash
./noriben_qemu_sandbox.sh ~/Downloads/malware.exe --dynamic-only
```

### Własny obraz QEMU i dłuższy timeout

```bash
./noriben_qemu_sandbox.sh ~/Downloads/malware.exe \
  --disk ~/my_windows10.qcow2 \
  --snapshot Clean_Baseline \
  --timeout 600 \
  --mem 8G
```

### Lista snapshotów w obrazie

```bash
./noriben_qemu_sandbox.sh --list-snapshots
```

### Analiza bez resetu snapshota

```bash
./noriben_qemu_sandbox.sh malware.exe --no-revert
```

---

## Opcje i flagi

```
Użycie: noriben_qemu_sandbox.sh <plik> [opcje]

  --setup                  Konfiguracja środowiska (pierwsze uruchomienie)
  --disk <ścieżka>         Ścieżka do obrazu QEMU qcow2
  --snapshot <nazwa>       Nazwa snapshota (domyślnie: Baseline_Clean)
  --timeout <s>            Czas analizy Noriben w sekundach (domyślnie: 300)
  --mem <RAM>              Pamięć VM, np. 4G lub 8G (domyślnie: 4G)
  --smp <N>                Liczba wirtualnych procesorów (domyślnie: 2)
  --ssh-port <port>        Port SSH do VM na hoście (domyślnie: 2222)
  --monitor-port <port>    Port monitora QEMU TCP (domyślnie: 4444)
  --archive-password <p>   Hasło do archiwum ZIP/RAR/7z
  --static-only            Tylko analiza statyczna — bez uruchamiania VM
  --dynamic-only           Tylko analiza dynamiczna — bez analizy statycznej
  --no-revert              Nie przywracaj snapshota przed analizą
  --list-snapshots         Lista snapshotów w obrazie qcow2
  --help                   Wyświetl pomoc
```

---

## Zmienne środowiskowe

Wszystkie parametry można przekazać przez zmienne środowiskowe bez edytowania skryptu:

```bash
# Konfiguracja QEMU
export QEMU_DISK="$HOME/NoribenTools/windows_sandbox.qcow2"
export QEMU_SNAPSHOT="Baseline_Clean"
export QEMU_MEM="4G"
export QEMU_SMP="2"
export QEMU_SSH_PORT="2222"
export QEMU_MONITOR_PORT="4444"

# Dane SSH do gościa Windows
export VM_USER="Administrator"
export VM_PASS="haslo_vm"

# Timeout analizy
export ANALYSIS_TIMEOUT="300"

# Domyślne hasła archiwów (rozdzielone spacją)
export ARCHIVE_PASSWORDS="infected malware virus password 1234 admin sample"
```

Lub jednorazowo przed komendą:

```bash
ANALYSIS_TIMEOUT=600 QEMU_MEM=8G \
  ./noriben_qemu_sandbox.sh ~/Downloads/malware.exe
```

---

## Obsługa archiwów z hasłem

Dystrybutorzy malware często pakują próbki w szyfrowane archiwa, aby ominąć skanery antywirusowe na bramkach pocztowych i w usługach wymiany plików.

**Obsługiwane formaty:** ZIP · RAR · 7z · tar.gz · tar.bz2 · tar.xz

### Automatyczna próba domyślnych haseł

Skrypt kolejno próbuje:
```
infected · malware · virus · password · 1234 · admin · sample
```

Własna lista (zmienna środowiskowa lub flaga):
```bash
# Przez zmienną
ARCHIVE_PASSWORDS="moje_haslo inne infected" ./noriben_qemu_sandbox.sh sample.zip

# Przez flagę (dodawane jako pierwsze)
./noriben_qemu_sandbox.sh sample.zip --archive-password "moje_haslo"
```

Jeśli żadne domyślne hasło nie zadziała — skrypt pyta interaktywnie o hasło ręczne.

### Wybór pliku z archiwum

Jeśli archiwum zawiera wiele plików, skrypt wyświetla menu wyboru lub opcję analizy wszystkich po kolei. Użyte hasło jest zapisywane w pliku `archive_password.txt` w katalogu wyników sesji.

---

## Analiza statyczna

Przeprowadzana lokalnie na macOS **przed** wysłaniem próbki do VM. Nie wymaga uruchamiania podejrzanego kodu.

| Moduł | Opis |
|---|---|
| **B1 — Metadane** | SHA256, MD5, SHA1, rozmiar, typ pliku (magic bytes) |
| **B2 — Magic bytes** | Pierwsze 32 bajty w hex — wykrywa ukryte rozszerzenie |
| **B3 — Nagłówek PE** | Architektura (x86/x64/ARM), timestamp kompilacji, subsystem (GUI/Console/Driver), sekcje PE z entropią, importy DLL, version info — przez `pefile` (Python) |
| **B4 — Entropia** | Entropia całego pliku — wysoka (>7.0) wskazuje na packer lub szyfrowanie |
| **B5 — IOC Strings** | 12 kategorii wskaźników kompromitacji wyekstrahowanych z pliku |
| **B6 — ExifTool** | Metadane osadzone w pliku (kompilator, wersja, autor dokumentu) |
| **B7 — Detekcja packera** | UPX (z opcją auto-rozpakowania) + sygnatury znanych protektorów |
| **B8 — YARA** | 8 reguł wbudowanych + własne z `~/NoribenTools/custom_rules.yar` |
| **B9 — ClamAV** | Skanowanie antywirusowe open-source z heurystyką |

### 12 kategorii IOC strings

| Kategoria | Przykłady wzorców | MITRE |
|---|---|---|
| URL/IP | `https://`, IPv4 | — |
| Tor/Darknet | `.onion`, `socks5://` | — |
| C2/Reverse Shell | `meterpreter`, `cobalt strike`, `powershell -enc` | T1059 |
| Pobieranie kodu | `URLDownloadToFile`, `Invoke-WebRequest`, `certutil -urlcache` | T1105 |
| Kodowanie | `FromBase64String`, `base64 -d` | T1027 |
| Persistence Win | `CurrentVersion\Run`, `schtasks /create`, `sc create` | T1547 |
| Anti-debug/VM | `IsDebuggerPresent`, `VirtualBox`, `VMware`, `QEMU`, `Parallels` | T1497, T1622 |
| Ransomware | `CryptEncrypt`, `.locked`, `.encrypted`, `bitcoin` | T1486 |
| Keylogger | `GetAsyncKeyState`, `SetWindowsHookEx`, `GetClipboardData` | T1056 |
| Privilege Esc | `SeDebugPrivilege`, `UAC bypass`, `ImpersonateToken` | T1548 |
| Lateral Movement | `psexec`, `wmiexec`, `net use`, `pass-the-hash` | T1021 |
| Dane wrażliwe | `.aws/credentials`, `.ssh`, `api_key`, `password` | T1552 |

### 8 wbudowanych reguł YARA

| Reguła | Wykrywa | MITRE |
|---|---|---|
| `Ransomware_Indicators` | CryptEncrypt, bitcoin, `.locked`, żądanie okupu | T1486 |
| `ProcessInjection` | VirtualAllocEx, WriteProcessMemory, CreateRemoteThread | T1055 |
| `Keylogger_Spyware` | GetAsyncKeyState, SetWindowsHookEx, GetClipboardData | T1056 |
| `AntiAnalysis` | IsDebuggerPresent, VirtualBox, VMware, QEMU, SbieDll | T1497, T1622 |
| `NetworkC2` | meterpreter, cobalt strike, mimikatz, `.onion` | T1071, T1059 |
| `Persistence_Registry` | `CurrentVersion\Run`, RunOnce, schtasks | T1547 |
| `EncodedPayload` | base64 ≥200 znaków, FromBase64String | T1027 |
| `CredentialTheft` | lsass, sekurlsa, NTLMhash, `.aws/credentials` | T1003 |

### Własne reguły YARA

Umieść plik `custom_rules.yar` w `~/NoribenTools/` — zostanie automatycznie załadowany podczas każdej analizy.

---

## Analiza dynamiczna

Przeprowadzana wewnątrz izolowanej Windows VM przez **Noriben.py** wspomagany **Sysinternals Procmon**. Komunikacja host↔gość przez SSH/SCP — bez żadnych dodatkowych agentów w VM.

### Przepływ

1. `qemu-img snapshot -a Baseline_Clean` — atomowy reset do czystego stanu (<3s)
2. QEMU startuje headless, monitor TCP na porcie 4444
3. Skrypt czeka na dostępność SSH (port 2222 na localhost)
4. Próbka kopiowana przez SCP do `C:\Malware\`
5. SSH → `powershell Start-Process python.exe Noriben.py --cmd próbka.exe`
6. Procmon zbiera zdarzenia przez czas `ANALYSIS_TIMEOUT` (domyślnie 5 min)
7. Wyniki kompresowane (`Compress-Archive`) i pobierane przez SCP
8. `qemu-img snapshot -a Baseline_Clean` — reset po analizie

### Co Noriben monitoruje

| Kategoria | Wykrywane zdarzenia |
|---|---|
| Procesy | tworzenie, kończenie, wstrzykiwanie (CreateProcess, Spawned) |
| Rejestr | zapisy Run/RunOnce, HKCU/HKLM — persistence |
| System plików | nowe `.exe`/`.dll`/`.bat`, dropped payloads, modyfikacje plików systemowych |
| Usługi | tworzenie usług Windows, zadania Harmonogramu zadań |

### Wykrywane IOC dynamiczne

| Kategoria | MITRE |
|---|---|
| Sieć TCP/UDP, DNS | T1071 — Application Layer Protocol |
| Autostart / Persistence | T1547 — Boot/Logon Autostart Execution |
| Wstrzykiwanie procesów | T1055 — Process Injection |
| Shadow Copy / VSS | T1490 — Inhibit System Recovery |
| Modyfikacje systemu | T1112 — Modify Registry |
| Nowe procesy | T1059 — Command & Scripting Interpreter |

### Opcjonalne przechwytywanie ruchu

Na początku analizy dynamicznej skrypt pyta o uruchomienie `tcpdump` na interfejsie loopback (jedyna ścieżka komunikacji, gdy sieć VM jest odizolowana). Plik PCAP jest zapisywany w katalogu sesji:

```bash
# Analiza PCAP po zakończeniu:
tshark -r ~/NoribenResults/malware_20250311_143022/network_capture.pcap -q -z conv,ip
```

---

## Model izolacji

### Atomowe snapshoty qcow2

Każda analiza zaczyna się od:
```bash
qemu-img snapshot -a Baseline_Clean windows_sandbox.qcow2   # <3s
```

I kończy się tym samym poleceniem — gwarantując że każda kolejna próbka trafia do identycznego, niezainfekowanego środowiska, niezależnie od tego co poprzednia próbka zrobiła z systemem.

### Izolacja sieciowa

QEMU uruchamia VM z opcją `-netdev user,restrict=on` — sieć w trybie user-mode z pełnym odcięciem od zewnętrznego świata. Jedyne dozwolone połączenie to SSH z localhost hosta do VM przez przekierowany port.

```
VM Windows ←──── SSH localhost:2222 ────→ macOS host
               (jedyna dozwolona ścieżka)
```

Malware w VM nie może połączyć się z zewnętrznym serwerem C2, pobrać dodatkowych modułów ani exfiltrować danych.

### Brak artefaktów hiperwizora

QEMU nie instaluje żadnych narzędzi w gościu — nie ma odpowiednika Parallels Tools ani VMware Tools. Brak procesów, usług ani kluczy rejestru zdradzających środowisko wirtualne. Malware sprawdzający listę `IsDebuggerPresent`, `VirtualBox` czy `Parallels` nie znajdzie typowych wskaźników.

> Wyrafinowany malware może nadal wykryć QEMU przez sprawdzenie CPUID, timing ataków czy niestandardowe dyski virtio. Dla próbek najwyższego ryzyka zalecane są dodatkowe techniki hardeningu QEMU (dostosowanie CPUID, ukrycie urządzeń virtio).

### Apple Hypervisor.framework

HVF zapewnia izolację na poziomie jądra macOS bez konieczności instalowania sterowników kernel-extension (kext). VM działa w odizolowanej przestrzeni adresowej — każde naruszenie granic VM jest przechwytywane przez system operacyjny hosta.

---

## Wyniki i raporty

Każda sesja tworzy unikalny katalog w `~/NoribenResults/`:

```
~/NoribenResults/<nazwa_pliku>_<timestamp>/
│
├── REPORT_<timestamp>.html        ← Główny raport HTML (otwórz w przeglądarce)
├── host_analysis.log              ← Pełny log z hosta macOS
├── sample_sha256.txt              ← Hash SHA256 próbki
├── qemu.log                       ← Log QEMU (boot, błędy)
│
├── Noriben_<timestamp>.txt        ← Raport tekstowy Noriben
├── Noriben_<timestamp>.csv        ← Surowe zdarzenia Procmon
├── noriben_stdout.txt             ← Stdout Noriben z VM
├── noriben_stderr.txt             ← Stderr / błędy Noriben z VM
│
├── network_capture.pcap           ← Przechwycony ruch (opcjonalnie)
├── extracted/                     ← Pliki z archiwum (jeśli dotyczy)
└── archive_password.txt           ← Użyte hasło archiwum (jeśli dotyczy)
```

### Raport HTML

Raport otwierany bezpośrednio w przeglądarce zawiera:

- **Karta modelu izolacji** — hiperwizor, sieć, snapshot, artefakty VM
- **Metadane próbki** — SHA256, typ, rozmiar + przycisk VirusTotal
- **Pasek ryzyka 0–100** z podziałem na wynik statyczny i dynamiczny
- **Wyniki statyczne i dynamiczne** w dwóch kolumnach
- **Tagi MITRE ATT&CK** — deduplikowane, klikalne
- **Konfiguracja sesji QEMU** — obraz, snapshot, RAM, vCPU, porty
- **Pełny raport Noriben** — raw output z VM
- **Log hosta** — ostatnie 80 linii
- **Log QEMU** — ostatnie 30 linii (diagnoza problemów z VM)

```bash
# Otwarcie raportu:
open ~/NoribenResults/malware_20250311_143022/REPORT_20250311_143022.html
```

---

## Struktura katalogów

```
.
├── noriben_qemu_sandbox.sh     ← Główny skrypt (macOS host)
├── Noriben.py                  ← Pobierany automatycznie do ~/NoribenTools/
└── README.md

~/NoribenTools/                 ← Tworzone przez --setup
├── windows_sandbox.qcow2       ← Obraz QEMU Windows (tworzysz ręcznie)
├── Noriben.py                  ← Pobierany z GitHub (github.com/Rurik/Noriben)
├── vm_setup.ps1                ← Skrypt konfiguracyjny Windows VM
└── custom_rules.yar            ← (opcjonalny) własne reguły YARA

~/NoribenResults/               ← Wyniki analiz
└── <próbka>_<timestamp>/       ← Jedna sesja = jeden katalog
```

---

## O Noriben.py

[Noriben](https://github.com/Rurik/Noriben) to lekkie narzędzie do analizy malware napisane przez Briana Lenziego. Działa jako wrapper wokół **Sysinternals Process Monitor (Procmon)** — zbiera zdarzenia systemowe generowane przez analizowaną próbkę, filtruje systemowy szum i eksportuje czytelne raporty TXT i CSV.

**Zalety w tym kontekście:**
- minimalna ingerencja w system gościa (nie wymaga sterownika kernel-mode)
- jeden plik `.py` — łatwe wgranie przez SCP bez instalacji
- działa na każdym Windows z Pythonem i Procmon
- dobrze zintegrowany z pipeline CLI — `--headless`, `--timeout`, `--output`

**Ograniczenia:**
- Procmon jest widoczny na liście procesów — malware sprawdzający może to wykryć
- nie analizuje ruchu sieciowego na poziomie pakietów (stąd opcjonalny tcpdump na hoście)
- nie przechwytuje wywołań systemowych na poziomie kernela (w przeciwieństwie do DRAKVUF)

Oficjalne repozytorium: [github.com/Rurik/Noriben](https://github.com/Rurik/Noriben)

---

## Znane ograniczenia

| Ograniczenie | Opis |
|---|---|
| Apple Silicon + x86 malware | HVF nie obsługuje emulacji x86 na ARM — skrypt używa TCG (software emulation), co jest znacznie wolniejsze |
| OpenSSH wymagany | VM musi mieć włączony i skonfigurowany OpenSSH Server — bez niego komunikacja host↔gość nie działa |
| Timeout | Malware opóźniające działanie (sleep, trigger czasowy, trigger sieciowy) może nie aktywować się w oknie analizy |
| Detekcja QEMU | Wyrafinowany malware może wykryć QEMU przez timing, CPUID lub urządzenia virtio — wymaga dodatkowego hardeningu |
| Jeden plik na raz | Analiza dynamiczna obsługuje jedną próbkę na sesję |
| Sieć odcięta | Malware wymagające dostępu C2 do aktywacji nie wykaże pełnego zachowania w odciętej sieci |

---

## Licencja

MIT License — szczegóły w pliku `LICENSE`.

Noriben.py objęty licencją Apache 2.0 — szczegóły w [repozytorium Noriben](https://github.com/Rurik/Noriben/blob/master/LICENSE).

---

## Zastrzeżenie

Narzędzie przeznaczone wyłącznie do celów **edukacyjnych i badań bezpieczeństwa** we własnym, kontrolowanym środowisku. Autor nie ponosi odpowiedzialności za użycie niezgodne z prawem lub szkody wynikłe z analizy złośliwego oprogramowania. Analizuj wyłącznie pliki, do których masz prawo i w środowisku, za które odpowiadasz.
