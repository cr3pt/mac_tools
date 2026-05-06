# Noriben SOC v6.8 — Manual
> Static + Dynamic | Win10 + Win11 rownolegla | PCAP Network IOC | Cr3pT 2026

## Szybki start

```bash
unzip Noriben_SOC_v6.8_FINAL_fix3.zip && cd Noriben_SOC_v6.8
chmod +x deploy.sh scripts/*.sh vms/*.sh
./deploy.sh
```

```
UI:        http://localhost:8000
Grafana:   http://localhost:3000     admin / admin
Win10 VNC: localhost:5901            bez hasla (instalacja) / noriben (sandbox)
Win11 VNC: localhost:5902            bez hasla (instalacja) / noriben (sandbox)
API docs:  http://localhost:8000/docs
```

---

## Wymagania

| | macOS M1/M2/M4 | Ubuntu 22/24 |
|-|----------------|-------------|
| Docker | Desktop >= 4.x | CE >= 24.x |
| QEMU | brew install qemu | apt install qemu-system-x86 qemu-utils |
| RAM | 10 GB+ | 10 GB+ |
| Dysk | 150 GB+ | 150 GB+ |
| ClamAV | brew install clamav | apt install clamav |
| Oletools | pip install oletools | pip install oletools |
| PyPDF2 | pip install PyPDF2 | pip install PyPDF2 |
| Requests | pip install requests | pip install requests |

## Konfiguracja API

Aby korzystać z VirusTotal i OTX, ustaw klucze API w kodzie:

- VirusTotal: Zastąp 'YOUR_VIRUSTOTAL_API_KEY' w `_check_virustotal`
- OTX: Zastąp 'YOUR_OTX_API_KEY' w `_check_otx`

---

## Obrazy VM — Win10 i Win11

### Co robi win_setup.sh automatycznie

| System | Akcja |
|--------|-------|
| Win10 | Pobiera ISO z Microsoft (10 prób, 2h timeout) → tworzy dysk 60 GB → instalacja przez VNC |
| Win11 | Pobiera ISO z Microsoft (10 prób, 2h timeout) → tworzy dysk 60 GB → instalacja przez VNC |

> Uwaga: gotowe qcow2 Win11 nie sa publicznie dostepne — Microsoft ich nie udostepnia.
> Instalacja jest jednorazowa (~30-45 min przez VNC).

### VNC podczas instalacji (bez hasla)

```bash
# macOS
open vnc://localhost:5901    # Win10
open vnc://localhost:5902    # Win11

# Linux
vncviewer localhost:5901
vncviewer localhost:5902
```

---

## Bypass TPM — Win11 (wymagane podczas instalacji)

Gdy instalator Win11 pokazuje blad "This PC doesn't meet the minimum requirements":

1. Nacisnij **Shift+F10** — otworzy sie wiersz polecen
2. Wpisz kolejno:

```cmd
reg add HKLM\SYSTEM\Setup\LabConfig /v BypassTPMCheck /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\Setup\LabConfig /v BypassSecureBootCheck /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\Setup\LabConfig /v BypassRAMCheck /t REG_DWORD /d 1 /f
```

3. Zamknij cmd (wpisz `exit`)
4. Kliknij "Refresh" lub cofnij i wznow instalacje

Skrypt `win_setup.sh` wyswietla te komendy automatycznie przed uruchomieniem QEMU.

### Alternatywy — jesli nie chcesz instalowac recznie

**Opcja A — konwersja z VirtualBox / VMware:**
```bash
# VirtualBox (.vdi):
qemu-img convert -f vdi  -O qcow2 win10.vdi  vms/win10.qcow2
qemu-img convert -f vdi  -O qcow2 win11.vdi  vms/win11.qcow2

# VMware (.vmdk):
qemu-img convert -f vmdk -O qcow2 win10.vmdk vms/win10.qcow2
qemu-img convert -f vmdk -O qcow2 win11.vmdk vms/win11.qcow2

# Hyper-V (.vhdx):
qemu-img convert -f vhdx -O qcow2 win11.vhdx vms/win11.qcow2
```

**Opcja B — skopiuj gotowy qcow2:**
```bash
cp /path/to/win10_ready.qcow2 vms/win10.qcow2
cp /path/to/win11_ready.qcow2 vms/win11.qcow2
# Wymagany rozmiar: > 1 GB (pelny system > 15 GB)
```

**Opcja C — cloudbase.it (obrazy OpenStack, konwersja):**
```bash
# Pobierz Windows Server evaluation z: https://cloudbase.it/windows-cloud-images/
# (wymagana konwersja z VHDX)
qemu-img convert -f vhdx -O qcow2 windows_server.vhdx vms/win11.qcow2
```

---

## Po instalacji systemu — Noriben setup w VM

Po zainstalowaniu Win10/Win11 przez VNC, uruchom w VM (przez VNC):

```powershell
Set-ExecutionPolicy Bypass -Scope Process
C:\shared
oriben_setup.ps1
```

Skrypt instaluje Python 3.11 i Noriben (Process Monitor wrapper).

---

## QEMU — kluczowe flagi (dysk zawsze podpiety)

```bash
-drive file=win10.qcow2,format=qcow2,if=virtio,index=0,media=disk,snapshot=on
```

| Flaga | Znaczenie |
|-------|-----------|
| `format=qcow2` | Jawny format — bez auto-detekcji |
| `if=virtio` | Sterownik VirtIO (wydajny) |
| `index=0` | Dysk jako pierwsze urzadzenie (nie CD-ROM) |
| `media=disk` | Typ: dysk |
| `snapshot=on` | VM czysta po kazdej analizie (zmiany w RAM) |

---


## QEMU — porty i logowanie

Skrypt automatycznie wybiera wolny port dla monitora QEMU, zamiast trzymac sie stalego 4440.
Dla kazdej uruchomionej VM wypisuje aktualny port monitora, zeby bylo od razu widac gdzie sie podlaczyc.

```bash
# Przyklad komunikatu:
# [win10] QEMU uruchomiony — monitor port: 4442
```

Jeśli port 5901/5902 albo monitor sa zajete, skrypt przesuwa je na pierwszy wolny numer.




## Sumy kontrolne ISO

Pliki ISO Win10 i Win11 sa sprawdzane sumą SHA256 po poprawnym pobraniu.
Jesli plik jest niekompletny albo suma nie pasuje, skrypt usuwa go i pobiera od nowa.
Przy ponownym uruchomieniu, jesli suma kontrolna istnieje, jest uzywana do walidacji lokalnego pliku.

Mozesz tez wymusic odswiezenie, usuwajac oba pliki:

```bash
rm -f vms/win11.iso vms/win11.iso.sha256
rm -f vms/win10.iso vms/win10.iso.sha256
```

## Konfiguracja i zmiany

Najwazniejsze parametry mozna zmieniac bez grzebania w logice skryptow:

| Zmienna / element | Domyslnie | Co zmienia |
|-------------------|-----------|------------|
| `VNC` display Win10 | `:1` | Port VNC dla Win10 |
| `VNC` display Win11 | `:2` | Port VNC dla Win11 |
| `Monitor` Win10 | `4440` | Port monitora QEMU |
| `Monitor` Win11 | `4441` | Port monitora QEMU |
| `RAM` VM | `4096` | Przydzial pamieci |
| `Dysk` | `60G` | Rozmiar qcow2 |

Zmiany konfiguracyjne i nowe opcje pracy warto dopisywac do README razem z opisem efektu, zeby kolejna wersja byla zrozumiala bez czytania skryptu.

## Zwolnienie portów recznie

Jesli trzeba zwolnic porty po poprzednim uruchomieniu:

```bash
# VNC
lsof -i :5901
lsof -i :5902
kill -9 $(lsof -t -i :5901)
kill -9 $(lsof -t -i :5902)

# Monitor QEMU
lsof -i :4440
lsof -i :4441
kill -9 $(lsof -t -i :4440)
kill -9 $(lsof -t -i :4441)
```

W praktyce wystarczy zamknac stary proces QEMU lub uruchomic skrypt ponownie — wybierze pierwszy wolny port.

## Porty VNC i monitor

| Element | Win10 | Win11 | Co robi skrypt gdy zajete |
|--------|-------|-------|---------------------------|
| VNC display | `:1` | `:2` | Przesuwa na kolejny wolny display `:3`, `:4`, ... |
| VNC port | `5901` | `5902` | Automatycznie zmienia na kolejny port `5903`, `5904`, ... |
| Monitor QEMU | `4440` | `4441` | Przesuwa na pierwszy wolny port monitora |

Przy starcie skrypt wypisuje realnie wybrany port VNC oraz port monitora, zebys mogl od razu polaczyc sie bez zgadywania.

### Przyklad

```bash
[win10] VNC port: 5912 (display :12)
[win10] QEMU uruchomiony — monitor port: 4442
```

## Przechwyt ruchu sieciowego (PCAP)

Kazda VM generuje osobny plik PCAP przez `-object filter-dump`:

```bash
-object filter-dump,id=dump10,netdev=net10,file=results/sample_win10.pcap
```

Wyniki parsowane przez `scapy` (network_analyzer.py):

| Typ IOC | Zrodlo | Severity |
|---------|--------|----------|
| Zewnetrzne IP | Pakiety IP | MEDIUM |
| DNS queries | DNS QNAME | HIGH jesli .ru .cn .tk .xyz .top |
| DGA domains | DNS QNAME entropy | HIGH |
| HTTP requests | TCP port 80 Raw | HIGH |
| HTTP responses | TCP port 80 Raw | MEDIUM |
| HTTP User-Agent | TCP port 80 Raw | HIGH jesli malware |
| HTTP Referer | TCP port 80 Raw | MEDIUM |
| HTTP Cookies | TCP port 80 Raw | MEDIUM |
| MIME exe | TCP port 80 Raw | HIGH |
| HTTPS SNI | TLS Client Hello port 443 | HIGH jesli podejrzana domena |
| TLS Certificate | TLS Certificate port 443 | MEDIUM |
| FTP commands | TCP port 21 Raw | HIGH |
| SMTP addresses | TCP port 25 Raw | HIGH |
| POP3 commands | TCP port 110 Raw | HIGH |
| IMAP commands | TCP port 143 Raw | HIGH |
| SSH versions | TCP port 22 Raw | MEDIUM |
| Telnet commands | TCP port 23 Raw | HIGH |
| RDP connections | TCP port 3389 Raw | MEDIUM |
| SMB connections | TCP port 445 Raw | MEDIUM |
| NTP servers | UDP port 123 NTP | LOW |
| DHCP domains | UDP ports 67/68 DHCP | MEDIUM |
| SNMP community | UDP port 161 Raw | HIGH |
| IRC commands | TCP port 6667 Raw | HIGH |
| MySQL queries | TCP port 3306 Raw | HIGH |
| PostgreSQL queries | TCP port 5432 Raw | HIGH |
| LDAP binds | TCP port 389 Raw | MEDIUM |
| Kerberos realms | UDP/TCP port 88 Raw | MEDIUM |
| SIP methods | UDP port 5060 Raw | MEDIUM |
| BitTorrent handshake | TCP Raw | LOW |
| JSON/XML URLs | HTTP payload | MEDIUM |
| DNS tunneling | DNS TXT large | HIGH |
| MQTT topics | TCP port 1883 Raw | MEDIUM |
| Beaconing | IP timestamps | HIGH |
| ICMP types | ICMP | LOW |
| Anomalies | Duże payloady | MEDIUM |
| Rare ports | Nietypowe porty | LOW |

Siec izolowana: `restrict=on` — VM nie ma dostepu do hosta ani LAN.

---

## Analiza dual-VM — jak dzialaja wyniki

```
Upload probka
  -> YARA + SIGMA (< 1s)
  -> score >= 70 LUB .exe/.dll/.ps1/.evtx
  -> asyncio.gather(win10, win11) — rownolegla analiza
  -> results_merger.py:
       - Deduplikacja IOC po value
       - seen_on: [win10] / [win11] / [win10, win11]
       - os_diff: co widac TYLKO na win10, TYLKO na win11
       - max_score = max(win10.score, win11.score)
```

---

## VNC — hasla

| VM | Port | Haslo | Kiedy |
|----|------|-------|-------|
| Win10 | 5901 | brak | podczas instalacji ISO |
| Win10 | 5901 | noriben | sandbox (analiza malware) |
| Win11 | 5902 | brak | podczas instalacji ISO |
| Win11 | 5902 | noriben | sandbox (analiza malware) |

---

## KVM na Ubuntu

```bash
egrep -c '(vmx|svm)' /proc/cpuinfo   # > 0 = OK
sudo apt install qemu-kvm
sudo usermod -aG kvm $USER && sudo chmod 666 /dev/kvm
newgrp kvm
```

---

## Troubleshooting

| Problem | Rozwiazanie |
|---------|-------------|
| Win11 blad TPM | Shift+F10 podczas instalacji → komendy bypass powyzej |
| VM nie bootuje, brak dysku | Sprawdz flage `index=0,media=disk` |
| VNC czarny ekran | Uzyj TigerVNC: `vncviewer localhost:5901` |
| ISO pobieranie zawiesza sie | Skrypt ponowi do 10 razy — czekaj lub pobierz recznie |
| PCAP pusty | Sprawdz czy QEMU >= 2.11 (`qemu-system-x86_64 --version`) |
| `docker compose` not found | `sudo apt install docker-compose-plugin` |
| Port 5901/5902 zajety | `kill $(lsof -t -i :5901)` |
| Brak wynikow dynamicznych | `docker compose logs celery` |
| Win11 wolno dziala (TCG) | Mac ARM/Intel bez KVM — normalny czas analizy 15-20 min |

---

## Automated installer

A convenience script is provided to prepare a development or testing host (macOS or Ubuntu). It performs a best-effort installation of system packages, creates a Python virtualenv and installs Python dependencies.

Run (from repository root):

```bash
chmod +x scripts/setup_env.sh
./scripts/setup_env.sh
```

The script will:
- Install system packages (Homebrew on macOS, apt on Ubuntu) such as Python, Postgres (psql), libpq (pg_config), yara, clamav, qemu, redis and Docker where available.
- Create a virtualenv at `.venv`, install runtime and dev Python dependencies (requirements.txt, requirements-dev.txt).
- Create a default upload directory (/tmp/noriben_uploads) and attempt to create a Postgres role/database 'noriben' with password 'noriben123' (best-effort).

Additionally, a simple web-based configuration UI is available at /admin (when the API is running). The admin UI allows:
- Viewing and editing runtime configuration (DATABASE_URL, CELERY_BROKER, UPLOAD_DIR, logging settings, API keys)
- Persisting configuration to .env and applying changes without restarting the server
- Attempting best-effort Postgres role/database creation
- Running the setup script from the server (best-effort)

Notes:
- The admin UI does not implement authentication — do not expose it to untrusted networks without adding access control.
- The setup and DB creation actions are best-effort and may require manual intervention or elevated privileges.
- Review the script before running, it uses sudo for system package installation and service control.


## Developer setup (macOS / Ubuntu)

Suggested manual steps (alternative to the installer):

- Create and activate a virtualenv:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -U pip
```

- Install Python dev/test dependencies:

```bash
pip install -r requirements-dev.txt
```

- System packages (if you plan to run full integration or YARA/psycopg2 builds):

macOS (Homebrew):

```bash
brew install postgresql yara clamav qemu
```

Ubuntu (apt):

```bash
sudo apt update
sudo apt install -y build-essential libpq-dev postgresql yara clamav qemu-system-x86
```

Note: `pg_config` is provided by libpq-dev/postgresql-client-dev. Install it before installing packages like psycopg2.

- Run tests (unit):

```bash
python -m pytest tests/test_pipeline.py::test_static -q
```

- For full test suite and integration tests you will need Docker and optionally QEMU images. See the top of this README for VM setup.

---

*Noriben SOC v6.8 — Cr3pT — 2026*
