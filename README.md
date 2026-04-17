# Noriben SOC v6.6 — Kompletny Manual

> **Platforma analizy malware** | Static + Dynamic | macOS M1/M2/M4 + Ubuntu | QEMU Win10

---

## Spis treści

1. [Wymagania](#1-wymagania)
2. [Szybki start](#2-szybki-start)
3. [Wykrywanie środowiska](#3-wykrywanie-środowiska)
4. [Instalacja Win10 qcow2](#4-instalacja-win10-qcow2)
5. [Analiza statyczna](#5-analiza-statyczna)
6. [Analiza dynamiczna QEMU](#6-analiza-dynamiczna-qemu)
7. [Interfejs UI v3](#7-interfejs-ui-v3)
8. [Grafana Dashboard](#8-grafana-dashboard)
9. [API Reference](#9-api-reference)
10. [Bezpieczeństwo](#10-bezpieczeństwo)
11. [Wydajność per środowisko](#11-wydajność-per-środowisko)
12. [Rozwiązywanie problemów](#12-rozwiązywanie-problemów)

---

## 1. Wymagania

### macOS (M1 / M2 / M4)
| Wymaganie | Wersja | Uwagi |
|-----------|--------|-------|
| Docker Desktop | >= 4.x | Włącz Rosetta w Settings |
| Homebrew | dowolna | https://brew.sh |
| QEMU | >= 8.x | `brew install qemu` (auto przez deploy.sh) |
| RAM | >= 8 GB | 4 GB dla VM + 2 GB dla stack |
| Dysk | >= 80 GB | Win10 qcow2 ~20 GB + próbki |

### Linux (Ubuntu 22.04 / 24.04)
| Wymaganie | Wersja | Uwagi |
|-----------|--------|-------|
| Docker CE | >= 24.x | https://docs.docker.com/engine/install/ubuntu/ |
| KVM | kernel module | `sudo modprobe kvm_intel` lub `kvm_amd` |
| QEMU | >= 8.x | `sudo apt install qemu-system-x86` |
| RAM | >= 8 GB | |
| Dysk | >= 80 GB | |

---

## 2. Szybki start

```bash
# 1. Rozpakuj archiwum
unzip Noriben_SOC_v6.6_DOWNLOAD.zip
cd Noriben_SOC_v6.6

# 2. Nadaj uprawnienia
chmod +x deploy.sh scripts/*.sh vms/*.sh

# 3. Deploy (auto-detect środowiska + Win10 setup)
./deploy.sh

# 4. Sprawdź status
docker-compose ps
curl http://localhost:8000/health
```

Po ~2 minutach (lub ~45 min przy pierwszym pobraniu Win10):

```
🌐  UI:      http://localhost:8000
📊  Grafana: http://localhost:3000   admin / admin
🖥️   VNC:     localhost:5901          hasło: noriben
📈  API:     http://localhost:8000/docs
🐘  PgSQL:   localhost:5432           noriben / noriben123
```

---

## 3. Wykrywanie środowiska

`scripts/detect_env.sh` auto-wykrywa środowisko i eksportuje `$NORIBEN_ENV`:

| Wartość | Opis | Akceleracja QEMU |
|---------|------|-----------------|
| `APPLE_M4` | Mac M4 / M4 Pro / M4 Max | TCG multi-thread + Rosetta |
| `APPLE_M2` | Mac M2 / M2 Pro / M2 Max | TCG multi-thread |
| `APPLE_M1` | Mac M1 / M1 Pro / M1 Max | TCG multi-thread |
| `APPLE_INTEL` | Mac Intel x86 | TCG |
| `LINUX_KVM` | Linux z /dev/kvm | **KVM** (najszybszy) |
| `LINUX_NO_KVM` | Linux bez KVM | TCG |

```bash
# Ręczne sprawdzenie środowiska
source scripts/detect_env.sh
echo $NORIBEN_ENV
```

### Aktywacja KVM na Ubuntu (jeśli brak)
```bash
# Sprawdź obsługę wirtualizacji
egrep -c '(vmx|svm)' /proc/cpuinfo   # > 0 = OK

# Zainstaluj KVM
sudo apt install qemu-kvm libvirt-daemon-system
sudo usermod -aG kvm $USER
sudo chmod 666 /dev/kvm
newgrp kvm
```

---

## 4. Instalacja Win10 qcow2

### Automatyczna (zalecana)
```bash
# deploy.sh robi to automatycznie przy pierwszym uruchomieniu
# Lub ręcznie:
bash scripts/win10_setup.sh
```

Skrypt:
1. Pobiera **Windows 10 Enterprise Evaluation** z Microsoft Evaluation Center
   - Licencja: 90-day trial, tylko do celów testowych
   - Źródło: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise
2. Tworzy dysk 60 GB: `qemu-img create -f qcow2 vms/win10.qcow2 60G`
3. Uruchamia instalację (20-40 min, VNC dostępny na `localhost:5902`)
4. Generuje `vms/noriben_setup.ps1` do instalacji Noriben w VM

### Manualna (jeśli masz własny obraz)
```bash
# Skopiuj swój obraz Win10:
cp /path/to/win10.qcow2 vms/win10.qcow2

# Lub konwertuj z ISO:
qemu-img create -f qcow2 vms/win10.qcow2 60G
qemu-system-x86_64 -m 4096 -cdrom win10.iso -drive file=vms/win10.qcow2,if=virtio -boot d

# Lub konwertuj z VDI/VMDK (VirtualBox/VMware):
qemu-img convert -f vdi  -O qcow2 win10.vdi  vms/win10.qcow2
qemu-img convert -f vmdk -O qcow2 win10.vmdk vms/win10.qcow2
```

### Instalacja Noriben w Win10 VM
```powershell
# Uruchom w VM (przez VNC localhost:5901):
Set-ExecutionPolicy Bypass -Scope Process
C:\shared\noriben_setup.ps1

# Ręcznie:
pip install psutil
git clone https://github.com/Rurik/Noriben C:\noriben
```

---

## 5. Analiza statyczna

Analiza statyczna działa **natywnie bez VM** (<1 sekunda).

### Wspierane formaty
| Format | Silnik | Co wykrywa |
|--------|--------|-----------|
| `.exe` `.dll` `.scr` | YARA | Sygnatury malware, packer, shellcode |
| `.ps1` `.vbs` `.js` | YARA + SIGMA | Obfuskacja, LOLbins, encoded commands |
| `.evtx` | EVTX parser | Podejrzane Event ID (4625, 4688, 7045...) |
| `.pml` | Noriben parser | Procmon log — procesy, rejestr, sieć |
| Dowolny | SIGMA | Pattern matching na tekście |

### Scoring (0-100)
```
YARA HIGH match    +25 pkt
YARA MEDIUM match  +15 pkt
SIGMA HIGH match   +20 pkt
SIGMA MEDIUM match +10 pkt
```

Score >= 70 → automatycznie uruchamia analizę dynamiczną.

### YARA rules (auto-pobierane)
```bash
# Zaktualizuj reguły:
cd vms/yara_rules && git pull
```
Źródło: https://github.com/Yara-Rules/rules (~3000 reguł)

---

## 6. Analiza dynamiczna QEMU

Analiza dynamiczna uruchamia próbkę w **izolowanej VM Windows 10**.

### Przepływ
```
Upload .exe
    ↓
Static score >= 70 LUB plik .exe/.dll/.ps1
    ↓
QEMU Win10 VM start (snapshot=on)
    ↓
Noriben Procmon monitoring
    ↓
Wykonaj próbkę (timeout: 5 min)
    ↓
Zbierz: sieć / pliki / procesy / rejestr
    ↓
JSON wynik → PostgreSQL
    ↓
VM auto-przywrócona do czystego stanu
```

### Ręczne uruchomienie
```bash
# Uruchom sandbox bezpośrednio:
bash vms/noriben_qemu_sandbox.sh /path/to/malware.exe 300

# VNC podgląd VM:
open vnc://localhost:5901          # macOS
vncviewer localhost:5901           # Linux (hasło: noriben)
```

### Wyniki dynamicznej
```json
{
  "behavior_score": 92,
  "network": ["192.168.1.100:4444", "evil.example.com"],
  "files_dropped": ["C:\Users\Public\dropper.exe"],
  "processes": ["cmd.exe", "powershell.exe -enc ..."],
  "registry": ["HKLM\Software\Run\malware"],
  "raw_pml": "/shared/results/malware.pml"
}
```

---

## 7. Interfejs UI v3

Adres: **http://localhost:8000**

### Funkcje
- **Dark / Light mode** — przycisk ☀️ w nagłówku
- **Drag & Drop upload** — przeciągnij próbkę na pole
- **Multi-file** — wiele próbek naraz (kolejka Celery)
- **Static tab** — YARA / SIGMA / EVTX metrics
- **Dynamic tab** — Network / Files / Processes / Registry
- **MITRE ATT&CK** — automatyczne mapowanie technik
- **VNC Live** — przycisk otwiera połączenie z VM
- **⌘K / Ctrl+K** — wyszukaj po SHA256 lub nazwie pliku
- **WebSocket** — metryki aktualizowane co 3 sekundy
- **Env badge** — pokazuje wykryte środowisko (APPLE_M4 / LINUX_KVM...)

---

## 8. Grafana Dashboard

Adres: **http://localhost:3000** (admin / admin)

### Panele
| Panel | Typ | Opis |
|-------|-----|------|
| Sessions/hour | Graph | Liczba analiz w czasie |
| Severity breakdown | Pie Chart | Clean / Suspicious / Malware |
| MITRE heatmap | Heatmap | Najczęstsze techniki ATT&CK |
| Top YARA rules | Bar Gauge | Najczęściej trafiające reguły |

### Dodawanie własnych dashboardów
```bash
# Wrzuć JSON do:
grafana/provisioning/dashboards/your_dashboard.json
docker-compose restart grafana
```

---

## 9. API Reference

Base URL: `http://localhost:8000`

| Endpoint | Metoda | Opis |
|----------|--------|------|
| `/` | GET | UI v3 |
| `/upload` | POST | Prześlij próbkę (multipart/form-data) |
| `/job/{id}` | GET | Status zadania Celery |
| `/sessions` | GET | Lista analiz (param: `limit`) |
| `/sessions/{sha256}` | GET | Szczegóły analizy |
| `/ws` | WS | Real-time metryki WebSocket |
| `/health` | GET | Status + wersja + środowisko |
| `/docs` | GET | Swagger UI |

### Przykłady
```bash
# Upload próbki
curl -F "file=@malware.exe" http://localhost:8000/upload
# → {"job_id":"abc123","filename":"malware.exe","status":"queued"}

# Status zadania
curl http://localhost:8000/job/abc123
# → {"status":"SUCCESS","result":{...}}

# Lista ostatnich analiz
curl http://localhost:8000/sessions?limit=10

# Szczegóły po SHA256
curl http://localhost:8000/sessions/a1b2c3...64hex

# Health check
curl http://localhost:8000/health
# → {"status":"ok","version":"6.6","env":"LINUX_KVM"}
```

---

## 10. Bezpieczeństwo

### Dlaczego QEMU, nie Docker do malware

| Kryterium | QEMU VM ✅ | Docker ❌ |
|-----------|-----------|---------|
| Izolacja kernela | Pełna (hypervisor) | Brak (shared kernel) |
| VM escape ryzyko | Niskie | Wysokie |
| Wykrywalność przez malware | Średnia | Bardzo łatwa |
| Snapshot/restore | ✅ Automatyczny | ❌ Brak |
| Zalecenie do analizy | ✅ TAK | ❌ NIE |

> ⚠️ **Nigdy nie uruchamiaj malware bezpośrednio na hoście ani w kontenerze Docker.**

### Konfiguracja sieci izolowanej
```bash
# W noriben_qemu_sandbox.sh używamy:
-netdev user,id=net0,restrict=on
# restrict=on = QEMU nie ma dostępu do hosta i sieci LAN
# Dozwolone: QEMU → internet (do analizy C2)
```

### Automatyczny snapshot
```bash
# snapshot=on w QEMU = zmiany tylko w RAM
-drive file=win10.qcow2,if=virtio,snapshot=on
# Po każdej analizie VM wraca do czystego stanu automatycznie
```

### Izolacja sieciowa hosta (Linux)
```bash
sudo iptables -I FORWARD -i virbr0 -d 192.168.122.1 -j DROP
sudo iptables -I INPUT -i virbr0 -j DROP
```

---

## 11. Wydajność per środowisko

| Środowisko | Static | Dynamic | QEMU accel | Uwagi |
|-----------|--------|---------|-----------|-------|
| **Ubuntu + KVM** | <1s | ~3-5 min | KVM | Najlepsza opcja |
| **Mac M4 Max** | <1s | ~10-12 min | TCG multi | Rosetta dla Docker |
| **Mac M4 Pro** | <1s | ~11-13 min | TCG multi | |
| **Mac M2 Pro** | <1s | ~13-15 min | TCG multi | |
| **Mac M1** | <1s | ~15-18 min | TCG multi | |
| **Mac Intel** | <1s | ~8-10 min | TCG | |

### Optymalizacja Mac M4
```bash
# 1. Włącz Rosetta w Docker Desktop
# Settings → General → ✅ Use Rosetta for x86/amd64 emulation

# 2. Zwiększ zasoby Docker
# Settings → Resources → CPUs: 8, Memory: 8 GB

# 3. UTM zamiast QEMU (opcjonalne, ~2x szybszy)
brew install --cask utm
```

---

## 12. Rozwiązywanie problemów

### ❌ `OSError: No space left on device`
```bash
docker system prune -a --volumes
docker volume prune -f
```

### ❌ `win10.qcow2 not found`
```bash
bash scripts/win10_setup.sh
# LUB skopiuj własny obraz do vms/win10.qcow2
```

### ❌ QEMU nie startuje na Mac
```bash
brew install qemu
# Sprawdź Rosetta:
softwareupdate --install-rosetta --agree-to-license
```

### ❌ KVM niedostępne na Linux
```bash
sudo modprobe kvm_intel   # Intel
sudo modprobe kvm_amd     # AMD
sudo usermod -aG kvm $USER
sudo chmod 666 /dev/kvm
newgrp kvm
```

### ❌ VNC nie łączy
```bash
# Sprawdź czy QEMU działa:
docker-compose logs qemu
# Sprawdź port:
nc -zv localhost 5901
```

### ❌ Brak wyników analizy dynamicznej
```bash
# Sprawdź logi Celery:
docker-compose logs celery
# Sprawdź folder wyników:
ls vms/results/
```

### ❌ Grafana pusta / brak danych
```bash
docker-compose restart grafana
# Sprawdź datasource:
curl http://localhost:3000/api/health
```

---

## Licencja i podziękowania

- **Noriben Procmon**: https://github.com/Rurik/Noriben (MIT)
- **YARA Rules**: https://github.com/Yara-Rules/rules (GPL)
- **Win10 Evaluation**: Microsoft Evaluation Center (90-day trial)
- **Platforma**: Noriben SOC v6.6 — Marcin Michalczyk, 2026
