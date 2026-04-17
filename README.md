# Noriben SOC v6.6 — Kompletny Manual
> Platforma analizy malware | Static + Dynamic | macOS M1/M2/M4 + Ubuntu | QEMU Win10
> Autor: Cr3pT | v6.6 | 2026

## Spis treści
1. [Wymagania](#1-wymagania)
2. [Szybki start](#2-szybki-start)
3. [Wykrywanie środowiska](#3-wykrywanie-środowiska)
4. [Instalacja Win10 qcow2](#4-instalacja-win10-qcow2)
5. [VNC — podgląd instalacji](#5-vnc--podgląd-instalacji)
6. [Analiza statyczna](#6-analiza-statyczna)
7. [Analiza dynamiczna QEMU](#7-analiza-dynamiczna-qemu)
8. [Interfejs UI v3](#8-interfejs-ui-v3)
9. [Grafana Dashboard](#9-grafana-dashboard)
10. [API Reference](#10-api-reference)
11. [Bezpieczeństwo](#11-bezpieczeństwo)
12. [Wydajność per środowisko](#12-wydajność-per-środowisko)
13. [Rozwiązywanie problemów](#13-rozwiązywanie-problemów)

---

## 1. Wymagania

### macOS (M1 / M2 / M4)
| Wymaganie | Wersja | Uwagi |
|-----------|--------|-------|
| Docker Desktop | >= 4.x | Włącz Rosetta w Settings → General |
| Homebrew | dowolna | https://brew.sh |
| QEMU | >= 8.x | `brew install qemu` (auto przez deploy.sh) |
| RAM | >= 8 GB | 4 GB dla VM + 2 GB stacku |
| Dysk | >= 80 GB | Win10 qcow2 ~20 GB + próbki |

### Linux (Ubuntu 22.04 / 24.04)
| Wymaganie | Wersja | Uwagi |
|-----------|--------|-------|
| Docker CE | >= 24.x | https://docs.docker.com/engine/install/ubuntu/ |
| KVM | kernel module | `sudo modprobe kvm_intel` lub `kvm_amd` |
| QEMU | >= 8.x | `sudo apt install qemu-system-x86 qemu-utils` |
| RAM | >= 8 GB | |
| Dysk | >= 80 GB | |

---

## 2. Szybki start

```bash
unzip Noriben_SOC_v6.6_FINAL.zip && cd Noriben_SOC_v6.6
chmod +x deploy.sh scripts/*.sh vms/*.sh
./deploy.sh
```

Po ~2 min (lub ~45 min przy pierwszym pobraniu Win10):
```
UI:      http://localhost:8000
Grafana: http://localhost:3000   admin / admin
VNC:     localhost:5901          haslo: noriben (sandbox) / bez hasla (instalacja)
API:     http://localhost:8000/docs
PgSQL:   localhost:5432          noriben / noriben123
```

---

## 3. Wykrywanie środowiska

`scripts/detect_env.sh` eksportuje `$NORIBEN_ENV`:

| Wartość | Opis | QEMU accel |
|---------|------|-----------|
| `APPLE_M4` | Mac M4 / M4 Pro / M4 Max | TCG multi + Rosetta |
| `APPLE_M2` | Mac M2 / M2 Pro / M2 Max | TCG multi |
| `APPLE_M1` | Mac M1 / M1 Pro / M1 Max | TCG multi |
| `APPLE_INTEL` | Mac Intel x86 | TCG |
| `LINUX_KVM` | Linux + /dev/kvm | KVM (najszybszy) |
| `LINUX_NO_KVM` | Linux bez KVM | TCG |

```bash
source scripts/detect_env.sh && echo $NORIBEN_ENV
```

### Aktywacja KVM na Ubuntu
```bash
egrep -c '(vmx|svm)' /proc/cpuinfo   # > 0 = OK
sudo apt install qemu-kvm libvirt-daemon-system
sudo usermod -aG kvm $USER && sudo chmod 666 /dev/kvm
newgrp kvm
```

---

## 4. Instalacja Win10 qcow2

### Automatyczna
```bash
bash scripts/win10_setup.sh   # bezpieczne do wielokrotnego uruchomienia
```

Skrypt:
1. Sprawdza `vms/win10.qcow2` — jesli istnieje, konczy od razu
2. Sprawdza `vms/win10.iso` — jesli kompletne (>3.2 GB), pomija pobieranie
3. Pobiera Win10 Enterprise Evaluation z Microsoft Evaluation Center (90-day trial)
4. Weryfikuje rozmiar ISO po pobraniu
5. Tworzy dysk: `qemu-img create -f qcow2 vms/win10.qcow2 60G`
6. Uruchamia instalacje Win10 z VNC na porcie 5901 (bez hasla)
7. Generuje `vms/noriben_setup.ps1`

### Konwersja wlasnego obrazu
```bash
qemu-img convert -f vdi  -O qcow2 win10.vdi  vms/win10.qcow2   # VirtualBox
qemu-img convert -f vmdk -O qcow2 win10.vmdk vms/win10.qcow2   # VMware
```

---

## 5. VNC — podgląd instalacji

Podczas instalacji Win10 VNC dziala **bez hasla** na porcie **5901**.

### Polaczenie z VNC
```bash
# macOS
open vnc://localhost:5901

# macOS — TigerVNC
vncviewer localhost:5901

# Linux — TigerVNC
vncviewer localhost:5901
vncviewer localhost::5901

# RealVNC Viewer — adres: localhost:5901  (bez hasla podczas instalacji)
```

### Porty VNC
| Faza | Port | Haslo | QEMU flag |
|------|------|-------|-----------|
| Instalacja Win10 | 5901 | brak | `-vnc 0.0.0.0:1` |
| Sandbox (analiza) | 5901 | `noriben` | `-vnc 0.0.0.0:0,password` |

> Jesli port 5901 zajety — skrypt auto-przelacza na 5902.

### Najczestsze bledy VNC

| Problem | Przyczyna | Rozwiazanie |
|---------|-----------|-------------|
| Connection refused | QEMU nie startuje | `ps aux | grep qemu` |
| Czarny ekran | `-display none` | Usunieto w v6.6 |
| Nie laczy localhost | `-vnc :1` tylko loopback | Zmieniono na `0.0.0.0:1` |
| Klient wymaga hasla | VNC client config | Uzyj TigerVNC lub RealVNC |

---

## 6. Analiza statyczna

Dziala natywnie bez VM — czas < 1 sekunda.

### Wspierane formaty
| Format | Silnik | Wykrywa |
|--------|--------|---------|
| `.exe` `.dll` `.scr` | YARA | Sygnatury malware, packer, shellcode |
| `.ps1` `.vbs` `.js` | YARA + SIGMA | Obfuskacja, LOLbins, encoded |
| `.evtx` | EVTX parser | Event ID 4625, 4688, 7045... |
| Dowolny | SIGMA | Pattern matching na tekscie |

### Scoring (0-100)
```
YARA HIGH    +25 pkt | YARA MEDIUM  +15 pkt
SIGMA HIGH   +20 pkt | SIGMA MEDIUM +10 pkt
Score >= 70  -> auto uruchamia analize dynamiczna
```

---

## 7. Analiza dynamiczna QEMU

```
Upload .exe -> static score >= 70 LUB .exe/.dll/.ps1
  -> QEMU Win10 start (snapshot=on, restrict=on)
  -> Noriben Procmon 5 min
  -> Zbierz: siec / pliki / procesy / rejestr
  -> JSON -> PostgreSQL -> UI
  -> VM auto-reset do czystego stanu
```

### Reczne uruchomienie
```bash
bash vms/noriben_qemu_sandbox.sh /path/to/malware.exe 300
open vnc://localhost:5901    # macOS — haslo: noriben
vncviewer localhost:5901     # Linux
```

---

## 8. Interfejs UI v3 — http://localhost:8000

| Funkcja | Opis |
|---------|------|
| Dark/Light mode | Przycisk w naglowku |
| Drag & Drop | Przeciagnij probke |
| Multi-file | Wiele probek naraz (Celery) |
| Static/Dynamic tabs | YARA/SIGMA/EVTX + Network/Files/Processes/Registry |
| MITRE ATT&CK | Auto-mapowanie technik |
| VNC Live | Przycisk -> polaczenie z VM |
| Ctrl+K / Cmd+K | Szukaj po SHA256 |
| WebSocket | Metryki live co 3s |
| Env badge | APPLE_M4 / LINUX_KVM / ... |

---

## 9. Grafana Dashboard — http://localhost:3000

Login: **admin / admin**

| Panel | Typ |
|-------|-----|
| Sessions/hour | Graph |
| Severity breakdown | Pie Chart |
| MITRE heatmap | Heatmap |
| Top YARA rules | Bar Gauge |

---

## 10. API Reference

| Endpoint | Metoda | Opis |
|----------|--------|------|
| `/` | GET | UI v3 |
| `/upload` | POST | Przeslij probke |
| `/job/{id}` | GET | Status Celery |
| `/sessions` | GET | Lista analiz |
| `/sessions/{sha256}` | GET | Szczegoly |
| `/ws` | WS | Real-time WebSocket |
| `/health` | GET | Status + env |
| `/docs` | GET | Swagger UI |

```bash
curl -F "file=@malware.exe" http://localhost:8000/upload
curl http://localhost:8000/health
# {"status":"ok","version":"6.6","env":"LINUX_KVM"}
```

---

## 11. Bezpieczenstwo

| Kryterium | QEMU VM | Docker |
|-----------|---------|--------|
| Izolacja kernela | Pelna (hypervisor) | Brak (shared kernel) |
| VM escape | Niskie | Wysokie (CVE-2019-5736) |
| Wykrywalnosc | Srednia | Bardzo latwa (/.dockerenv) |
| Snapshot | Automatyczny | Brak |

> Nigdy nie uruchamiaj malware na hoscie ani w Docker.

```bash
# Izolacja sieci QEMU:
-netdev user,id=net0,restrict=on    # brak dostepu do hosta/LAN
-drive file=win10.qcow2,snapshot=on # VM czysta po kazdej analizie

# Dodatkowa izolacja hosta (Linux):
sudo iptables -I FORWARD -i virbr0 -d 192.168.122.1 -j DROP
```

---

## 12. Wydajnosc per srodowisko

| Srodowisko | Static | Dynamic | Accel |
|-----------|--------|---------|-------|
| Ubuntu + KVM | <1s | ~3-5 min | KVM |
| Mac M4 Max | <1s | ~10-12 min | TCG |
| Mac M2 Pro | <1s | ~13-15 min | TCG |
| Mac M1 | <1s | ~15-18 min | TCG |
| Mac Intel | <1s | ~8-10 min | TCG |

### Optymalizacja Mac M4
```bash
# Docker Desktop -> Settings -> General -> Use Rosetta
# Resources -> CPUs: 8, Memory: 8 GB
```

---

## 13. Rozwiazywanie problemow

| Problem | Rozwiazanie |
|---------|-------------|
| VNC "Connection refused" | `ps aux | grep qemu` — czy QEMU dziala |
| VNC czarny ekran | Uzywaj TigerVNC lub RealVNC |
| `win10.qcow2 not found` | `bash scripts/win10_setup.sh` |
| ISO niekompletne | Skrypt ponowi pobieranie automatycznie |
| KVM niedostepne | `sudo modprobe kvm_intel && sudo chmod 666 /dev/kvm` |
| Brak wynikow dynamicznych | `docker-compose logs celery` |
| No space left | `docker system prune -a --volumes` |
| Port 5901 zajety | Skrypt auto-przelacza na 5902 |

---
*Noriben SOC v6.6 — Cr3pT — 2026*
