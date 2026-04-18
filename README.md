# Noriben SOC v6.8 — Manual
> Static + Dynamic | Win10 + Win11 rownolegla | PCAP Network IOC | Cr3pT 2026

## Szybki start

```bash
unzip Noriben_SOC_v6.8_FINAL.zip && cd Noriben_SOC_v6.8
chmod +x deploy.sh scripts/*.sh vms/*.sh
./deploy.sh
```

```
UI:        http://localhost:8000
Grafana:   http://localhost:3000     admin / admin
Win10 VNC: localhost:5901            instalacja: BEZ hasla / sandbox: noriben
Win11 VNC: localhost:5902            haslo: noriben
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

---

## Obrazy VM — co skrypt robi automatycznie

### Win11 — gotowy qcow2 (bez instalacji)
```
scripts/win_setup.sh -> pobiera win11_enterprise_eval_notpm.qcow2.zst
                     -> rozpakowuje do vms/win11.qcow2
                     -> gotowe do uzycia od razu
```

### Win10 — ISO + instalacja przez VNC
```
scripts/win_setup.sh -> pobiera Win10 Enterprise Evaluation ISO (~4.5 GB)
                     -> tworzy dysk vms/win10.qcow2 (60 GB)
                     -> uruchamia QEMU z VNC (bez hasla) na localhost:5901
                     -> czekasz na instalacje przez VNC, potem uruchamiasz noriben_setup.ps1
```

### VNC podczas instalacji Win10
```bash
open vnc://localhost:5901    # macOS (bez hasla)
vncviewer localhost:5901     # Linux (bez hasla)
```

Po instalacji Win10 — w VM przez VNC:
```powershell
Set-ExecutionPolicy Bypass -Scope Process
C:\shared\noriben_setup.ps1
```

### Gotowy qcow2 (opcja szybka)
```bash
cp /path/to/win10_ready.qcow2 vms/win10.qcow2
cp /path/to/win11_ready.qcow2 vms/win11.qcow2
```

### Konwersja z VirtualBox / VMware
```bash
qemu-img convert -f vdi  -O qcow2 win10.vdi  vms/win10.qcow2
qemu-img convert -f vmdk -O qcow2 win11.vmdk vms/win11.qcow2
```

---

## QEMU — kluczowe flagi (dysk zawsze podpiety)

```bash
-drive file=win10.qcow2,format=qcow2,if=virtio,index=0,media=disk,snapshot=on
```

| Flaga | Znaczenie |
|-------|-----------|
| `format=qcow2` | Jawny format — bez auto-detekcji |
| `if=virtio` | Sterownik VirtIO (wydajny) |
| `index=0` | Dysk jako pierwsze urzadzenie |
| `media=disk` | Typ: dysk (nie CD-ROM) |
| `snapshot=on` | Zmiany tylko w RAM — VM czysta po kazdej analizie |

---

## Przechwyt ruchu sieciowego (PCAP)

Kazda VM uzywa `-object filter-dump` — przechwytuje 100% ruchu:

```bash
-object filter-dump,id=dump10,netdev=net10,file=results/sample_win10.pcap
```

Wyniki parsowane przez `scapy` (network_analyzer.py):
- Zewnetrzne IP (nie RFC1918)
- DNS queries (domeny podejrzane: .ru .cn .tk .xyz oznaczone HIGH)
- HTTP GET/POST (port 80)

Siec izolowana: `restrict=on` — VM nie ma dostepu do hosta ani LAN.

---

## Analiza dual-VM — jak dzialaja wyniki

```
Upload probka
  -> YARA + SIGMA (< 1s)
  -> score >= 70 LUB .exe/.dll/.ps1
  -> asyncio.gather(win10, win11) — rownolegla analiza
  -> results_merger.py:
       - Deduplikacja IOC po value
       - seen_on: [win10] / [win11] / [win10, win11]
       - os_diff: co widac TYLKO na win10, TYLKO na win11
       - max_score = max(win10.score, win11.score)
  -> Wyniki w UI: tabela IOC + panel roznic OS
```

---

## VNC — hasla

| VM | Port | Haslo | Kiedy |
|----|------|-------|-------|
| Win10 | 5901 | brak | podczas instalacji ISO |
| Win10 | 5901 | noriben | sandbox (analiza malware) |
| Win11 | 5902 | noriben | zawsze (gotowy obraz) |

Haslo ustawiane przez QEMU monitor:
```bash
echo "change vnc password noriben" | nc -q1 127.0.0.1 4441
```

---

## KVM na Ubuntu

```bash
egrep -c '(vmx|svm)' /proc/cpuinfo   # > 0 = OK
sudo apt install qemu-kvm
sudo usermod -aG kvm $USER
sudo chmod 666 /dev/kvm
newgrp kvm
# deploy.sh automatycznie wykrywa i uzywa KVM
```

---

## Troubleshooting

| Problem | Rozwiazanie |
|---------|-------------|
| VM nie bootuje, brak dysku | Sprawdz flage `index=0,media=disk` w qemu cmd |
| VNC czarny ekran | Uzyj TigerVNC: `vncviewer localhost:5901` |
| win11.qcow2 nie pobiera | Sprawdz URL archiwum lub skopiuj recznie |
| Win11 nie startuje (TPM) | Obraz ma wylaczony TPM — jesli problem: dodaj `-device tpm-tis` |
| PCAP pusty | Sprawdz czy `filter-dump` wspiera twoja wersje QEMU (>= 2.11) |
| `docker compose` not found | `sudo apt install docker-compose-plugin` |
| Port 5901/5902 zajety | `kill $(lsof -t -i:5901)` |
| Brak wynikow dynamicznych | `docker compose logs celery` |

---
*Noriben SOC v6.8 — Cr3pT — 2026*
