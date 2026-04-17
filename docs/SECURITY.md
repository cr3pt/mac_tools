# Bezpieczenstwo — Noriben SOC v6.6 — Cr3pT

## QEMU vs Docker do analizy malware

| Kryterium | QEMU VM | Docker |
|-----------|---------|--------|
| Izolacja kernela | Pelna (hypervisor) | Brak (shared kernel) |
| VM escape | Niskie | Wysokie (CVE-2019-5736) |
| Wykrywalnosc | Srednia | Bardzo latwa (/.dockerenv) |
| Snapshot/restore | Automatyczny | Brak |
| Zalecenie | TAK | NIE |

> Nigdy nie uruchamiaj malware w Docker ani na hoscie.

## Kluczowe flagi QEMU
```
snapshot=on          VM czysta po kazdej analizie (zmiany tylko w RAM)
restrict=on          brak dostepu do hosta i sieci LAN z VM
0.0.0.0:0,password   VNC z haslem (sandbox)
0.0.0.0:1            VNC bez hasla (instalacja Win10)
```

## Dodatkowa izolacja hosta (Linux)
```bash
sudo iptables -I FORWARD -i virbr0 -d 192.168.122.1 -j DROP
sudo iptables -I INPUT -i virbr0 -j DROP
```
