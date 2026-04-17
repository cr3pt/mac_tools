# Bezpieczeństwo analizy malware — Noriben SOC v6.6

## Porównanie środowisk izolacji

| Środowisko     | Izolacja kernela | VM escape ryzyko | Wykrywalność | Zalecenie |
|----------------|-----------------|-----------------|--------------|-----------|
| **QEMU VM**    | ✅ PEŁNA (hypervisor) | Niskie | Średnia | ✅ UŻYWAMY |
| Docker         | ❌ Shared kernel | Wysokie (cgroups escape) | Bardzo łatwe | ❌ NIE DO MALWARE |
| VirtualBox     | ✅ Dobra         | Średnie | Łatwa | ⚠️ Opcja zapasowa |
| Bare metal     | ✅ Najlepsza    | Brak | Brak | 💰 Kosztowne |

## Dlaczego Docker NIE jest bezpieczny do analizy malware

1. **Shared kernel** — Docker dzieli kernel hosta z kontenerem
   - Malware z kernel exploit może uciec do hosta
   - Podatności: CVE-2019-5736 (runc), CVE-2022-0492 (cgroups)

2. **Łatwo wykrywalne** — nowoczesne malware sprawdza:
   ```
   - /.dockerenv
   - /proc/1/cgroup zawiera "docker"
   - hostname = losowy hash
   ```
   → malware się nie uruchomi, analiza bezużyteczna

3. **Brak snapshots** — nie można przywrócić stanu po infekcji

## Dlaczego QEMU jest bezpieczne

1. **Pełna wirtualizacja** — oddzielny kernel, oddzielna pamięć
2. **Snapshot po każdej analizie** — `snapshot=on` w qemu-img
3. **Sieć izolowana** — QEMU user networking (brak routingu)
4. **KVM na Linux** = hardware isolation (Intel VT-x / AMD-V)

## Konfiguracja sieci izolowanej (QEMU)

```bash
# W noriben_qemu_sandbox.sh:
-netdev user,id=net0,restrict=on   # restrict=on blokuje dostęp do hosta!
# Dozwolone tylko: QEMU → internet (do analizy C2)
# Blokowane: QEMU → host, QEMU → sieć lokalna
```

## Dodatkowe zabezpieczenia

### Izolacja hosta (iptables — Linux)
```bash
# Blokuj ruch z QEMU do hosta
sudo iptables -I FORWARD -i virbr0 -d 192.168.122.1 -j DROP
sudo iptables -I INPUT -i virbr0 -j DROP
```

### Snapshot — automatyczne przywracanie
```bash
# QEMU z snapshot=on kasuje zmiany po każdym uruchomieniu
qemu-system-x86_64 -drive file=win10.qcow2,if=virtio,snapshot=on
# ↑ snapshot=on = wszystkie zmiany w RAM, nie na dysku!
```

### Monitoring sieci
```bash
# Nagrywaj cały ruch sieciowy z VM
tcpdump -i virbr0 -w /shared/results/network_$(date +%s).pcap
