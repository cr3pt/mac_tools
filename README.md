# Noriben SOC v6.6
# Static + Dynamic | Mac M1/M2/M4 + Ubuntu | Win10 qcow2 auto-setup

## Deploy:
    chmod +x deploy.sh && ./deploy.sh
    # Skrypt auto-wykryje: Apple M1/M2/M4 lub Ubuntu/Linux
    # Pobierze Win10 ISO i skonwertuje do .qcow2 automatycznie

## URLs:
    UI:      http://localhost:8000
    Grafana: http://localhost:3000  (admin/admin)
    VNC:     localhost:5901         (noriben)
    API:     http://localhost:8000/docs

## Bezpieczeństwo analizy malware:
    QEMU VM  = najwyższa izolacja (kernel-level VM)
    Docker   = NIE używamy do uruchamiania malware (shared kernel!)
    Sieć     = izolowana (iptables + no-internet w QEMU)
    Snapshot = Win10 przywracany po każdej analizie

## Wymagania:
    macOS: Docker Desktop >= 4.x, Homebrew
    Linux: Docker CE, KVM (auto-install przez setup.sh)
