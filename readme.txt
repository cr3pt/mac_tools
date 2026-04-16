Noriben QEMU Sandbox - v5.8 prepare cross-platform

Najważniejsze nowości:
- opcja --prepare do przygotowania środowiska hosta
- prepare tworzy katalogi host_tools_dir i host_results_dir
- prepare zapisuje plan do prepare_plan.json
- rekomendacja profilu hosta: macos-arm64, ubuntu-x86_64, ubuntu-arm64 lub generic
- rozwinięta warstwa cross-platform dla QEMU
- dodatkowe testy dla prepare

Czy działa na Ubuntu i macOS?
Tak, projekt jest rozwijany właśnie w tym kierunku.

Co robi prepare:
1. wykrywa platformę i architekturę hosta
2. sprawdza dostępność narzędzi: python3, ssh, scp, qemu-img, qemu-system-aarch64, qemu-system-x86_64
3. tworzy katalogi na narzędzia i wyniki
4. wybiera rekomendowany profil platformy
5. zapisuje plan przygotowania do JSON

Przykłady:
- przygotowanie środowiska:
  PYTHONPATH=. python3 -m noriben58.cli --prepare
- host info:
  PYTHONPATH=. python3 -m noriben58.cli --show-host-info --preflight-only
- pojedyncza próbka:
  PYTHONPATH=. python3 -m noriben58.cli /path/sample.exe
- batch:
  PYTHONPATH=. python3 -m noriben58.cli /path/samples --batch --dual-vm

Uwaga praktyczna:
Opcja prepare nie instaluje pakietów systemowych automatycznie. Przygotowuje plan, katalogi i podpowiedzi, ale instalację QEMU/OpenSSH/Python trzeba wykonać odpowiednio dla Ubuntu lub macOS.
