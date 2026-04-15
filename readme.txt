Noriben QEMU Sandbox - v5.7 cross-platform

Ta wersja rozwija linię 5.5 -> 5.6 -> 5.7 i skupia się na przenośności host-side między Ubuntu i macOS.

Co doszło od 5.5/5.6:
- osobny moduł platform_qemu.py
- wykrywanie hosta: platforma, architektura, kvm/hvf
- wybór akceleracji: auto/hvf/kvm/tcg
- budowanie komendy QEMU zależnie od platformy i guest arch
- raport HTML z host_info
- więcej detekcji: credential access i discovery rozszerzone o dodatkowe MITRE
- dodatkowe testy dla warstwy platformowej QEMU
- Makefile i pytest.ini

Czy działa na Ubuntu i na macOS?
Tak, host-side jest przygotowany pod oba systemy.

Praktycznie:
- macOS Apple Silicon: preferowany guest ARM/aarch64; x86_64 możliwy, ale zwykle wolniejszy przez emulację
- Ubuntu x86_64: preferowany guest x86_64 z KVM, jeśli /dev/kvm jest dostępne
- Ubuntu bez KVM lub nietypowy host: fallback do TCG

Ograniczenia:
- pełna zgodność zależy od obrazu Windows, dostępności OpenSSH, Noriben i zgodności guest/host arch
- profile QEMU są ogólne i mogą wymagać dopracowania pod konkretny obraz
- macOS + x86 Windows guest na Apple Silicon pozostanie wolniejszy niż natywnie zgodny guest ARM

Szybki start:
- host info:
  PYTHONPATH=. python3 -m noriben57.cli --show-host-info --preflight-only
- pojedyncza próbka:
  PYTHONPATH=. python3 -m noriben57.cli /path/sample.exe
- batch:
  PYTHONPATH=. python3 -m noriben57.cli /path/samples --batch --dual-vm

Najważniejszy sens 5.7:
Skrypt nie jest już tylko 'napisany w Pythonie', ale zaczyna świadomie rozróżniać platformę hosta i dobierać sposób uruchamiania QEMU pod Ubuntu albo macOS.
