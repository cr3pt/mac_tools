Noriben QEMU Sandbox - v5.5.1 modular plus

Dodatki względem 5.5:
- więcej testów: test_config.py, test_reporting.py, test_detection.py
- requirements.txt z podstawowymi zależnościami pomocniczymi
- czytelniejszy raport HTML
- możliwość łatwego spakowania całego projektu do ZIP

Uruchomienie testów:
PYTHONPATH=. pytest -q

Uruchomienie narzędzia:
PYTHONPATH=. python3 -m noriben55.cli /path/sample.exe
PYTHONPATH=. python3 -m noriben55.cli /path/samples --batch --dual-vm
