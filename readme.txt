Noriben QEMU Sandbox - v5.5 modular

Ta wersja przechodzi z jednego pliku na projekt wieloplikowy.

Struktura:
- noriben55/config.py      - konfiguracja i loader
- noriben55/models.py      - modele danych sesji, findingów i VM
- noriben55/detection.py   - dodatkowe detekcje i mapowanie MITRE
- noriben55/reporting.py   - eksporty raportów
- noriben55/orchestrator.py- główny runner kampanii i VM
- noriben55/cli.py         - prosty entrypoint
- tests/test_detection.py  - prosty test jednostkowy
- config.yaml.example      - przykładowa konfiguracja

Dodatkowe detekcje względem 5.4:
- AMSI bypass / AmsiUtils
- Process injection: CreateRemoteThread, WriteProcessMemory, NtMapViewOfSection
- Downloader activity: WinHttpOpen, URLDownloadToFile, InternetOpenUrl
- Discovery: whoami, ipconfig, systeminfo, net user, tasklist, quser, nltest
- Rozszerzona sieć: HTTP/HTTPS
- Dodatkowe MITRE: T1055, T1070.001, T1105

Uruchomienie:
- python3 -m noriben55.cli /path/sample.exe
- python3 -m noriben55.cli /path/samples --batch --dual-vm
- python3 -m noriben55.cli --preflight-only

Uwaga:
To nadal wersja do testów integracyjnych z realnym środowiskiem QEMU/Windows.
