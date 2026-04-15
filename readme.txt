Noriben QEMU Sandbox - v5.4 stable

Pliki:
- noriben_qemu_sandbox_v5_4_stable.py
- readme.txt

Najważniejsze cechy wersji v5.4:
1. Osobna sesja robocza dla każdej próbki w trybie batch.
2. Stabilniejszy model kampanii z katalogiem campaign_YYYYMMDD_HHMMSS.
3. Bezpieczniejsze przetwarzanie wielowątkowe przez izolację danych per-próbka.
4. Raport HTML, findings.csv, timeline.csv i session_summary.json dla każdej próbki.
5. campaign_summary.csv i campaign_summary.json dla całej kampanii.
6. Mapowanie części detekcji do MITRE ATT&CK.
7. SIGMA-like detekcje z raportów Noriben i logów pomocniczych.
8. Próba parsowania EVTX przez python-evtx z fallbackiem tekstowym.
9. Retry dla SSH/SCP i obsługa dual-VM.
10. Tryby: --batch, --dry-run, --static-only, --dynamic-only, --preflight-only.

Przykłady użycia:
- Pojedyncza próbka:
  python3 noriben_qemu_sandbox_v5_4_stable.py /path/sample.exe

- Batch z katalogu:
  python3 noriben_qemu_sandbox_v5_4_stable.py /path/samples --batch --dual-vm

- Tylko preflight:
  python3 noriben_qemu_sandbox_v5_4_stable.py --preflight-only

Uwagi:
- Wymagane są QEMU, ssh, scp i qemu-img na hoście.
- Windows VM powinien mieć dostępne OpenSSH i Python.
- Noriben.py powinien być dostępny lokalnie w katalogu ~/NoribenTools lub wskazanym przez HOST_TOOLS_DIR.
- To jest wersja bardziej stabilna architektonicznie, ale nadal wymaga testów integracyjnych w docelowym środowisku.
