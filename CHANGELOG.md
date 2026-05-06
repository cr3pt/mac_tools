# Changelog

All notable changes to this project are documented in this file.
Format follows a Keep a Changelog style.

## [Unreleased]
- Dodano skrypt instalacyjny scripts/setup_env.sh — automatyczna instalacja zależności systemowych, tworzenie venv, instalacja paczek Python oraz próbne utworzenie bazy Postgres.
- Dodano centralną konfigurację (.env/.env.example) i strukturalne logowanie (JSON/plain).
- Rozdzielono zależności runtime i dev (requirements.txt, requirements-dev.txt).


## [v6.8-final-fix9] - 2026-05-05
### Added
- deploy.sh: instalacja pakietów systemowych, Rust oraz filtracja niekompilowalnych zależności.
- noriben_soc/core/db.py: obsługa opcjonalnego asyncpg, zapisy do pliku JSON w trybie testowym.
- noriben_soc/core/pipeline.py: obsługa opcjonalnego requests, zwracanie pustych słowników przy braku biblioteki.

### Changed
- deploy.sh: pełny proces tworzenia środowiska wirtualnego i instalacji zależności.
- Testy: wszystkie przechodzą (2 passed).

### Fixed
- Brak przerwania działania przy brakujących pakietach (psycopg2‑binary, asyncpg, pydantic‑core, requests).

## [v6.8-final-fix8] - 2026-04-18
### Added
- README: mapa portow VNC i monitora.
- README: sekcja o zmianach konfiguracyjnych i recznym zwalnianiu portow.
- README: alternatywy dla obrazow qcow2 oraz instrukcje bypass TPM dla Win11.

### Changed
- win_setup.sh: automatyczny wybor wolnych portow VNC.
- win_setup.sh: automatyczny wybor wolnego portu monitora QEMU.
- win_setup.sh: instalacja Win11 przez ISO zamiast wymagania gotowego qcow2.

### Fixed
- Usunieto sztywne zalozenie, ze port 4440 jest zawsze wolny.
- Usunieto zalozenie, ze display VNC :11 jest zawsze wolny.
- Dodano ponawianie pobierania ISO i lepsza diagnostyke portow.

## [v6.8-final-fix7] - 2026-04-18
### Added
- README: tabela portow VNC i monitora.

### Changed
- README: dopisano informacje o automatycznym wyborze portu monitora.

## [v6.8-final-fix6] - 2026-04-18
### Fixed
- win_setup.sh: VNC display wybierany przez skan kolejnych numerow, a nie jednorazowy skok.

## [v6.8-final-fix5] - 2026-04-18
### Added
- README: logowanie portu monitora QEMU.

## [v6.8-final-fix4] - 2026-04-18
### Fixed
- win_setup.sh: monitor QEMU wybiera pierwszy wolny port zamiast stalego 4440.

## [v6.8-final-fix3] - 2026-04-18
### Added
- README: bypass TPM dla Win11.
- README: alternatywy dla qcow2 (VDI, VMDK, VHDX, cloudbase.it).

### Changed
- win_setup.sh: Win11 instalowany z ISO Microsoft zamiast gotowego qcow2.

## [v6.8-final-fix2] - 2026-04-18
### Fixed
- win_setup.sh: usunieto zaleznosc od niedostepnego pliku qcow2 z archive.org.

## [v6.8-final-fix] - 2026-04-18
### Added
- win_setup.sh: wielokrotne proby pobierania i fallback placeholder.

### Fixed
- win_setup.sh: poprawione zrodla pobierania i logika retry.
