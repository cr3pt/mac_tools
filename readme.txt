Noriben QEMU Sandbox - v5.9 guest checklist

Nowości względem 5.8.1:
- prepare generuje już trzy artefakty: prepare_plan.json, prepare_commands.sh i windows_guest_checklist.txt
- plan przygotowania obejmuje teraz host oraz checklistę dla Windows guest
- checklista guest uwzględnia OpenSSH Server, Python, Noriben, katalogi robocze, firewall i snapshot
- nadal zachowana jest logika cross-platform dla Ubuntu i macOS

Co robi --prepare w 5.9:
1. wykrywa hosta i rekomendowany profil
2. sprawdza narzędzia hosta
3. tworzy katalogi hostowe
4. zapisuje komendy instalacyjne hosta
5. generuje checklistę przygotowania Windows guest

Przykład:
PYTHONPATH=. python3 -m noriben59.cli --prepare

Dlaczego to pomaga:
Wersje 5.8.x przygotowywały głównie host. W 5.9 prepare obejmuje też to, co trzeba mieć w samym Windows guest, aby analiza naprawdę działała end-to-end.
