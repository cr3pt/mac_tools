Noriben SOC Starter 7.1

To jest działający starter backendu SOC-grade:
- FastAPI API
- pipeline analizy pliku
- canonical events z parsera tekstowego
- IOC extraction
- YARA integration (yara-python if available, otherwise fallback)
- SIGMA matching
- persistent store sesji
- prosty dashboard WWW

Uruchomienie:
1. pip install -r requirements.txt
2. PYTHONPATH=. uvicorn noriben_soc.api.app:app --reload
3. otwórz http://127.0.0.1:8000/
