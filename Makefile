lint:
	PYTHONPATH=. python3 -m py_compile noriben_soc/**/*.py tests/*.py

test:
	PYTHONPATH=. pytest -q

run-api:
	PYTHONPATH=. uvicorn noriben_soc.api.app:app --reload

run-worker:
	PYTHONPATH=. celery -A noriben_soc.core.tasks worker -Q analysis --loglevel=info
