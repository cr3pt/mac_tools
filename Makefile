lint:
	PYTHONPATH=. python3 -m py_compile noriben_soc/**/*.py tests/*.py

test:
	PYTHONPATH=. pytest -q

run:
	PYTHONPATH=. uvicorn noriben_soc.api.app:app --reload
