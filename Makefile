lint:
	PYTHONPATH=. python3 -m py_compile noriben57/*.py tests/*.py

test:
	PYTHONPATH=. pytest -q

host-info:
	PYTHONPATH=. python3 -m noriben57.cli --show-host-info --preflight-only

run:
	PYTHONPATH=. python3 -m noriben57.cli $(SAMPLE)

batch:
	PYTHONPATH=. python3 -m noriben57.cli $(SAMPLES) --batch --dual-vm
