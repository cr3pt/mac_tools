lint:
	PYTHONPATH=. python3 -m py_compile noriben59/*.py tests/*.py

test:
	PYTHONPATH=. pytest -q

prepare:
	PYTHONPATH=. python3 -m noriben59.cli --prepare

host-info:
	PYTHONPATH=. python3 -m noriben59.cli --show-host-info --preflight-only

run:
	PYTHONPATH=. python3 -m noriben59.cli $(SAMPLE)

batch:
	PYTHONPATH=. python3 -m noriben59.cli $(SAMPLES) --batch --dual-vm
