lint:
	PYTHONPATH=. python3 -m py_compile noriben58/*.py tests/*.py

test:
	PYTHONPATH=. pytest -q

prepare:
	PYTHONPATH=. python3 -m noriben58.cli --prepare

host-info:
	PYTHONPATH=. python3 -m noriben58.cli --show-host-info --preflight-only

run:
	PYTHONPATH=. python3 -m noriben58.cli $(SAMPLE)

batch:
	PYTHONPATH=. python3 -m noriben58.cli $(SAMPLES) --batch --dual-vm
