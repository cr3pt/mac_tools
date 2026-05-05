"""Simple end‑to‑end integration test.
It starts the application using the existing Docker‑Compose configuration
(if present) and checks that the API health endpoint returns 200.
"""
import subprocess
import time
import requests

COMPOSE_FILE = "docker-compose.yml"


def start_services():
    subprocess.run(["docker", "compose", "-f", COMPOSE_FILE, "up", "-d"], check=True)
    # wait for services to become ready
    time.sleep(5)


def stop_services():
    subprocess.run(["docker", "compose", "-f", COMPOSE_FILE, "down"], check=True)


def test_api_health():
    start_services()
    try:
        resp = requests.get("http://localhost:8000/health")
        assert resp.status_code == 200
    finally:
        stop_services()

