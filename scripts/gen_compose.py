#!/usr/bin/env python3
"""Generate a docker-compose.yml tailored to the target environment.

Enhancements:
- argparse for clearer CLI and flags
- --output to choose output path
- --no-grafana / --no-celery to disable services
- --dry-run to print instead of writing file
- explicit platform/accel overrides
- --services to select which services to include
- basic templating via --var KEY=VALUE (replaces {{KEY}} in output)
"""
from __future__ import annotations
import argparse
from pathlib import Path
import sys
from typing import Iterable


def _apply_substitutions(lines: Iterable[str], substitutions: dict[str, str] | None) -> list[str]:
    if not substitutions:
        return list(lines)
    out: list[str] = []
    for line in lines:
        new = line
        for k, v in substitutions.items():
            new = new.replace(f"{{{{{k}}}}}", v)
        out.append(new)
    return out


def make_compose_lines(env: str, *, platform_override: str | None = None,
                      accel_override: str | None = None,
                      enable_celery: bool = True,
                      enable_grafana: bool = True,
                      services: list[str] | None = None,
                      substitutions: dict[str, str] | None = None) -> list[str]:
    """Return list of docker-compose lines. services: list of service names to include (None = all)."""
    is_arm = env.startswith("APPLE_M")
    is_kvm = (env == "LINUX_KVM")
    platform = platform_override or ("linux/arm64" if is_arm else "linux/amd64")
    accel = accel_override or ("kvm" if is_kvm else "tcg")

    svc_blocks: dict[str, list[str]] = {}

    svc_blocks["postgres"] = [
        "  postgres:",
        "    image: postgres:15",
        "    platform: linux/amd64",
        "    environment:",
        "      POSTGRES_DB: noriben",
        "      POSTGRES_USER: noriben",
        "      POSTGRES_PASSWORD: noriben123",
        "    ports:",
        "      - \"5432:5432\"",
        "    volumes:",
        "      - noriben_pg:/var/lib/postgresql/data",
        "    healthcheck:",
        "      test: [\"CMD\",\"pg_isready\",\"-U\",\"noriben\"]",
        "      interval: \"5s\"",
        "      retries: 5",
    ]

    svc_blocks["redis"] = [
        "  redis:",
        "    image: redis:7-alpine",
        "    ports:",
        "      - \"6379:6379\"",
    ]

    svc_blocks["api"] = [
        "  api:",
        "    build:",
        "      context: .",
        "      dockerfile: Dockerfile",
        f"      platform: {platform}",
        "    ports:",
        "      - \"8000:8000\"",
        "    volumes:",
        "      - .:/app",
        "      - ./vms:/shared",
        "    environment:",
        "      DATABASE_URL: postgresql://noriben:noriben123@postgres/{{DB_NAME}}",
        "      CELERY_BROKER: redis://redis:6379/0",
        f"      NORIBEN_ENV: {env}",
        "    depends_on:",
        "      postgres:",
        "        condition: service_healthy",
        "      redis:",
        "        condition: service_started",
    ]

    if enable_celery:
        svc_blocks["celery"] = [
            "  celery:",
            "    build:",
            "      context: .",
            "      dockerfile: Dockerfile",
            f"      platform: {platform}",
            "    command: celery -A noriben_soc.tasks worker --loglevel=info --concurrency=4",
            "    volumes:",
            "      - .:/app",
            "      - ./vms:/shared",
            "    environment:",
            "      DATABASE_URL: postgresql://noriben:noriben123@postgres/noriben",
            "      CELERY_BROKER: redis://redis:6379/0",
            f"      QEMU_ACCEL: {accel}",
            f"      NORIBEN_ENV: {env}",
            "    depends_on:",
            "      - redis",
            "      - postgres",
        ]

    if enable_grafana:
        svc_blocks["grafana"] = [
            "  grafana:",
            "    image: grafana/grafana:latest",
            "    ports:",
            "      - \"3000:3000\"",
            "    environment:",
            "      GF_SECURITY_ADMIN_PASSWORD: admin",
            "    volumes:",
            "      - noriben_grafana:/var/lib/grafana",
            "      - ./grafana/provisioning:/etc/grafana/provisioning",
        ]

    order = ["postgres", "redis", "api", "celery", "grafana"]

    # Determine which services to include
    if services is None:
        selected = [s for s in order if s in svc_blocks]
    else:
        # normalize requested service names
        req = {s.strip() for s in services}
        selected = [s for s in order if s in svc_blocks and s in req]

    lines: list[str] = []
    lines.append('version: "3.8"')
    lines.append("services:")

    for s in selected:
        lines.extend(svc_blocks[s])

    lines.append("volumes:")
    lines.append("  noriben_pg: {}")
    if "grafana" in selected:
        lines.append("  noriben_grafana: {}")

    # Apply substitutions (templating)
    lines = _apply_substitutions(lines, substitutions)

    return lines


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generate docker-compose for noriben environments")
    p.add_argument("env", nargs="?", default="LINUX_NO_KVM",
                   help="Target environment (e.g., APPLE_M1, LINUX_KVM, LINUX_NO_KVM)")
    p.add_argument("--output", "-o", default="docker-compose.yml",
                   help="Output path for docker-compose file")
    p.add_argument("--no-grafana", dest="grafana", action="store_false",
                   help="Disable grafana service")
    p.add_argument("--no-celery", dest="celery", action="store_false",
                   help="Disable celery service")
    p.add_argument("--platform", dest="platform_override", default=None,
                   help="Override the build platform (e.g., linux/arm64)")
    p.add_argument("--accel", dest="accel_override", default=None,
                   help="Override QEMU accel (kvm/tcg)")
    p.add_argument("--dry-run", action="store_true", help="Print output instead of writing file")
    p.add_argument("--services", dest="services", default=None,
                   help="Comma-separated list of services to include (postgres,redis,api,celery,grafana)")
    p.add_argument("--var", dest="vars", action="append", default=[],
                   help="Template variable in KEY=VALUE form. Can be repeated.")
    return p.parse_args(argv)


def _parse_vars(pairs: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for pair in pairs:
        if "=" in pair:
            k, v = pair.split("=", 1)
            out[k] = v
    return out


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    services = args.services.split(",") if args.services else None
    substitutions = _parse_vars(args.vars)

    lines = make_compose_lines(args.env,
                               platform_override=args.platform_override,
                               accel_override=args.accel_override,
                               enable_celery=args.celery,
                               enable_grafana=args.grafana,
                               services=services,
                               substitutions=substitutions)
    out_path = Path(args.output)
    content = "\n".join(lines) + "\n"
    if args.dry_run:
        print(content)
    else:
        out_path.write_text(content)
        print(f"[gen_compose] OK ({args.env} | output={out_path} | platform={args.platform_override or 'auto'})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
