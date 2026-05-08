import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "gen_compose",
    str(Path(__file__).resolve().parents[1] / "scripts" / "gen_compose.py")
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def test_services_selection():
    lines = mod.make_compose_lines("LINUX_NO_KVM", services=["api", "postgres"])
    content = "\n".join(lines)
    assert "  grafana:" not in content
    assert "  api:" in content
    assert "  postgres:" in content


def test_templating():
    lines = mod.make_compose_lines("LINUX_NO_KVM", substitutions={"DB_NAME": "testdb"})
    content = "\n".join(lines)
    assert "testdb" in content
    assert "postgresql://noriben:noriben123@postgres/testdb" in content
