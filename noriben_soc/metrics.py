# Optional Prometheus metrics wrapper
try:
    from prometheus_client.core import CollectorRegistry
    from prometheus_client import Counter, Gauge, generate_latest
    registry = CollectorRegistry()
    uploads = Counter('noriben_uploads_total', 'Total uploads', registry=registry)
    rules_loaded = Counter('noriben_rules_loaded_total', 'Total rule reloads', registry=registry)
    prunes = Counter('noriben_prunes_total', 'Total prunes executed', registry=registry)
    PROMETHEUS_AVAILABLE = True
    def generate_latest_wrapper():
        return generate_latest(registry)
    registry.generate_latest = generate_latest_wrapper
except Exception:
    PROMETHEUS_AVAILABLE = False
    registry = None
    uploads = None
    rules_loaded = None
    prunes = None
