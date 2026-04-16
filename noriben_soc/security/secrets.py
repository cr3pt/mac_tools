import os, json
try:
    import hvac
except ImportError:
    hvac = None
from ..core.config import settings
class SecretsProvider:
    def get(self, key, default=None):
        if settings.secret_backend == "env": return os.environ.get(key, default)
        if settings.secret_backend == "vault" and hvac and settings.vault_addr and settings.vault_token:
            client = hvac.Client(url=settings.vault_addr)
            client.token = settings.vault_token
            if client.is_authenticated():
                secret = client.secrets.kv.v2.read_secret_version(path="noriben")
                return secret["data"]["data"].get(key, default)
        return default
