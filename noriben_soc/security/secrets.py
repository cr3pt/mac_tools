import os, json, urllib.request
from ..core.config import settings
class SecretsProvider:
    def get(self, key, default=None):
        if settings.secret_backend == 'env': return os.environ.get(key, default)
        if settings.secret_backend == 'vault-http' and settings.vault_addr and settings.vault_token:
            req = urllib.request.Request(settings.vault_addr.rstrip('/') + '/v1/secret/data/noriben', headers={'X-Vault-Token': settings.vault_token})
            try:
                with urllib.request.urlopen(req, timeout=3) as resp:
                    data = json.loads(resp.read().decode('utf-8'))
                    return data.get('data', {}).get('data', {}).get(key, default)
            except Exception:
                return default
        return default
