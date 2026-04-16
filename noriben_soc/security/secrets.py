import os
from ..core.config import settings
class SecretsProvider:
    def get(self, key, default=None):
        if settings.secret_backend == 'env': return os.environ.get(key, default)
        return os.environ.get(key, default)
