"""Base classes for scanner plugins.
Each plugin must implement a `scan(file_path: str) -> dict` method returning a dict
with at least ``"engine"`` and ``"result"`` keys.
The plugin system loads all modules in the ``noriben_soc.scanners`` package that
inherit from :class:`ScannerPlugin`.
"""

from abc import ABC, abstractmethod

class ScannerPlugin(ABC):
    """Abstract base class for all scanner plugins."""

    @abstractmethod
    def scan(self, file_path: str) -> dict:
        """Scan the given file and return a result dictionary.

        The returned dict should contain:
        * ``engine`` – name of the scanner
        * ``result`` – arbitrary data (e.g., detections)
        """
        pass

# Helper to discover plugins dynamically
def load_plugins() -> list[ScannerPlugin]:
    """Import all modules in this package and return instantiated plugins.

    Plugins are expected to expose a class inheriting from ``ScannerPlugin``
    with a name ending in ``Plugin``.
    """
    import importlib
    import pkgutil
    import pathlib
    plugins = []
    package_path = pathlib.Path(__file__).parent
    for _, module_name, _ in pkgutil.iter_modules([str(package_path)]):
        if module_name.startswith("__"):
            continue
        module = importlib.import_module(f"noriben_soc.scanners.{module_name}")
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if isinstance(attr, type) and issubclass(attr, ScannerPlugin) and attr is not ScannerPlugin:
                plugins.append(attr())
    return plugins
