"""Example scanner plugin that wraps the existing ClamAV scan.
It demonstrates how a plugin should be structured.
"""
from .base import ScannerPlugin
from ..core.pipeline import _scan_clamav

class ClamAVPlugin(ScannerPlugin):
    def scan(self, file_path: str) -> dict:
        # Reuse the internal _scan_clamav function
        result = _scan_clamav(file_path)
        # Ensure a consistent dict format
        return {
            "engine": "clamav",
            "result": result,
        }

