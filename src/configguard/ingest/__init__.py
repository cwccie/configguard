"""Config ingestion — multi-vendor parser and inventory."""

from configguard.ingest.parser import ConfigParser, detect_vendor
from configguard.ingest.inventory import ConfigInventory
from configguard.ingest.scanner import DirectoryScanner, GitRepoScanner

__all__ = [
    "ConfigParser",
    "ConfigInventory",
    "DirectoryScanner",
    "GitRepoScanner",
    "detect_vendor",
]
