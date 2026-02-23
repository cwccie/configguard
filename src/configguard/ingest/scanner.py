"""Directory and Git repository scanners for config files."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterator

from configguard.ingest.parser import ConfigParser
from configguard.models import ParsedConfig

logger = logging.getLogger(__name__)

CONFIG_EXTENSIONS = {".conf", ".cfg", ".txt", ".config", ".ios", ".junos", ".eos", ".pan"}


class DirectoryScanner:
    """Scan a directory for network configuration files."""

    def __init__(self, parser: ConfigParser | None = None) -> None:
        self.parser = parser or ConfigParser()

    def scan(self, directory: str | Path, recursive: bool = True) -> list[ParsedConfig]:
        """Scan a directory and parse all config files."""
        directory = Path(directory)
        if not directory.is_dir():
            raise NotADirectoryError(f"Not a directory: {directory}")

        configs = []
        for filepath in self._find_configs(directory, recursive):
            try:
                config = self.parser.parse_file(filepath)
                configs.append(config)
                logger.info("Parsed: %s (%s)", filepath.name, config.vendor.value)
            except Exception as e:
                logger.warning("Failed to parse %s: %s", filepath, e)
        return configs

    def _find_configs(self, directory: Path, recursive: bool) -> Iterator[Path]:
        """Find configuration files in a directory."""
        pattern = "**/*" if recursive else "*"
        for path in directory.glob(pattern):
            if path.is_file() and (
                path.suffix.lower() in CONFIG_EXTENSIONS
                or self._looks_like_config(path)
            ):
                yield path

    def _looks_like_config(self, path: Path) -> bool:
        """Heuristic check if a file looks like a network config."""
        if path.stat().st_size > 10 * 1024 * 1024:  # Skip files > 10MB
            return False
        try:
            head = path.read_text(errors="replace")[:500].lower()
            indicators = ["hostname", "interface", "set system", "set deviceconfig",
                          "access-list", "router ", "firewall {"]
            return any(ind in head for ind in indicators)
        except (OSError, UnicodeDecodeError):
            return False


class GitRepoScanner:
    """Scan a Git repository for config files, tracking changes."""

    def __init__(self, parser: ConfigParser | None = None) -> None:
        self.parser = parser or ConfigParser()
        self._dir_scanner = DirectoryScanner(self.parser)

    def scan(self, repo_path: str | Path, branch: str = "HEAD") -> list[ParsedConfig]:
        """Scan a git repository for configs."""
        repo_path = Path(repo_path)
        if not (repo_path / ".git").exists():
            raise ValueError(f"Not a git repository: {repo_path}")

        # Scan the working tree
        return self._dir_scanner.scan(repo_path)

    def get_changed_configs(self, repo_path: str | Path,
                            since_commit: str = "HEAD~1") -> list[str]:
        """Get list of config files changed since a given commit."""
        try:
            import git
            repo = git.Repo(str(repo_path))
            diffs = repo.head.commit.diff(since_commit)
            changed = []
            for diff in diffs:
                path = Path(diff.a_path or diff.b_path)
                if path.suffix.lower() in CONFIG_EXTENSIONS:
                    changed.append(str(path))
            return changed
        except Exception as e:
            logger.warning("Git diff failed: %s", e)
            return []
