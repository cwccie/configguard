"""Tests for the CLI."""

import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from configguard.cli import cli


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def config_file():
    content = "hostname CLI-TEST\nenable password weak\nservice finger\n"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
        f.write(content)
        f.flush()
        return f.name


class TestCLI:
    def test_version(self, runner):
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "1.0.0" in result.output

    def test_help(self, runner):
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "ConfigGuard" in result.output
        assert "scan" in result.output
        assert "check" in result.output
        assert "report" in result.output

    def test_scan_command(self, runner, config_file):
        result = runner.invoke(cli, ["scan", config_file])
        assert result.exit_code == 0
        assert "Compliance Score" in result.output

    def test_check_command(self, runner, config_file):
        result = runner.invoke(cli, ["check", config_file])
        assert result.exit_code == 0
        assert "Compliance Score" in result.output

    def test_explain_command(self, runner, config_file):
        result = runner.invoke(cli, ["explain", config_file])
        assert result.exit_code == 0

    def test_remediate_command(self, runner, config_file):
        result = runner.invoke(cli, ["remediate", config_file])
        assert result.exit_code == 0

    def test_rules_command(self, runner):
        result = runner.invoke(cli, ["rules"])
        assert result.exit_code == 0
        assert "Loaded rules" in result.output

    def test_demo_command(self, runner):
        result = runner.invoke(cli, ["demo"])
        assert result.exit_code == 0
        assert "ConfigGuard Demo" in result.output
        assert "Compliance Score" in result.output

    def test_scan_with_json_output(self, runner, config_file):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            result = runner.invoke(cli, ["scan", config_file, "-o", f.name, "--format", "json"])
            assert result.exit_code == 0
            assert Path(f.name).exists()

    def test_scan_nonexistent_file(self, runner):
        result = runner.invoke(cli, ["scan", "/nonexistent/file.conf"])
        assert result.exit_code != 0
