import json

from typer.testing import CliRunner

from irx import __version__
from irx.cli.app import app

runner = CliRunner()


def test_help_and_version():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "evidence" in result.stdout
    version = runner.invoke(app, ["--version"])
    assert version.exit_code == 0
    assert version.stdout.strip() == __version__


def test_case_and_evidence_commands(tmp_path):
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({"data_dir": str(tmp_path / "data")}), encoding="utf-8")
    args = ["--config", str(config_file)]
    validated = runner.invoke(app, args + ["config", "validate"])
    assert validated.exit_code == 0, validated.stdout
    assert "Configuration is valid" in validated.stdout
    made = runner.invoke(app, args + ["case", "create", "--name", "CLI Test"])
    assert made.exit_code == 0, made.stdout
    case_id = made.stdout.split()[2]
    listed = runner.invoke(app, args + ["case", "list", "--format", "json"])
    assert listed.exit_code == 0
    assert case_id in listed.stdout

    source = tmp_path / "sample.txt"
    source.write_text("cli evidence", encoding="utf-8")
    added = runner.invoke(app, args + ["evidence", "add", "--case", case_id, "--path", str(source)])
    assert added.exit_code == 0, added.stdout
    verified = runner.invoke(
        app, args + ["evidence", "verify", "--case", case_id, "--format", "json"]
    )
    assert verified.exit_code == 0, verified.stdout
    assert '"ok": true' in verified.stdout
    report = tmp_path / "case-report.html"
    generated = runner.invoke(
        app,
        args
        + ["report", "generate", "--case", case_id, "--format", "html", "--output", str(report)],
    )
    assert generated.exit_code == 0, generated.stdout
    assert report.is_file()
