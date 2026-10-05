import subprocess

import pytest
import requests

from simple_detect_secrets.main import main


@pytest.mark.parametrize('prefix', ['AKIA', 'ASIA'])
@pytest.mark.parametrize('scan_mode', ['file', 'tracked', 'all-files', 'untracked'])
def test_aws_scan_is_offline(prefix, scan_mode, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('sys.argv', ['simple-detect-secrets', 'scan'])

    def reject_network(*args, **kwargs):
        pytest.fail('Scanning must not make network requests')

    monkeypatch.setattr(requests.sessions.Session, 'request', reject_network)
    key = prefix + 'Z' * 16
    filename = tmp_path / 'credentials.ini'
    filename.write_text(
        f'aws_access_key_id = "{key}"\naws_secret_access_key = "{"Z" * 40}"\n',
    )
    subprocess.run(['git', 'init', '-q'], check=True)
    if scan_mode == 'tracked':
        subprocess.run(['git', 'add', filename.name], check=True)

    arguments = []
    if scan_mode == 'file':
        arguments.append(filename.name)
    elif scan_mode == 'all-files':
        arguments.extend(['--all-files', '.'])

    assert main(arguments) == 0
    output = capsys.readouterr().out
    if scan_mode == 'untracked':
        assert key not in output
    else:
        assert filename.name in output
        assert key in output


@pytest.mark.parametrize('prefix', ['AKIA', 'ASIA'])
def test_aws_string_scan(prefix, monkeypatch, capsys):
    monkeypatch.setattr('sys.argv', ['simple-detect-secrets', 'scan'])
    assert main(['--string', prefix + 'Z' * 16]) == 0
    output = capsys.readouterr().out
    aws_result = next(
        line for line in output.splitlines() if line.split(':', 1)[0].strip() == 'AWSKeyDetector'
    )
    assert aws_result.split(':', 1)[1].strip() == 'True'
