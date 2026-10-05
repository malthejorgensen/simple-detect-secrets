import socket
import subprocess

import pytest

from simple_detect_secrets.main import main


@pytest.fixture(autouse=True)
def reject_network(monkeypatch):
    def reject(*args, **kwargs):
        pytest.fail('Scanning must not make network connections')

    monkeypatch.setattr(socket.socket, 'connect', reject)
    monkeypatch.setattr(socket.socket, 'connect_ex', reject)
    monkeypatch.setattr(socket, 'create_connection', reject)


@pytest.mark.parametrize('prefix', ['AKIA', 'ASIA'])
@pytest.mark.parametrize('scan_mode', ['file', 'tracked', 'all-files', 'untracked'])
def test_aws_scan_is_offline(prefix, scan_mode, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('sys.argv', ['simple-detect-secrets', 'scan'])

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


def test_service_credentials_scan_offline(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    lines = [
        'aws_access_key_id = "AKIAZZZZZZZZZZZZZZZZ"',
        'aws_secret_access_key = "' + 'Z' * 40 + '"',
        'slack_token = "xoxb-1234567890-1234567890-abcdefgh"',
        'stripe_key = "sk_live_' + 'Z' * 24 + '"',
        'mailchimp_key = "' + 'a' * 32 + '-us1"',
        'cloudant_key = "' + 'a' * 24 + '"',
        'cloudant_host = "example"',
        'softlayer_api_key = "' + 'a' * 64 + '"',
        'softlayer_username = "example"',
        'ibm_cloud_iam_key = "' + 'Z' * 44 + '"',
    ]
    (tmp_path / 'credentials').write_text('\n'.join(lines) + '\n')
    assert main(['credentials', '--profile']) == 0
    output = capsys.readouterr().out
    for lineno in (1, 3, 4, 5, 6, 8, 10):
        assert f'credentials:{lineno}:{lines[lineno - 1]}\n' in output
