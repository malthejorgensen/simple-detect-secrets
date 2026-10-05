import subprocess

from simple_detect_secrets.core import baseline
from simple_detect_secrets.main import main
from simple_detect_secrets.plugins.aws import AWSKeyDetector

KEY = 'AKIAZZZZZZZZZZZZZZZZ'


def write_secret(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f'aws_access_key_id = "{KEY}"\n')


def test_non_git_directory_scans_recursively(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    write_secret(tmp_path / 'nested' / 'credentials')
    result = baseline.initialize(['.'], (AWSKeyDetector(),))
    assert set(result.data) == {'nested/credentials'}
    assert 'No git repository detected: Scanning all files.' in capsys.readouterr().err


def test_git_directory_scans_only_tracked_files(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    subprocess.run(['git', 'init', '-q'], check=True)
    write_secret(tmp_path / 'tracked credentials')
    write_secret(tmp_path / 'untracked')
    subprocess.run(['git', 'add', 'tracked credentials'], check=True)
    result = baseline.initialize(['.'], (AWSKeyDetector(),))
    assert set(result.data) == {'tracked credentials'}
    assert 'Detected git repository: Scanning only Git-tracked files.' in capsys.readouterr().err


def test_empty_git_repository_does_not_scan_untracked_files(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    subprocess.run(['git', 'init', '-q'], check=True)
    write_secret(tmp_path / 'credentials')
    result = baseline.initialize(['.'], (AWSKeyDetector(),))
    assert not result.data
    assert 'Scanning 0 file(s).' in capsys.readouterr().err


def test_git_subdirectory_detected(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    subprocess.run(['git', 'init', '-q'], check=True)
    write_secret(tmp_path / 'nested' / 'credentials')
    subprocess.run(['git', 'add', 'nested/credentials'], check=True)
    result = baseline.initialize(['nested'], (AWSKeyDetector(),))
    assert set(result.data) == {'nested/credentials'}


def test_all_files_overrides_git_and_skips_metadata(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    subprocess.run(['git', 'init', '-q'], check=True)
    write_secret(tmp_path / 'credentials')
    write_secret(tmp_path / '.git' / 'synthetic-secret')
    result = baseline.initialize(['.'], (AWSKeyDetector(),), should_scan_all_files=True)
    assert set(result.data) == {'credentials'}


def test_directory_outside_working_directory(tmp_path, monkeypatch):
    working = tmp_path / 'working'
    working.mkdir()
    monkeypatch.chdir(working)
    write_secret(tmp_path / 'other' / 'credentials')
    result = baseline.initialize([tmp_path / 'other'], (AWSKeyDetector(),))
    assert set(result.data) == {'../other/credentials'}


def test_no_findings_diagnostic(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('sys.argv', ['simple-detect-secrets', 'scan'])
    (tmp_path / 'empty').touch()
    assert main(['--no-verify', 'empty']) == 0
    captured = capsys.readouterr()
    assert 'No secrets found.' in captured.err
    assert 'Scanning 1 file(s).' in captured.err
    assert 'No secrets found.' not in captured.out


def test_no_arguments_scans_current_directory(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('sys.argv', ['simple-detect-secrets'])
    write_secret(tmp_path / 'credentials')
    assert main() == 0
    captured = capsys.readouterr()
    assert KEY in captured.out
    assert 'No git repository detected' in captured.err
