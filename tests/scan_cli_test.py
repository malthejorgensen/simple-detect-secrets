import subprocess

import pytest

from simple_detect_secrets.core import baseline
from simple_detect_secrets.core.secrets_collection import SecretsCollection
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


@pytest.mark.parametrize('git_repository', [False, True])
def test_repeatable_excludes_filter_scan_results(tmp_path, monkeypatch, capsys, git_repository):
    monkeypatch.chdir(tmp_path)
    for filename in ('keep.py', 'debug.log', 'nested/debug.log', 'vendor/private.py'):
        write_secret(tmp_path / filename)
    if git_repository:
        subprocess.run(['git', 'init', '-q'], check=True)
        subprocess.run(['git', 'add', '.'], check=True)
    assert main(['--exclude', '*.log', '--exclude', 'vendor/*']) == 0
    output = capsys.readouterr().out
    assert 'Filename: keep.py' in output
    assert 'debug.log' not in output
    assert 'private.py' not in output


def test_excludes_apply_to_explicit_files(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    write_secret(tmp_path / 'credentials')
    assert main([str(tmp_path / 'credentials'), '--exclude', 'credentials']) == 0
    captured = capsys.readouterr()
    assert KEY not in captured.out
    assert 'Scanning 0 file(s).' in captured.err


def test_exclusions_can_be_interleaved_with_paths(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    write_secret(tmp_path / 'keep.py')
    write_secret(tmp_path / 'debug.log')
    assert main(['keep.py', '--exclude', '*.log', 'debug.log', '--exclude', 'vendor/*']) == 0
    output = capsys.readouterr().out
    assert 'Filename: keep.py' in output
    assert 'debug.log' not in output


def test_excluded_directories_are_not_walked(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    write_secret(tmp_path / '.venv' / 'credentials')
    write_secret(tmp_path / 'keep.py')
    visited = []
    original_walk = baseline.os.walk

    def record_walk(*args, **kwargs):
        for item in original_walk(*args, **kwargs):
            visited.append(item[0])
            yield item

    monkeypatch.setattr(baseline.os, 'walk', record_walk)
    result = baseline.initialize(['.'], (AWSKeyDetector(),), exclude_patterns=['.venv'])
    assert set(result.data) == {'keep.py'}
    assert not any('.venv' in path for path in visited)


def test_glob_exclusions_survive_baseline_roundtrip(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    write_secret(tmp_path / 'credentials')
    result = baseline.initialize(['.'], (AWSKeyDetector(),), exclude_patterns=['*.log', 'vendor/*'])
    loaded = SecretsCollection.load_baseline_from_dict(result.format_for_baseline_output())
    assert loaded.exclude_files == ['*.log', 'vendor/*']
    assert loaded.get_secret('credentials', KEY, 'AWS Access Key') is not None
