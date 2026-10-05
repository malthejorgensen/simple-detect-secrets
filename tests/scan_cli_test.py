import subprocess
from io import StringIO

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
    assert 'No git repository detected: Scanning all files (1 file)' in capsys.readouterr().err


def test_git_directory_scans_only_tracked_files(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    subprocess.run(['git', 'init', '-q'], check=True)
    write_secret(tmp_path / 'tracked credentials')
    write_secret(tmp_path / 'untracked')
    subprocess.run(['git', 'add', 'tracked credentials'], check=True)
    result = baseline.initialize(['.'], (AWSKeyDetector(),))
    assert set(result.data) == {'tracked credentials'}
    assert (
        'Detected git repository: Scanning only Git-tracked files (1 file)'
        in capsys.readouterr().err
    )


def test_empty_git_repository_does_not_scan_untracked_files(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    subprocess.run(['git', 'init', '-q'], check=True)
    write_secret(tmp_path / 'credentials')
    result = baseline.initialize(['.'], (AWSKeyDetector(),))
    assert not result.data
    assert 'No files detected (0 files)' in capsys.readouterr().err


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
    assert 'Scanning explicit files (1 file)' in captured.err
    assert captured.out == ''


def test_no_arguments_scans_current_directory(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('sys.argv', ['simple-detect-secrets'])
    write_secret(tmp_path / 'credentials')
    assert main() == 0
    captured = capsys.readouterr()
    assert captured.out == f'credentials:1:aws_access_key_id = "{KEY}"\n'
    assert 'No git repository detected' in captured.err


def test_full_source_line_is_printed_once_for_multiple_secrets(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    source_line = f'  keys = ["{KEY}", "ASIAZZZZZZZZZZZZZZZZ"]  '
    (tmp_path / 'credentials').write_text(f'# credentials\n{source_line}\n')
    assert main(['credentials']) == 0
    assert capsys.readouterr().out == f'credentials:2:{source_line}\n'


@pytest.mark.parametrize('mode', ['files', 'string', 'update'])
def test_profile_reports_only_enabled_detectors_to_stderr(tmp_path, monkeypatch, capsys, mode):
    monkeypatch.chdir(tmp_path)
    write_secret(tmp_path / 'credentials')
    args = ['--profile', '--no-keyword-scan']
    if mode == 'string':
        args.extend(['--string', KEY])
    elif mode == 'update':
        args.extend(['--update', 'results.json', 'credentials'])
    else:
        args.append('credentials')
    assert main(args) == 0
    captured = capsys.readouterr()
    assert 'Detector profile (elapsed seconds):' in captured.err
    assert 'AWSKeyDetector' in captured.err
    assert 'KeywordDetector' not in captured.err
    assert 'Total' in captured.err
    assert 'Detector profile' not in captured.out
    if mode == 'files':
        assert captured.out == f'credentials:1:aws_access_key_id = "{KEY}"\n'
    elif mode == 'update':
        assert captured.out == ''
        assert 'Detector profile' not in (tmp_path / 'results.json').read_text()


def test_profile_is_opt_in(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    write_secret(tmp_path / 'credentials')
    assert main(['credentials']) == 0
    assert 'Detector profile' not in capsys.readouterr().err


def test_profile_reports_zero_for_empty_scan(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(['--profile']) == 0
    captured = capsys.readouterr()
    assert captured.out == ''
    assert 'AWSKeyDetector' in captured.err
    assert '0.000000 s' in captured.err


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
    assert output == f'keep.py:1:aws_access_key_id = "{KEY}"\n'
    assert 'debug.log' not in output
    assert 'private.py' not in output


def test_excludes_apply_to_explicit_files(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    write_secret(tmp_path / 'credentials')
    assert main([str(tmp_path / 'credentials'), '--exclude', 'credentials']) == 0
    captured = capsys.readouterr()
    assert KEY not in captured.out
    assert 'No files detected (0 files)' in captured.err


def test_exclusions_can_be_interleaved_with_paths(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    write_secret(tmp_path / 'keep.py')
    write_secret(tmp_path / 'debug.log')
    assert main(['keep.py', '--exclude', '*.log', 'debug.log', '--exclude', 'vendor/*']) == 0
    output = capsys.readouterr().out
    assert output == f'keep.py:1:aws_access_key_id = "{KEY}"\n'
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


@pytest.mark.parametrize('git_repository', [False, True])
@pytest.mark.parametrize('count', [0, 1, 2])
def test_scan_mode_and_count_share_one_line(tmp_path, monkeypatch, capsys, git_repository, count):
    monkeypatch.chdir(tmp_path)
    if git_repository:
        subprocess.run(['git', 'init', '-q'], check=True)
    for index in range(count):
        (tmp_path / str(index)).touch()
    if git_repository and count:
        subprocess.run(['git', 'add', '.'], check=True)
    baseline.initialize(['.'], ())
    prefix = 'Detected git repository: ' if git_repository else 'No git repository detected: '
    if not count:
        expected = 'No files detected (0 files)'
    else:
        mode = 'Scanning only Git-tracked files' if git_repository else 'Scanning all files'
        noun = 'file' if count == 1 else 'files'
        expected = f'{mode} ({count} {noun})'
    assert capsys.readouterr().err == prefix + expected + '\n\n'


def test_scan_prefix_is_flushed_before_enumeration(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    class RecordingStream(StringIO):
        def flush(self):
            self.last_flushed = self.getvalue()
            super().flush()

    stream = RecordingStream()
    monkeypatch.setattr(baseline.sys, 'stderr', stream)
    monkeypatch.setattr(baseline, '_is_git_repository', lambda path: False)

    def enumerate_files(*args):
        assert stream.last_flushed == 'No git repository detected: '
        return []

    monkeypatch.setattr(baseline, '_get_files_recursively', enumerate_files)
    baseline.initialize(['.'], ())
    assert stream.last_flushed == 'No git repository detected: No files detected (0 files)\n\n'
