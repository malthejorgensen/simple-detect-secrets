import os
import subprocess
import sys

from .excludes import is_excluded
from .log import get_logger
from .secrets_collection import SecretsCollection

log = get_logger(format_string='%(message)s')


def initialize(
    path,
    plugins,
    exclude_patterns=None,
    exclude_lines_regex=None,
    word_list_file=None,
    word_list_hash=None,
    should_scan_all_files=False,
):
    """Scans the entire codebase for secrets, and returns a
    SecretsCollection object.

    :type path: list

    :type plugins: tuple of detect_secrets.plugins.base.BasePlugin
    :param plugins: rules to initialize the SecretsCollection with.

    :type exclude_patterns: list(str)|None
    :type exclude_lines_regex: str|None

    :type word_list_file: str|None
    :param word_list_file: optional word list file for ignoring certain words.

    :type word_list_hash: str|None
    :param word_list_hash: optional iterated sha1 hash of the words in the word list.

    :type should_scan_all_files: bool

    :rtype: SecretsCollection
    """
    output = SecretsCollection(
        plugins,
        exclude_files=exclude_patterns or [],
        exclude_lines=exclude_lines_regex,
        word_list_file=word_list_file,
        word_list_hash=word_list_hash,
    )

    if isinstance(path, (str, os.PathLike)):
        path = [path]

    files_to_scan = set()
    explicit_files = []
    for element in path:
        if os.path.isdir(element):
            if should_scan_all_files:
                prefix = ''
                message = 'Scanning all files (--all-files)'
                git_tracked = False
            elif _is_git_repository(element):
                prefix = 'Detected git repository: '
                message = 'Scanning only Git-tracked files'
                git_tracked = True
            else:
                prefix = 'No git repository detected: '
                message = 'Scanning all files'
                git_tracked = False

            # Flush the mode before enumerating a potentially large directory.
            print(prefix, end='', file=sys.stderr, flush=True)
            candidates = (
                _get_git_tracked_files(element)
                if git_tracked
                else _get_files_recursively(element, exclude_patterns)
            )
            selected = {file for file in candidates if not is_excluded(file, exclude_patterns)}
            _report_file_count(message, len(selected))
            files_to_scan.update(selected)
        elif os.path.isfile(element):
            explicit_files.append(element)
        else:
            log.error('detect-secrets: %s: No such file or directory', element)

    if explicit_files:
        selected = {file for file in explicit_files if not is_excluded(file, exclude_patterns)}
        _report_file_count('Scanning explicit files', len(selected))
        files_to_scan.update(selected)

    files_to_scan = sorted(files_to_scan)
    for file in files_to_scan:
        output.scan_file(file)

    return output


def _report_file_count(message, count):
    if not count:
        message = 'No files detected'
    noun = 'file' if count == 1 else 'files'
    print(f'{message} ({count} {noun})\n', file=sys.stderr, flush=True)


def get_secrets_not_in_baseline(results, baseline):
    """
    :type results: SecretsCollection
    :param results: SecretsCollection of current results

    :type baseline: SecretsCollection
    :param baseline: SecretsCollection of baseline results.
                     This will be updated accordingly (by reference)

    :rtype: SecretsCollection
    :returns: SecretsCollection of new results (filtering out baseline)
    """
    new_secrets = SecretsCollection()
    for filename in results.data:
        if is_excluded(filename, baseline.exclude_files):
            continue

        if filename not in baseline.data:
            # We don't have a previous record of this file, so obviously
            # everything is new.
            new_secrets.data[filename] = results.data[filename]
            continue

        # The __hash__ method of PotentialSecret makes this work
        filtered_results = {
            secret: secret
            for secret in results.data[filename]
            if secret not in baseline.data[filename]
        }

        if filtered_results:
            new_secrets.data[filename] = filtered_results

    return new_secrets


def trim_baseline_of_removed_secrets(results, baseline, filelist):
    """
    NOTE: filelist is not a comprehensive list of all files in the repo
    (because we can't be sure whether --all-files is passed in as a
    parameter to pre-commit).

    :type results: SecretsCollection
    :type baseline: SecretsCollection

    :type filelist: list(str)
    :param filelist: filenames that are scanned.

    :rtype: bool
    :returns: True if baseline was updated
    """
    updated = False
    for filename in filelist:
        if filename not in baseline.data:
            # Nothing to modify, because not even there in the first place.
            continue

        if filename not in results.data:
            # All secrets relating to that file was removed.
            # We know this because:
            #   1. It's a file that was scanned (in filelist)
            #   2. It was in the baseline
            #   3. It has no results now.
            del baseline.data[filename]
            updated = True
            continue

        # We clone the baseline, so that we can modify the baseline,
        # without messing up the iteration.
        for baseline_secret in baseline.data[filename].copy():
            new_secret_found = results.get_secret(
                filename,
                baseline_secret.secret_value,
                baseline_secret.type,
            )

            if not new_secret_found:
                # No longer in results, so can remove from baseline
                old_secret_to_delete = baseline.get_secret(
                    filename,
                    baseline_secret.secret_value,
                    baseline_secret.type,
                )
                del baseline.data[filename][old_secret_to_delete]
                updated = True

            elif new_secret_found.lineno != baseline_secret.lineno:
                # Secret moved around, should update baseline with new location
                old_secret_to_update = baseline.get_secret(
                    filename,
                    baseline_secret.secret_value,
                    baseline_secret.type,
                )
                old_secret_to_update.lineno = new_secret_found.lineno
                updated = True

    return updated


def format_baseline_for_output(baseline):
    """
    :type baseline: dict
    :rtype: str
    """
    lines = []
    for filename, secret_list in baseline['results'].items():
        lines.extend(
            f'{filename}:{secret["line_number"]}:{secret["secret_value"]}' for secret in secret_list
        )

    return '\n'.join(lines)


def _is_git_repository(rootdir):
    try:
        result = subprocess.run(
            ['git', '-C', os.fspath(rootdir), 'rev-parse', '--is-inside-work-tree'],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return False
    return result.returncode == 0 and result.stdout.strip() == 'true'


def _get_git_tracked_files(rootdir='.'):
    """Parsing .gitignore rules is hard.

    However, a way we can get around this problem by just listing all
    currently tracked git files, and start our search from there.
    After all, if it isn't in the git repo, we're not concerned about
    it, because secrets aren't being entered in a shared place.

    :type rootdir: str
    :param rootdir: root directory of where you want to list files from

    :rtype: set|None
    :returns: filepaths to files which git currently tracks (locally)
    """
    output = []
    try:
        with open(os.devnull, 'w') as fnull:
            git_files = subprocess.check_output(
                [
                    'git',
                    '-C',
                    rootdir,
                    'ls-files',
                    '-z',
                ],
                stderr=fnull,
            )
        for filename in os.fsdecode(git_files).split('\0'):
            if filename:
                relative_path = os.path.relpath(os.path.join(rootdir, filename))
                if os.path.isfile(relative_path):
                    output.append(relative_path)
    except subprocess.CalledProcessError:
        pass
    return output


def _get_files_recursively(rootdir, exclude_patterns=None):
    """Sometimes, we want to use this tool with non-git repositories.
    This function allows us to do so.
    """
    output = []
    for root, directories, files in os.walk(rootdir):
        # Git's internal metadata is not source content.
        directories[:] = [
            directory
            for directory in directories
            if directory != '.git'
            and not is_excluded(os.path.join(root, directory), exclude_patterns)
        ]
        for filename in files:
            relative_path = os.path.relpath(os.path.join(root, filename))
            if os.path.isfile(relative_path):
                output.append(relative_path)
    return output
