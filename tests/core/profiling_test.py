import pytest

from simple_detect_secrets.core.profiling import PluginProfiler
from simple_detect_secrets.core.secrets_collection import SecretsCollection


class FastDetector:
    def analyze(self, source, filename):
        source.read()
        return {}


class SlowDetector(FastDetector):
    pass


def test_timings_accumulate_across_files(tmp_path, monkeypatch, capsys):
    clock = iter([0, 1, 1, 4, 4, 6, 6, 10])
    monkeypatch.setattr('simple_detect_secrets.core.profiling.perf_counter', lambda: next(clock))
    plugins = (FastDetector(), SlowDetector())
    profiler = PluginProfiler(plugins)
    collection = SecretsCollection(plugins, profiler=profiler)
    for filename in ('first', 'second'):
        path = tmp_path / filename
        path.write_text('ordinary text\n')
        assert collection.scan_file(str(path))

    assert profiler.timings == {'FastDetector': 3, 'SlowDetector': 7}
    profiler.report()
    captured = capsys.readouterr()
    assert captured.out == ''
    assert captured.err.index('SlowDetector') < captured.err.index('FastDetector')
    assert '3.000000 s' in captured.err
    assert '7.000000 s' in captured.err
    assert '10.000000 s' in captured.err


def test_timing_is_recorded_when_detector_raises(monkeypatch):
    clock = iter([1, 3])
    monkeypatch.setattr('simple_detect_secrets.core.profiling.perf_counter', lambda: next(clock))
    plugin = FastDetector()
    profiler = PluginProfiler((plugin,))

    def fail():
        raise UnicodeDecodeError('utf-8', b'\xff', 0, 1, 'invalid byte')

    with pytest.raises(UnicodeDecodeError):
        profiler.call(plugin, fail)
    assert profiler.timings == {'FastDetector': 2}
