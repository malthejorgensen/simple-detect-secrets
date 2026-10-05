import sys
from time import perf_counter


class PluginProfiler:
    def __init__(self, plugins):
        self.timings = {plugin.__class__.__name__: 0.0 for plugin in plugins}

    def call(self, plugin, method, *args):
        start = perf_counter()
        try:
            return method(*args)
        finally:
            self.timings[plugin.__class__.__name__] += perf_counter() - start

    def report(self):
        print('\nDetector profile (elapsed seconds):', file=sys.stderr)
        for name, seconds in sorted(self.timings.items(), key=lambda item: (-item[1], item[0])):
            print(f'  {name:<25} {seconds:.6f} s', file=sys.stderr)
        print(f'  {"Total":<25} {sum(self.timings.values()):.6f} s', file=sys.stderr, flush=True)
