
from enum import Enum


class AnsiColor(Enum):
    RESET = '[0m'
    BOLD = '[1m'
    RED = '[91m'
    RED_BACKGROUND = '[41m'
    LIGHT_GREEN = '[92m'
    PURPLE = '[95m'


def colorize(text, color):
    return f'\x1b{color.value}{text}\x1b{AnsiColor.RESET.value}'
