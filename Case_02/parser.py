from collections.abc import Iterator  # Modern standard for type hinting generators/iterators (PEP 585)
from dataclasses import dataclass
import os
import re
from typing import Optional

@dataclass(frozen=True, slots=True) #slots=True for memory efficiency and faster attribute access
class Finding:
    path: str
    line: int
    col: Optional[int]
    code: str
    message: str

# Pre-compile the regex pattern once at the module level for performance
LOG_PATTERN = re.compile(
    r"^(?P<path>(?:[A-Za-z]:)?[^:]+):(?P<line>\d+)(?::(?P<col>\d+))?: (?P<error>[A-Z]\d+)\s+(?P<message>.+)$"
)

def parse_file(path: str | os.PathLike) -> Iterator[Finding]:
    """
    Parses a file line by line, yielding Finding objects lazily.
    Accepts both strings and pathlib.Path objects 
    """
    # encoding="utf-8" to ensure cross-platform compatibility
    with open(path, "r", encoding="utf-8") as file:
        for raw_line in file:
            if not raw_line.isspace() and raw_line != "\n":
                 finding = parse_line(raw_line)
                 if finding is not None:
                     yield finding

def parse_line(line: str) -> Optional[Finding]:
    """
    Parses a single line into a Finding object or returns None if invalid.
    Raises TypeError if input is not a string.
    """
    if not isinstance(line, str):
        raise TypeError("Input must be a string")

    # Strip trailing newlines (\n) and whitespace
    cleaned_line = line.rstrip("\r\n")
    if not cleaned_line:
        return None

    # Use re.match instead of re.search to ensure that parsing starts from character zero, preventing accidental matches hidden inside random garbage text.
    result = LOG_PATTERN.match(cleaned_line)
    if not result:
        return None

    path = result.group("path")
    line_num = int(result.group("line"))
    col_str = result.group("col")
    col = int(col_str) if col_str is not None else None
    
    return Finding(
        path=path,
        line=line_num,
        col=col,
        code=result.group("error"),
        message=result.group("message")
    )