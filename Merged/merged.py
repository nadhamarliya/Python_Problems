# ============================================================
# IMPORTS
# ============================================================

import copy
import math
import os
import re
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

# ============================================================
# DATA MODELS
# ============================================================

@dataclass(frozen=True, slots=True)
class LogFinding:
    """A finding parsed from a text-based linter or scanner log."""
    path: str
    line: int
    col: int | None
    code: str
    message: str

@dataclass(frozen=True)
class SecurityFinding:
    """A normalised security finding reported by a security tool."""
    path: str
    line: int
    cwe: str
    severity: str
    tools: tuple[str, ...]

# ============================================================
# GENERAL UTILITY FUNCTIONS (from solution.py)
# ============================================================


def add_finding(finding, bucket=None):
    """Append a finding to a bucket, creating a new bucket if needed."""
    if bucket is None:
        bucket = []
    bucket.append(finding)
    return bucket


def make_multipliers():
    """Return functions that multiply their input by 0, 1, and 2."""
    return [lambda x, i=i: x * i for i in range(3)]


def drop_info(findings):
    """Return findings whose severity is not 'info'."""
    return [finding for finding in findings if finding["sev"] != "info"]


def is_same_rule(rule_a, rule_b):
    """Check whether two rule identifiers are equal."""
    return rule_a == rule_b


def clone_report(report):
    """Return a deep copy of a report."""
    return copy.deepcopy(report)


def budget_met(costs):
    """Check whether the sum of costs is approximately 0.3."""
    return math.isclose(sum(costs), 0.3)


def average(total, count):
    """Return the arithmetic average of total and count."""
    return total / count


# ============================================================
# LOG PARSING (from parser.py)
# ============================================================

# Compile the pattern once so it can be reused for every parsed line.
LOG_PATTERN = re.compile(
    r"^(?P<path>(?:[A-Za-z]:)?[^:]+):(?P<line>\d+)(?::(?P<col>\d+))?: "
    r"(?P<error>[A-Z]\d+)\s+(?P<message>.+)$"
)


def parse_file(path: str | os.PathLike) -> Iterator[LogFinding]:
    """Parse a log file line by line, yielding valid findings lazily."""
    with open(path, "r", encoding="utf-8") as file:
        for raw_line in file:
            if raw_line.isspace() or raw_line == "\n":
                continue

            finding = parse_line(raw_line)
            if finding is not None:
                yield finding


def parse_line(line: str) -> LogFinding | None:
    """Parse one log line; return None for invalid lines."""
    if not isinstance(line, str):
        raise TypeError("Input must be a string")

    cleaned_line = line.rstrip("\r\n")
    if not cleaned_line:
        return None

    result = LOG_PATTERN.match(cleaned_line)
    if result is None:
        return None

    col_text = result.group("col")

    return LogFinding(
        path=result.group("path"),
        line=int(result.group("line")),
        col=int(col_text) if col_text is not None else None,
        code=result.group("error"),
        message=result.group("message"),
    )


# ============================================================
# SECURITY FINDING NORMALISATION (from normalise.py)
# ============================================================

SEVERITY_MAP = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "NONE": "NONE",
}

SEVERITY_RANKS = {
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "NONE": 0,
}


def normalise_path(path: str) -> str:
    """Convert a path to a consistent slash-separated lowercase format."""
    if not path:
        return ""

    return Path(path.replace("\\", "/")).as_posix().removeprefix("./").lower()


def normalise_severity(raw_severity: object) -> str:
    """Map tool-specific severity labels to HIGH, MEDIUM, LOW, or NONE."""
    if not raw_severity:
        return "NONE"

    severity = str(raw_severity).upper()
    return SEVERITY_MAP.get(severity, "NONE")


def parse_line_number(raw_line: object) -> int | None:
    """Convert a supported line-number value to int, or return None."""
    if raw_line is None or isinstance(raw_line, bool):
        return None

    try:
        return int(raw_line)
    except (ValueError, TypeError, OverflowError):
        return None


def parse_cwe(raw_cwe: object) -> str:
    """Extract a normalised CWE identifier from supported input formats."""
    if isinstance(raw_cwe, dict):
        raw_cwe = raw_cwe.get("id")
    elif isinstance(raw_cwe, list):
        raw_cwe = raw_cwe[0] if raw_cwe else None

    if raw_cwe is None:
        return "NONE"

    cwe = str(raw_cwe).strip().upper()

    if not cwe or cwe == "NONE":
        return "NONE"

    if cwe.startswith("CWE-"):
        return cwe.split(":")[0].strip()

    return f"CWE-{cwe}"


def normalise_bandit(raw: dict) -> SecurityFinding | None:
    """Convert a raw Bandit finding into a SecurityFinding."""
    if not raw:
        return None

    path = normalise_path(raw.get("filename"))
    line = parse_line_number(raw.get("line_number"))

    if not path or line is None:
        return None

    return SecurityFinding(
        path=path,
        line=line,
        cwe=parse_cwe(raw.get("issue_cwe")),
        severity=normalise_severity(raw.get("issue_severity")),
        tools=("bandit",),
    )


def normalise_semgrep(raw: dict) -> SecurityFinding | None:
    """Convert a raw Semgrep finding into a SecurityFinding."""
    if not raw:
        return None

    path = normalise_path(raw.get("path"))

    start_data = raw.get("start")
    raw_line = start_data.get("line") if isinstance(start_data, dict) else None
    line = parse_line_number(raw_line)

    if not path or line is None:
        return None

    extra = raw.get("extra")
    extra = extra if isinstance(extra, dict) else {}

    metadata = extra.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}

    return SecurityFinding(
        path=path,
        line=line,
        cwe=parse_cwe(metadata.get("cwe")),
        severity=normalise_severity(extra.get("severity")),
        tools=("semgrep",),
    )


def normalise_ruff(raw: dict) -> SecurityFinding | None:
    """Convert a raw Ruff finding into a SecurityFinding."""
    if not raw:
        return None

    path = normalise_path(raw.get("filename"))

    location = raw.get("location")
    raw_line = location.get("row") if isinstance(location, dict) else None
    line = parse_line_number(raw_line)

    if not path or line is None:
        return None

    return SecurityFinding(
        path=path,
        line=line,
        cwe="NONE",
        severity="LOW",
        tools=("ruff",),
    )


# ============================================================
# SECURITY FINDING MERGING
# ============================================================


def highest_severity(sev1: str, sev2: str) -> str:
    """Return whichever severity has the higher configured rank."""
    rank1 = SEVERITY_RANKS.get(sev1, 0)
    rank2 = SEVERITY_RANKS.get(sev2, 0)
    return sev1 if rank1 >= rank2 else sev2


def reduce_cluster(
    path: str, cwe: str, cluster: list[SecurityFinding]
) -> SecurityFinding:
    """Collapse nearby findings into one finding with combined metadata."""
    highest_sev = "NONE"
    all_tools = set()

    for finding in cluster:
        highest_sev = highest_severity(highest_sev, finding.severity)
        all_tools.update(finding.tools)

    return SecurityFinding(
        path=path,
        line=cluster[0].line,
        cwe=cwe,
        severity=highest_sev,
        tools=tuple(sorted(all_tools)),
    )


def merge(
    findings: list[SecurityFinding], tol: int = 2
) -> list[SecurityFinding]:
    """Merge findings sharing a path and CWE when consecutive lines are within tol."""
    if not findings:
        return []

    # Group findings that have the same file path and CWE.
    groups = defaultdict(list)
    for finding in findings:
        groups[(finding.path, finding.cwe)].append(finding)

    merged_findings = []

    # Sort and merge each path/CWE group independently.
    for (path, cwe), group in groups.items():
        sorted_group = sorted(group, key=lambda finding: finding.line)
        current_cluster = [sorted_group[0]]

        # Compare each finding with the previous finding in its cluster (chaining).
        for current in sorted_group[1:]:
            last_finding = current_cluster[-1]

            if current.line - last_finding.line <= tol:
                current_cluster.append(current)
            else:
                merged_findings.append(reduce_cluster(path, cwe, current_cluster))
                current_cluster = [current]

        # The final cluster has no later gap to trigger its reduction.
        merged_findings.append(reduce_cluster(path, cwe, current_cluster))

    return sorted(
        merged_findings,
        key=lambda finding: (finding.path, finding.line),
    )


# ============================================================
# SECURITY REPORT DISPATCH AND MAIN PIPELINE
# ============================================================


def normalise_finding(raw: dict) -> SecurityFinding | None:
    """Identify the source tool and call its matching normaliser."""
    if not isinstance(raw, dict):
        return None

    if "filename" in raw and "issue_severity" in raw:
        return normalise_bandit(raw)

    if "path" in raw and "extra" in raw:
        return normalise_semgrep(raw)

    if "filename" in raw and "location" in raw and "code" in raw:
        return normalise_ruff(raw)

    return None


def main_pipeline(
    raw_reports: list[dict], tol: int = 2
) -> list[SecurityFinding]:
    """Normalise raw security reports and merge the resulting findings."""
    unified_findings = []

    for raw_record in raw_reports:
        finding = normalise_finding(raw_record)
        if finding is not None:
            unified_findings.append(finding)

    return merge(unified_findings, tol=tol)
