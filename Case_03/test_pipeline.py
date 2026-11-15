import pytest
from normalise import (  # Replace with your actual filename (e.g., pipeline)
    Finding,
    main_pipeline,
    merge,
    normalise_bandit,
    normalise_semgrep,
    normalise_ruff
)

def test_empty_inputs():
    """Verify empty input returns empty list without errors."""
    assert merge([], tol=2) == []
    assert main_pipeline([], tol=2) == []


def test_line_chaining():
    """Verify that lines 10, 12, and 14 collapse into a single finding with tol=2."""
    findings = [
        Finding(path="src/app.py", line=10, cwe="CWE-89", severity="LOW", tools=("bandit",)),
        Finding(path="src/app.py", line=12, cwe="CWE-89", severity="MEDIUM", tools=("semgrep",)),
        Finding(path="src/app.py", line=14, cwe="CWE-89", severity="LOW", tools=("ruff",)),
    ]
    
    result = merge(findings, tol=2)
    
    assert len(result) == 1
    assert result[0].line == 10
    assert result[0].severity == "MEDIUM"  # MEDIUM wins over LOW
    assert result[0].tools == ("bandit", "ruff", "semgrep")  # Sorted & unique


def test_gap_exceeds_tolerance():
    """Verify that a gap exceeding tol creates separate findings."""
    findings = [
        Finding(path="src/app.py", line=10, cwe="CWE-89", severity="LOW", tools=("bandit",)),
        Finding(path="src/app.py", line=15, cwe="CWE-89", severity="LOW", tools=("semgrep",)),  # Gap of 5 > tol=2
    ]
    
    result = merge(findings, tol=2)
    
    assert len(result) == 2
    assert result[0].line == 10
    assert result[1].line == 15


def test_input_immutability():
    """Verify that merge() does not mutate the original input list or order."""
    original_findings = [
        Finding(path="src/app.py", line=14, cwe="CWE-89", severity="LOW", tools=("ruff",)),
        Finding(path="src/app.py", line=10, cwe="CWE-89", severity="HIGH", tools=("bandit",)),
    ]
    # Keep a copy of the original list and tuple elements
    original_copy = list(original_findings)
    
    merge(original_findings, tol=2)
    
    # Ensure original list reference and contents are untouched
    assert original_findings == original_copy


def test_end_to_end_pipeline():
    """Verify raw multi-tool reports successfully ingest, normalise, and merge."""
    raw_reports = [
        {"filename": "src\\app.py", "line_number": "10", "issue_severity": "HIGH", "issue_cwe": {"id": 89}},
        {"path": "./src/app.py", "start": {"line": 12}, "extra": {"severity": "WARNING", "metadata": {"cwe": ["CWE-89: SQL Injection"]}}},
    ]
    
    results = main_pipeline(raw_reports, tol=2)
    
    assert len(results) == 1
    assert results[0].path == "src/app.py"
    assert results[0].line == 10
    assert results[0].cwe == "CWE-89"
    assert results[0].severity == "HIGH"  # HIGH wins over WARNING (MEDIUM)
    assert results[0].tools == ("bandit", "semgrep")

def test_different_paths_stay_separate():
    findings = [
        Finding("src/app.py", 10, "CWE-89", "HIGH", ("bandit",)),
        Finding("src/login.py", 10, "CWE-89", "LOW", ("semgrep",)),
    ]

    result = merge(findings, tol=2)

    assert len(result) == 2
    assert result[0].path == "src/app.py"
    assert result[1].path == "src/login.py"