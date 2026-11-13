import pytest
from normalise import (  # Replace with your actual filename (e.g., pipeline)
    Finding,
    run_security_pipeline,
    merge,
    normalise_bandit,
    normalise_semgrep,
    normalise_ruff
)

def test_empty_inputs():
    """Verify empty input returns empty list without errors."""
    assert merge([], tol=2) == []
    assert run_security_pipeline([], tol=2) == []


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
    
    results = run_security_pipeline(raw_reports, tol=2)
    
    assert len(results) == 1
    assert results[0].path == "src/app.py"
    assert results[0].line == 10
    assert results[0].cwe == "CWE-89"
    assert results[0].severity == "HIGH"  # HIGH wins over WARNING (MEDIUM)
    assert results[0].tools == ("bandit", "semgrep")


def test_ruff_combines_when_bucket_matches():
    """Verify that Ruff findings combine if they share the exact same path and CWE-NONE bucket within tolerance."""
    raw_reports = [
        {"filename": "src/utils.py", "location": {"row": 5}, "code": "E722"},
        {"filename": "src\\utils.py", "location": {"row": 6}, "code": "F401"},  # Within tol=2, same path, both CWE-NONE
    ]
    
    results = run_security_pipeline(raw_reports, tol=2)
    
    assert len(results) == 1
    assert results[0].path == "src/utils.py"
    assert results[0].line == 5
    assert results[0].cwe == "NONE"
    assert results[0].tools == ("ruff",)


def test_ruff_stays_separate_from_cwe_findings():
    """Verify that Ruff (CWE-NONE) does not combine with Bandit/Semgrep findings that have specific CWEs."""
    raw_reports = [
        {"filename": "src/app.py", "line_number": "10", "issue_severity": "HIGH", "issue_cwe": {"id": 89}}, # CWE-89
        {"filename": "src/app.py", "location": {"row": 10}, "code": "E722"},                              # CWE-NONE
    ]
    
    results = run_security_pipeline(raw_reports, tol=2)
    
    # Expect 2 separate findings because CWE-89 and CWE-NONE go into different buckets
    assert len(results) == 2
    assert {results[0].cwe, results[1].cwe} == {"CWE-89", "NONE"}