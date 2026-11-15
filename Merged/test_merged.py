"""Combined tests for utilities, log parsing, and security processing."""

# ============================================================
# IMPORTS
# ============================================================

import builtins
import tracemalloc
import types

import pytest

from merged import (
    LogFinding,
    SecurityFinding,
    add_finding,
    average,
    budget_met,
    clone_report,
    drop_info,
    is_same_rule,
    make_multipliers,
    main_pipeline,
    merge,
    normalise_bandit,
    normalise_ruff,
    normalise_semgrep,
    parse_file,
    parse_line,
)


# ============================================================
# GENERAL UTILITY FUNCTION TESTS (from buggy_test.py)
# ============================================================


def test_add_finding():
    first = add_finding("a")
    second = add_finding("b")

    assert first == ["a"]
    assert second == ["b"]


def test_make_multipliers():
    result = [function(10) for function in make_multipliers()]
    assert result == [0, 10, 20]


@pytest.mark.parametrize(
    "findings, expected",
    [
        ([{"sev": "info"}, {"sev": "high"}], [{"sev": "high"}]),
        ([{"sev": "info"}, {"sev": "info"}, {"sev": "high"}], [{"sev": "high"}]),
        ([{"sev": "info"}, {"sev": "info"}, {"sev": "info"}], []),
    ],
)
def test_drop_info(findings, expected):
    assert drop_info(findings) == expected


def test_is_same_rule():
    rule_a = "".join(["sem", "grep"])
    rule_b = "semgrep"

    assert is_same_rule(rule_a, rule_b) is True


def test_clone_report():
    report = {"files": ["a.py"]}
    cloned_report = clone_report(report)
    cloned_report["files"].append("b.py")

    assert report["files"] == ["a.py"]


def test_budget_met():
    assert budget_met([0.1, 0.2]) is True


def test_average():
    assert average(7, 2) == 3.5


# ============================================================
# LOG PARSER TESTS (from parser_test.py)
# ============================================================


@pytest.mark.parametrize(
    "line, expected",
    [
        (
            "src/app.py:12:5: E722 Do not use bare except",
            LogFinding("src/app.py", 12, 5, "E722", "Do not use bare except"),
        ),
        (
            "src/main.py:20: E501 Line too long",
            LogFinding("src/main.py", 20, None, "E501", "Line too long"),
        ),
        (
            r"C:\Users\nadha\proj\app.py:12:5: E722 Bare except",
            LogFinding(r"C:\Users\nadha\proj\app.py", 12, 5, "E722", "Bare except"),
        ),
        (
            "src/my project/app.py:15:3: E501 Line too long",
            LogFinding("src/my project/app.py", 15, 3, "E501", "Line too long"),
        ),
        (
            "src/café/app.py:8:2: E722 Invalid exception",
            LogFinding("src/café/app.py", 8, 2, "E722", "Invalid exception"),
        ),
    ],
)
def test_parse_line_valid(line, expected):
    assert parse_line(line) == expected


@pytest.mark.parametrize(
    "line",
    [
        "",
        "hello world",
        "This is just garbage",
        "src/app.py:abc:5: E722 Invalid line number",
        "src/app.py:12:abc: E722 Invalid column",
        "src/app.py:12:5 E722 Missing separator",
        "src/app.py:12:5: Invalid error code",
        "src/app.py:12:5: E722",
        "random text without a valid format",
    ],
)
def test_parse_line_invalid_returns_none(line):
    assert parse_line(line) is None


@pytest.mark.parametrize(
    "line",
    [123, None, 45.6, ["src/app.py:12:5: E722 Error"], {"path": "src/app.py"}],
)
def test_parse_line_non_string_raises_type_error(line):
    with pytest.raises(TypeError):
        parse_line(line)


def test_parse_file_ignores_invalid_lines(tmp_path):
    file_path = tmp_path / "errors.txt"
    file_path.write_text(
        "src/app.py:12:5: E722 Do not use bare except\n"
        "This is garbage\n"
        "src/main.py:20: E501 Line too long\n"
        "Invalid input\n",
        encoding="utf-8",
    )

    findings = list(parse_file(file_path))
    expected = [
        LogFinding("src/app.py", 12, 5, "E722", "Do not use bare except"),
        LogFinding("src/main.py", 20, None, "E501", "Line too long"),
    ]

    assert findings == expected


def test_file_closes_after_early_stop(tmp_path, monkeypatch):
    file_path = tmp_path / "errors.txt"
    file_path.write_text(
        "src/app.py:12:5: E722 Do not use bare except\n"
        "src/main.py:20: E501 Line too long\n",
        encoding="utf-8",
    )

    real_open = builtins.open
    opened_files = []

    def tracked_open(*args, **kwargs):
        file = real_open(*args, **kwargs)
        opened_files.append(file)
        return file

    monkeypatch.setattr(builtins, "open", tracked_open)

    findings = parse_file(file_path)
    next(findings)

    assert opened_files[0].closed is False

    findings.close()

    assert opened_files[0].closed is True


def test_parse_file_is_lazy(tmp_path):
    file_path = tmp_path / "errors.txt"
    lines = [
        f"src/file{index}.py:{index}:5: E722 Error message\n"
        for index in range(100_000)
    ]
    file_path.write_text("".join(lines), encoding="utf-8")

    findings = parse_file(file_path)
    assert isinstance(findings, types.GeneratorType)

    tracemalloc.start()
    try:
        count = sum(1 for _ in findings)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert count == 100_000
    assert peak < 5_000_000


# ============================================================
# SECURITY NORMALISATION AND MERGING TESTS (from test_pipeline.py)
# ============================================================


def test_empty_inputs():
    assert merge([], tol=2) == []
    assert main_pipeline([], tol=2) == []


def test_line_chaining():
    findings = [
        SecurityFinding("src/app.py", 10, "CWE-89", "LOW", ("bandit",)),
        SecurityFinding("src/app.py", 12, "CWE-89", "MEDIUM", ("semgrep",)),
        SecurityFinding("src/app.py", 14, "CWE-89", "LOW", ("ruff",)),
    ]

    result = merge(findings, tol=2)

    assert len(result) == 1
    assert result[0].line == 10
    assert result[0].severity == "MEDIUM"
    assert result[0].tools == ("bandit", "ruff", "semgrep")


def test_gap_exceeds_tolerance():
    findings = [
        SecurityFinding("src/app.py", 10, "CWE-89", "LOW", ("bandit",)),
        SecurityFinding("src/app.py", 15, "CWE-89", "LOW", ("semgrep",)),
    ]

    result = merge(findings, tol=2)

    assert len(result) == 2
    assert result[0].line == 10
    assert result[1].line == 15


def test_input_immutability():
    original_findings = [
        SecurityFinding("src/app.py", 14, "CWE-89", "LOW", ("ruff",)),
        SecurityFinding("src/app.py", 10, "CWE-89", "HIGH", ("bandit",)),
    ]
    original_copy = list(original_findings)

    merge(original_findings, tol=2)

    assert original_findings == original_copy


def test_end_to_end_pipeline():
    raw_reports = [
        {
            "filename": "src\\app.py",
            "line_number": "10",
            "issue_severity": "HIGH",
            "issue_cwe": {"id": 89},
        },
        {
            "path": "./src/app.py",
            "start": {"line": 12},
            "extra": {
                "severity": "WARNING",
                "metadata": {"cwe": ["CWE-89: SQL Injection"]},
            },
        },
    ]

    results = main_pipeline(raw_reports, tol=2)

    assert len(results) == 1
    assert results[0].path == "src/app.py"
    assert results[0].line == 10
    assert results[0].cwe == "CWE-89"
    assert results[0].severity == "HIGH"
    assert results[0].tools == ("bandit", "semgrep")


def test_different_paths_stay_separate():
    findings = [
        SecurityFinding("src/app.py", 10, "CWE-89", "HIGH", ("bandit",)),
        SecurityFinding("src/login.py", 10, "CWE-89", "LOW", ("semgrep",)),
    ]

    result = merge(findings, tol=2)

    assert len(result) == 2
    assert result[0].path == "src/app.py"
    assert result[1].path == "src/login.py"


def test_normalise_bandit():
    raw = {
        "filename": "src\\app.py",
        "line_number": "10",
        "issue_severity": "HIGH",
        "issue_cwe": {"id": 89},
    }

    assert normalise_bandit(raw) == SecurityFinding(
        "src/app.py", 10, "CWE-89", "HIGH", ("bandit",)
    )


def test_normalise_semgrep():
    raw = {
        "path": "./src/app.py",
        "start": {"line": 12},
        "extra": {
            "severity": "WARNING",
            "metadata": {"cwe": ["CWE-89: SQL Injection"]},
        },
    }

    assert normalise_semgrep(raw) == SecurityFinding(
        "src/app.py", 12, "CWE-89", "MEDIUM", ("semgrep",)
    )


def test_normalise_ruff():
    raw = {
        "filename": "src/utils.py",
        "location": {"row": 5},
        "code": "E722",
    }

    assert normalise_ruff(raw) == SecurityFinding(
        "src/utils.py", 5, "NONE", "LOW", ("ruff",)
    )
