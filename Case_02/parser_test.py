
from parser import Finding, parse_line,parse_file
import tracemalloc
import types
import pytest
import builtins

#to test the parse_line function with various valid inputs and expected outputs
@pytest.mark.parametrize("lines,expected",
                         [("src/app.py:12:5: E722 Do not use bare except",
                           Finding("src/app.py", 12, 5, "E722", "Do not use bare except")),
                          ("src/main.py:20: E501 Line too long",
                           Finding("src/main.py", 20, None, "E501", "Line too long")),
                          (r"C:\Users\nadha\proj\app.py:12:5: E722 Bare except",
                           Finding(r"C:\Users\nadha\proj\app.py", 12, 5, "E722", "Bare except")),
                          ("src/my project/app.py:15:3: E501 Line too long",
                           Finding("src/my project/app.py", 15, 3, "E501", "Line too long")),
                          ("src/café/app.py:8:2: E722 Invalid exception",
                           Finding("src/café/app.py", 8, 2, "E722", "Invalid exception"))])
def test_parse_line_valid(lines, expected):
    assert parse_line(lines) == expected

#to test if garbage values or invalid path outputs to None
@pytest.mark.parametrize("lines", [
    "",
    "hello world",
    "This is just garbage",
    "src/app.py:abc:5: E722 Invalid line number",
    "src/app.py:12:abc: E722 Invalid column",
    "src/app.py:12:5 E722 Missing separator",
    "src/app.py:12:5: Invalid error code",
    "src/app.py:12:5: E722",
    "random text without a valid format"
])
def test_parse_line_None(lines):
    assert parse_line(lines) is None

#to test non string inputs to parse_line function raises TypeError
@pytest.mark.parametrize("lines", [
    123,
    None,
    45.6,
    ["src/app.py:12:5: E722 Error"],
    {"path": "src/app.py"}
])
def test_parse_line_non_string(lines):
    with pytest.raises(TypeError):
        parse_line(lines)

#to test parse_file function to ignore invalid lines and only yield valid Finding objects
def test_parse_file_ignores_invalid_lines(tmp_path):

    file_path = tmp_path / "errors.txt"

    file_path.write_text(
        "src/app.py:12:5: E722 Do not use bare except\n"
        "This is garbage\n"
        "src/main.py:20: E501 Line too long\n"
        "Invalid input\n"
    )

    findings = list(parse_file(str(file_path)))

    expected = [
        Finding("src/app.py", 12, 5, "E722", "Do not use bare except"),
        Finding("src/main.py", 20, None, "E501", "Line too long")
    ]

    assert findings == expected

#to test that parse_file function closes the file after an early stop in iteration
def test_file_closes_after_early_stop(tmp_path, monkeypatch): #monkeypatch - temporarily replaces fn or attributes during testing

    file_path = tmp_path/"errors.txt"

    file_path.write_text("src/app.py:12:5: E722 Do not use bare except\n"
                         "src/main.py:20: E501 Line too long\n")

    real_open = builtins.open #python open() is stored 
    opened_files = [] #to track the opened files

    #track the file when it is open
    def tracked_open(*args, **kwargs): #accepts the same arguments as open(path, "r")
        file = real_open(*args, **kwargs) #calls the actual open() and stores the file object 
        opened_files.append(file) #add it to the list
        return file

    monkeypatch.setattr(builtins, "open", tracked_open) #replaces the builtins.open with tracked open fn

    findings = parse_file(str(file_path))

    first = next(findings)

    # File should still be open
    assert opened_files[0].closed is False 

    findings.close()

    # File should now be closed
    assert opened_files[0].closed is True

#to test that parse_file function is lazy and does not read the entire file into memory at once
def test_parse_file_is_lazy(tmp_path):
    file_path = tmp_path/"errors.txt"

    lines = [f"src/file{i}.py:{i}:5: E722 Error message\n" for i in range(100_000)]

    file_path.write_text("".join(lines))

    findings = parse_file(str(file_path))
    assert isinstance(findings, types.GeneratorType)
    tracemalloc.start()
    count = sum(1 for _ in findings)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert count == 100_000
    assert peak < 5_000_000
