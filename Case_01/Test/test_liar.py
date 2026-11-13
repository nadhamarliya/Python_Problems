
import pytest

from solution import (process_scores,clean_username,update_data,calculate_total)


@pytest.mark.parametrize("scores, expected", [
    ([5, 2, 8], [2, 5, 8]),
    ([10, 1, 4], [1, 4, 10])
])
def test_process_scores(scores, expected):
    assert process_scores(scores) == expected


@pytest.mark.parametrize("username, expected", [
    ("PYPYTHONPY", "PYTHON"),
    ("PYTHON123", "THON123"),
    ("PYPYTHON", "PYTHON")
])
def test_clean_username(username, expected):
    assert clean_username(username) == expected


def test_update_data_tuple():
    data = (10, 20, [30, 40])
    result = update_data(data)

    assert result == (10, 20, [30, 40, 50, 60])


def test_update_data_list():
    data = [10, 20, [30, 40]]
    result = update_data(data)

    assert result == [10, 20, [30, 40, 50, 60]]


def test_calculate_total():
    assert calculate_total([10, 20, 30]) == 20


def test_calculate_total_decimal():
    assert calculate_total([1, 2]) == 1.5


def test_calculate_total_empty():
    with pytest.raises(ValueError):
        calculate_total([])
