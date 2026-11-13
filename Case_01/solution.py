import math
import copy

def add_finding(finding, bucket=None):
    if bucket is None:
        bucket = []
    bucket.append(finding)
    return bucket

def make_multipliers():
    return [lambda x, i=i: x * i for i in range(3)]

def drop_info(findings):
    return [f for f in findings if f["sev"] != "info"]

def is_same_rule(a, b):
    return a == b


def clone_report(report):
    return copy.deepcopy(report)

def budget_met(costs):
    return math.isclose(sum(costs), 0.3)

def average(total, count):
    return total / count
