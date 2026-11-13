"""Case 01 starter: six liars. Every function below looks right. None of them is."""
    
def add_finding(finding, bucket=[]):
    bucket.append(finding)
    return bucket

def make_multipliers():
    return [lambda x: x * i for i in range(3)]

def drop_info(findings):
    for f in findings:
        if f["sev"] == "info":
            findings.remove(f)
    return findings

def is_same_rule(a, b):
    return a is b

def clone_report(report):
    return report.copy()

def budget_met(costs):
    return sum(costs) == 0.3

def average(total, count):
    return total // count

