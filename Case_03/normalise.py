from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    cwe: str
    severity: str
    tools: tuple[str, ...]

SEVERITY_MAP = {"ERROR": "HIGH","WARNING": "MEDIUM","INFO": "LOW","HIGH": "HIGH","MEDIUM": "MEDIUM","LOW": "LOW","NONE": "NONE"}
SEVERITY_RANKS = {"HIGH": 3,"MEDIUM": 2,"LOW": 1,"NONE": 0}

"""normalises file paths to a standard format"""
def normalise_path(path: str) -> str:
    if not path:
        return ""

    return Path(path.replace("\\", "/")).as_posix().removeprefix("./").lower()

"""normalises severity levels to a standard set of values: HIGH, MEDIUM, LOW, NONE. If the input is unrecognised, defaults to LOW."""
def normalise_severity(raw_severity: object) -> str:
    if not raw_severity:
        return "NONE"

    severity = str(raw_severity).upper()
    return SEVERITY_MAP.get(severity, "NONE")
    
"""converts line numbers from strings, ints, or None."""
def parse_line_number(raw_line: object) -> int | None:
    if raw_line is None or isinstance(raw_line, bool):
        return None
    try:
        return int(raw_line)
    except (ValueError, TypeError, OverflowError):
        return None

"""Extracts a CWE string from dicts, lists, or plain strings."""

def parse_cwe(raw_cwe: object) -> str:
    # Extract CWE from dictionary
    if isinstance(raw_cwe, dict):
        raw_cwe = raw_cwe.get("id")

    # Extract first CWE from list
    elif isinstance(raw_cwe, list):
        raw_cwe = raw_cwe[0] if raw_cwe else None

    # Handle missing or empty values
    if raw_cwe is None:
        return "NONE"

    cwe = str(raw_cwe).strip().upper()

    if not cwe or cwe == "NONE":
        return "NONE"

    if cwe.startswith("CWE-"):
        return cwe.split(":")[0].strip()

    return f"CWE-{cwe}"

"""Transforms a raw Bandit finding dictionary into a standard Finding object"""
def normalise_bandit(raw: dict) -> Finding | None:
    if not raw:
        return None
        
    path = normalise_path(raw.get("filename")) #normalise the file path
    line = parse_line_number(raw.get("line_number")) #normalise the line number
    
    #If path or line number is missing, the record is unusable
    if not path or line is None:
        return None
        
    cwe = parse_cwe(raw.get("issue_cwe")) #retrieve the CWE from the raw data
    severity = normalise_severity(raw.get("issue_severity")) #retrieve the severity from the raw data
    
    return Finding(
        path=path,
        line=line,
        cwe=cwe,
        severity=severity,
        tools=("bandit",)
    )

"""Transforms a raw Semgrep finding dictionary into a standard Finding object."""
def normalise_semgrep(raw: dict) -> Finding | None:
    if not raw:
        return None
        
    path = normalise_path(raw.get("path"))
    
    # Semgrep nests line number under 'start' -> 'line'
    start_data = raw.get("start")
    raw_line = start_data.get("line") if isinstance(start_data, dict) else None # Extract the line number
    line = parse_line_number(raw_line) #normalise the line number
    
    if not path or line is None:
        return None
        
    # Semgrep nests extra -> metadata -> cwe and extra -> severity
    extra = raw.get("extra")
    extra = extra if isinstance(extra, dict) else {}
    
    metadata = extra.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
        
    cwe = parse_cwe(metadata.get("cwe"))
    severity = normalise_severity(extra.get("severity"))
    
    return Finding(
        path=path,
        line=line,
        cwe=cwe,
        severity=severity,
        tools=("semgrep",)
    )

"""Transforms a raw Ruff finding dictionary into a standard Finding object."""
def normalise_ruff(raw: dict) -> Finding | None:
    
    if not raw:
        return None
        
    path = normalise_path(raw.get("filename"))
    
    # Ruff nests row under 'location' -> 'row'
    location = raw.get("location")
    raw_line = location.get("row") if isinstance(location, dict) else None
    line = parse_line_number(raw_line)
    
    if not path or line is None:
        return None
        
    # Ruff has no CWE in this format so use "NONE"
    cwe = "NONE"
    severity = "LOW"  # Default INFO -> LOW
    
    return Finding(
        path=path,
        line=line,
        cwe=cwe,
        severity=severity,
        tools=("ruff",)
    )

#MERGE FUNCTION PART

"""Compares two severity strings and returns the higher one"""
def highest_severity(sev1: str, sev2: str) -> str:
    rank1 = SEVERITY_RANKS.get(sev1, 0)
    rank2 = SEVERITY_RANKS.get(sev2, 0)

    return sev1 if rank1 >= rank2 else sev2

    
"""Collapses a cluster of overlapping findings into a single unified Finding."""
def reduce_cluster(path: str, cwe: str, cluster: list[Finding]) -> Finding:
    highest_sev = "NONE"
    all_tools = set()
    
    for finding in cluster:
        highest_sev = highest_severity(highest_sev, finding.severity)
        all_tools.update(finding.tools)
        
    return Finding(
        path=path,
        line=cluster[0].line,
        cwe=cwe,
        severity=highest_sev,
        tools=tuple(sorted(all_tools))
    )


def merge(findings: list[Finding], tol: int = 2) -> list[Finding]:
    """
    Merge overlapping findings based on path, cwe, and line tolerance
    picks highest severity, groups unique tools, 
    and returns findings ordered by path then line
    """
    if not findings:
        return []

    #Group findings by (path, cwe) 
    groups = defaultdict(list)

    for f in findings:
        groups[(f.path, f.cwe)].append(f)

    merged_findings = []

    #Process each bucket independently
    for (path, cwe), group in groups.items():
        sorted_group = sorted(group, key=lambda x: x.line)# Sort the group by line number 

        # Initialise irst cluster with the first finding
        current_cluster = [sorted_group[0]]
        
        # Merge using chaining
        for current in sorted_group[1:]:
            last_finding = current_cluster[-1]
            
            # If current line is within tol of the previous item in the cluster then join it
            if (current.line - last_finding.line) <= tol:
                current_cluster.append(current)
            else:
                # if Gap exceeds tol then finalize current cluster and start a new one
                merged_findings.append(reduce_cluster(path, cwe, current_cluster))
                current_cluster = [current]
        
        # Append the final remaining cluster in this bucket
        merged_findings.append(reduce_cluster(path, cwe, current_cluster))

    # sort all merged findings by path, then line number ascending
    return sorted(merged_findings, key=lambda f: (f.path, f.line))


"""
    Mapping the input to the appropriate tool normalisation function
"""
def normalise_finding(raw: dict) -> Finding | None:

    if not isinstance(raw, dict):
        return None
        
    # Bandit has 'filename' and 'issue_severity'
    if "filename" in raw and "issue_severity" in raw:
        return normalise_bandit(raw)
        
    # Semgrep  has 'path' and 'extra'
    if "path" in raw and "extra" in raw:
        return normalise_semgrep(raw)
        
    # Ruff has 'filename', 'location', and 'code'
    if "filename" in raw and "location" in raw and "code" in raw:
        return normalise_ruff(raw)
        
    # If no tool matches drop the record 
    return None

"""
    Ingests raw reports, normalises them 
    into a list of Finding objects, and runs the merge function
"""
def main_pipeline(raw_reports: list[dict], tol: int = 2) -> list[Finding]:

    unified_findings: list[Finding] = []
    
    # 1. Ingestion & Normalisation Phase
    for raw_record in raw_reports:
        finding = normalise_finding(raw_record)
        if finding is not None:
            unified_findings.append(finding)
            
    # 2. Reduction & Merging Phase 
    final_merged_report = merge(unified_findings, tol=tol)
    
    return final_merged_report

