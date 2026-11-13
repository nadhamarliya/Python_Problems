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


"""normalises file paths to a standard format"""
def normalise_path(path: str) -> str:
    if not path:
        return ""

    cleaned= path.replace("\\","/")
    path_obj= Path(cleaned)
    normalise_str = path_obj.as_posix()
    if normalise_str.startswith("./"):
        normalise_str = normalise_str.removeprefix("./")


    return normalise_str

"""normalises severity levels to a standard set of values: HIGH, MEDIUM, LOW, NONE. If the input is unrecognised, defaults to LOW."""
def normalise_severity(raw_severity) -> str:
    if not raw_severity:
        return "LOW"

    sev_str = str(raw_severity).upper()
    if sev_str == "ERROR":
        return "HIGH"
    if sev_str == "WARNING":
        return "MEDIUM"
    if sev_str == "INFO":
        return "LOW"

    if sev_str in ("HIGH", "MEDIUM", "LOW", "NONE"):
        return sev_str
        
    return "LOW"
    
"""converts line numbers from strings, ints, or None."""
def parse_line_number(raw_line) -> int | None:
    if raw_line is None:
        return None
    try:
        return int(raw_line)
    except (ValueError, TypeError):
        return None

"""Extracts a CWE string from dicts, lists, or plain strings."""

def parse_cwe(raw_cwe) -> str:
    if not raw_cwe:
        return "NONE"
        
    # Bandit-style: {"id": 89}
    if isinstance(raw_cwe, dict): #check the type of raw_cwe to see if it is a dictionary
        cwe_id = raw_cwe.get("id")
        return f"CWE-{cwe_id}" if cwe_id is not None else "NONE" # Return the CWE string or "NONE" if the ID is not found
        
    # Semgrep-style: ["CWE-89: Improper Neutralization ..."]
    if isinstance(raw_cwe, list) and len(raw_cwe) > 0: #check if raw_cwe is a list and has at least one item
        first_item = str(raw_cwe[0])
        # Extract just the CWE-XX part if it contains a colon or description
        if "CWE-" in first_item.upper():
            parts = first_item.split(":")
            return parts[0].strip().upper()
        return first_item
        
    # Plain string
    if isinstance(raw_cwe, str):
        cleaned = raw_cwe.strip()
        if not cleaned or cleaned.upper() == "NONE":
            return "NONE"
        if "CWE-" in cleaned.upper():
            return cleaned.split(":")[0].strip().upper()
        return f"CWE-{cleaned}"
        
    return "NONE"

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
    start_data = raw.get("start", {}) #using {} as a default to avoid KeyError if 'start' is missing
    raw_line = start_data.get("line") if isinstance(start_data, dict) else None # Extract the line number
    line = parse_line_number(raw_line) #normalise the line number
    
    if not path or line is None:
        return None
        
    # Semgrep nests extra -> metadata -> cwe and extra -> severity
    extra = raw.get("extra", {})
    if not isinstance(extra, dict):
        extra = {}
        
    metadata = extra.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}
        
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
    location = raw.get("location", {})
    raw_line = location.get("row") if isinstance(location, dict) else None
    line = parse_line_number(raw_line)
    
    if not path or line is None:
        return None
        
    # Ruff has no CWE in this format so use "NONE"
    cwe = "NONE"
    severity = normalise_severity("INFO")  # Maps to LOW
    
    return Finding(
        path=path,
        line=line,
        cwe=cwe,
        severity=severity,
        tools=("ruff",)
    )

#MERGE FUNCTION PART

# Numerical values to determine severity
SEVERITY_RANKS = {
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "NONE": 0
}

"""Compares two severity strings and returns the higher one"""
def get_highest_severity(sev1: str, sev2: str) -> str:

    rank1 = SEVERITY_RANKS.get(sev1.upper(), 0)
    rank2 = SEVERITY_RANKS.get(sev2.upper(), 0)
    return sev1 if rank1 >= rank2 else sev2

    
"""Combines two tool tuples, removes duplicates, and sorts them alphabetically"""
def merge_tools(tools_1: tuple[str, ...], tools_2: tuple[str, ...]) -> tuple[str, ...]:
    combined = set(tools_1).union(set(tools_2))
    return tuple(sorted(combined))

"""Collapses a cluster of overlapping findings into a single unified Finding."""
def _reduce_cluster(path: str, cwe: str, cluster: list[Finding]) -> Finding:
    min_line = cluster[0].line
    
    highest_sev = "NONE"
    all_tools = ()
    
    for f in cluster:
        highest_sev = get_highest_severity(highest_sev, f.severity)
        all_tools = merge_tools(all_tools, f.tools)
        
    return Finding(
        path=path,
        line=min_line,
        cwe=cwe,
        severity=highest_sev,
        tools=all_tools
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
        # Sort the group by line number ascending
        sorted_group = sorted(group, key=lambda x: x.line)
        
        if not sorted_group:
            continue

        # Initialise irst cluster with the first finding
        current_cluster = [sorted_group[0]]
        
        # Merging & Chaining Loop
        for current in sorted_group[1:]:
            last_finding = current_cluster[-1]
            
            # If current line is within tol of the previous item in the cluster then join it
            if (current.line - last_finding.line) <= tol:
                current_cluster.append(current)
            else:
                # if Gap exceeds tol then finalize current cluster and start a new one
                merged_findings.append(_reduce_cluster(path, cwe, current_cluster))
                current_cluster = [current]
        
        # Append the final remaining cluster in this bucket
        if current_cluster:
            merged_findings.append(_reduce_cluster(path, cwe, current_cluster))

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
def run_security_pipeline(raw_reports: list[dict], tol: int = 2) -> list[Finding]:

    unified_findings: list[Finding] = []
    
    # 1. Ingestion & Normalisation Phase
    for raw_record in raw_reports:
        finding = normalise_finding(raw_record)
        if finding is not None:
            unified_findings.append(finding)
            
    # 2. Reduction & Merging Phase 
    final_merged_report = merge(unified_findings, tol=tol)
    
    return final_merged_report