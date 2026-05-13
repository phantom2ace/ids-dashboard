CVE_MAP = {
    "ET WEB_SERVER Apache Log4j Attempt": {
        "cve": "CVE-2021-44228",
        "severity": "Critical",
        "cvss": 10.0,
        "behavior": "Remote Code Execution, JNDI Lookup"
    },
    "ET SCAN Nmap Scripting Engine": {
        "cve": "Recon Activity",
        "severity": "Medium",
        "cvss": 5.3,
        "behavior": "Service Fingerprinting, Port Enumeration"
    },
    "ET EXPLOIT Possible SQL Injection Attempt": {
        "cve": "Generic SQLi",
        "severity": "High",
        "cvss": 8.5,
        "behavior": "Database probing, Query manipulation"
    },
    "ET DROP Spamhaus DROP Listed Traffic Inbound": {
        "cve": "Known Malicious",
        "severity": "High",
        "cvss": 7.5,
        "behavior": "Connecting from known bad actor IP"
    },
    "ET POLICY SSH Brute Force Attempt": {
        "cve": "CVE-2018-15473",
        "severity": "High",
        "cvss": 7.2,
        "behavior": "Credential spraying, multiple failed logins"
    },
    "ET EXPLOIT Apache Struts RCE Attempt": {
        "cve": "CVE-2017-5638",
        "severity": "Critical",
        "cvss": 10.0,
        "behavior": "Remote Code Execution via Content-Type"
    }
}

def get_cve_info(signature):
    # Fallback default if not matched perfectly
    default_info = {
        "cve": "N/A",
        "severity": "Low",
        "cvss": 0.0,
        "behavior": "Unknown anomalous traffic"
    }
    
    # Try an exact match first
    if signature in CVE_MAP:
        return CVE_MAP[signature]
    
    # Try a partial match
    for sig, info in CVE_MAP.items():
        if signature.lower() in sig.lower() or sig.lower() in signature.lower():
            return info
            
    # Keywords matching
    lower_sig = signature.lower()
    if "log4j" in lower_sig:
        return CVE_MAP["ET WEB_SERVER Apache Log4j Attempt"]
    elif "nmap" in lower_sig or "scan" in lower_sig:
        return CVE_MAP["ET SCAN Nmap Scripting Engine"]
    elif "sql" in lower_sig or "sqli" in lower_sig:
        return CVE_MAP["ET EXPLOIT Possible SQL Injection Attempt"]
    elif "ssh" in lower_sig or "brute" in lower_sig:
        return CVE_MAP["ET POLICY SSH Brute Force Attempt"]
        
    return default_info
