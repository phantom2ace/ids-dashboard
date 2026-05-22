CVE_MAP = {
    "ET WEB_SERVER Apache Log4j Attempt": {
        "cve": "CVE-2021-44228",
        "severity": "Critical",
        "cvss": 10.0,
        "behavior": "Remote Code Execution, JNDI Lookup",
        "mitre_id": "T1190",
        "mitre_tactic": "Initial Access",
        "recommendation": "Block source IP immediately. Patch Apache Log4j to >=2.17.1. Scan internal systems for successful JNDI callbacks."
    },
    "ET SCAN Nmap Scripting Engine": {
        "cve": "Recon Activity",
        "severity": "Medium",
        "cvss": 5.3,
        "behavior": "Service Fingerprinting, Port Enumeration",
        "mitre_id": "T1595.001",
        "mitre_tactic": "Reconnaissance",
        "recommendation": "Rate-limit IP. Verify if exposed ports are required for business operations. Consider geo-blocking if IP is foreign."
    },
    "ET EXPLOIT Possible SQL Injection Attempt": {
        "cve": "Generic SQLi",
        "severity": "High",
        "cvss": 8.5,
        "behavior": "Database probing, Query manipulation",
        "mitre_id": "T1190",
        "mitre_tactic": "Initial Access",
        "recommendation": "Enable WAF blocking rules for SQL injection signatures. Review database logs for successful query execution."
    },
    "ET DROP Spamhaus DROP Listed Traffic Inbound": {
        "cve": "Known Malicious",
        "severity": "High",
        "cvss": 7.5,
        "behavior": "Connecting from known bad actor IP",
        "mitre_id": "T1105",
        "mitre_tactic": "Command and Control",
        "recommendation": "Automatically DROP traffic at perimeter firewall. Ensure internal hosts haven't beaconed out to this IP."
    },
    "ET POLICY SSH Brute Force Attempt": {
        "cve": "CVE-2018-15473",
        "severity": "High",
        "cvss": 7.2,
        "behavior": "Credential spraying, multiple failed logins",
        "mitre_id": "T1110.001",
        "mitre_tactic": "Credential Access",
        "recommendation": "Implement fail2ban. Enforce SSH key-based authentication only. Disable password logins on exposed SSH servers."
    },
    "ET EXPLOIT Apache Struts RCE Attempt": {
        "cve": "CVE-2017-5638",
        "severity": "Critical",
        "cvss": 10.0,
        "behavior": "Remote Code Execution via Content-Type",
        "mitre_id": "T1190",
        "mitre_tactic": "Initial Access",
        "recommendation": "Block source IP. Verify Struts version is patched. Monitor for unauthorized web shell creation."
    }
}

def get_cve_info(signature):
    # Fallback default if not matched perfectly
    default_info = {
        "cve": "N/A",
        "severity": "Low",
        "cvss": 0.0,
        "behavior": "Unknown anomalous traffic",
        "mitre_id": "T1000",
        "mitre_tactic": "Unknown",
        "recommendation": "Investigate payload manually for zero-day characteristics."
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
