"""
MITRE ATT&CK framework seed data.
"""

from typing import Dict, List, Any

# MITRE ATT&CK Tactics
MITRE_TACTICS = [
    {
        "tactic_id": "TA0001",
        "name": "Initial Access",
        "description": "The adversary is trying to get into your network.",
        "url": "https://attack.mitre.org/tactics/TA0001/"
    },
    {
        "tactic_id": "TA0002",
        "name": "Execution",
        "description": "The adversary is trying to run malicious code.",
        "url": "https://attack.mitre.org/tactics/TA0002/"
    },
    {
        "tactic_id": "TA0003",
        "name": "Persistence",
        "description": "The adversary is trying to maintain their foothold.",
        "url": "https://attack.mitre.org/tactics/TA0003/"
    },
    {
        "tactic_id": "TA0004",
        "name": "Privilege Escalation",
        "description": "The adversary is trying to gain higher-level permissions.",
        "url": "https://attack.mitre.org/tactics/TA0004/"
    },
    {
        "tactic_id": "TA0005",
        "name": "Defense Evasion",
        "description": "The adversary is trying to avoid being detected.",
        "url": "https://attack.mitre.org/tactics/TA0005/"
    },
    {
        "tactic_id": "TA0006",
        "name": "Credential Access",
        "description": "The adversary is trying to steal account names and passwords.",
        "url": "https://attack.mitre.org/tactics/TA0006/"
    },
    {
        "tactic_id": "TA0007",
        "name": "Discovery",
        "description": "The adversary is trying to figure out your environment.",
        "url": "https://attack.mitre.org/tactics/TA0007/"
    },
    {
        "tactic_id": "TA0008",
        "name": "Lateral Movement",
        "description": "The adversary is trying to move through your environment.",
        "url": "https://attack.mitre.org/tactics/TA0008/"
    },
    {
        "tactic_id": "TA0009",
        "name": "Collection",
        "description": "The adversary is trying to gather data of interest to their goal.",
        "url": "https://attack.mitre.org/tactics/TA0009/"
    },
    {
        "tactic_id": "TA0010",
        "name": "Exfiltration",
        "description": "The adversary is trying to steal data.",
        "url": "https://attack.mitre.org/tactics/TA0010/"
    },
    {
        "tactic_id": "TA0011",
        "name": "Command and Control",
        "description": "The adversary is trying to communicate with compromised systems to control them.",
        "url": "https://attack.mitre.org/tactics/TA0011/"
    },
    {
        "tactic_id": "TA0040",
        "name": "Impact",
        "description": "The adversary is trying to manipulate, interrupt, or destroy your systems and data.",
        "url": "https://attack.mitre.org/tactics/TA0040/"
    }
]

# MITRE ATT&CK Techniques (representative set)
MITRE_TECHNIQUES = [
    # Initial Access
    {
        "technique_id": "T1078",
        "name": "Valid Accounts",
        "description": "Adversaries may obtain and abuse credentials of existing accounts.",
        "tactic_id": "TA0001",
        "parent_technique_id": None,
        "url": "https://attack.mitre.org/techniques/T1078/",
        "platforms": ["Windows", "macOS", "Linux", "Cloud"],
        "data_sources": ["Authentication logs", "Process monitoring"]
    },
    {
        "technique_id": "T1078.001",
        "name": "Valid Accounts: Default Accounts",
        "description": "Adversaries may obtain and abuse credentials of default accounts.",
        "tactic_id": "TA0001",
        "parent_technique_id": "T1078",
        "url": "https://attack.mitre.org/techniques/T1078/001/",
        "platforms": ["Windows", "macOS", "Linux"],
        "data_sources": ["Authentication logs"]
    },
    {
        "technique_id": "T1190",
        "name": "Exploit Public-Facing Application",
        "description": "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program.",
        "tactic_id": "TA0001",
        "parent_technique_id": None,
        "url": "https://attack.mitre.org/techniques/T1190/",
        "platforms": ["Windows", "macOS", "Linux", "Cloud"],
        "data_sources": ["Network traffic", "Application logs"]
    },
    {
        "technique_id": "T1566",
        "name": "Phishing",
        "description": "Adversaries may send phishing messages to gain access to victim systems.",
        "tactic_id": "TA0001",
        "parent_technique_id": None,
        "url": "https://attack.mitre.org/techniques/T1566/",
        "platforms": ["Windows", "macOS", "Linux"],
        "data_sources": ["Email gateway", "Network traffic"]
    },
    {
        "technique_id": "T1566.001",
        "name": "Phishing: Spearphishing Attachment",
        "description": "Adversaries may send spearphishing emails with a malicious attachment.",
        "tactic_id": "TA0001",
        "parent_technique_id": "T1566",
        "url": "https://attack.mitre.org/techniques/T1566/001/",
        "platforms": ["Windows", "macOS", "Linux"],
        "data_sources": ["Email gateway", "File monitoring"]
    },

    # Execution
    {
        "technique_id": "T1059",
        "name": "Command and Scripting Interpreter",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        "tactic_id": "TA0002",
        "parent_technique_id": None,
        "url": "https://attack.mitre.org/techniques/T1059/",
        "platforms": ["Windows", "macOS", "Linux"],
        "data_sources": ["Process monitoring", "Command execution"]
    },
    {
        "technique_id": "T1059.001",
        "name": "Command and Scripting Interpreter: PowerShell",
        "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
        "tactic_id": "TA0002",
        "parent_technique_id": "T1059",
        "url": "https://attack.mitre.org/techniques/T1059/001/",
        "platforms": ["Windows"],
        "data_sources": ["PowerShell logs", "Process monitoring"]
    },
    {
        "technique_id": "T1059.003",
        "name": "Command and Scripting Interpreter: Windows Command Shell",
        "description": "Adversaries may abuse the Windows command shell for execution.",
        "tactic_id": "TA0002",
        "parent_technique_id": "T1059",
        "url": "https://attack.mitre.org/techniques/T1059/003/",
        "platforms": ["Windows"],
        "data_sources": ["Process monitoring", "Command execution"]
    },

    # Persistence
    {
        "technique_id": "T1053",
        "name": "Scheduled Task/Job",
        "description": "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.",
        "tactic_id": "TA0003",
        "parent_technique_id": None,
        "url": "https://attack.mitre.org/techniques/T1053/",
        "platforms": ["Windows", "macOS", "Linux"],
        "data_sources": ["Process monitoring", "Scheduled task logs"]
    },
    {
        "technique_id": "T1547",
        "name": "Boot or Logon Autostart Execution",
        "description": "Adversaries may configure system settings to automatically execute a program during system boot or logon.",
        "tactic_id": "TA0003",
        "parent_technique_id": None,
        "url": "https://attack.mitre.org/techniques/T1547/",
        "platforms": ["Windows", "macOS", "Linux"],
        "data_sources": ["Process monitoring", "Registry monitoring"]
    },

    # Privilege Escalation
    {
        "technique_id": "T1055",
        "name": "Process Injection",
        "description": "Adversaries may inject code into processes in order to evade process-based defenses.",
        "tactic_id": "TA0004",
        "parent_technique_id": None,
        "url": "https://attack.mitre.org/techniques/T1055/",
        "platforms": ["Windows", "macOS", "Linux"],
        "data_sources": ["Process monitoring", "API monitoring"]
    },
    {
        "technique_id": "T1055.001",
        "name": "Process Injection: Dynamic-link Library Injection",
        "description": "Adversaries may inject dynamic-link libraries (DLLs) into processes.",
        "tactic_id": "TA0004",
        "parent_technique_id": "T1055",
        "url": "https://attack.mitre.org/techniques/T1055/001/",
        "platforms": ["Windows"],
        "data_sources": ["Process monitoring", "DLL monitoring"]
    },

    # Defense Evasion
    {
        "technique_id": "T1070",
        "name": "Indicator Removal on Host",
        "description": "Adversaries may delete or alter generated artifacts on a host system.",
        "tactic_id": "TA0005",
        "parent_technique_id": None,
        "url": "https://attack.mitre.org/techniques/T1070/",
        "platforms": ["Windows", "macOS", "Linux"],
        "data_sources": ["File monitoring", "Process monitoring"]
    },
    {
        "technique_id": "T1027",
        "name": "Obfuscated Files or Information",
        "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze.",
        "tactic_id": "TA0005",
        "parent_technique_id": None,
        "url": "https://attack.mitre.org/techniques/T1027/",
        "platforms": ["Windows", "macOS", "Linux"],
        "data_sources": ["File monitoring", "Process monitoring"]
    },

    # Credential Access
    {
        "technique_id": "T1003",
        "name": "OS Credential Dumping",
        "description": "Adversaries may attempt to dump credentials to obtain account login and credential material.",
        "tactic_id": "TA0006",
        "parent_technique_id": None,
        "url": "https://attack.mitre.org/techniques/T1003/",
        "platforms": ["Windows", "macOS", "Linux"],
        "data_sources": ["Process monitoring", "API monitoring"]
    },
    {
        "technique_id": "T1003.001",
        "name": "OS Credential Dumping: LSASS Memory",
        "description": "Adversaries may attempt to access credential material stored in LSASS.",
        "tactic_id": "TA0006",
        "parent_technique_id": "T1003",
        "url": "https://attack.mitre.org/techniques/T1003/001/",
        "platforms": ["Windows"],
        "data_sources": ["Process monitoring", "Process access"]
    },

    # Discovery
    {
        "technique_id": "T1082",
        "name": "System Information Discovery",
        "description": "An adversary may attempt to get detailed information about the operating system and hardware.",
        "tactic_id": "TA0007",
        "parent_technique_id": None,
        "url": "https://attack.mitre.org/techniques/T1082/",
        "platforms": ["Windows", "macOS", "Linux"],
        "data_sources": ["Process monitoring", "Command execution"]
    },
    {
        "technique_id": "T1018",
        "name": "Remote System Discovery",
        "description": "Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier.",
        "tactic_id": "TA0007",
        "parent_technique_id": None,
        "url": "https://attack.mitre.org/techniques/T1018/",
        "platforms": ["Windows", "macOS", "Linux"],
        "data_sources": ["Network traffic", "Process monitoring"]
    },

    # Lateral Movement
    {
        "technique_id": "T1021",
        "name": "Remote Services",
        "description": "Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections.",
        "tactic_id": "TA0008",
        "parent_technique_id": None,
        "url": "https://attack.mitre.org/techniques/T1021/",
        "platforms": ["Windows", "macOS", "Linux"],
        "data_sources": ["Authentication logs", "Network traffic"]
    },
    {
        "technique_id": "T1021.001",
        "name": "Remote Services: Remote Desktop Protocol",
        "description": "Adversaries may use Remote Desktop Protocol (RDP) to remotely control Windows systems.",
        "tactic_id": "TA0008",
        "parent_technique_id": "T1021",
        "url": "https://attack.mitre.org/techniques/T1021/001/",
        "platforms": ["Windows"],
        "data_sources": ["Authentication logs", "Network traffic"]
    },

    # Collection
    {
        "technique_id": "T1560",
        "name": "Archive Collected Data",
        "description": "An adversary may compress and/or encrypt data that is collected prior to exfiltration.",
        "tactic_id": "TA0009",
        "parent_technique_id": None,
        "url": "https://attack.mitre.org/techniques/T1560/",
        "platforms": ["Windows", "macOS", "Linux"],
        "data_sources": ["File monitoring", "Process monitoring"]
    },

    # Exfiltration
    {
        "technique_id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel.",
        "tactic_id": "TA0010",
        "parent_technique_id": None,
        "url": "https://attack.mitre.org/techniques/T1041/",
        "platforms": ["Windows", "macOS", "Linux"],
        "data_sources": ["Network traffic", "Process monitoring"]
    },

    # Command and Control
    {
        "technique_id": "T1071",
        "name": "Application Layer Protocol",
        "description": "Adversaries may communicate using application layer protocols.",
        "tactic_id": "TA0011",
        "parent_technique_id": None,
        "url": "https://attack.mitre.org/techniques/T1071/",
        "platforms": ["Windows", "macOS", "Linux"],
        "data_sources": ["Network traffic", "Process monitoring"]
    },
    {
        "technique_id": "T1071.001",
        "name": "Application Layer Protocol: Web Protocols",
        "description": "Adversaries may communicate using application layer protocols associated with web traffic.",
        "tactic_id": "TA0011",
        "parent_technique_id": "T1071",
        "url": "https://attack.mitre.org/techniques/T1071/001/",
        "platforms": ["Windows", "macOS", "Linux"],
        "data_sources": ["Network traffic", "Process monitoring"]
    },

    # Impact
    {
        "technique_id": "T1486",
        "name": "Data Encrypted for Impact",
        "description": "Adversaries may encrypt data on target systems or on large numbers of systems in a network.",
        "tactic_id": "TA0040",
        "parent_technique_id": None,
        "url": "https://attack.mitre.org/techniques/T1486/",
        "platforms": ["Windows", "macOS", "Linux"],
        "data_sources": ["File monitoring", "Process monitoring"]
    },
    {
        "technique_id": "T1489",
        "name": "Service Stop",
        "description": "Adversaries may stop or disable services on a system to render those services unavailable to legitimate users.",
        "tactic_id": "TA0040",
        "parent_technique_id": None,
        "url": "https://attack.mitre.org/techniques/T1489/",
        "platforms": ["Windows", "macOS", "Linux"],
        "data_sources": ["Service monitoring", "Process monitoring"]
    }
]

# Severity levels
SEVERITY_LEVELS = [
    {
        "name": "Low",
        "level": 1,
        "color": "#28a745",  # Green
        "description": "Low risk detection with minimal impact"
    },
    {
        "name": "Medium",
        "level": 2,
        "color": "#ffc107",  # Yellow
        "description": "Moderate risk detection requiring attention"
    },
    {
        "name": "High",
        "level": 3,
        "color": "#fd7e14",  # Orange
        "description": "High risk detection requiring immediate attention"
    },
    {
        "name": "Critical",
        "level": 4,
        "color": "#dc3545",  # Red
        "description": "Critical risk detection requiring urgent response"
    }
]