"""
Sample threat actor data for seeding the database.
"""

from datetime import datetime, timedelta
from typing import List, Dict, Any
from uuid import UUID

threat_actor_samples = [
    {
        "name": "FIN7",
        "aliases": ["Carbanak Group", "Carbon Spider", "Elbrus"],
        "actor_type": "group",
        "attribution_confidence": 0.92,
        "attribution_rationale": "Extensive technical analysis of TTPs, infrastructure, and timeline correlation across multiple campaigns",
        "primary_attribution": "Financially motivated cybercriminal group",
        "sophistication_level": "high",
        "threat_level": "high",
        "motivations": ["financial", "data theft"],
        "origin_country": "RUS",
        "target_countries": ["USA", "GBR", "CAN", "AUS", "DEU"],
        "target_sectors": ["retail", "restaurant", "hospitality", "financial"],
        "suspected_attribution": "Criminal organization",
        "first_observed": datetime(2015, 8, 1),
        "last_observed": datetime(2024, 1, 15),
        "status": "active",
        "description": "FIN7 is a financially motivated threat group that has been active since at least 2015. The group is known for targeting retail, restaurant, and hospitality industries with point-of-sale malware and various social engineering tactics. FIN7 operations are characterized by sophisticated spear-phishing campaigns, custom backdoors, and extensive use of legitimate tools for persistence and lateral movement.",
        "summary": "Financially motivated group targeting retail and hospitality with sophisticated social engineering and custom malware",
        "mitre_attack_id": "G0046",
        "external_ids": {
            "mandiant": "FIN7",
            "crowdstrike": "CARBON SPIDER",
            "microsoft": "ELBRUS"
        },
        "references": [
            "https://attack.mitre.org/groups/G0046/",
            "https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html",
            "https://www.crowdstrike.com/blog/carbon-spider-embraces-big-game-hunting-part-1/"
        ],
        "analyst_notes": "Highly active group with sophisticated TTPs. Known for adapting quickly to defensive measures and maintaining long-term access to victim networks.",
        "is_validated": True,
        "validation_notes": "Attribution validated through extensive technical analysis and law enforcement actions",
        "custom_attributes": {
            "primary_tools": ["Carbanak", "More_eggs", "Griffon", "Cobalt Strike"],
            "attack_patterns": ["T1566.001", "T1059.003", "T1055", "T1090"],
            "estimated_size": "50-100 members",
            "revenue_estimates": "$1B+ stolen"
        },
        "tags": ["fin", "carbanak", "pos-malware", "spear-phishing", "high-confidence"]
    },
    {
        "name": "FIN8",
        "aliases": ["Syssphinx"],
        "actor_type": "group",
        "attribution_confidence": 0.85,
        "attribution_rationale": "Consistent TTPs and infrastructure patterns observed across multiple campaigns",
        "primary_attribution": "Financially motivated cybercriminal group",
        "sophistication_level": "medium",
        "threat_level": "medium",
        "motivations": ["financial"],
        "origin_country": "UKR",
        "target_countries": ["USA", "GBR", "CAN"],
        "target_sectors": ["financial", "retail", "hospitality", "technology"],
        "suspected_attribution": "Criminal organization",
        "first_observed": datetime(2016, 1, 1),
        "last_observed": datetime(2023, 8, 30),
        "status": "active",
        "description": "FIN8 is a financially motivated cybercriminal group that has been active since at least 2016. The group typically gains initial access through spear-phishing emails containing malicious attachments, then uses various tools and techniques to establish persistence and steal payment card data from point-of-sale systems.",
        "summary": "Financially motivated group targeting payment card data through POS malware and spear-phishing",
        "mitre_attack_id": "G0061",
        "external_ids": {
            "fireeye": "FIN8"
        },
        "references": [
            "https://attack.mitre.org/groups/G0061/",
            "https://www.fireeye.com/blog/threat-research/2019/01/a-nasty-trick.html"
        ],
        "analyst_notes": "Less sophisticated than FIN7 but maintains consistent operational patterns. Focus on POS systems and payment card theft.",
        "is_validated": True,
        "validation_notes": "Attribution based on consistent TTPs and infrastructure analysis",
        "custom_attributes": {
            "primary_tools": ["Punchtrack", "Punchbuggy", "Badhatch"],
            "attack_patterns": ["T1566.001", "T1059.001", "T1003", "T1005"],
            "estimated_size": "10-20 members"
        },
        "tags": ["fin", "pos-malware", "spear-phishing", "payment-cards"]
    },
    {
        "name": "Scattered Spider",
        "aliases": ["UNC3944", "Oktapus", "Starfraud"],
        "actor_type": "group",
        "attribution_confidence": 0.78,
        "attribution_rationale": "Consistent social engineering tactics and collaboration with ransomware groups",
        "primary_attribution": "Financially motivated cybercriminal collective",
        "sophistication_level": "high",
        "threat_level": "critical",
        "motivations": ["financial", "data theft"],
        "origin_country": "USA",
        "target_countries": ["USA", "GBR", "CAN", "AUS"],
        "target_sectors": ["technology", "telecommunications", "gaming", "cryptocurrency", "retail"],
        "suspected_attribution": "Loosely affiliated cybercriminal collective",
        "first_observed": datetime(2022, 5, 1),
        "last_observed": datetime(2024, 2, 1),
        "status": "active",
        "description": "Scattered Spider is a cybercriminal collective that emerged in 2022, known for sophisticated social engineering attacks targeting employees of major corporations. The group specializes in SIM swapping, credential theft, and has been observed collaborating with ransomware groups like BlackCat/ALPHV. They are particularly notable for their ability to bypass multi-factor authentication through social engineering and their targeting of cloud infrastructure.",
        "summary": "Sophisticated social engineering group targeting cloud infrastructure and collaborating with ransomware operators",
        "mitre_attack_id": None,
        "external_ids": {
            "mandiant": "UNC3944",
            "microsoft": "Oktapus"
        },
        "references": [
            "https://www.microsoft.com/en-us/security/blog/2022/10/25/dev-0832-vice-society-opportunistic-ransomware-campaigns-impacting-us-education-sector/",
            "https://www.mandiant.com/resources/blog/unc3944-sms-phishing-sim-swapping-ransomware"
        ],
        "analyst_notes": "Highly adaptive group with strong social engineering capabilities. Notable for their ability to target cloud environments and collaboration with multiple ransomware groups.",
        "is_validated": True,
        "validation_notes": "Well-documented by multiple security vendors with consistent reporting on TTPs",
        "custom_attributes": {
            "primary_tools": ["Social Engineering", "SIM Swapping", "Credential Theft", "Cloud Access"],
            "attack_patterns": ["T1566.004", "T1621", "T1556", "T1078.004"],
            "ransomware_affiliations": ["BlackCat/ALPHV", "RansomHub"],
            "estimated_size": "Unknown - loosely affiliated collective"
        },
        "tags": ["social-engineering", "sim-swapping", "cloud", "ransomware-affiliate", "emerging"]
    },
    {
        "name": "FIN11",
        "aliases": ["TA505"],
        "actor_type": "group",
        "attribution_confidence": 0.88,
        "attribution_rationale": "Overlap in infrastructure, TTPs, and timeline analysis with known TA505 campaigns",
        "primary_attribution": "Financially motivated cybercriminal group",
        "sophistication_level": "high",
        "threat_level": "high",
        "motivations": ["financial"],
        "origin_country": "RUS",
        "target_countries": ["USA", "GBR", "DEU", "FRA", "ITA", "ESP"],
        "target_sectors": ["financial", "retail", "healthcare", "government"],
        "suspected_attribution": "Criminal organization with potential state tolerance",
        "first_observed": datetime(2018, 3, 1),
        "last_observed": datetime(2023, 11, 15),
        "status": "active",
        "description": "FIN11 is a financially motivated threat group that has been active since at least 2018. The group is known for conducting large-scale malicious email campaigns delivering various malware families including FlawedAmmyy, More_eggs, and SDBbot. FIN11 operations typically focus on initial access and credential theft, often selling access to other criminal groups.",
        "summary": "Financially motivated group conducting large-scale email campaigns and selling network access",
        "mitre_attack_id": "G0066",
        "external_ids": {
            "fireeye": "FIN11",
            "proofpoint": "TA505"
        },
        "references": [
            "https://attack.mitre.org/groups/G0066/",
            "https://www.fireeye.com/blog/threat-research/2020/10/fin11-email-campaigns-precursor-for-ransomware-data-theft.html"
        ],
        "analyst_notes": "Operates as initial access broker, often selling access to ransomware groups. High volume email campaigns with rotating malware families.",
        "is_validated": True,
        "validation_notes": "Strong attribution based on infrastructure analysis and campaign correlation",
        "custom_attributes": {
            "primary_tools": ["FlawedAmmyy", "More_eggs", "SDBbot", "Ramnit"],
            "attack_patterns": ["T1566.001", "T1059.003", "T1074.001", "T1005"],
            "estimated_size": "20-30 members",
            "business_model": "Initial access broker"
        },
        "tags": ["fin", "initial-access-broker", "email-campaigns", "malware-distribution"]
    },
    {
        "name": "APT29",
        "aliases": ["Cozy Bear", "The Dukes", "YTTRIUM"],
        "actor_type": "group",
        "attribution_confidence": 0.95,
        "attribution_rationale": "Extensive government attribution, technical analysis, and pattern correlation over multiple years",
        "primary_attribution": "Russian Foreign Intelligence Service (SVR)",
        "sophistication_level": "advanced",
        "threat_level": "critical",
        "motivations": ["espionage", "intelligence collection"],
        "origin_country": "RUS",
        "target_countries": ["USA", "GBR", "DEU", "FRA", "NOR", "SWE", "UKR"],
        "target_sectors": ["government", "defense", "technology", "healthcare", "energy"],
        "suspected_attribution": "Russian state-sponsored",
        "first_observed": datetime(2008, 1, 1),
        "last_observed": datetime(2024, 1, 30),
        "status": "active",
        "description": "APT29 is a highly sophisticated threat group attributed to Russia's Foreign Intelligence Service (SVR). The group has been active since at least 2008 and is known for long-term persistent access to victim networks, advanced evasion techniques, and targeting of government and high-value commercial entities for intelligence collection purposes.",
        "summary": "Russian state-sponsored group conducting long-term espionage operations against government and commercial targets",
        "mitre_attack_id": "G0016",
        "external_ids": {
            "crowdstrike": "COZY BEAR",
            "microsoft": "YTTRIUM",
            "fireeye": "APT29"
        },
        "references": [
            "https://attack.mitre.org/groups/G0016/",
            "https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/",
            "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-116a"
        ],
        "analyst_notes": "Extremely sophisticated adversary with patient, long-term operational approach. Known for supply chain attacks and advanced persistent threats.",
        "is_validated": True,
        "validation_notes": "Attribution validated by multiple government agencies and extensive technical analysis",
        "custom_attributes": {
            "primary_tools": ["WellMess", "WellMail", "CozyDuke", "SolarWinds Backdoor"],
            "attack_patterns": ["T1195.002", "T1078", "T1071.001", "T1027"],
            "estimated_size": "100+ members",
            "notable_campaigns": ["SolarWinds", "DNC", "COVID-19 research targeting"]
        },
        "tags": ["apt", "russia", "svr", "espionage", "supply-chain", "state-sponsored"]
    }
]


def get_sample_campaigns() -> List[Dict[str, Any]]:
    """Get sample campaign data linked to threat actors."""
    return [
        {
            "name": "SolarWinds Supply Chain Attack",
            "aliases": ["SUNBURST", "Solorigate"],
            "start_date": datetime(2019, 9, 1),
            "end_date": datetime(2020, 12, 13),
            "status": "ended",
            "threat_actor_name": "APT29",  # Will be linked during seeding
            "attribution_confidence": 0.95,
            "objectives": ["espionage", "intelligence collection", "network access"],
            "target_sectors": ["government", "technology", "consulting"],
            "target_countries": ["USA", "GBR", "CAN", "BEL", "DEU"],
            "description": "A sophisticated supply chain attack that compromised SolarWinds Orion software, affecting thousands of organizations including US government agencies. The campaign involved the insertion of malicious code into legitimate software updates, providing widespread access to victim networks.",
            "summary": "Supply chain compromise of SolarWinds Orion affecting government and enterprise targets",
            "tactics_techniques": ["T1195.002", "T1071.001", "T1027", "T1078.002"],
            "external_ids": {
                "cisa": "AA20-352A",
                "microsoft": "Solorigate"
            },
            "references": [
                "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a",
                "https://blogs.microsoft.com/on-the-issues/2020/12/17/cyberattacks-cybersecurity-solarwinds-fireeye/"
            ],
            "tags": ["supply-chain", "solarwinds", "apt29", "government-targeting"]
        },
        {
            "name": "Restaurant Point-of-Sale Campaign",
            "aliases": ["Carbanak Restaurant Campaign"],
            "start_date": datetime(2018, 3, 1),
            "end_date": datetime(2019, 8, 15),
            "status": "ended",
            "threat_actor_name": "FIN7",
            "attribution_confidence": 0.90,
            "objectives": ["financial gain", "payment card theft"],
            "target_sectors": ["restaurant", "retail", "hospitality"],
            "target_countries": ["USA", "CAN"],
            "description": "Large-scale campaign targeting restaurant chains and retail establishments with sophisticated spear-phishing attacks leading to point-of-sale malware deployment. The campaign resulted in the theft of millions of payment card details.",
            "summary": "Large-scale POS malware campaign targeting restaurant and retail payment systems",
            "tactics_techniques": ["T1566.001", "T1059.003", "T1005", "T1041"],
            "external_ids": {
                "fireeye": "FIN7-2018-REST"
            },
            "references": [
                "https://www.fireeye.com/blog/threat-research/2018/08/fin7-targeting-pos-systems.html"
            ],
            "tags": ["fin7", "pos-malware", "payment-cards", "restaurants"]
        }
    ]


def get_sample_malware_families() -> List[Dict[str, Any]]:
    """Get sample malware family data linked to threat actors."""
    return [
        {
            "name": "Carbanak",
            "aliases": ["Anunak"],
            "family_type": "backdoor",
            "threat_actor_name": "FIN7",
            "attribution_confidence": 0.95,
            "platforms": ["windows"],
            "capabilities": [
                "remote access", "credential theft", "lateral movement",
                "screen capture", "keylogging", "file system access"
            ],
            "first_seen": datetime(2014, 6, 1),
            "last_seen": datetime(2019, 12, 31),
            "status": "retired",
            "description": "Carbanak is a sophisticated remote access trojan used primarily by the FIN7 threat group. The malware provides extensive backdoor capabilities including credential theft, lateral movement, and persistent access to compromised networks.",
            "summary": "Sophisticated RAT providing comprehensive network access and credential theft capabilities",
            "external_ids": {
                "kaspersky": "Carbanak",
                "symantec": "Anunak"
            },
            "references": [
                "https://securelist.com/the-great-bank-robbery-the-carbanak-apt/68732/"
            ],
            "tags": ["rat", "banking", "credential-theft", "fin7"]
        },
        {
            "name": "More_eggs",
            "aliases": ["Terra Loader", "SpicyOmelette"],
            "family_type": "loader",
            "threat_actor_name": "FIN7",
            "attribution_confidence": 0.88,
            "platforms": ["windows"],
            "capabilities": [
                "payload delivery", "evasion", "persistence",
                "credential access", "lateral movement"
            ],
            "first_seen": datetime(2018, 1, 1),
            "last_seen": datetime(2023, 6, 15),
            "status": "active",
            "description": "More_eggs is a sophisticated malware loader used by multiple threat groups including FIN7. The malware is designed to evade detection and deliver additional payloads while maintaining persistence on compromised systems.",
            "summary": "Sophisticated loader malware with advanced evasion and persistence capabilities",
            "external_ids": {
                "proofpoint": "More_eggs"
            },
            "references": [
                "https://www.proofpoint.com/us/blog/threat-insight/updated-more_eggs-backdoor-targeting-worldwide"
            ],
            "tags": ["loader", "evasion", "persistence", "multi-group"]
        }
    ]