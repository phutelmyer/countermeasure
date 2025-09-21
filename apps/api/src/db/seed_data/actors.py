"""
Sample actor data for seeding the database.
"""

from datetime import datetime, timezone

# Sample actor data based on real-world threat groups
actor_samples = [
    {
        "name": "FIN7",
        "aliases": ["Carbanak Group", "FIN7.1"],
        "actor_type": "group",
        "attribution_confidence": 0.95,
        "attribution_rationale": "High confidence based on TTPs, infrastructure, and victimology patterns",
        "primary_attribution": "Financially motivated cybercriminal organization",
        "sophistication_level": "high",
        "threat_level": "high",
        "motivations": ["financial"],
        "origin_country": "RUS",
        "target_countries": ["USA", "GBR", "CAN", "AUS"],
        "target_sectors": ["retail", "hospitality", "financial_services"],
        "suspected_attribution": "Criminal organization",
        "first_observed": datetime(2015, 1, 1, tzinfo=timezone.utc),
        "last_observed": datetime(2023, 12, 1, tzinfo=timezone.utc),
        "status": "active",
        "description": "FIN7 is a financially motivated threat group that has been active since at least 2015. The group is known for targeting retail, hospitality, and financial organizations through spear-phishing campaigns and point-of-sale malware.",
        "summary": "Sophisticated financially motivated group targeting retail and hospitality sectors",
        "mitre_attack_id": None,
        "external_ids": ["G0046"],
        "references": [
            "https://attack.mitre.org/groups/G0046/",
            "https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html"
        ],
        "analyst_notes": "Notable for their use of legitimate tools like PowerShell and WMI for persistence and lateral movement",
        "quality_score": 0.9,
        "is_validated": True,
        "validation_notes": "Validated through multiple threat intelligence sources",
        "custom_attributes": {"attribution_level": "high", "threat_category": "cybercriminal"},
        "tags": ["cybercrime", "pos_malware", "spear_phishing", "retail"]
    },
    {
        "name": "FIN8",
        "aliases": ["Syssphinx"],
        "actor_type": "group",
        "attribution_confidence": 0.85,
        "attribution_rationale": "Strong indicators based on malware signatures and targeting patterns",
        "primary_attribution": "Financially motivated cybercriminal group",
        "sophistication_level": "medium",
        "threat_level": "medium",
        "motivations": ["financial"],
        "origin_country": None,
        "target_countries": ["USA"],
        "target_sectors": ["hospitality", "retail", "entertainment"],
        "suspected_attribution": "Criminal organization",
        "first_observed": datetime(2016, 1, 1, tzinfo=timezone.utc),
        "last_observed": datetime(2023, 6, 1, tzinfo=timezone.utc),
        "status": "active",
        "description": "FIN8 is a financially motivated threat group known to launch tailored spear-phishing campaigns targeting the hospitality industry since at least 2016.",
        "summary": "Financial threat group targeting hospitality and retail through spear-phishing",
        "mitre_attack_id": None,
        "external_ids": ["G0061"],
        "references": [
            "https://attack.mitre.org/groups/G0061/",
            "https://www.fireeye.com/blog/threat-research/2016/05/windows-zero-day-payment-cards.html"
        ],
        "analyst_notes": "Known for exploiting zero-day vulnerabilities and targeting point-of-sale systems",
        "quality_score": 0.8,
        "is_validated": True,
        "validation_notes": "Confirmed through incident response engagements",
        "custom_attributes": {"attribution_level": "medium", "threat_category": "cybercriminal"},
        "tags": ["cybercrime", "hospitality", "zero_day", "pos_systems"]
    },
    {
        "name": "APT29",
        "aliases": ["Cozy Bear", "The Dukes", "Group 100"],
        "actor_type": "group",
        "attribution_confidence": 0.9,
        "attribution_rationale": "High confidence attribution to Russian intelligence services based on infrastructure and targeting",
        "primary_attribution": "Russian Foreign Intelligence Service (SVR)",
        "sophistication_level": "advanced",
        "threat_level": "critical",
        "motivations": ["espionage", "intelligence_gathering"],
        "origin_country": "RUS",
        "target_countries": ["USA", "GBR", "DEU", "FRA", "NOR"],
        "target_sectors": ["government", "defense", "technology", "healthcare"],
        "suspected_attribution": "Nation-state",
        "first_observed": datetime(2008, 1, 1, tzinfo=timezone.utc),
        "last_observed": datetime(2024, 1, 1, tzinfo=timezone.utc),
        "status": "active",
        "description": "APT29 is a highly sophisticated threat group that has been attributed to Russia's Foreign Intelligence Service (SVR). The group has been observed targeting government, defense, technology, and healthcare organizations.",
        "summary": "Advanced persistent threat group attributed to Russian SVR conducting espionage operations",
        "mitre_attack_id": "G0016",
        "external_ids": ["G0016"],
        "references": [
            "https://attack.mitre.org/groups/G0016/",
            "https://www.mandiant.com/resources/blog/unc2452-merged-into-apt29"
        ],
        "analyst_notes": "Notable for sophisticated supply chain attacks including SolarWinds compromise",
        "quality_score": 0.95,
        "is_validated": True,
        "validation_notes": "Extensively documented by multiple intelligence agencies",
        "custom_attributes": {"attribution_level": "high", "threat_category": "nation_state"},
        "tags": ["nation_state", "espionage", "supply_chain", "apt", "russia"]
    },
    {
        "name": "Scattered Spider",
        "aliases": ["UNC3944", "Roasted 0ktapus"],
        "actor_type": "group",
        "attribution_confidence": 0.75,
        "attribution_rationale": "Medium confidence based on TTPs and social engineering techniques",
        "primary_attribution": "Financially motivated cybercriminal collective",
        "sophistication_level": "medium",
        "threat_level": "high",
        "motivations": ["financial"],
        "origin_country": "USA",
        "target_countries": ["USA", "GBR", "CAN"],
        "target_sectors": ["technology", "telecommunications", "financial_services"],
        "suspected_attribution": "Criminal organization",
        "first_observed": datetime(2022, 1, 1, tzinfo=timezone.utc),
        "last_observed": datetime(2024, 1, 1, tzinfo=timezone.utc),
        "status": "active",
        "description": "Scattered Spider is a financially motivated threat group that specializes in social engineering and identity theft attacks, particularly targeting cloud and SaaS environments.",
        "summary": "Modern social engineering focused group targeting cloud infrastructure and SaaS platforms",
        "mitre_attack_id": None,
        "external_ids": ["UNC3944"],
        "references": [
            "https://www.mandiant.com/resources/blog/scattered-spider-profile",
            "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a"
        ],
        "analyst_notes": "Known for sophisticated social engineering attacks against help desks and IT support",
        "quality_score": 0.8,
        "is_validated": True,
        "validation_notes": "Confirmed through multiple incident response cases",
        "custom_attributes": {"attribution_level": "medium", "threat_category": "cybercriminal"},
        "tags": ["social_engineering", "cloud", "saas", "identity_theft", "modern"]
    },
    {
        "name": "FIN11",
        "aliases": ["TA505"],
        "actor_type": "group",
        "attribution_confidence": 0.8,
        "attribution_rationale": "Strong correlation based on malware families and infrastructure overlap",
        "primary_attribution": "Financially motivated cybercriminal organization",
        "sophistication_level": "high",
        "threat_level": "high",
        "motivations": ["financial"],
        "origin_country": None,
        "target_countries": ["USA", "GBR", "DEU", "FRA"],
        "target_sectors": ["financial_services", "retail", "hospitality"],
        "suspected_attribution": "Criminal organization",
        "first_observed": datetime(2018, 1, 1, tzinfo=timezone.utc),
        "last_observed": datetime(2023, 8, 1, tzinfo=timezone.utc),
        "status": "active",
        "description": "FIN11 is a financially motivated threat group that conducts high-volume spam campaigns and deploys point-of-sale malware to steal payment card data.",
        "summary": "High-volume spam campaign operators targeting payment card data",
        "mitre_attack_id": None,
        "external_ids": ["G0085"],
        "references": [
            "https://attack.mitre.org/groups/G0085/",
            "https://www.mandiant.com/resources/blog/fin11-email-campaigns-precursor-to-ransomware"
        ],
        "analyst_notes": "Often serves as initial access broker for other threat groups including ransomware operators",
        "quality_score": 0.85,
        "is_validated": True,
        "validation_notes": "Tracked across multiple campaigns with high fidelity indicators",
        "custom_attributes": {"attribution_level": "medium", "threat_category": "cybercriminal"},
        "tags": ["cybercrime", "spam", "initial_access", "payment_cards"]
    }
]


def get_sample_campaigns():
    """Return sample campaign data associated with actors."""
    return [
        {
            "actor_name": "FIN7",
            "name": "Restaurant Chain Campaign 2023",
            "description": "Large-scale spear-phishing campaign targeting restaurant chains",
            "start_date": datetime(2023, 3, 1, tzinfo=timezone.utc),
            "end_date": datetime(2023, 8, 31, tzinfo=timezone.utc),
            "status": "completed",
            "objectives": ["payment_card_theft", "pos_compromise"],
            "target_sectors": ["hospitality", "retail"],
            "target_countries": ["USA", "CAN"],
        },
        {
            "actor_name": "APT29",
            "name": "Government Targeting Campaign 2024",
            "description": "Sophisticated espionage campaign targeting government agencies",
            "start_date": datetime(2024, 1, 1, tzinfo=timezone.utc),
            "end_date": None,
            "status": "active",
            "objectives": ["intelligence_gathering", "persistence"],
            "target_sectors": ["government", "defense"],
            "target_countries": ["USA", "GBR", "DEU"],
        },
        {
            "actor_name": "Scattered Spider",
            "name": "Cloud Infrastructure Campaign 2023",
            "description": "Social engineering campaign targeting cloud service providers",
            "start_date": datetime(2023, 6, 1, tzinfo=timezone.utc),
            "end_date": datetime(2023, 12, 31, tzinfo=timezone.utc),
            "status": "completed",
            "objectives": ["credential_theft", "cloud_access"],
            "target_sectors": ["technology", "telecommunications"],
            "target_countries": ["USA", "GBR"],
        }
    ]


def get_sample_malware_families():
    """Return sample malware family data associated with actors."""
    return [
        {
            "actor_name": "FIN7",
            "name": "Carbanak",
            "aliases": ["Anunak", "FIN7 Backdoor"],
            "family_type": "backdoor",
            "description": "Sophisticated backdoor used by FIN7 for persistent access and data exfiltration",
            "first_seen": datetime(2015, 6, 1, tzinfo=timezone.utc),
            "last_seen": datetime(2023, 10, 1, tzinfo=timezone.utc),
            "platforms": ["windows"],
            "capabilities": ["persistence", "command_execution", "data_exfiltration"],
        },
        {
            "actor_name": "APT29",
            "name": "CozyDuke",
            "aliases": ["CosmicDuke", "EuroAPT"],
            "family_type": "backdoor",
            "description": "Advanced backdoor used by APT29 for espionage operations",
            "first_seen": datetime(2014, 1, 1, tzinfo=timezone.utc),
            "last_seen": datetime(2023, 12, 1, tzinfo=timezone.utc),
            "platforms": ["windows", "linux"],
            "capabilities": ["persistence", "credential_theft", "lateral_movement"],
        },
        {
            "actor_name": "Scattered Spider",
            "name": "Spider Stealer",
            "aliases": ["DataSpider", "InfoStealer"],
            "family_type": "infostealer",
            "description": "Information stealer focused on cloud credentials and browser data",
            "first_seen": datetime(2022, 8, 1, tzinfo=timezone.utc),
            "last_seen": datetime(2024, 1, 1, tzinfo=timezone.utc),
            "platforms": ["windows", "macos"],
            "capabilities": ["credential_theft", "browser_hijacking", "token_theft"],
        }
    ]