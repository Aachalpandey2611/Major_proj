"""
compliance_mapper.py — Maps OWASP categories to compliance frameworks (EU AI Act, ISO, NIST).

Enforces the non-negotiable legal disclaimer requirement:
- Response includes "guidance_only": True.
- Response includes the COMPLIANCE_DISCLAIMER plain-text warning.
"""

from typing import Dict

COMPLIANCE_DISCLAIMER = (
    "GUIDANCE ONLY -- NOT LEGAL ADVICE. "
    "This compliance mapping is informational. OWASP LLM Top 10, EU AI Act, "
    "NIST AI RMF, and ISO 42001 interpretations vary by jurisdiction and context. "
    "Consult qualified legal and compliance professionals before making compliance "
    "claims to regulators or enterprise customers."
)

# Detailed mapping from OWASP categories to regulatory articles
REGULATORY_MAP = {
    "OWASP LLM01:2025 - Prompt Injection": {
        "eu_ai_act": "Article 15 (Accuracy, robustness and cybersecurity)",
        "iso_42001": "Annex A.8.4 (System and information integrity)",
        "nist_ai_rmf": "MITIGATE 1.2 (Manage AI system vulnerability risks)",
    },
    "OWASP LLM02:2025 - Insecure Tool Call": {
        "eu_ai_act": "Article 15 (Robustness and cybersecurity controls)",
        "iso_42001": "Annex A.8.2 (Access control rules)",
        "nist_ai_rmf": "MITIGATE 1.1 (Manage AI system component security)",
    },
    "OWASP LLM03:2025 - Improper Output Handling": {
        "eu_ai_act": "Article 13 (Transparency and provision of information)",
        "iso_42001": "Annex A.8.4 (System and information integrity)",
        "nist_ai_rmf": "MITIGATE 1.2 (System output validation)",
    },
    "OWASP LLM04:2025 - Model Denial of Service": {
        "eu_ai_act": "Article 15 (System availability and resilience)",
        "iso_42001": "Annex A.8.4 (System availability)",
        "nist_ai_rmf": "MITIGATE 1.3 (System robustness)",
    },
    "OWASP LLM06:2025 - Sensitive Information Disclosure": {
        "eu_ai_act": "Article 10 (Data and data governance - PII leakage prevention)",
        "iso_42001": "Annex A.8.5 (Data privacy protection)",
        "nist_ai_rmf": "MITIGATE 1.1 (Information disclosure controls)",
    },
}


def get_compliance_mapping(owasp_category: str) -> Dict[str, any]:
    """
    Get regulatory compliance mappings for a given OWASP category.

    Args:
        owasp_category: The string category name.

    Returns:
        dict: containing the regulatory mappings, the legal disclaimer,
              and the guidance_only flag.
    """
    base = REGULATORY_MAP.get(
        owasp_category,
        {
            "eu_ai_act": "Article 15 (Security and robustness)",
            "iso_42001": "Annex A.8 (System controls)",
            "nist_ai_rmf": "MITIGATE 1.0 (Risk management controls)",
        },
    )

    return {
        **base,
        "disclaimer": COMPLIANCE_DISCLAIMER,
        "guidance_only": True,
    }
