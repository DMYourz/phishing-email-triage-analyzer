"""phishtriage - an offline-first phishing email triage analyzer.

Parses a raw .eml message, evaluates a set of weighted detection rules
(sender authentication, domain look-alikes, link manipulation, risky
attachments, social-engineering language), and produces an analyst-ready
triage report with a score, verdict, and MITRE ATT&CK mapping.
"""
__version__ = "1.0.0"
