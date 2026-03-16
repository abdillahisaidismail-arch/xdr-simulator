"""
XDR Simulator — Extended Detection & Response Platform
=======================================================
Simulateur XDR développé dans le contexte d'un SI bancaire critique
sous contrainte PCI-DSS. Traitement de +10 000 événements/jour,
corrélation multi-sources et détection automatisée d'incidents.

Modules:
    generators  — Génération d'événements (Syslog, Filebeat, JSON)
    parsers     — Normalisation et parsing des événements
    correlation — Moteur de corrélation multi-sources
    detection   — Règles de détection (brute force SSH, accès anormaux, élévation de privilèges)
    compliance  — Conformité PCI-DSS, audit trail, traçabilité
    dashboard   — Tableau de bord et reporting
    utils       — Utilitaires communs
"""

__version__ = "1.0.0"
__author__ = "Abdillahi Said Ismail"
__description__ = "XDR Simulator — Banque Centrale de Djibouti"
