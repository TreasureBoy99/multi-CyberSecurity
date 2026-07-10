"""CVE 智能匹配引擎 (修正版)"""
from .patterns import (
    AttackPattern,
    RiskLevel,
    ATTACK_PATTERNS,
    match_patterns,
    get_top_patterns,
)
from .matcher import (
    ExploitContext,
    CVEMatch,
    CVEDatabase,
    CVEMatcher,
    CVEDatabaseInitializer,
    recommend_attack_paths,
)
from .loader import (
    CVERecord,
    CVELoader,
    get_cve_loader,
    load_all_sources,
)
from .nvd_client import (
    NVDClient,
    NVDCVERecord,
    CVSSData,
    enrich_cvss_batch,
)
from .mitre import (
    ATTACKTactic,
    ATTACKTechnique,
    ATTACKMapping,
    map_cve_to_attack,
    match_exploit_chain,
)

__all__ = [
    # Patterns
    "AttackPattern",
    "RiskLevel",
    "ATTACK_PATTERNS",
    "match_patterns",
    "get_top_patterns",
    # Matcher
    "ExploitContext",
    "CVEMatch",
    "CVEDatabase",
    "CVEMatcher",
    "CVEDatabaseInitializer",
    "recommend_attack_paths",
    # Loader
    "CVERecord",
    "CVELoader",
    "get_cve_loader",
    "load_all_sources",
    # NVD Client
    "NVDClient",
    "NVDCVERecord",
    "CVSSData",
    "enrich_cvss_batch",
    # MITRE ATT&CK
    "ATTACKTactic",
    "ATTACKTechnique",
    "ATTACKMapping",
    "map_cve_to_attack",
    "match_exploit_chain",
]
