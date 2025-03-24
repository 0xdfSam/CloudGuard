"""Unified interface for security framework mappings."""

from dataclasses import dataclass
from typing import Dict, List, Optional, Any, Set

from cloudguard.core.findings import FrameworkMapping
from cloudguard.frameworks import mitre, cwe, cis


@dataclass
class FrameworkMapResult:
    """Result of mapping a tag to a security framework."""
    framework: str
    framework_id: str
    name: str
    url: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    version: Optional[str] = None


def map_tag_to_frameworks(tag: str) -> List[FrameworkMapResult]:
    """Map a tag to all relevant security frameworks.
    
    Args:
        tag: Tag to look up in mappings
        
    Returns:
        List of framework mapping results
    """
    results = []
    
    # Map to MITRE ATT&CK
    mitre_mapping = mitre.get_mitre_mapping_by_tag(tag)
    if mitre_mapping:
        results.append(FrameworkMapResult(
            framework="MITRE ATT&CK",
            framework_id=mitre_mapping["id"],
            name=mitre_mapping["name"],
            url=mitre_mapping["url"],
            description=mitre_mapping.get("description"),
            category=mitre_mapping.get("tactic")
        ))
    
    # Map to CWE
    cwe_mapping = cwe.get_cwe_mapping_by_tag(tag)
    if cwe_mapping:
        results.append(FrameworkMapResult(
            framework="CWE",
            framework_id=cwe_mapping["id"],
            name=cwe_mapping["name"],
            url=cwe_mapping["url"],
            description=cwe_mapping.get("description")
        ))
    
    # Map to CIS
    cis_mapping = cis.get_cis_mapping_by_tag(tag)
    if cis_mapping:
        results.append(FrameworkMapResult(
            framework="CIS",
            framework_id=cis_mapping["id"],
            name=cis_mapping["name"],
            url=cis_mapping["url"],
            description=cis_mapping.get("description"),
            version=cis_mapping.get("version")
        ))
    
    return results


def get_framework_mappings_from_tags(tags: Set[str]) -> List[FrameworkMapping]:
    """Convert a set of tags to a list of FrameworkMapping objects for use in findings.
    
    Args:
        tags: Set of tags to map to frameworks
        
    Returns:
        List of FrameworkMapping objects
    """
    results = []
    
    for tag in tags:
        framework_results = map_tag_to_frameworks(tag)
        for result in framework_results:
            mapping = FrameworkMapping(
                framework=result.framework,
                id=result.framework_id,
                name=result.name,
                url=result.url
            )
            # Avoid duplicates
            if mapping not in results:
                results.append(mapping)
    
    return results


def get_all_mapped_tags() -> Dict[str, List[str]]:
    """Get all tags that have mappings, organized by framework.
    
    Returns:
        Dictionary mapping framework names to lists of tags with mappings
    """
    results = {
        "MITRE ATT&CK": [],
        "CWE": [],
        "CIS": []
    }
    
    # MITRE ATT&CK tags
    for tag in mitre.MITRE_ATTACK_MAPPINGS.keys():
        results["MITRE ATT&CK"].append(tag)
    
    # CWE tags
    for tag in cwe.CWE_MAPPINGS.keys():
        results["CWE"].append(tag)
    
    # CIS tags
    for tag in cis.CIS_MAPPINGS.keys():
        results["CIS"].append(tag)
    
    return results 