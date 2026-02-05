"""
VDR (Vulnerability Disclosure Report) Support

VDR is a vulnerability disclosure report in CycloneDX format.
Technically, VDR and CycloneDX VEX use the same format (CycloneDX 1.7),
but they differ in their intended use.

Differences:
- CycloneDX VEX: Focuses on affects and analysis.state (status communication)
- VDR: Focuses on detail, recommendation, workaround, proofOfConcept, credits (detailed report)

Usage:
1. VEX to VDR:
   vdr = vex_to_vdr(cim)
   
2. VDR to VEX (requires input_vdr=True):
   vex = vdr_to_vex(vdr_data, target_format="openvex", input_vdr=True)
   
3. Enhance with NVD API:
   cim = enhance_vdr_with_nvd(cim, api_key="...")
"""

from typing import Optional, Dict, Any
from .models import CIM, VulnerabilityStatus, ConversionOptions
from .nvd_client import NVDAPIClient


def vex_to_vdr(cim: CIM) -> Dict:
    """
    Convert VEX (CIM) to VDR
    
    Maps VEX information to VDR fields:
    - description + impact_statement to detail
    - action_statement to recommendation
    - status to analysis.state
    
    VDR-specific fields not in VEX are created with placeholders:
    - workaround: "[User Input Required]"
    - proofOfConcept: {"reproductionSteps": "[User Input Required]"}
    - credits: {"individuals": [{"name": "[User Input Required]"}]}
    
    Args:
        cim: CIM object (converted from VEX format)
    
    Returns:
        VDR document (CycloneDX)
    
    Example:
        >>> openvex = load_openvex()
        >>> cim = OpenVEXToCIM().convert(openvex)
        >>> vdr = vex_to_vdr(cim)
    """
    from .from_cim import CIMToCycloneDX
    
    # Map VEX information to VDR fields
    for vuln in cim.vulnerabilities:
        # detail: description + impact_statement
        if vuln.description and not vuln.extension_data.get("cyclonedx.detail"):
            detail = vuln.description
            
            # Add impact_statement from statements
            vuln_statements = [s for s in cim.statements if s.vulnerability_id == vuln.id]
            for stmt in vuln_statements:
                if stmt.status.impact_statement:
                    detail += f"\n\nImpact: {stmt.status.impact_statement}"
                    break
            
            vuln.extension_data["cyclonedx.detail"] = detail
        
        # recommendation: action_statement
        if not vuln.extension_data.get("cyclonedx.recommendation"):
            vuln_statements = [s for s in cim.statements if s.vulnerability_id == vuln.id]
            for stmt in vuln_statements:
                if stmt.action_statement:
                    vuln.extension_data["cyclonedx.recommendation"] = stmt.action_statement
                    break
        
        # analysis.state: inferred from status
        if not vuln.extension_data.get("cyclonedx.analysis.state"):
            status_to_state = {
                VulnerabilityStatus.AFFECTED: "exploitable",
                VulnerabilityStatus.FIXED: "resolved",
                VulnerabilityStatus.NOT_AFFECTED: "not_affected",
                VulnerabilityStatus.UNDER_INVESTIGATION: "in_triage"
            }
            
            vuln_statements = [s for s in cim.statements if s.vulnerability_id == vuln.id]
            for stmt in vuln_statements:
                state = status_to_state.get(stmt.status.value)
                if state:
                    vuln.extension_data["cyclonedx.analysis.state"] = state
                    break
        
        # VDR-specific fields: Create placeholders (not in VEX)
        # workaround
        if not vuln.extension_data.get("cyclonedx.workaround"):
            vuln.extension_data["cyclonedx.workaround"] = "[User Input Required]"
        
        # proofOfConcept
        if not vuln.extension_data.get("cyclonedx.proofOfConcept"):
            vuln.extension_data["cyclonedx.proofOfConcept"] = {
                "reproductionSteps": "[User Input Required]",
                "environment": "[User Input Required]"
            }
        
        # credits
        if not vuln.extension_data.get("cyclonedx.credits"):
            vuln.extension_data["cyclonedx.credits"] = {
                "individuals": [
                    {
                        "name": "[User Input Required]",
                        "email": "[User Input Required]"
                    }
                ]
            }
    
    # CIM to VDR (CycloneDX)
    return CIMToCycloneDX(ConversionOptions()).convert(cim)


def vdr_to_vex(vdr: Dict, target_format: str = "openvex", 
               input_vdr: bool = False) -> Dict:
    """
    Convert VDR to VEX or general CycloneDX to VEX
    
    input_vdr=True: Treat as VDR, convert detailed info to simple info
    input_vdr=False: Treat as general CycloneDX VEX, convert as-is
    
    VDR to VEX mapping (when input_vdr=True):
    - detail to impact_statement (200 char summary)
    - recommendation to action_statement
    - analysis.state to status
    
    Args:
        vdr: VDR or CycloneDX document
        target_format: Output VEX format ("openvex", "csaf", "cyclonedx")
        input_vdr: True to treat as VDR, False to treat as general CycloneDX
    
    Returns:
        VEX document (specified format)
    
    Example:
        # VDR to VEX
        >>> vdr = load_vdr()
        >>> openvex = vdr_to_vex(vdr, "openvex", input_vdr=True)
        
        # General CycloneDX VEX to OpenVEX
        >>> cdx_vex = load_cyclonedx_vex()
        >>> openvex = vdr_to_vex(cdx_vex, "openvex", input_vdr=False)
    """
    from .to_cim import CycloneDXToCIM
    from .from_cim import CIMToOpenVEX, CIMToCSAF, CIMToCycloneDX
    
    # VDR to CIM (pass input_vdr option)
    cim = CycloneDXToCIM(
        ConversionOptions(input_vdr=input_vdr)
    ).convert(vdr)
    
    if input_vdr:
        # VDR detailed info to VEX simple info
        for vuln in cim.vulnerabilities:
            # detail to impact_statement (200 char summary)
            detail = vuln.extension_data.get("cyclonedx.detail")
            if detail:
                summary = detail[:200] + "..." if len(detail) > 200 else detail
                
                # Add impact_statement to statements
                for stmt in cim.statements:
                    if stmt.vulnerability_id == vuln.id:
                        if not stmt.status.impact_statement:
                            stmt.status.impact_statement = summary
            
            # recommendation to action_statement
            recommendation = vuln.extension_data.get("cyclonedx.recommendation")
            if recommendation:
                for stmt in cim.statements:
                    if stmt.vulnerability_id == vuln.id:
                        if not stmt.action_statement:
                            stmt.action_statement = recommendation
    
    # CIM to VEX (specified format)
    if target_format.lower() == "openvex":
        return CIMToOpenVEX(ConversionOptions()).convert(cim)
    elif target_format.lower() == "csaf":
        return CIMToCSAF(ConversionOptions()).convert(cim)
    else:  # cyclonedx
        return CIMToCycloneDX(ConversionOptions()).convert(cim)


def enhance_vdr_with_nvd(cim: CIM, api_key: Optional[str] = None) -> CIM:
    """
    Enhance CIM vulnerability information using NVD API
    
    Automatically adds for vulnerabilities with CVE ID:
    - CVSS ratings (CVSSv2, CVSSv3, CVSSv3.1)
    - CWE list
    
    Args:
        cim: CIM object
        api_key: NVD API key (optional, without it rate limit is lower)
    
    Returns:
        Enhanced CIM object
    
    Example:
        >>> from vex_converter import *
        >>> cim = OpenVEXToCIM().convert(openvex_data)
        >>> cim = enhance_vdr_with_nvd(cim, api_key="...")
        >>> vdr = CIMToCycloneDX().convert(cim)
    """
    if not cim.vulnerabilities:
        return cim
    
    client = NVDAPIClient(api_key)
    
    for vuln in cim.vulnerabilities:
        # Check CVE ID
        if not vuln.id or not vuln.id.upper().startswith("CVE-"):
            continue
        
        # Fetch data from NVD
        try:
            cve_data = client.get_cve_data(vuln.id)
            if not cve_data:
                continue
            
            # Add CVSS ratings
            if cve_data.get("ratings"):
                # Only add if not already present
                existing_methods = {r.method for r in vuln.ratings if r.method}
                for rating in cve_data["ratings"]:
                    if rating.get("method") not in existing_methods:
                        from .models import CvssRating
                        vuln.ratings.append(CvssRating(
                            method=rating.get("method"),
                            score=rating.get("score"),
                            severity=rating.get("severity"),
                            vector=rating.get("vector")
                        ))
            
            # Add CWEs
            if cve_data.get("cwes"):
                # Only add if not already present
                existing_cwes = set(vuln.cwes)
                for cwe in cve_data["cwes"]:
                    if cwe not in existing_cwes:
                        vuln.cwes.append(cwe)
        
        except Exception:
            # Ignore NVD API errors (optional feature)
            continue
    
    return cim