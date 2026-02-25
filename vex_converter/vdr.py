"""
VDR (취약점 공개 보고서) 지원

VDR은 CycloneDX 형식의 취약점 공개 보고서입니다.
기술적으로 VDR과 CycloneDX VEX는 같은 형식(CycloneDX 1.7)을 사용하지만,
의도된 용도가 다릅니다.

차이점:
- CycloneDX VEX: affects와 analysis.state에 초점 (상태 전달)
- VDR: detail, recommendation, workaround, proofOfConcept, credits에 초점 (상세 보고서)

사용법:
1. VEX에서 VDR로:
   vdr = vex_to_vdr(cim)
   
2. VDR에서 VEX로 (input_vdr=True 필요):
   vex = vdr_to_vex(vdr_data, target_format="openvex", input_vdr=True)
   
3. NVD API로 보강:
   cim = enhance_vdr_with_nvd(cim, api_key="...")
"""

from typing import Optional, Dict, Any
from .models import CIM, VulnerabilityStatus, ConversionOptions
from .nvd_client import NVDAPIClient


def vex_to_vdr(cim: CIM) -> Dict:
    """
    VEX (CIM)에서 VDR로 변환
    
    VEX 정보를 VDR 필드에 매핑:
    - description + impact_statement를 detail로
    - action_statement를 recommendation으로
    - status를 analysis.state로
    
    VEX에 없는 VDR 전용 필드는 플레이스홀더로 생성:
    - workaround: "[User Input Required]"
    - proofOfConcept: {"reproductionSteps": "[User Input Required]"}
    - credits: {"individuals": [{"name": "[User Input Required]"}]}
    
    Args:
        cim: CIM 객체 (VEX 형식에서 변환됨)
    
    Returns:
        VDR 문서 (CycloneDX)
    
    예:
        >>> openvex = load_openvex()
        >>> cim = OpenVEXToCIM().convert(openvex)
        >>> vdr = vex_to_vdr(cim)
    """
    from .from_cim import CIMToCycloneDX
    
    # VEX 정보를 VDR 필드에 매핑
    for vuln in cim.vulnerabilities:
        # detail: description + impact_statement
        if vuln.description and not vuln.extension_data.get("cyclonedx.detail"):
            detail = vuln.description
            
            # statement에서 impact_statement 추가
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
        
        # analysis.state: status에서 추론
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
        
        # VDR 전용 필드: 플레이스홀더 생성 (VEX에 없음)
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
    
    # CIM에서 VDR (CycloneDX)로
    return CIMToCycloneDX(ConversionOptions()).convert(cim)


def vdr_to_vex(vdr: Dict, target_format: str = "openvex", 
               input_vdr: bool = False) -> Dict:
    """
    VDR에서 VEX로 또는 일반 CycloneDX에서 VEX로 변환
    
    input_vdr=True: VDR로 취급, 상세 정보를 간단한 정보로 변환
    input_vdr=False: 일반 CycloneDX VEX로 취급, 그대로 변환
    
    VDR에서 VEX 매핑 (input_vdr=True일 때):
    - detail을 impact_statement로 (200자 요약)
    - recommendation을 action_statement로
    - analysis.state를 status로
    
    Args:
        vdr: VDR 또는 CycloneDX 문서
        target_format: 출력 VEX 형식 ("openvex", "csaf", "cyclonedx")
        input_vdr: True면 VDR로 취급, False면 일반 CycloneDX로 취급
    
    Returns:
        VEX 문서 (지정된 형식)
    
    예:
        # VDR에서 VEX로
        >>> vdr = load_vdr()
        >>> openvex = vdr_to_vex(vdr, "openvex", input_vdr=True)
        
        # 일반 CycloneDX VEX에서 OpenVEX로
        >>> cdx_vex = load_cyclonedx_vex()
        >>> openvex = vdr_to_vex(cdx_vex, "openvex", input_vdr=False)
    """
    from .to_cim import CycloneDXToCIM
    from .from_cim import CIMToOpenVEX, CIMToCSAF, CIMToCycloneDX
    
    # VDR에서 CIM으로 (input_vdr 옵션 전달)
    cim = CycloneDXToCIM(
        ConversionOptions(input_vdr=input_vdr)
    ).convert(vdr)
    
    if input_vdr:
        # VDR 상세 정보를 VEX 간단한 정보로
        for vuln in cim.vulnerabilities:
            # detail을 impact_statement로 (200자 요약)
            detail = vuln.extension_data.get("cyclonedx.detail")
            if detail:
                summary = detail[:200] + "..." if len(detail) > 200 else detail
                
                # statement에 impact_statement 추가
                for stmt in cim.statements:
                    if stmt.vulnerability_id == vuln.id:
                        if not stmt.status.impact_statement:
                            stmt.status.impact_statement = summary
            
            # recommendation을 action_statement로
            recommendation = vuln.extension_data.get("cyclonedx.recommendation")
            if recommendation:
                for stmt in cim.statements:
                    if stmt.vulnerability_id == vuln.id:
                        if not stmt.action_statement:
                            stmt.action_statement = recommendation
    
    # CIM에서 VEX로 (지정된 형식)
    if target_format.lower() == "openvex":
        return CIMToOpenVEX(ConversionOptions()).convert(cim)
    elif target_format.lower() == "csaf":
        return CIMToCSAF(ConversionOptions()).convert(cim)
    else:  # cyclonedx
        return CIMToCycloneDX(ConversionOptions()).convert(cim)


def enhance_vdr_with_nvd(cim: CIM, api_key: Optional[str] = None) -> CIM:
    """
    NVD API를 사용하여 CIM 취약점 정보 보강
    
    CVE ID가 있는 취약점에 대해 자동으로 추가:
    - CVSS 등급 (CVSSv2, CVSSv3, CVSSv3.1)
    - CWE 목록
    
    Args:
        cim: CIM 객체
        api_key: NVD API 키 (선택, 없으면 속도 제한이 낮음)
    
    Returns:
        보강된 CIM 객체
    
    예:
        >>> from vex_converter import *
        >>> cim = OpenVEXToCIM().convert(openvex_data)
        >>> cim = enhance_vdr_with_nvd(cim, api_key="...")
        >>> vdr = CIMToCycloneDX().convert(cim)
    """
    if not cim.vulnerabilities:
        return cim
    
    client = NVDAPIClient(api_key)
    
    for vuln in cim.vulnerabilities:
        # CVE ID 확인
        if not vuln.id or not vuln.id.upper().startswith("CVE-"):
            continue
        
        # NVD에서 데이터 가져오기
        try:
            cve_data = client.get_cve_data(vuln.id)
            if not cve_data:
                continue
            
            # CVSS 등급 추가
            if cve_data.get("ratings"):
                # 이미 존재하지 않는 것만 추가
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
            
            # CWE 추가
            if cve_data.get("cwes"):
                # 이미 존재하지 않는 것만 추가
                existing_cwes = set(vuln.cwes)
                for cwe in cve_data["cwes"]:
                    if cwe not in existing_cwes:
                        vuln.cwes.append(cwe)
        
        except Exception:
            # NVD API 에러 무시 (선택적 기능)
            continue
    
    return cim