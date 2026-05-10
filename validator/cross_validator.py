"""
cross_validator.py
Cross-document validation 모듈.
VEX 문서와 BOM 문서를 함께 입력받아 semantic consistency를 검증한다.

기존 integrated_validators의 format-native validation과 별개로 동작하며,
cross_doc_routes.py에서 호출된다.

핵심 흐름:
  1. VEX -> IR 변환
  2. BOM -> IR 변환
  3. Strong matching (purl, cpe, bom-ref exact)
  4. Weak matching (name + version)  -- strong 실패 시에만 수행
  5. Traceability map 생성
  6. Cross-document rule 검증
  7. Verdict 결정
"""
from dataclasses import asdict
from typing import Dict, List, Any, Optional, Tuple
import re

from validation_common import (
    MatchStrength, MatchStatus, Verdict,
    IRVulnerability, IRProduct, IRStatement, IRDocument,
    BOMComponent, BOMDocument,
    MatchResult, CrossRuleResult,
)


# ========================================================================
# VEX -> IR 변환
# ========================================================================

def _normalize_purl(purl: str) -> str:
    """purl에서 qualifier(?...)와 subpath(#...)를 제거하고 URL 디코딩한다.
    매칭 비교용 정규화 함수."""
    if not purl:
        return ""
    import urllib.parse
    base = purl.split("?")[0].split("#")[0]
    return urllib.parse.unquote(base)


def _parse_purl_name_version(purl: str) -> Tuple[str, str]:
    """purl 문자열에서 name, version을 추출한다.
    golang처럼 namespace가 긴 형식은 type/ 이후 전체를 name으로 반환한다.
    예: pkg:golang/github.com/docker/cli@v29.1.3 -> ("github.com/docker/cli", "v29.1.3")
        pkg:npm/express@4.18.2 -> ("express", "4.18.2")"""
    if not purl:
        return ("", "")
    try:
        import urllib.parse
        # qualifier, subpath 제거 및 URL 디코딩
        base = urllib.parse.unquote(purl.split("?")[0].split("#")[0])
        # pkg: scheme 제거
        without_scheme = base.split("pkg:")[-1] if "pkg:" in base else base
        # type/... 분리
        if "/" not in without_scheme:
            return ("", "")
        purl_type = without_scheme.split("/", 1)[0]
        remainder = without_scheme.split("/", 1)[1]  # namespace/name@version
        # version 분리
        if "@" in remainder:
            path_part, ver = remainder.rsplit("@", 1)
        else:
            path_part, ver = remainder, ""
        # golang 등 namespace가 긴 형식: type/ 이후 전체를 name으로 사용
        # 이렇게 해야 BOM의 name 필드 (예: "github.com/docker/cli")와 매칭됨
        name = path_part
        return (name, ver)
    except Exception:
        return ("", "")


def _parse_cpe_name_version(cpe: str) -> Tuple[str, str]:
    """CPE 2.3 문자열에서 product, version을 추출한다.
    예: cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:* -> ("product", "1.0")"""
    if not cpe:
        return ("", "")
    parts = cpe.split(":")
    if len(parts) >= 6:
        product = parts[4] if parts[4] != "*" else ""
        version = parts[5] if parts[5] != "*" else ""
        return (product, version)
    return ("", "")


def _extract_identifier_from_id(id_str: str) -> str:
    """@id 또는 identifier 문자열에서 핵심 식별자를 추출한다."""
    if not id_str:
        return ""
    # purl 형식이면 그대로 반환
    if id_str.startswith("pkg:"):
        return id_str
    return id_str


def vex_to_ir(vex_doc: Dict[str, Any]) -> IRDocument:
    """VEX 문서(OpenVEX, CycloneDX, CSAF)를 IR로 변환한다."""
    fmt = _detect_vex_format(vex_doc)
    if fmt == "openvex":
        return _openvex_to_ir(vex_doc)
    elif fmt == "cyclonedx":
        return _cyclonedx_vex_to_ir(vex_doc)
    elif fmt == "csaf":
        return _csaf_to_ir(vex_doc)
    # 알 수 없는 형식이면 빈 IR 반환
    return IRDocument(format_type="unknown")


def _detect_vex_format(doc: Dict[str, Any]) -> str:
    """VEX 문서 형식을 감지한다."""
    if doc.get("@context") and "openvex" in str(doc.get("@context", "")):
        return "openvex"
    if doc.get("statements") and "@id" in doc:
        return "openvex"
    if doc.get("document", {}).get("tracking"):
        return "csaf"
    if doc.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    return "unknown"


def _openvex_to_ir(doc: Dict[str, Any]) -> IRDocument:
    """OpenVEX -> IR 변환"""
    ir = IRDocument(
        format_type="openvex",
        format_version="0.2.0",
        doc_id=doc.get("@id", ""),
        timestamp=doc.get("timestamp", ""),
        author=doc.get("author", ""),
    )

    for idx, stmt in enumerate(doc.get("statements", [])):
        vuln_raw = stmt.get("vulnerability", {})
        if isinstance(vuln_raw, str):
            vuln_raw = {"name": vuln_raw}
        ir_vuln = IRVulnerability(
            vuln_id=vuln_raw.get("name", vuln_raw.get("@id", "")),
            aliases=vuln_raw.get("aliases", []),
        )

        ir_products = []
        for prod in stmt.get("products", []):
            if isinstance(prod, str):
                # 문자열이 purl 형식이면 purl로 처리
                p = IRProduct(identifier=prod)
                if prod.startswith("pkg:"):
                    p.purl = prod
                    p.name, p.version = _parse_purl_name_version(prod)
                ir_products.append(p)
                continue
            prod_id = prod.get("@id", "")
            identifiers = prod.get("identifiers", {})
            purl = identifiers.get("purl", "")
            cpe = identifiers.get("cpe23", identifiers.get("cpe", ""))
            # @id가 purl 형식이면 purl로 사용
            if not purl and prod_id.startswith("pkg:"):
                purl = prod_id
            name, version = "", ""
            if purl:
                name, version = _parse_purl_name_version(purl)
            elif cpe:
                name, version = _parse_cpe_name_version(cpe)
            # parent product가 "test"같은 placeholder이고 subcomponents가 있으면
            # parent IRProduct를 추가하지 않는다 (실제 대상은 subcomponent).
            # placeholder 판단: purl/cpe가 없고 @id가 표준 식별자 형식이 아닌 경우
            has_subcomponents = bool(prod.get("subcomponents"))
            is_real_identifier = bool(
                purl or cpe or
                (isinstance(prod_id, str) and (
                    prod_id.startswith("pkg:") or
                    prod_id.startswith("cpe:") or
                    prod_id.startswith("urn:") or
                    prod_id.startswith("http://") or
                    prod_id.startswith("https://")
                ))
            )
            if is_real_identifier or not has_subcomponents:
                ir_products.append(IRProduct(
                    identifier=prod_id or purl or cpe,
                    name=name,
                    version=version,
                    purl=purl,
                    cpe=cpe,
                ))
            # subcomponents도 별도 product로 추가
            for sub in prod.get("subcomponents", []):
                if isinstance(sub, dict):
                    sub_id = sub.get("@id", "")
                    sub_ids = sub.get("identifiers", {})
                    sub_purl = sub_ids.get("purl", "")
                    sub_cpe = sub_ids.get("cpe23", sub_ids.get("cpe", ""))
                    # @id가 purl 형식이면 purl로도 사용 (parent product와 동일 처리)
                    if not sub_purl and sub_id.startswith("pkg:"):
                        sub_purl = sub_id
                    sn, sv = "", ""
                    if sub_purl:
                        sn, sv = _parse_purl_name_version(sub_purl)
                    elif sub_cpe:
                        sn, sv = _parse_cpe_name_version(sub_cpe)
                    ir_products.append(IRProduct(
                        identifier=sub_id or sub_purl or sub_cpe,
                        name=sn, version=sv,
                        purl=sub_purl, cpe=sub_cpe,
                    ))

        ir_stmt = IRStatement(
            vulnerability=ir_vuln,
            products=ir_products,
            status=stmt.get("status", ""),
            justification=stmt.get("justification", ""),
            timestamp=stmt.get("timestamp", doc.get("timestamp", "")),
        )
        ir.statements.append(ir_stmt)

    return ir


def _cyclonedx_vex_to_ir(doc: Dict[str, Any]) -> IRDocument:
    """CycloneDX VEX -> IR 변환"""
    ir = IRDocument(
        format_type="cyclonedx",
        format_version=doc.get("specVersion", ""),
        doc_id=doc.get("serialNumber", ""),
        timestamp=(doc.get("metadata", {}) or {}).get("timestamp", ""),
    )
    # CycloneDX 컴포넌트 인덱스 구축 (bom-ref -> component)
    comp_index = {}
    _index_cdx_components(doc.get("components", []), comp_index)
    meta_comp = (doc.get("metadata", {}) or {}).get("component", {})
    if meta_comp and meta_comp.get("bom-ref"):
        comp_index[meta_comp["bom-ref"]] = meta_comp

    for idx, vuln in enumerate(doc.get("vulnerabilities", [])):
        ir_vuln = IRVulnerability(
            vuln_id=vuln.get("id", ""),
            aliases=[],
            cwes=[c.get("id") if isinstance(c, dict) else c
                  for c in vuln.get("cwes", [])],
        )

        ir_products = []
        for aff in vuln.get("affects", []):
            ref = aff.get("ref", "")
            comp = comp_index.get(ref, {})
            purl = comp.get("purl", "")
            cpe = comp.get("cpe", "")
            name = comp.get("name", "")
            version = comp.get("version", "")
            if not name and purl:
                name, _ = _parse_purl_name_version(purl)
            if not version and purl:
                _, version = _parse_purl_name_version(purl)
            ir_products.append(IRProduct(
                identifier=ref,
                name=name, version=version,
                purl=purl, cpe=cpe,
            ))

        analysis = vuln.get("analysis", {}) or {}
        # CycloneDX state -> VEX 공통 status 매핑
        state_map = {
            "exploitable": "affected",
            "not_affected": "not_affected",
            "resolved": "fixed",
            "in_triage": "under_investigation",
        }
        raw_state = analysis.get("state", "")
        ir_stmt = IRStatement(
            vulnerability=ir_vuln,
            products=ir_products,
            status=state_map.get(raw_state, raw_state),
            justification=analysis.get("justification", ""),
            timestamp=(doc.get("metadata", {}) or {}).get("timestamp", ""),
        )
        ir.statements.append(ir_stmt)

    return ir


def _index_cdx_components(components: list, index: dict):
    """CycloneDX 컴포넌트를 bom-ref 기준으로 인덱싱한다."""
    for comp in (components or []):
        ref = comp.get("bom-ref", "")
        if ref:
            index[ref] = comp
        if "components" in comp:
            _index_cdx_components(comp["components"], index)


def _csaf_to_ir(doc: Dict[str, Any]) -> IRDocument:
    """CSAF VEX -> IR 변환"""
    tracking = doc.get("document", {}).get("tracking", {})
    ir = IRDocument(
        format_type="csaf",
        format_version=doc.get("document", {}).get("csaf_version", ""),
        doc_id=tracking.get("id", ""),
        timestamp=tracking.get("current_release_date", ""),
        author=doc.get("document", {}).get("publisher", {}).get("name", ""),
    )

    # product_tree에서 product_id -> 이름/purl/cpe 매핑 구축
    product_map = {}
    pt = doc.get("product_tree", {})
    _index_csaf_products(pt, product_map)

    # containment 정보 추출 (extended)
    containment = {}
    for branch in pt.get("branches", []):
        _extract_csaf_containment(branch, containment)
    if containment:
        ir.extended["containment"] = containment

    # status 카테고리 -> VEX 공통 status 매핑
    csaf_status_map = {
        "known_affected": "affected",
        "known_not_affected": "not_affected",
        "fixed": "fixed",
        "under_investigation": "under_investigation",
        "first_affected": "affected",
        "first_fixed": "fixed",
        "last_affected": "affected",
        "recommended": "fixed",
    }

    for vuln in doc.get("vulnerabilities", []):
        ir_vuln = IRVulnerability(
            vuln_id=vuln.get("cve", ""),
            cwes=[vuln.get("cwe", {}).get("id", "")] if vuln.get("cwe") else [],
        )

        product_status = vuln.get("product_status", {})
        for status_key, product_ids in product_status.items():
            if not isinstance(product_ids, list):
                continue
            mapped_status = csaf_status_map.get(status_key, status_key)

            ir_products = []
            for pid in product_ids:
                info = product_map.get(pid, {})
                purl = ""
                cpe = ""
                pih = info.get("product_identification_helper", {})
                if isinstance(pih, dict):
                    purl = pih.get("purl", "")
                    cpe = pih.get("cpe", "")
                # product_id 자체가 purl 형식이면 purl로도 사용
                # CSAF spec은 product_id를 임의 문자열로 허용하지만, 일부 도구는 purl을 직접 사용
                if not purl and isinstance(pid, str) and pid.startswith("pkg:"):
                    purl = pid
                name = info.get("name", "")
                version = ""
                if purl and not name:
                    name, version = _parse_purl_name_version(purl)
                ir_products.append(IRProduct(
                    identifier=pid, name=name, version=version,
                    purl=purl, cpe=cpe,
                ))

            # justification 추출 (flags에서)
            justification = ""
            for flag in vuln.get("flags", []):
                flag_pids = flag.get("product_ids", [])
                if any(p in flag_pids for p in product_ids):
                    justification = flag.get("label", "")
                    break

            ir_stmt = IRStatement(
                vulnerability=ir_vuln,
                products=ir_products,
                status=mapped_status,
                justification=justification,
                timestamp=tracking.get("current_release_date", ""),
            )
            ir.statements.append(ir_stmt)

    return ir


def _index_csaf_products(product_tree: dict, product_map: dict):
    """CSAF product_tree에서 product_id -> 정보 매핑을 구축한다."""
    for fp in product_tree.get("full_product_names", []):
        pid = fp.get("product_id", "")
        if pid:
            product_map[pid] = fp
    for branch in product_tree.get("branches", []):
        _index_csaf_branches(branch, product_map)
    for rel in product_tree.get("relationships", []):
        fp = rel.get("full_product_name", {})
        pid = fp.get("product_id", "")
        if not pid:
            continue
        # relationship의 full_product_name은 합성 product_id인 경우가 많다.
        # 실제 식별자(purl)는 product_reference 또는 relates_to_product_reference에 있을 수 있다.
        # 이를 helper에 보강하여 저장한다.
        enriched = dict(fp)
        prod_ref = rel.get("product_reference", "")
        relates_ref = rel.get("relates_to_product_reference", "")
        # purl 후보 결정
        purl_candidate = ""
        if isinstance(prod_ref, str) and prod_ref.startswith("pkg:"):
            purl_candidate = prod_ref
        elif isinstance(relates_ref, str) and relates_ref.startswith("pkg:"):
            purl_candidate = relates_ref
        # helper가 없거나 purl이 비어있으면 보강
        if purl_candidate:
            pih = enriched.get("product_identification_helper")
            if not isinstance(pih, dict):
                pih = {}
            if not pih.get("purl"):
                pih["purl"] = purl_candidate
                enriched["product_identification_helper"] = pih
        product_map[pid] = enriched


def _index_csaf_branches(branch: dict, product_map: dict):
    """CSAF branch를 재귀적으로 순회하여 product 정보를 수집한다."""
    prod = branch.get("product", {})
    pid = prod.get("product_id", "")
    if pid:
        product_map[pid] = prod
    for child in branch.get("branches", []):
        _index_csaf_branches(child, product_map)


def _extract_csaf_containment(branch: dict, containment: dict):
    """CSAF branch 트리에서 parent->child 포함 관계를 추출한다."""
    parent_prod = branch.get("product", {})
    parent_id = parent_prod.get("product_id", "")
    children = branch.get("branches", [])
    if parent_id and children:
        child_ids = []
        for child in children:
            cp = child.get("product", {})
            cid = cp.get("product_id", "")
            if cid:
                child_ids.append(cid)
        if child_ids:
            containment[parent_id] = child_ids
    for child in children:
        _extract_csaf_containment(child, containment)


# ========================================================================
# BOM -> IR 변환
# ========================================================================

def bom_to_ir(bom_doc: Dict[str, Any]) -> BOMDocument:
    """BOM 문서(CycloneDX SBOM)를 BOM IR로 변환한다."""
    fmt = _detect_bom_format(bom_doc)
    if fmt == "cyclonedx":
        return _cyclonedx_bom_to_ir(bom_doc)
    elif fmt == "spdx":
        return _spdx_bom_to_ir(bom_doc)
    return BOMDocument(format_type="unknown")


def _detect_bom_format(doc: Dict[str, Any]) -> str:
    """BOM 문서 형식을 감지한다."""
    if doc.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    if doc.get("spdxVersion"):
        return "spdx"
    return "unknown"


def _cyclonedx_bom_to_ir(doc: Dict[str, Any]) -> BOMDocument:
    """CycloneDX SBOM -> BOM IR 변환"""
    bom = BOMDocument(
        format_type="cyclonedx",
        format_version=doc.get("specVersion", ""),
        serial=doc.get("serialNumber", ""),
    )

    containment = {}

    # metadata.component
    meta_comp = (doc.get("metadata", {}) or {}).get("component", {})
    if meta_comp:
        mc = _cdx_comp_to_bom_component(meta_comp)
        bom.components.append(mc)
        # metadata.component -> top-level components 포함 관계
        if mc.bom_ref:
            child_refs = []
            for c in doc.get("components", []):
                cr = c.get("bom-ref", "")
                if cr:
                    child_refs.append(cr)
            if child_refs:
                containment[mc.bom_ref] = child_refs

    # top-level components (재귀)
    _collect_cdx_bom_components(doc.get("components", []), bom.components, containment)

    if containment:
        bom.extended["containment"] = containment

    return bom


def _cdx_comp_to_bom_component(comp: dict) -> BOMComponent:
    """CycloneDX 컴포넌트 dict -> BOMComponent 변환"""
    return BOMComponent(
        name=comp.get("name", ""),
        version=comp.get("version", ""),
        purl=comp.get("purl", ""),
        cpe=comp.get("cpe", ""),
        bom_ref=comp.get("bom-ref", ""),
    )


def _collect_cdx_bom_components(components: list, result: list, containment: dict):
    """CycloneDX 컴포넌트 목록을 재귀적으로 수집한다."""
    for comp in (components or []):
        bc = _cdx_comp_to_bom_component(comp)
        result.append(bc)
        nested = comp.get("components", [])
        if nested and bc.bom_ref:
            child_refs = [c.get("bom-ref", "") for c in nested if c.get("bom-ref")]
            if child_refs:
                containment[bc.bom_ref] = child_refs
            _collect_cdx_bom_components(nested, result, containment)


def _spdx_bom_to_ir(doc: Dict[str, Any]) -> BOMDocument:
    """SPDX BOM -> BOM IR 변환 (기본 지원)"""
    bom = BOMDocument(
        format_type="spdx",
        format_version=doc.get("spdxVersion", ""),
        serial=doc.get("documentNamespace", ""),
    )
    for pkg in doc.get("packages", []):
        purl = ""
        cpe = ""
        for ref in pkg.get("externalRefs", []):
            ref_type = ref.get("referenceType", "")
            if ref_type == "purl":
                purl = ref.get("referenceLocator", "")
            elif "cpe" in ref_type.lower():
                cpe = ref.get("referenceLocator", "")
        bom.components.append(BOMComponent(
            name=pkg.get("name", ""),
            version=pkg.get("versionInfo", ""),
            purl=purl,
            cpe=cpe,
            bom_ref=pkg.get("SPDXID", ""),
        ))
    return bom


# ========================================================================
# Matching Engine
# ========================================================================

def _build_traceability_map(
    vex_ir: IRDocument,
    bom_ir: BOMDocument,
) -> List[MatchResult]:
    """VEX IR과 BOM IR 사이의 Traceability Map을 구축한다.

    매칭 지침:
      - strong matching 실패 시 즉시 invalid로 처리하지 않고 weak matching 수행
      - weak matching 결과는 support/contradiction의 강한 근거로 쓰지 않음
    """
    results = []

    for stmt_idx, stmt in enumerate(vex_ir.statements):
        vuln_id = stmt.vulnerability.vuln_id if stmt.vulnerability else ""
        for prod in stmt.products:
            match = _match_product_to_bom(prod, bom_ir, vuln_id, stmt_idx)
            results.append(match)

    return results


def _match_product_to_bom(
    vex_prod: IRProduct,
    bom_ir: BOMDocument,
    vuln_id: str,
    stmt_idx: int,
) -> MatchResult:
    """단일 VEX product를 BOM에서 매칭한다.

    Strong matching 우선순위 (각 단계는 이전 단계가 0개 후보를 반환했을 때만 수행):
      1. bom-ref / identifier exact match (BOM 내부 식별자가 가장 강력)
      2. purl exact match (qualifier 포함, 정규화 X)
      3. purl normalized match (qualifier 제거)
      4. cpe exact match
    Weak matching: strong 실패 시에만 name + version으로 수행
    """
    # --- 1단계: Strong matching ---
    strong_candidates = []

    # vex_prod.identifier가 BOM-Link 형식(urn:cdx:.../...#bom-ref)이면 # 뒤를 추출
    # 명세: https://cyclonedx.org/capabilities/bomlink/
    vex_ref = vex_prod.identifier or ""
    vex_ref_extracted = vex_ref
    if vex_ref.startswith("urn:cdx:") and "#" in vex_ref:
        vex_ref_extracted = vex_ref.split("#", 1)[1]

    # 1순위: bom-ref / identifier exact match (BOM 내부 식별자)
    # vex의 affects.ref가 BOM의 bom-ref와 일치하면 가장 deterministic
    # BOM-Link 형식과 raw bom-ref 둘 다 시도
    if vex_ref:
        for bc in bom_ir.components:
            if bc.bom_ref and (bc.bom_ref == vex_ref or bc.bom_ref == vex_ref_extracted):
                strong_candidates.append((bc, "bom-ref", bc.bom_ref))

    # 2순위: purl exact match (qualifier 포함, 정규화하지 않음)
    # arch=arm64 vs arch=all 같은 qualifier 차이를 보존
    # BOM-Link에서 추출한 ref가 purl 형식이면 그것도 시도
    if not strong_candidates:
        candidate_purls = []
        if vex_prod.purl:
            candidate_purls.append(vex_prod.purl)
        if vex_ref_extracted.startswith("pkg:") and vex_ref_extracted not in candidate_purls:
            candidate_purls.append(vex_ref_extracted)
        for vp in candidate_purls:
            for bc in bom_ir.components:
                if bc.purl and bc.purl == vp:
                    strong_candidates.append((bc, "purl", bc.purl))
            if strong_candidates:
                break

    # 3순위: purl normalized match (qualifier 제거)
    # qualifier가 없거나 다르더라도 base purl이 같으면 매칭
    # 이 단계에서 여러 후보가 나오면 ambiguous
    if not strong_candidates:
        candidate_purls = []
        if vex_prod.purl:
            candidate_purls.append(vex_prod.purl)
        if vex_ref_extracted.startswith("pkg:") and vex_ref_extracted not in candidate_purls:
            candidate_purls.append(vex_ref_extracted)
        for vp in candidate_purls:
            vex_purl_norm = _normalize_purl(vp)
            for bc in bom_ir.components:
                if bc.purl and _normalize_purl(bc.purl) == vex_purl_norm:
                    strong_candidates.append((bc, "purl-normalized", bc.purl))
            if strong_candidates:
                break

    # 4순위: cpe exact match
    if not strong_candidates and vex_prod.cpe:
        for bc in bom_ir.components:
            if bc.cpe and bc.cpe == vex_prod.cpe:
                strong_candidates.append((bc, "cpe", bc.cpe))

    if len(strong_candidates) == 1:
        bc, basis, val = strong_candidates[0]
        return MatchResult(
            vex_product_id=vex_prod.identifier,
            bom_component_id=bc.bom_ref or bc.purl or bc.name,
            strength=MatchStrength.STRONG,
            status=MatchStatus.MATCHED,
            matching_basis=basis,
            match_field=val,
            detail=f"Strong match via {basis}: {val}",
            vuln_id=vuln_id,
            statement_index=stmt_idx,
        )
    if len(strong_candidates) > 1:
        ids = [c[0].bom_ref or c[0].purl or c[0].name for c in strong_candidates]
        return MatchResult(
            vex_product_id=vex_prod.identifier,
            bom_component_id=", ".join(ids),
            strength=MatchStrength.STRONG,
            status=MatchStatus.AMBIGUOUS,
            matching_basis=strong_candidates[0][1],
            match_field=strong_candidates[0][2],
            detail=f"Strong match found {len(strong_candidates)} candidates: {', '.join(ids)}",
            vuln_id=vuln_id,
            statement_index=stmt_idx,
        )

    # --- 2단계: Weak matching (name + version) ---
    # strong 실패 시에만 수행
    import urllib.parse as _urlparse
    weak_candidates = []
    if vex_prod.name:
        vex_name_lower = vex_prod.name.lower()
        vex_ver_decoded = _urlparse.unquote(vex_prod.version) if vex_prod.version else ""
        for bc in bom_ir.components:
            if not bc.name:
                continue
            # name 비교: exact match 또는 한쪽이 다른쪽을 포함 (golang namespace 대응)
            bc_name_lower = bc.name.lower()
            name_match = (bc_name_lower == vex_name_lower
                          or bc_name_lower.endswith("/" + vex_name_lower)
                          or vex_name_lower.endswith("/" + bc_name_lower))
            if name_match:
                bc_ver_decoded = _urlparse.unquote(bc.version) if bc.version else ""
                if vex_ver_decoded and bc_ver_decoded:
                    if bc_ver_decoded == vex_ver_decoded:
                        weak_candidates.append((bc, "name+version",
                                                f"{bc.name}@{bc.version}"))
                elif not vex_ver_decoded:
                    # version 미지정 시 name만으로 매칭
                    weak_candidates.append((bc, "name", bc.name))

    if len(weak_candidates) == 1:
        bc, basis, val = weak_candidates[0]
        return MatchResult(
            vex_product_id=vex_prod.identifier,
            bom_component_id=bc.bom_ref or bc.purl or bc.name,
            strength=MatchStrength.WEAK,
            status=MatchStatus.MATCHED,
            matching_basis=basis,
            match_field=val,
            detail=f"Weak match via {basis}: {val}",
            vuln_id=vuln_id,
            statement_index=stmt_idx,
        )
    if len(weak_candidates) > 1:
        ids = [c[0].bom_ref or c[0].purl or c[0].name for c in weak_candidates]
        return MatchResult(
            vex_product_id=vex_prod.identifier,
            bom_component_id=", ".join(ids),
            strength=MatchStrength.WEAK,
            status=MatchStatus.AMBIGUOUS,
            matching_basis="name+version",
            match_field=f"{vex_prod.name}@{vex_prod.version}",
            detail=f"Weak match found {len(weak_candidates)} candidates: {', '.join(ids)}",
            vuln_id=vuln_id,
            statement_index=stmt_idx,
        )

    # --- 매칭 실패 (unresolved) ---
    return MatchResult(
        vex_product_id=vex_prod.identifier,
        bom_component_id="",
        strength=MatchStrength.NONE,
        status=MatchStatus.UNRESOLVED,
        matching_basis="",
        match_field="",
        detail=f"No matching BOM component found for: {vex_prod.identifier}",
        vuln_id=vuln_id,
        statement_index=stmt_idx,
    )


# ========================================================================
# Cross-Document Rules
# ========================================================================

def _rule_target_resolvability(
    matches: List[MatchResult],
) -> List[CrossRuleResult]:
    """CROSS-001: Target Resolvability
    VEX가 가리키는 product_ref가 BOM의 실제 컴포넌트로 해석되어야 한다.
    - unresolved -> error (invalid)
    - weak matched -> warning
    """
    results = []
    for m in matches:
        if m.status == MatchStatus.UNRESOLVED:
            results.append(CrossRuleResult(
                rule_id="CROSS-001",
                rule_name="Target Resolvability",
                severity="error",
                passed=False,
                message=(
                    f"VEX product '{m.vex_product_id}' "
                    f"(vuln: {m.vuln_id}) cannot be resolved to any BOM component."
                ),
                context={"vex_product_id": m.vex_product_id,
                          "vuln_id": m.vuln_id,
                          "statement_index": m.statement_index},
            ))
        elif m.strength == MatchStrength.WEAK and m.status == MatchStatus.MATCHED:
            results.append(CrossRuleResult(
                rule_id="CROSS-001",
                rule_name="Target Resolvability",
                severity="warning",
                passed=True,
                message=(
                    f"VEX product '{m.vex_product_id}' resolved via weak match "
                    f"({m.matching_basis}={m.match_field}). "
                    f"Strong identifier (purl/cpe) recommended."
                ),
                context={"vex_product_id": m.vex_product_id,
                          "bom_component_id": m.bom_component_id,
                          "matching_basis": m.matching_basis},
            ))
    return results


def _rule_target_uniqueness(
    matches: List[MatchResult],
) -> List[CrossRuleResult]:
    """CROSS-002: Target Uniqueness
    VEX의 한 product_ref는 BOM 내에서 유일하게 해석되어야 한다.
    - strong + ambiguous -> error
    - weak + ambiguous -> warning (unverifiable)
    """
    results = []
    for m in matches:
        if m.status != MatchStatus.AMBIGUOUS:
            continue
        if m.strength == MatchStrength.STRONG:
            results.append(CrossRuleResult(
                rule_id="CROSS-002",
                rule_name="Target Uniqueness",
                severity="error",
                passed=False,
                message=(
                    f"VEX product '{m.vex_product_id}' matches multiple BOM components "
                    f"even with strong identifier ({m.matching_basis}): {m.bom_component_id}"
                ),
                context={"vex_product_id": m.vex_product_id,
                          "candidates": m.bom_component_id,
                          "strength": m.strength},
            ))
        else:
            results.append(CrossRuleResult(
                rule_id="CROSS-002",
                rule_name="Target Uniqueness",
                severity="warning",
                passed=False,
                message=(
                    f"VEX product '{m.vex_product_id}' has ambiguous weak match "
                    f"({m.matching_basis}): {m.bom_component_id}"
                ),
                context={"vex_product_id": m.vex_product_id,
                          "candidates": m.bom_component_id,
                          "strength": m.strength},
            ))
    return results


def _rule_identifier_consistency(
    matches: List[MatchResult],
    vex_ir: IRDocument,
    bom_ir: BOMDocument,
) -> List[CrossRuleResult]:
    """CROSS-003: Identifier Preservation / Consistency
    BOM에서 VEX로 데이터가 전파될 때 식별자 정보가 손실되거나 변조되지 않아야 한다.
    - BOM에 purl이 있는데 VEX에서 누락 -> warning
    - BOM과 VEX의 purl/cpe가 다르면 -> error
    """
    results = []
    # BOM 컴포넌트를 빠르게 찾기 위한 인덱스 구축
    bom_by_ref = {}
    bom_by_purl = {}
    for bc in bom_ir.components:
        if bc.bom_ref:
            bom_by_ref[bc.bom_ref] = bc
        if bc.purl:
            bom_by_purl[bc.purl] = bc

    for m in matches:
        if m.status == MatchStatus.UNRESOLVED:
            continue

        # 매칭된 BOM 컴포넌트 찾기
        bom_comp = bom_by_ref.get(m.bom_component_id) or bom_by_purl.get(m.bom_component_id)
        if not bom_comp:
            continue

        # 매칭된 VEX product 찾기
        vex_prod = None
        for stmt in vex_ir.statements:
            for p in stmt.products:
                if p.identifier == m.vex_product_id:
                    vex_prod = p
                    break
            if vex_prod:
                break
        if not vex_prod:
            continue

        # purl 일관성 검사
        if bom_comp.purl and vex_prod.purl:
            if bom_comp.purl != vex_prod.purl:
                results.append(CrossRuleResult(
                    rule_id="CROSS-003",
                    rule_name="Identifier Consistency",
                    severity="error",
                    passed=False,
                    message=(
                        f"PURL mismatch: BOM='{bom_comp.purl}' vs VEX='{vex_prod.purl}' "
                        f"for product '{m.vex_product_id}'"
                    ),
                    context={"bom_purl": bom_comp.purl, "vex_purl": vex_prod.purl},
                ))
        elif bom_comp.purl and not vex_prod.purl:
            results.append(CrossRuleResult(
                rule_id="CROSS-003",
                rule_name="Identifier Consistency",
                severity="warning",
                passed=True,
                message=(
                    f"BOM component has purl '{bom_comp.purl}' but VEX product "
                    f"'{m.vex_product_id}' does not include it. "
                    f"Consider preserving identifiers for traceability."
                ),
                context={"bom_purl": bom_comp.purl, "vex_product_id": m.vex_product_id},
            ))

        # cpe 일관성 검사
        if bom_comp.cpe and vex_prod.cpe:
            if bom_comp.cpe != vex_prod.cpe:
                results.append(CrossRuleResult(
                    rule_id="CROSS-003",
                    rule_name="Identifier Consistency",
                    severity="error",
                    passed=False,
                    message=(
                        f"CPE mismatch: BOM='{bom_comp.cpe}' vs VEX='{vex_prod.cpe}' "
                        f"for product '{m.vex_product_id}'"
                    ),
                    context={"bom_cpe": bom_comp.cpe, "vex_cpe": vex_prod.cpe},
                ))

    return results


def _rule_scope_overreach(
    matches: List[MatchResult],
    vex_ir: IRDocument,
    bom_ir: BOMDocument,
) -> List[CrossRuleResult]:
    """CROSS-004: Scope Precision / Overreach (보조 규칙)
    VEX가 BOM의 근거보다 과도하게 넓은 범위로 선언하지 않았는지 검증한다.
    containment 정보가 있을 때만 수행한다.
    """
    results = []
    bom_containment = bom_ir.extended.get("containment", {})
    vex_containment = vex_ir.extended.get("containment", {})

    if not bom_containment and not vex_containment:
        return results

    # VEX에서 매칭된 product들의 identifier 수집
    matched_vex_ids = set()
    for m in matches:
        if m.status == MatchStatus.MATCHED:
            matched_vex_ids.add(m.vex_product_id)

    # BOM의 최상위 컴포넌트(다른 것의 자식이 아닌 것)에 대해
    # VEX가 해당 최상위를 직접 참조하면서 하위만 해당하는 status를 선언하는 경우
    all_children = set()
    for children in bom_containment.values():
        all_children.update(children)

    parent_refs = set(bom_containment.keys()) - all_children

    for parent in parent_refs:
        if parent in matched_vex_ids:
            children = bom_containment.get(parent, [])
            if children:
                results.append(CrossRuleResult(
                    rule_id="CROSS-004",
                    rule_name="Scope Precision",
                    severity="info",
                    passed=True,
                    message=(
                        f"VEX references top-level component '{parent}' which has "
                        f"{len(children)} child components in BOM. "
                        f"Verify the VEX status applies to all children."
                    ),
                    context={"parent": parent, "child_count": len(children)},
                ))

    return results


def _rule_justification_bom_consistency(
    matches: List[MatchResult],
    vex_ir: IRDocument,
) -> List[CrossRuleResult]:
    """CROSS-005: Justification-BOM Consistency (component_not_present)
    VEX가 not_affected + component_not_present로 선언했는데
    BOM에 해당 컴포넌트가 존재하면 semantic contradiction이다.

    판정 로직:
      - strong matched -> error (BOM에 존재하므로 모순)
      - weak matched   -> warning (애매하게 연결됨)
      - ambiguous       -> info (unverifiable)
      - unresolved      -> info (BOM 부재가 명확히 확인되지 않음, 식별자 mismatch일 수 있음)
    """
    results = []

    # statement별 justification 인덱스 구축
    # {statement_index: (status, justification)}
    stmt_justifications = {}
    for idx, stmt in enumerate(vex_ir.statements):
        if stmt.status == "not_affected" and stmt.justification:
            stmt_justifications[idx] = stmt.justification.lower().replace("-", "_")

    # CycloneDX justification 값 정규화
    # "component_not_present"는 OpenVEX/CycloneDX 공통
    CNP_VALUES = {"component_not_present"}

    for m in matches:
        si = m.statement_index
        if si not in stmt_justifications:
            continue
        just = stmt_justifications[si]
        if just not in CNP_VALUES:
            continue

        vuln_label = m.vuln_id or "(unknown)"
        prod_label = m.vex_product_id or "(unknown)"

        if m.status == MatchStatus.MATCHED and m.strength == MatchStrength.STRONG:
            # BOM에 해당 컴포넌트가 존재 -> component_not_present와 모순
            results.append(CrossRuleResult(
                rule_id="CROSS-005",
                rule_name="Justification-BOM Consistency",
                severity="error",
                passed=False,
                message=(
                    f"Contradiction: VEX declares component_not_present for "
                    f"'{prod_label}' (vuln: {vuln_label}), "
                    f"but BOM contains this component via strong match "
                    f"({m.matching_basis}={m.match_field})."
                ),
                context={
                    "vex_product_id": prod_label,
                    "bom_component_id": m.bom_component_id,
                    "vuln_id": vuln_label,
                    "justification": "component_not_present",
                    "match_strength": m.strength,
                    "match_basis": m.matching_basis,
                },
            ))

        elif m.status == MatchStatus.MATCHED and m.strength == MatchStrength.WEAK:
            # weak match -> 모순 가능성이 있지만 확정 불가
            results.append(CrossRuleResult(
                rule_id="CROSS-005",
                rule_name="Justification-BOM Consistency",
                severity="warning",
                passed=False,
                message=(
                    f"Potential contradiction: VEX declares component_not_present for "
                    f"'{prod_label}' (vuln: {vuln_label}), "
                    f"but a weak match ({m.matching_basis}) found BOM component "
                    f"'{m.bom_component_id}'. Verify with strong identifiers."
                ),
                context={
                    "vex_product_id": prod_label,
                    "bom_component_id": m.bom_component_id,
                    "vuln_id": vuln_label,
                    "justification": "component_not_present",
                    "match_strength": m.strength,
                },
            ))

        elif m.status == MatchStatus.AMBIGUOUS:
            # 후보 여러 개 -> 판단 불가
            results.append(CrossRuleResult(
                rule_id="CROSS-005",
                rule_name="Justification-BOM Consistency",
                severity="info",
                passed=False,
                message=(
                    f"Cannot verify component_not_present for '{prod_label}' "
                    f"(vuln: {vuln_label}): ambiguous match with multiple BOM candidates. "
                    f"Manual review required."
                ),
                context={
                    "vex_product_id": prod_label,
                    "vuln_id": vuln_label,
                    "justification": "component_not_present",
                    "match_status": "ambiguous",
                },
            ))

        elif m.status == MatchStatus.UNRESOLVED:
            # BOM에서 못 찾음 -> 식별자 mismatch일 수 있으므로
            # justification을 지지한다고 볼 수 없음 (unverifiable)
            results.append(CrossRuleResult(
                rule_id="CROSS-005",
                rule_name="Justification-BOM Consistency",
                severity="info",
                passed=False,
                message=(
                    f"Cannot verify component_not_present for '{prod_label}' "
                    f"(vuln: {vuln_label}): no matching BOM component found, but this "
                    f"may be due to identifier mismatch rather than genuine absence. "
                    f"The justification is unverifiable with available evidence."
                ),
                context={
                    "vex_product_id": prod_label,
                    "vuln_id": vuln_label,
                    "justification": "component_not_present",
                    "match_status": "unresolved",
                    "note": "unverifiable_absence",
                },
            ))

    return results


# ========================================================================
# Verdict 결정
# ========================================================================

def _determine_verdict(
    rule_results: List[CrossRuleResult],
    matches: List[MatchResult],
) -> str:
    """판정 지침에 따라 최종 verdict를 결정한다.

    Invalid: unresolved, strong ambiguity, strong identifier inconsistency
    Warning: weak matched, scope overreach, 일부 native SHOULD 위반
    Unverifiable: weak ambiguous, BOM evidence만으로 판정 불가
    Valid: 주요 규칙 위반 없음
    """
    has_error = any(not r.passed and r.severity == "error" for r in rule_results)
    has_warning = any(r.severity == "warning" for r in rule_results)
    has_unresolved = any(m.status == MatchStatus.UNRESOLVED for m in matches)
    has_weak_ambiguous = any(
        m.status == MatchStatus.AMBIGUOUS and m.strength == MatchStrength.WEAK
        for m in matches
    )

    if has_error or has_unresolved:
        return Verdict.INVALID
    if has_weak_ambiguous:
        return Verdict.UNVERIFIABLE
    if has_warning:
        return Verdict.WARNING
    return Verdict.VALID


# ========================================================================
# Match Statistics
# ========================================================================

def _compute_match_stats(
    matches: List[MatchResult],
    rule_results: List[CrossRuleResult] = None,
) -> Dict[str, Any]:
    """매칭 통계를 계산한다. 확장 통계 포함."""
    total = len(matches)
    if total == 0:
        return {"total": 0}

    strong_matched = sum(1 for m in matches
                         if m.strength == MatchStrength.STRONG
                         and m.status == MatchStatus.MATCHED)
    weak_matched = sum(1 for m in matches
                       if m.strength == MatchStrength.WEAK
                       and m.status == MatchStatus.MATCHED)
    ambiguous = sum(1 for m in matches if m.status == MatchStatus.AMBIGUOUS)
    unresolved = sum(1 for m in matches if m.status == MatchStatus.UNRESOLVED)

    # --- 확장 통계 ---

    # 1. Unique Products: 중복 제거한 실제 product 수
    unique_products = len(set(m.vex_product_id for m in matches if m.vex_product_id))

    # 2. Matching Basis Breakdown: basis별 카운트
    basis_breakdown = {}
    for m in matches:
        if m.status != MatchStatus.UNRESOLVED and m.matching_basis:
            basis_breakdown[m.matching_basis] = basis_breakdown.get(m.matching_basis, 0) + 1

    # 3. Identifier Inconsistency Count: statement 기준 + product 기준
    id_inconsistency = {
        "purl_mismatch": 0, "purl_missing": 0, "cpe_mismatch": 0,
        "purl_mismatch_products": 0, "purl_missing_products": 0, "cpe_mismatch_products": 0,
    }
    if rule_results:
        # statement 기준
        purl_mismatch_pids = set()
        purl_missing_pids = set()
        cpe_mismatch_pids = set()
        for r in rule_results:
            if r.rule_id == "CROSS-003":
                ctx = r.context if isinstance(r, CrossRuleResult) else r.get("context", {})
                if isinstance(ctx, dict):
                    pid = ctx.get("vex_product_id", ctx.get("vex_purl", ""))
                    if ctx.get("bom_purl") and ctx.get("vex_purl"):
                        id_inconsistency["purl_mismatch"] += 1
                        purl_mismatch_pids.add(pid)
                    elif ctx.get("bom_purl") and pid:
                        id_inconsistency["purl_missing"] += 1
                        purl_missing_pids.add(pid)
                    elif ctx.get("bom_cpe") and ctx.get("vex_cpe"):
                        id_inconsistency["cpe_mismatch"] += 1
                        cpe_mismatch_pids.add(pid)
        id_inconsistency["purl_mismatch_products"] = len(purl_mismatch_pids)
        id_inconsistency["purl_missing_products"] = len(purl_missing_pids)
        id_inconsistency["cpe_mismatch_products"] = len(cpe_mismatch_pids)

    # 4. Product-level Stats: unique product 기준 매칭 분포
    product_stats = {}
    for m in matches:
        pid = m.vex_product_id
        if pid not in product_stats:
            product_stats[pid] = {"strength": m.strength, "status": m.status}
    product_strong = sum(1 for v in product_stats.values()
                         if v["strength"] == MatchStrength.STRONG
                         and v["status"] == MatchStatus.MATCHED)
    product_weak = sum(1 for v in product_stats.values()
                       if v["strength"] == MatchStrength.WEAK
                       and v["status"] == MatchStatus.MATCHED)
    product_ambiguous = sum(1 for v in product_stats.values()
                            if v["status"] == MatchStatus.AMBIGUOUS)
    product_unresolved = sum(1 for v in product_stats.values()
                             if v["status"] == MatchStatus.UNRESOLVED)

    # 5. Rule Violation Breakdown: rule_id + severity별 카운트
    rule_breakdown = {}
    if rule_results:
        for r in rule_results:
            rid = r.rule_id if isinstance(r, CrossRuleResult) else r.get("rule_id", "")
            sev = r.severity if isinstance(r, CrossRuleResult) else r.get("severity", "")
            key = f"{rid} {sev}"
            rule_breakdown[key] = rule_breakdown.get(key, 0) + 1

    return {
        "total": total,
        "strong_matched": strong_matched,
        "weak_matched": weak_matched,
        "ambiguous": ambiguous,
        "unresolved": unresolved,
        "strong_match_rate": round(strong_matched / total * 100, 1) if total else 0,
        "weak_match_rate": round(weak_matched / total * 100, 1) if total else 0,
        "ambiguous_rate": round(ambiguous / total * 100, 1) if total else 0,
        "unresolved_rate": round(unresolved / total * 100, 1) if total else 0,
        # 확장 통계
        "unique_products": unique_products,
        "basis_breakdown": basis_breakdown,
        "id_inconsistency": id_inconsistency,
        "product_level": {
            "total": unique_products,
            "strong": product_strong,
            "weak": product_weak,
            "ambiguous": product_ambiguous,
            "unresolved": product_unresolved,
        },
        "rule_breakdown": rule_breakdown,
    }


# ========================================================================
# Public API
# ========================================================================

def validate_cross(
    vex_doc: Dict[str, Any],
    bom_doc: Dict[str, Any],
) -> Dict[str, Any]:
    """Cross-document validation의 진입점.

    Args:
        vex_doc: VEX 문서 (OpenVEX, CycloneDX, CSAF)
        bom_doc: BOM 문서 (CycloneDX SBOM, SPDX)

    Returns:
        {
          "verdict": "valid" | "warning" | "unverifiable" | "invalid",
          "match_stats": { ... },
          "traceability_map": [ ... ],
          "rule_results": [ ... ],
          "vex_format": "openvex" | "cyclonedx" | "csaf",
          "bom_format": "cyclonedx" | "spdx",
        }
    """
    # 1. IR 변환
    vex_ir = vex_to_ir(vex_doc)
    bom_ir = bom_to_ir(bom_doc)

    # BOM 형식 검증
    if bom_ir.format_type == "unknown":
        return {
            "verdict": Verdict.INVALID,
            "match_stats": {"total": 0},
            "traceability_map": [],
            "rule_results": [CrossRuleResult(
                rule_id="BOM-FORMAT-001",
                rule_name="BOM Format Detection",
                severity="error",
                passed=False,
                message="Could not detect BOM format. Supported: CycloneDX, SPDX.",
            ).to_dict()],
            "vex_format": vex_ir.format_type,
            "bom_format": "unknown",
        }

    # 2. Traceability Map 구축
    matches = _build_traceability_map(vex_ir, bom_ir)

    # 3. Cross-document rule 검증
    rule_results = []
    rule_results.extend(_rule_target_resolvability(matches))
    rule_results.extend(_rule_target_uniqueness(matches))
    rule_results.extend(_rule_identifier_consistency(matches, vex_ir, bom_ir))
    rule_results.extend(_rule_scope_overreach(matches, vex_ir, bom_ir))
    rule_results.extend(_rule_justification_bom_consistency(matches, vex_ir))

    # 4. Verdict 결정
    verdict = _determine_verdict(rule_results, matches)

    # 5. 통계 (rule_results 포함)
    stats = _compute_match_stats(matches, rule_results)

    return {
        "verdict": verdict,
        "match_stats": stats,
        "traceability_map": [m.to_dict() for m in matches],
        "rule_results": [r.to_dict() for r in rule_results],
        "vex_format": vex_ir.format_type,
        "bom_format": bom_ir.format_type,
    }