"""
CIM → 형식 변환기
CIM(Common Information Model)에서 OpenVEX, CycloneDX, CSAF로 변환
"""
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple, Set, Any
from .models import (
    CIM, Subject, Vulnerability, VEXStatement, VulnerabilityStatus,
    Justification, DocumentFormat, ConversionMetadata, ConversionOptions,
    TrackingTable, Identifier, CvssRating, Reference, Publisher, Metadata
)
from .utils import (
    dt_to_iso_z, ensure_urn_uuid, normalize_purl, classify_component_type,
    create_product_identification_helper, encode_structured_text,
    set_extension_field, get_extension_field, generate_bomlink,
    dedupe_components, now_utc, safe_str, dedupe_ratings, unique_list,
    filter_placeholder_ratings, simplify_product_id, normalize_identifier,
    dedupe_references
)
from .constants import (
    MAPPING_TABLE, justification_enum_to_openvex_str,
    justification_enum_to_cyclonedx_str, justification_enum_to_csaf_flag,
    map_openvex_justification_str_to_enum, get_cwe_name
)

# ===== 필드 순서 정의 =====
# OpenVEX v0.2.0 스키마 순서
OPENVEX_DOCUMENT_ORDER = [
    "@context", "@id", "author", "role", "timestamp", "last_updated", 
    "version", "tooling", "statements"
]

# 수정: OpenVEX statement 순서 - 사용자 BP 예제 기반
# not_affected: vulnerability → timestamp → products → status → justification → impact_statement
# affected: vulnerability → timestamp → products → status → status_notes → action_statement → action_statement_timestamp
# fixed: vulnerability → timestamp → products → status → status_notes
OPENVEX_STATEMENT_ORDER = [
    "vulnerability", "timestamp", "last_updated", "products", "status",
    "justification", "impact_statement", "status_notes",
    "action_statement", "action_statement_timestamp",
    "@id", "version", "supplier"
]

OPENVEX_VULNERABILITY_ORDER = ["@id", "name", "description", "aliases"]

# CycloneDX 1.7 스키마 순서
CYCLONEDX_DOCUMENT_ORDER = [
    "$schema", "bomFormat", "specVersion", "serialNumber", "version",
    "metadata", "components", "externalReferences", "vulnerabilities"
]

# CycloneDX vulnerability 순서 (사용자 예제 기반)
CYCLONEDX_VULNERABILITY_ORDER = [
    "id", "source", "ratings", "cwes", "description", "recommendation",
    "analysis", "affects", "references", "properties"
]

# CSAF 2.1 스키마 순서 (사용자 예제 기반)
CSAF_DOCUMENT_ORDER = ["$schema", "document", "product_tree", "vulnerabilities"]

CSAF_DOCUMENT_META_ORDER = [
    "category", "csaf_version", "distribution", "publisher", "title",
    "tracking", "notes", "references"
]

CSAF_TRACKING_ORDER = [
    "id", "status", "version", "initial_release_date", "current_release_date",
    "revision_history", "generator"
]

# 수정: CSAF vulnerability 순서 - threats 전에 flags
CSAF_VULNERABILITY_ORDER = [
    "cve", "title", "notes", "product_status", "flags", "threats",
    "remediations", "references", "metrics", "cwes"
]

def order_dict(d: Dict, order: List[str]) -> Dict:
    """지정된 순서에 따라 딕셔너리 키 재정렬. 알 수 없는 키는 끝에 배치."""
    result = {}
    # 지정된 순서로 키 추가
    for key in order:
        if key in d:
            result[key] = d[key]
    # 나머지 키 추가
    for key in d:
        if key not in result:
            result[key] = d[key]
    return result

def order_openvex_statement(stmt: Dict) -> Dict:
    """스키마에 따라 OpenVEX statement 필드 정렬."""
    # 먼저 vulnerability 객체 정렬
    if "vulnerability" in stmt and isinstance(stmt["vulnerability"], dict):
        stmt["vulnerability"] = order_dict(stmt["vulnerability"], OPENVEX_VULNERABILITY_ORDER)
    # 그 다음 statement 자체 정렬
    return order_dict(stmt, OPENVEX_STATEMENT_ORDER)

def order_openvex_document(doc: Dict) -> Dict:
    """스키마에 따라 OpenVEX 문서 필드 정렬."""
    # statements 정렬
    if "statements" in doc and isinstance(doc["statements"], list):
        doc["statements"] = [order_openvex_statement(s) for s in doc["statements"]]
    # document 정렬
    return order_dict(doc, OPENVEX_DOCUMENT_ORDER)

def order_csaf_vulnerability(vuln: Dict) -> Dict:
    """스키마에 따라 CSAF vulnerability 필드 정렬."""
    return order_dict(vuln, CSAF_VULNERABILITY_ORDER)

def order_csaf_document(doc: Dict) -> Dict:
    """스키마에 따라 CSAF 문서 필드 정렬."""
    # document 정렬 metadata
    if "document" in doc and isinstance(doc["document"], dict):
        # tracking 정렬
        if "tracking" in doc["document"] and isinstance(doc["document"]["tracking"], dict):
            doc["document"]["tracking"] = order_dict(doc["document"]["tracking"], CSAF_TRACKING_ORDER)
        doc["document"] = order_dict(doc["document"], CSAF_DOCUMENT_META_ORDER)
    
    # vulnerabilities 정렬
    if "vulnerabilities" in doc and isinstance(doc["vulnerabilities"], list):
        doc["vulnerabilities"] = [order_csaf_vulnerability(v) for v in doc["vulnerabilities"]]
    
    # 최상위 수준 정렬
    return order_dict(doc, CSAF_DOCUMENT_ORDER)

def order_cyclonedx_vulnerability(vuln: Dict) -> Dict:
    """스키마에 따라 CycloneDX vulnerability 필드 정렬."""
    return order_dict(vuln, CYCLONEDX_VULNERABILITY_ORDER)

def order_cyclonedx_document(doc: Dict) -> Dict:
    """스키마에 따라 CycloneDX 문서 필드 정렬."""
    # vulnerabilities 정렬
    if "vulnerabilities" in doc and isinstance(doc["vulnerabilities"], list):
        doc["vulnerabilities"] = [order_cyclonedx_vulnerability(v) for v in doc["vulnerabilities"]]
    
    # 최상위 수준 정렬
    return order_dict(doc, CYCLONEDX_DOCUMENT_ORDER)


# ========================================
# 헬퍼 함수
# ========================================

def _sanitize_product_id(ref: str) -> str:
    """
    product_id로 사용할 수 있도록 문자열 정제
    PURL이나 기타 ID에서 특수문자를 제거/변환
    """
    import re
    
    # pkg: 접두사 제거
    if ref.startswith("pkg:"):
        ref = ref[4:]
    
    # 특수문자를 하이픈으로 변환
    sanitized = re.sub(r'[/@:?#&=+]', '-', ref)
    
    # 연속 하이픈 제거
    sanitized = re.sub(r'-+', '-', sanitized)
    
    # 앞뒤 하이픈 제거
    sanitized = sanitized.strip('-')
    
    # 너무 길면 자르기
    if len(sanitized) > 50:
        sanitized = sanitized[:50]
    
    return sanitized.upper()


def _extract_name_from_purl(purl: str) -> str:
    """
    PURL에서 패키지 이름 추출
    예: pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1 → log4j-core
    """
    if not purl:
        return "Unknown"
    
    # pkg: 접두사 제거
    if purl.startswith("pkg:"):
        purl = purl[4:]
    
    # 버전(@) 이전까지만
    if '@' in purl:
        purl = purl.split('@')[0]
    
    # 쿼리(?) 제거
    if '?' in purl:
        purl = purl.split('?')[0]
    
    # 마지막 / 이후의 이름
    if '/' in purl:
        parts = purl.split('/')
        # namespace/name 구조면 마지막 부분
        return parts[-1]
    
    return purl


def _infer_component_type_from_purl(purl: str) -> str:
    """
    PURL scheme에서 CycloneDX component type 추론
    """
    if not purl or not purl.startswith("pkg:"):
        return "library"
    
    # pkg:type/... 에서 type 추출
    scheme_part = purl[4:]  # 'pkg:' 제거
    if '/' in scheme_part:
        purl_type = scheme_part.split('/')[0]
    else:
        return "library"
    
    # PURL type → CycloneDX component type 매핑 매핑
    type_mapping = {
        # 컨테이너
        "oci": "container",
        "docker": "container",
        # 라이브러리 (대부분의 패키지 매니저)
        "maven": "library",
        "npm": "library",
        "pypi": "library",
        "nuget": "library",
        "gem": "library",
        "cargo": "library",
        "golang": "library",
        "composer": "library",
        "cocoapods": "library",
        "swift": "library",
        "hex": "library",
        "pub": "library",
        "hackage": "library",
        "cpan": "library",
        # 시스템 패키지 → application
        "deb": "application",
        "rpm": "application",
        "apk": "application",
        "alpm": "application",
        # 기타
        "github": "library",
        "bitbucket": "library",
        "generic": "library",
    }
    
    return type_mapping.get(purl_type, "library")

class CIMToOpenVEX:
    def __init__(self, options: ConversionOptions, tracking_table: TrackingTable = None):
        self.options = options
        self.tracking_table = tracking_table or TrackingTable()

    def convert(self, cim: CIM) -> Dict:
        # extension_data에서 원본 @id 복원 시도
        doc_id = get_extension_field(cim.metadata, "openvex", "@id")
        
        if not doc_id:
            # original_id로 폴백
            doc_id = cim.metadata.original_id
            
        if not doc_id or not doc_id.startswith("http"):
            doc_id = f"https://openvex.dev/docs/public/vex-{cim.metadata.id}"

        # 충돌 방지를 위해 statements 통합
        # OpenVEX는 동일 product+vulnerability에 대해 다중 statements 불허
        statements = self._consolidate_statements(cim.statements)

        # 버전 가져오기: CIM 필드 먼저 시도, 그 다음 extension_data
        version = cim.metadata.document_version
        if version is None:
            version = get_extension_field(cim.metadata, "openvex", "version")
        if version is None:
            csaf_version = get_extension_field(cim.metadata, "csaf", "document.tracking.version")
            if csaf_version:
                try:
                    version = int(csaf_version)
                except (ValueError, TypeError):
                    version = 1
            else:
                version = 1

        # statements 생성
        raw_statements = [self._stmt(s, cim) for s in statements]
        
        # 수정 (이슈 1): 동일한 조합의 statements 병합 (vulnerability, status, justification, impact_statement)
        # OpenVEX 0.2.0은 하나의 statement에 여러 products 허용
        merged_statements = []
        merge_key_map = {}  # (vuln_name, status, justification, impact_statement) → statement_idx
        
        for stmt in raw_statements:
            vuln_name = stmt.get("vulnerability", {}).get("name", "")
            status = stmt.get("status", "")
            justification = stmt.get("justification", "")
            impact_statement = stmt.get("impact_statement", "")
            
            merge_key = (vuln_name, status, justification, impact_statement)
            
            if merge_key in merge_key_map:
                # 기존 statement에 products 병합
                existing_idx = merge_key_map[merge_key]
                existing_stmt = merged_statements[existing_idx]
                
                # 아직 없는 products 추가
                existing_product_ids = {p.get("@id") for p in existing_stmt.get("products", [])}
                for prod in stmt.get("products", []):
                    if prod.get("@id") not in existing_product_ids:
                        existing_stmt["products"].append(prod)
            else:
                # 새 병합된 statement 생성
                merge_key_map[merge_key] = len(merged_statements)
                merged_statements.append(stmt)
        
        raw_statements = merged_statements
        
        # 후처리: 동일 (product, vuln)에 대한 충돌 statements 제거
        # 가장 높은 우선순위 유지: FIXED > AFFECTED > NOT_AFFECTED > UNDER_INVESTIGATION
        status_priority = {
            "fixed": 0,
            "affected": 1,
            "not_affected": 2,
            "under_investigation": 3
        }
        
        # 각 (vuln_name, product_id) 조합에 대해 최적의 statement 추적
        best_by_pair = {}  # (vuln_name, product_id) → (priority, statement_idx, product_idx)
        
        for stmt_idx, stmt in enumerate(raw_statements):
            vuln_name = stmt.get("vulnerability", {}).get("name", "")
            status = stmt.get("status", "")
            priority = status_priority.get(status, 999)
            
            for prod_idx, prod in enumerate(stmt.get("products", [])):
                prod_id = prod.get("@id", "")
                key = (vuln_name, prod_id)
                
                if key not in best_by_pair:
                    best_by_pair[key] = (priority, stmt_idx, prod_idx)
                else:
                    existing_priority = best_by_pair[key][0]
                    if priority < existing_priority:
                        best_by_pair[key] = (priority, stmt_idx, prod_idx)
        
        # 충돌하지 않는 products만으로 statements 재구성
        # 원본 statement 구조 유지를 위해 (stmt_idx, status)로 그룹화
        products_to_keep = {}  # stmt_idx → 유지할 product_ids set
        for (vuln_name, prod_id), (priority, stmt_idx, prod_idx) in best_by_pair.items():
            if stmt_idx not in products_to_keep:
                products_to_keep[stmt_idx] = set()
            products_to_keep[stmt_idx].add(prod_id)
        
        # statements 필터링
        final_statements = []
        for stmt_idx, stmt in enumerate(raw_statements):
            if stmt_idx not in products_to_keep:
                continue
            
            # products 필터링
            kept_products = products_to_keep[stmt_idx]
            filtered_products = [p for p in stmt.get("products", []) 
                                if p.get("@id", "") in kept_products]
            
            if filtered_products:
                stmt_copy = stmt.copy()
                stmt_copy["products"] = filtered_products
                final_statements.append(stmt_copy)

        # ===== 작성자 네임스페이스 포함 구성 (이슈 5) =====
        # CycloneDX→OpenVEX: metadata.component.supplier.name 또는 manufacturer → author
        # 형식: "Name <namespace>" like "Spring Builds <spring-builds@users.noreply.github.com>"
        author = cim.metadata.publisher.name
        publisher_namespace = cim.metadata.publisher.namespace
        
        # 수정 (CycloneDX 이슈 4): CycloneDX 소스의 경우, metadata.component.supplier 또는 manufacturer를 author로 사용
        if cim.metadata.source_format == DocumentFormat.CYCLONEDX:
            metadata_component = get_extension_field(cim.metadata, "cyclonedx", "metadata.component")
            if metadata_component:
                # 우선순위: supplier.name > manufacturer.name > publisher.name
                supplier = metadata_component.get("supplier", {})
                manufacturer = metadata_component.get("manufacturer", {})
                if supplier and supplier.get("name"):
                    author = supplier["name"]
                    if supplier.get("url"):
                        publisher_namespace = supplier["url"][0] if isinstance(supplier["url"], list) else supplier["url"]
                elif manufacturer and manufacturer.get("name"):
                    author = manufacturer["name"]
                    if manufacturer.get("url"):
                        publisher_namespace = manufacturer["url"][0] if isinstance(manufacturer["url"], list) else manufacturer["url"]
        
        if publisher_namespace:
            author = f"{author} <{publisher_namespace}>"
        
        # ===== 타임스탬프 결정 (이슈 4) =====
        # CSAF→OpenVEX: timestamp = current_release_date
        # CycloneDX→OpenVEX: timestamp = firstIssued (statement level) 또는 metadata.timestamp
        timestamp_to_use = cim.metadata.created_at
        current_release_date = get_extension_field(cim.metadata, "csaf", "document.tracking.current_release_date")
        if current_release_date:
            try:
                timestamp_to_use = datetime.fromisoformat(current_release_date.replace('Z', '+00:00'))
            except:
                pass
        elif cim.metadata.last_updated:
            timestamp_to_use = cim.metadata.last_updated
        
        # ===== role 결정 (이슈 2) =====
        # CSAF→OpenVEX: publisher.category → role
        # CycloneDX→OpenVEX: role 필드 건너뛰기 (OpenVEX에서 선택사항, CycloneDX에는 동등 개념 없음)
        role = get_extension_field(cim.metadata, "openvex", "role")
        if not role:
            if cim.metadata.source_format == DocumentFormat.CYCLONEDX:
                # 수정: CycloneDX 소스에서 role 건너뛰기 (동등 개념 없음)
                role = None
            else:
                # 수정: CIM의 publisher.role 사용 (to_cim.py에서 CSAF publisher.category로 설정됨)
                if cim.metadata.publisher and cim.metadata.publisher.role:
                    role = cim.metadata.publisher.role
                else:
                    # extension_data로 폴백
                    publisher_category = get_extension_field(cim.metadata, "csaf", "document.publisher.category")
                    if publisher_category:
                        role = publisher_category
        
        # ===== tooling 결정 (이슈 6) =====
        # CSAF→OpenVEX: generator.engine.name + version → tooling
        # CycloneDX→OpenVEX: metadata.tools.name + version → tooling
        tooling = get_extension_field(cim.metadata, "openvex", "tooling")
        if not tooling:
            if cim.metadata.source_format == DocumentFormat.CYCLONEDX:
                # 수정 (CycloneDX 이슈 4): metadata.tools 사용 for CycloneDX source
                tools_data = get_extension_field(cim.metadata, "cyclonedx", "metadata.tools")
                if tools_data:
                    tool_name = None
                    tool_version = None
                    if isinstance(tools_data, dict):
                        # 새 형식: {"components": [...]}
                        tool_components = tools_data.get("components", [])
                        if tool_components:
                            first_tool = tool_components[0]
                            tool_name = first_tool.get("name")
                            tool_version = first_tool.get("version")
                    elif isinstance(tools_data, list) and tools_data:
                        # 이전 형식: [{"name": "...", "version": "..."}]
                        first_tool = tools_data[0]
                        tool_name = first_tool.get("name")
                        tool_version = first_tool.get("version")
                    
                    if tool_name and tool_version:
                        tooling = f"{tool_name} v{tool_version}"
                    elif tool_name:
                        tooling = tool_name
            else:
                # CSAF 소스
                generator = get_extension_field(cim.metadata, "csaf", "document.tracking.generator")
                if generator and isinstance(generator, dict):
                    engine = generator.get("engine", {})
                    if isinstance(engine, dict):
                        engine_name = engine.get("name", "")
                        engine_version = engine.get("version", "")
                        if engine_name and engine_version:
                            tooling = f"{engine_name} {engine_version}"
                        elif engine_name:
                            tooling = engine_name

        # ===== 특정 순서로 출력 구성 (OpenVEX 스키마 순서) =====
        # 순서: @context, @id, author, role, timestamp, last_updated, version, tooling, statements
        out = {}
        out["@context"] = get_extension_field(cim.metadata, "openvex", "@context", "https://openvex.dev/ns/v0.2.0")
        out["@id"] = doc_id
        out["author"] = author
        
        if role:
            out["role"] = role
        
        out["timestamp"] = dt_to_iso_z(timestamp_to_use)
        
        # 수정: OpenVEX 스키마에서 last_updated가 version 앞에 옴
        # 참고: CSAF→OpenVEX에서는 last_updated 추가 안 함 (Issue 4)
        last_updated_value = None
        if cim.metadata.source_format.value.lower() != "csaf":
            # 수정 (CycloneDX 이슈 3): CycloneDX는 lastUpdated 사용 from vulnerabilities
            if cim.metadata.source_format == DocumentFormat.CYCLONEDX:
                # 첫 번째 vulnerability의 extension_data에서 lastUpdated 가져오기
                for vuln in cim.vulnerabilities:
                    last_updated_val = get_extension_field(vuln, "cyclonedx", "analysis.lastUpdated")
                    if last_updated_val:
                        last_updated_value = last_updated_val
                        break
                # metadata.last_updated로 폴백
                if not last_updated_value and cim.metadata.last_updated:
                    last_updated_value = dt_to_iso_z(cim.metadata.last_updated)
            elif cim.metadata.last_updated:
                last_updated_value = dt_to_iso_z(cim.metadata.last_updated)
            else:
                last_updated_value = get_extension_field(cim.metadata, "openvex", "last_updated")
        
        if last_updated_value:
            out["last_updated"] = last_updated_value
        
        out["version"] = version
        
        # statements 전에 tooling 추가
        if tooling:
            out["tooling"] = tooling
        
        out["statements"] = final_statements
        
        # 가역 모드: 첫 번째 statement의 status_notes에 메타데이터 저장
        if self.options.reversible:
            lost_data = self._collect_lost_data(cim)
            
            # extension_data 수집
            extension_data = {}
            if cim.metadata.extension_data:
                extension_data["metadata"] = cim.metadata.extension_data
            for idx, subj in enumerate(cim.subjects):
                if subj.extension_data:
                    extension_data[f"subject_{idx}"] = subj.extension_data
            for vuln in cim.vulnerabilities:
                vuln_ext = {}
                if vuln.extension_data:
                    vuln_ext.update(vuln.extension_data)
                
                # references 저장 (OpenVEX에서 손실됨)
                if vuln.references:
                    refs_data = []
                    for r in vuln.references:
                        ref_dict = {"url": r.url}
                        if r.summary:
                            ref_dict["summary"] = r.summary
                        if r.category:
                            ref_dict["category"] = r.category
                        if r.id:
                            ref_dict["id"] = r.id
                        refs_data.append(ref_dict)
                    vuln_ext["references"] = refs_data
                
                # ratings 저장 (OpenVEX에서 손실됨)
                if vuln.ratings:
                    ratings_data = []
                    for r in vuln.ratings:
                        rating_dict = {}
                        if r.method:
                            rating_dict["method"] = r.method
                        if r.score is not None:
                            rating_dict["score"] = r.score
                        if r.severity:
                            rating_dict["severity"] = r.severity
                        if r.vector:
                            rating_dict["vector"] = r.vector
                        ratings_data.append(rating_dict)
                    vuln_ext["ratings"] = ratings_data
                
                # cwes 저장 (일부 경우 OpenVEX에서 손실됨)
                if vuln.cwes:
                    vuln_ext["cwes"] = vuln.cwes
                
                if vuln_ext:
                    extension_data[f"vulnerability_{vuln.id}"] = vuln_ext
            for idx, stmt in enumerate(cim.statements):
                if stmt.extension_data:
                    extension_data[f"statement_{idx}"] = stmt.extension_data
            
            # subject_mappings 수집
            subject_mappings = {}
            for subj in cim.subjects:
                if subj.original_id:
                    subject_mappings[subj.ref] = subj.original_id
                else:
                    subject_mappings[subj.ref] = subj.ref
            
            if lost_data or extension_data or subject_mappings:
                conv_meta = ConversionMetadata(
                    version="1.0",
                    source_format="CIM",
                    target_format="OpenVEX",
                    timestamp=dt_to_iso_z(now_utc()),
                    lost_data=lost_data,
                    extension_data=extension_data,
                    subject_mappings=subject_mappings
                )
                encoded = conv_meta.encode()
                
                # 첫 번째 statement의 status_notes에 저장
                if out["statements"]:
                    if "status_notes" not in out["statements"][0]:
                        out["statements"][0]["status_notes"] = encoded
                    else:
                        # 기존 notes 앞에 추가
                        out["statements"][0]["status_notes"] = encoded + " | " + out["statements"][0]["status_notes"]
                
                items_count = len(lost_data) + len(extension_data) + len(subject_mappings)
                print(f"\n[Reversible Mode] Stored {items_count} item(s) in status_notes:")
                if lost_data:
                    print(f"  - {len(lost_data)} lost fields (not recoverable)")
                else:
                    print(f"  - 0 lost fields (all data preserved!)")
                if extension_data:
                    print(f"  - {len(extension_data)} extension data entries (recoverable)")
                if subject_mappings:
                    print(f"  - {len(subject_mappings)} subject ID mappings (recoverable)")

        # 수정: OpenVEX v0.2.0 스키마에 따라 필드 순서 적용
        return order_openvex_document(out)
    
    def _collect_lost_data(self, cim: CIM) -> Dict[str, Any]:
        """OpenVEX 변환에서 손실될 데이터 수집 (최소화)"""
        return {}
    
    def _consolidate_statements(self, statements: List[VEXStatement]) -> List[VEXStatement]:
        """
        OpenVEX에서 충돌을 피하기 위해 statements 통합.
        OpenVEX는 (product @id, vulnerability) 쌍당 하나의 statement만 허용.
        
        전략:
        1. (vulnerability_id, effective_product_id)로 그룹화
        2. 다른 상태로 충돌하는 경우, 다른 @ids 생성
        3. 정말로 동일한 product/version이 다른 상태를 가지면, FIXED 유지 (가장 최신 정보)
        4. 우선순위: FIXED > AFFECTED > NOT_AFFECTED > UNDER_INVESTIGATION
        """
        # 각 subject_ref에 대해 유효한 product @id 구성
        def get_effective_product_id(subject_ref: str, subjects: List[Subject]) -> str:
            """이 subject에 대해 OpenVEX에서 사용될 @id 가져오기"""
            subj = next((s for s in subjects if s.ref == subject_ref), None)
            if not subj:
                return subject_ref
            
            # _stmt 메서드와 동일한 로직
            if ':v' in subject_ref:
                base_ref = subject_ref.split(':v')[0]
                version_suffix = subject_ref.split(':v', 1)[1]
                
                # 스코프 패키지 처리
                base_without_version = base_ref
                if '@' in base_ref:
                    last_at = base_ref.rfind('@')
                    if last_at > 0 and '/' in base_ref[last_at:]:
                        # @는 패키지 이름의 일부 (스코프)
                        base_without_version = base_ref
                    elif last_at > 0:
                        base_without_version = base_ref[:last_at]
                
                if version_suffix.startswith('vers:'):
                    # Range: 버전 없이 기본값 사용
                    return base_without_version
                else:
                    # 특정 버전
                    return f"{base_without_version}@{version_suffix}"
            elif subj.original_id:
                return subj.original_id
            else:
                return normalize_identifier(subject_ref)
        
        # 우선순위 - FIXED가 가장 높음 (가장 최신 정보)
        priority_order = {
            VulnerabilityStatus.FIXED: 0,
            VulnerabilityStatus.AFFECTED: 1,
            VulnerabilityStatus.NOT_AFFECTED: 2,
            VulnerabilityStatus.UNDER_INVESTIGATION: 3
        }
        
        # product_id 계산을 위한 subjects 목록 구성
        subjects = []
        for stmt in statements:
            for sref in stmt.subject_refs:
                # subjects 접근 필요 - 첫 번째 statement의 컨텍스트 사용
                # 제한사항이지만 통합에는 동작함
                pass
        
        # 인덱스: (vuln_id, product_@id) → (priority, statement)
        conflict_map = {}
        
        for stmt in statements:
            vuln_id = stmt.vulnerability_id
            priority = priority_order.get(stmt.status.value, 999)
            
            # 이 statement가 생성할 product @id 추적
            stmt_product_ids = set()
            for subject_ref in stmt.subject_refs:
                # 유효한 product @id 계산 (_stmt와 동일한 로직)
                if ':v' in subject_ref:
                    base_ref = subject_ref.split(':v')[0]
                    version_suffix = subject_ref.split(':v', 1)[1]
                    
                    # 버전 없는 기본값 가져오기 - 스코프 패키지 처리
                    # pkg:npm/@webframe/auth@1.0.0 → pkg:npm/@webframe/auth
                    if '@' in base_ref:
                        last_at = base_ref.rfind('@')
                        if last_at > 0 and '/' in base_ref[last_at:]:
                            # @는 패키지 이름의 일부 (스코프), 버전 없음
                            base_without_version = base_ref
                        elif last_at > 0:
                            base_without_version = base_ref[:last_at]
                        else:
                            base_without_version = base_ref
                    else:
                        base_without_version = base_ref
                    
                    if version_suffix.startswith('vers:'):
                        # Range: @id에 범위 표기 포함
                        # vers:semver/<1.0.1 → pkg:maven/product@range:<1.0.1
                        if '/' in version_suffix:
                            version_constraint = version_suffix.split('/', 1)[1]
                        else:
                            version_constraint = version_suffix
                        product_id = f"{base_without_version}@range:{version_constraint}"
                    else:
                        # 특정 버전: @id에 버전 포함
                        product_id = f"{base_without_version}@{version_suffix}"
                else:
                    product_id = subject_ref
                
                stmt_product_ids.add(product_id)
            
            # 각 product_id와 충돌 확인
            for product_id in stmt_product_ids:
                key = (vuln_id, product_id)
                
                if key not in conflict_map:
                    conflict_map[key] = (priority, stmt)
                else:
                    existing_priority = conflict_map[key][0]
                    if priority < existing_priority:
                        # 더 높은 우선순위 - 교체
                        conflict_map[key] = (priority, stmt)
        
        # 고유 statements 수집 (여러 products 포함 시 중복 가능)
        unique_stmts = set()
        for _, stmt in conflict_map.values():
            unique_stmts.add(id(stmt))  # 고유성 추적을 위해 객체 id 사용
        
        # 통합에서 살아남은 statements 반환
        result = [stmt for stmt in statements if id(stmt) in unique_stmts]
        
        return result

    def _stmt(self, stmt: VEXStatement, cim: CIM) -> Dict:
        products = []
        seen_ids = set()  # 중복 제거
        version_range_notes = []  # 버전 범위 노트 수집
        
        for sref in stmt.subject_refs:
            subj = next((s for s in cim.subjects if s.ref == sref), None)
            if subj:
                # product @id 결정
                # OpenVEX는 product+version 조합당 고유 @id 필요
                
                product_id = None
                
                # 버전 범위 subject인지 확인 (extension_data에서)
                is_version_range = get_extension_field(subj, "cyclonedx", "is_version_range")
                if is_version_range:
                    # 비표준 @range: 형식 대신 원본 ref 버전 사용
                    # OpenVEX 0.2.0은 @id에서 버전 범위를 지원하지 않음
                    # 원본 ref의 버전 사용 (예: pkg:npm/@webframe/auth@2.8.0)
                    base_ref = get_extension_field(subj, "cyclonedx", "base_ref")
                    version_range = get_extension_field(subj, "cyclonedx", "version_range")
                    
                    if base_ref:
                        # base_ref 직접 사용 (원본 버전 포함)
                        # 예: pkg:npm/@webframe/auth@2.8.0
                        product_id = base_ref
                    else:
                        # 폴백: sref에서 base 추출
                        product_id = sref.split(':range:')[0] if ':range:' in sref else sref
                    
                    # status_notes용 버전 범위 수집 (@id에는 포함 안 함)
                    # 원본 범위 정보를 @id가 아닌 필드에 보존
                    # 수정됨 (CycloneDX 이슈 2, 4): 올바른 레이블을 위해 원본 version_status 사용
                    if version_range:
                        # extension_data에서 원본 version_status 가져오기 (CycloneDX에서)
                        original_version_status = get_extension_field(subj, "cyclonedx", "version_status")
                        
                        # 올바른 형식을 위해 각 버전 범위 노트 뒤에 쉼표 추가
                        if original_version_status == "affected":
                            # 이 범위는 영향받는 버전 포함
                            if stmt.status.value == VulnerabilityStatus.FIXED:
                                # affected 범위를 가진 FIXED statement = "이전에 영향받음"
                                version_range_notes.append(f"Affected versions: {version_range},")
                            else:
                                version_range_notes.append(f"Affected versions: {version_range},")
                        elif original_version_status in ["unaffected", "not_affected"]:
                            # 이 범위는 영향받지 않는/수정된 버전 포함
                            if stmt.status.value == VulnerabilityStatus.FIXED:
                                version_range_notes.append(f"Fixed versions: {version_range},")
                            else:
                                version_range_notes.append(f"Unaffected versions: {version_range},")
                        else:
                            # 폴백: statement 상태 기반 로직
                            if stmt.status.value == VulnerabilityStatus.AFFECTED:
                                version_range_notes.append(f"Affected versions: {version_range},")
                            elif stmt.status.value == VulnerabilityStatus.FIXED:
                                version_range_notes.append(f"Fixed versions: {version_range},")
                            else:
                                version_range_notes.append(f"Unaffected versions: {version_range},")
                
                # 버전별 subject인지 확인 (ref에 :v 포함)
                elif ':v' in sref:
                    # CycloneDX versions 배열에서 온 버전별 subject
                    # 예시: pkg:maven/product@1.0.0:vvers:semver/<1.0.1
                    
                    # base ref와 버전 추출
                    base_ref = sref.split(':v')[0]
                    version_suffix = sref.split(':v', 1)[1]
                    
                    # 버전 없는 기본 패키지 가져오기 - 스코프 패키지 처리를 위해 rfind 사용
                    # pkg:npm/@webframe/auth@1.0.0 → pkg:npm/@webframe/auth
                    if '@' in base_ref:
                        # 마지막 @ 찾기 (버전 구분자)
                        last_at = base_ref.rfind('@')
                        # 이 @가 스코프 패키지용인지 확인 (@webframe 같은)
                        # 앞에 /가 있는지 확인
                        if last_at > 0 and '/' in base_ref[last_at:]:
                            # @는 패키지 이름의 일부 (스코프), base에 버전 없음
                            base_without_version = base_ref
                        elif last_at > 0:
                            # @는 버전 구분자
                            base_without_version = base_ref[:last_at]
                        else:
                            base_without_version = base_ref
                    else:
                        base_without_version = base_ref
                    
                    # 범위의 경우 범위 표기법으로 설명적인 @id 생성
                    if version_suffix.startswith('vers:'):
                        # 범위 형식: vers:semver/<1.0.1
                        # 다음처럼 @id 생성: pkg:maven/com.acme/product@range:<1.0.1
                        # vers: 형식에서 버전 제약 추출
                        # vers:semver/<1.0.1 → <1.0.1
                        # vers:semver/>=2.0.0|<2.3.0 → >=2.0.0|<2.3.0
                        
                        range_spec = version_suffix  # vers:semver/<1.0.1
                        
                        # vers:scheme/ 이후의 버전 부분만 추출
                        if '/' in range_spec:
                            version_constraint = range_spec.split('/', 1)[1]  # <1.0.1
                        else:
                            version_constraint = range_spec
                        
                        # 범위 표기법으로 @id 생성
                        product_id = f"{base_without_version}@range:{version_constraint}"
                    else:
                        # 특정 버전: v1.0.1
                        # 해당 버전으로 @id 생성: pkg:maven/com.acme/product@1.0.1
                        product_id = f"{base_without_version}@{version_suffix}"
                else:
                    # 버전별이 아님
                    # 수정됨 (CSAF 이슈 1): 가능하면 PURL을 @id로 사용해야 함
                    # @id 결정을 위해 먼저 PURL 수집
                    purls_from_identifiers = []
                    if subj.identifiers:
                        for ident in subj.identifiers:
                            if ident.type == "purl" and ident.value:
                                purls_from_identifiers.append(ident.value)
                    
                    # @id는 항상 원본 ref 사용 (참조 무결성 유지)
                    if subj.original_id:
                        product_id = subj.original_id
                    else:
                        product_id = subj.ref

                # 중복 확인
                if product_id in seen_ids:
                    continue
                seen_ids.add(product_id)

                # 다중 PURL 처리
                purls_list = []
                cpe_value = None
                cpe23_value = None
                
                if subj.identifiers:
                    for ident in subj.identifiers:
                        if ident.type == "purl" and ident.value:
                            purls_list.append(ident.value)
                        elif ident.type == "cpe" and ident.value:
                            if ident.value.startswith("cpe:2.3:"):
                                cpe23_value = ident.value
                            else:
                                cpe_value = ident.value
                
                # 수정됨 (CycloneDX 이슈 2): PURL 버전이 @id 버전과 일치하도록 보장
                # @id가 특정 버전을 가지면 (예: pkg:npm/@webframe/auth@2.8.1),
                # identifiers.purl도 base ref 버전이 아닌 해당 버전을 반영해야 함
                def update_purl_version(purl: str, target_version: str) -> str:
                    """대상 버전과 일치하도록 PURL 업데이트."""
                    if not purl or not target_version:
                        return purl
                    # 범위 버전 건너뛰기
                    if target_version.startswith("vers:") or target_version.startswith("range:"):
                        return purl
                    if '@' in purl:
                        # 버전 없는 base purl 추출
                        last_at = purl.rfind('@')
                        # 스코프 패키지 확인 (예: @webframe/auth)
                        # @ 뒤에 /가 있으면 스코프이지 버전이 아님
                        slash_after_at = purl.find('/', last_at) if last_at >= 0 else -1
                        if slash_after_at > last_at:
                            # @는 스코프의 일부, purl에 버전 없음 - 버전 추가
                            return f"{purl}@{target_version}"
                        else:
                            # @가 버전 구분자 - 교체
                            base_purl = purl[:last_at]
                            return f"{base_purl}@{target_version}"
                    else:
                        return f"{purl}@{target_version}"
                
                # 버전이 있는 ID인 경우 product_id에서 버전 추출
                target_version = None
                if '@' in product_id and not product_id.startswith('pkg:'):
                    # "product@1.0.0" 같은 단순 버전 ID
                    target_version = product_id.split('@')[-1]
                elif product_id.startswith('pkg:') and '@' in product_id:
                    # PURL 형식 - 버전 추출
                    last_at = product_id.rfind('@')
                    slash_after_at = product_id.find('/', last_at) if last_at >= 0 else -1
                    if slash_after_at == -1 or slash_after_at < last_at:
                        # 버전은 마지막 @ 이후
                        target_version = product_id[last_at + 1:].split('?')[0]  # qualifier 제거
                
                # 수정됨 (CycloneDX 이슈 2): subject.version도 사용 가능하면 사용
                if not target_version and subj.version:
                    # @id에 버전이 없으면 subject의 버전 사용
                    target_version = subj.version
                
                # 단일 product 생성 (다중 PURL이어도 @id는 원본 유지)
                product_entry = {"@id": product_id}
                
                identifiers = {}
                if purls_list:
                    corrected_purl = purls_list[0]
                    if target_version:
                        corrected_purl = update_purl_version(purls_list[0], target_version)
                    identifiers["purl"] = corrected_purl
                else:
                    # PURL이 없으면 Subject 정보로 자동 생성
                    generated_purl = self._generate_purl_for_openvex(
                        product_id=product_id,
                        name=subj.name if subj else None,
                        version=target_version or (subj.version if subj else None)
                    )
                    if generated_purl:
                        identifiers["purl"] = generated_purl
                
                if cpe23_value:
                    identifiers["cpe23"] = cpe23_value
                if cpe_value:
                    identifiers["cpe"] = cpe_value
                
                if identifiers:
                    product_entry["identifiers"] = identifiers
                
                # 가능하면 해시 추가
                if subj.hashes:
                    hashes = {}
                    for hash_info in subj.hashes:
                        alg = hash_info.get("algorithm")
                        val = hash_info.get("value")
                        if alg and val:
                            hashes[alg] = val
                    if hashes:
                        product_entry["hashes"] = hashes

                products.append(product_entry)
            else:
                if sref not in seen_ids:
                    seen_ids.add(sref)
                    product_entry = {"@id": sref}
                    
                    generated_purl = self._generate_purl_for_openvex(
                        product_id=sref,
                        name=None,
                        version=None
                    )
                    if generated_purl:
                        product_entry["identifiers"] = {"purl": generated_purl}
                    
                    products.append(product_entry)

        # description과 함께 vulnerability 객체 구성
        # 필드 순서는 @id, name, description, aliases (BP 준수)
        vuln_data = next((v for v in cim.vulnerabilities if v.id == stmt.vulnerability_id), None)
        
        vuln_obj = {}
        
        # 1. @id 먼저 (source URL에서 또는 CVE의 경우 자동 생성)
        source_url = None
        if vuln_data and vuln_data.references:
            for ref in vuln_data.references:
                if ref.url:
                    source_url = ref.url
                    break
        
        # source URL 없으면 CVE ID에 대해 NVD URL 자동 생성
        if not source_url and stmt.vulnerability_id.startswith("CVE-"):
            source_url = f"https://nvd.nist.gov/vuln/detail/{stmt.vulnerability_id}"
        
        if source_url:
            vuln_obj["@id"] = source_url
        
        # 2. name 두 번째
        vuln_obj["name"] = stmt.vulnerability_id
        
        # 3. description 세 번째
        if vuln_data and vuln_data.description:
            vuln_obj["description"] = vuln_data.description
        
        # 4. aliases 마지막
        if vuln_data and vuln_data.aliases:
            vuln_obj["aliases"] = vuln_data.aliases

        # Statement 타임스탬프 처리
        # CSAF의 경우: 기본값으로 initial_release_date 사용하되, revision_history에서
        #             CVE별 날짜 확인 (이후 리비전에서 추가된 CVE)
        # CycloneDX의 경우: 가능하면 firstIssued 사용, 그렇지 않으면 metadata.timestamp
        stmt_timestamp = stmt.timestamp
        
        if cim.metadata.source_format == DocumentFormat.CSAF:
            initial_release_date = get_extension_field(cim.metadata, "csaf", "document.tracking.initial_release_date")
            revision_history = get_extension_field(cim.metadata, "csaf", "document.tracking.revision_history")
            
            # 기본값은 initial_release_date
            if initial_release_date:
                try:
                    stmt_timestamp = datetime.fromisoformat(initial_release_date.replace('Z', '+00:00'))
                except:
                    pass
            
            # CVE별 타임스탬프를 위해 revision_history 확인
            # revision summary (number > 1)에서 CVE가 언급되면 해당 리비전의 날짜 사용
            if revision_history and stmt.vulnerability_id:
                cve_id = stmt.vulnerability_id  # 예: "CVE-2025-20006"
                for revision in revision_history:
                    rev_number = revision.get("number")
                    rev_summary = revision.get("summary", "")
                    rev_date = revision.get("date")
                    
                    # 리비전 1 건너뛰기 (초기 릴리스는 initial_release_date 사용)
                    if rev_number and rev_date:
                        try:
                            rev_num_int = int(str(rev_number).split('.')[0])
                            if rev_num_int > 1 and cve_id in rev_summary:
                                # 이 CVE가 이 리비전에서 추가/수정됨
                                stmt_timestamp = datetime.fromisoformat(rev_date.replace('Z', '+00:00'))
                                break
                        except (ValueError, TypeError):
                            pass
        elif cim.metadata.source_format == DocumentFormat.CYCLONEDX:
            # 수정됨 (CycloneDX 이슈 3): 가능하면 타임스탬프에 firstIssued 사용
            # 그렇지 않으면 metadata.timestamp로 폴백
            if vuln_data:
                first_issued = get_extension_field(vuln_data, "cyclonedx", "analysis.firstIssued")
                if first_issued:
                    try:
                        stmt_timestamp = datetime.fromisoformat(first_issued.replace('Z', '+00:00'))
                    except:
                        pass
            # firstIssued 없으면 stmt_timestamp는 stmt.timestamp 유지 (metadata.timestamp에서 온 것)

        result = {
            "vulnerability": vuln_obj,
            "timestamp": dt_to_iso_z(stmt_timestamp),
            "products": products,
            "status": stmt.status.value.value
        }
        
        # 상태 변환 추적
        self.tracking_table.add(
            source_field="CIM.statement.status.value",
            source_value=str(stmt.status.value),
            target_field="statements.status",
            target_value=stmt.status.value.value,
            rule=f"{stmt.status.value} → OpenVEX status",
            status="TRANSFORMED" if stmt.status.value.value != str(stmt.status.value).split('.')[-1].lower() else "OK"
        )

        # not_affected 상태에 대해 justification 추가
        if stmt.status.value == VulnerabilityStatus.NOT_AFFECTED:
            # 수정됨 (CycloneDX 이슈 1): false_positive 처리
            is_false_positive = stmt.status.original_state == "false_positive"
            
            # CycloneDX 소스의 false_positive는 justification 완전히 건너뛰기
            # 원래 의미 보존을 위해 impact_statement만 사용
            # (false_positive는 "코드가 없다"가 아니라 "이 CVE가 적용되지 않는다"를 의미)
            if cim.metadata.source_format == DocumentFormat.CYCLONEDX and is_false_positive:
                # CycloneDX false_positive의 경우 justification 건너뛰기
                # 대신 impact_statement 사용
                if stmt.status.impact_statement:
                    result["impact_statement"] = stmt.status.impact_statement
                else:
                    result["impact_statement"] = "This CVE was determined to be a false positive for this product."
            else:
                # false_positive가 아니거나 CycloneDX 소스가 아닌 경우 일반 justification 처리
                # 우선순위 1: custom_justification에서 유효한 원본 OpenVEX justification 사용
                # 우선순위 2: justification enum 사용
                # 우선순위 3: false_positive(비CycloneDX)의 경우 식별자 기반 결정
                justification_to_use = None
                
                if stmt.status.custom_justification:
                    # custom_justification이 유효한 OpenVEX justification인지 확인 (cyclonedx: 접두사 없이)
                    custom_just = stmt.status.custom_justification
                    if not custom_just.startswith("cyclonedx:") and custom_just != "false_positive":
                        # OpenVEX justification임 - 직접 사용 (원본 보존)
                        valid_openvex_just = [
                            "component_not_present",
                            "vulnerable_code_not_present",
                            "vulnerable_code_not_in_execute_path",
                            "vulnerable_code_cannot_be_controlled_by_adversary",
                            "inline_mitigations_already_exist"
                        ]
                        if custom_just in valid_openvex_just:
                            justification_to_use = custom_just
                
                # enum 변환으로 폴백
                if not justification_to_use and stmt.status.justification:
                    justification_to_use = justification_enum_to_openvex_str(stmt.status.justification)
                
                # justification 없는 CSAF 소스 false_positive의 경우,
                # 제품이 purl/cpe 식별자를 가지는지 기반으로 결정
                if is_false_positive and not justification_to_use:
                    # 어떤 제품이 purl/cpe 식별자를 가지는지 확인
                    has_purl_or_cpe = False
                    for prod in products:
                        identifiers = prod.get("identifiers", {})
                        if identifiers.get("purl") or identifiers.get("cpe23") or identifiers.get("cpe"):
                            has_purl_or_cpe = True
                            break
                    
                    if has_purl_or_cpe:
                        justification_to_use = "vulnerable_code_not_present"
                    else:
                        justification_to_use = "component_not_present"
                
                if justification_to_use:
                    result["justification"] = justification_to_use
                    # justification 추적
                    self.tracking_table.add(
                        source_field="CIM.statement.status.justification",
                        source_value=str(stmt.status.custom_justification or stmt.status.justification or "false_positive"),
                        target_field="statements.justification",
                        target_value=result["justification"],
                        rule="Justification mapping",
                        status="TRANSFORMED"
                    )
                
                # 중요: OpenVEX는 not_affected에 대해 justification 또는 impact_statement 중 하나 필요
                # 둘 다 없으면 기본 impact_statement 추가
                if not justification_to_use and not stmt.status.impact_statement:
                    if is_false_positive:
                        result["impact_statement"] = "This CVE was determined to be a false positive for this product."
                    else:
                        result["impact_statement"] = "This product is not affected by this vulnerability."

        # impact_statement 추가 (not_affected 상태에만)
        # 다른 상태의 경우 impact_statement는 OpenVEX 스펙에 없음
        if stmt.status.value == VulnerabilityStatus.NOT_AFFECTED and stmt.status.impact_statement:
            result["impact_statement"] = stmt.status.impact_statement

        # action_statement 추가 (affected 상태에만)
        action_parts = []
        seen_action_content = set()
        
        def normalize_action_text(text):
            """중복 감지를 위해 action 텍스트 정규화.
            카테고리 접두사를 제거하고 핵심 내용 추출."""
            if not text:
                return ""
            # 카테고리 접두사 제거 (예: "vendor_fix: ", "workaround: ")
            for prefix in ["vendor_fix: ", "workaround: ", "mitigation: ", "no_fix_planned: ", "none_available: "]:
                if text.lower().startswith(prefix.lower()):
                    text = text[len(prefix):]
                    break
            # [Patch: ...] 같은 URL 접미사 제거
            if " [Patch:" in text:
                text = text.split(" [Patch:")[0]
            return text.strip().lower()

        # AFFECTED 상태에만
        if stmt.status.value == VulnerabilityStatus.AFFECTED:
            # 기존 action_statement (CSAFToCIM remediations_map에서)
            if stmt.action_statement:
                # 줄바꿈으로 분리하고 각 부분 추가
                for line in stmt.action_statement.split('\n'):
                    line = line.strip()
                    if line:
                        normalized = normalize_action_text(line)
                        if normalized and normalized not in seen_action_content:
                            action_parts.append(line)
                            seen_action_content.add(normalized)

            # remediation을 action_statement로 추가 (아직 추가되지 않은 경우에만)
            if vuln_data and vuln_data.remediations:
                for rem in vuln_data.remediations:
                    category = rem.get("category", "")
                    details = rem.get("details", "")

                    # 이 remediation이 이 statement의 어떤 제품에 적용되는지 확인
                    rem_product_ids = set(rem.get("product_ids", []))
                    stmt_product_ids = set(stmt.subject_refs)

                    # 일치 조건:
                    # 1. rem_product_ids가 비어있음 (모든 제품에 적용)
                    # 2. 직접 일치: rem_product_id in stmt_product_ids
                    # 3. 부분 일치: rem_product_id가 어떤 stmt_product_id에 포함됨
                    matches = False
                    if not rem_product_ids:
                        matches = True
                    else:
                        # 직접 일치 확인
                        if rem_product_ids.intersection(stmt_product_ids):
                            matches = True
                        else:
                            # 부분 일치 확인 (rem_product_id가 stmt_product_id에 포함됨)
                            for rem_pid in rem_product_ids:
                                for stmt_pid in stmt_product_ids:
                                    if rem_pid in stmt_pid:
                                        matches = True
                                        break
                                if matches:
                                    break

                    if matches:
                        # action statement 구성: "category: details" 형식
                        # vendor_fix, mitigation, workaround만 포함
                        if category in ["vendor_fix", "mitigation", "workaround"]:
                            if category and details:
                                action_text = f"{category}: {details}"
                            elif details:
                                action_text = details
                            else:
                                continue
                            
                            # 수정됨 (이슈 3): 가능하면 URL을 [Patch: ...]로 추가
                            rem_url = rem.get("url")
                            if rem_url:
                                action_text += f" [Patch: {rem_url}]"
                            
                            # 정규화된 텍스트로 중복 확인
                            normalized = normalize_action_text(action_text)
                            if normalized and normalized not in seen_action_content:
                                action_parts.append(action_text)
                                seen_action_content.add(normalized)

            # 수집된 parts가 있으면 action_statement 추가 (줄바꿈으로 연결)
            # OpenVEX는 affected 상태에 action_statement 필요
            if action_parts:
                result["action_statement"] = "\n".join(action_parts)
            else:
                # resolved_with_pedigree 상태에서 왔는지 확인
                if stmt.status.original_state == "resolved_with_pedigree":
                    result["action_statement"] = "Update to a newer version that includes the fix"
                elif stmt.status.original_state == "exploitable":
                    result["action_statement"] = "Apply available patches or mitigations"
                else:
                    # affected 상태의 기본 action_statement
                    result["action_statement"] = "No remediation information available"

        # UNDER_INVESTIGATION 상태에 대해 impact_statement/action_statement 추가
        # 특수: in_triage (UNDER_INVESTIGATION)의 경우 impact_statement 필드 건너뛰기
        # and put all information in status_notes to avoid duplication
        if stmt.status.value == VulnerabilityStatus.UNDER_INVESTIGATION:
            # UNDER_INVESTIGATION 상태에 impact_statement 추가하지 않음
            # 모든 정보는 status_notes로 이동
            
            # 가능하면 action_statement 추가
            if stmt.action_statement and not result.get("action_statement"):
                result["action_statement"] = stmt.action_statement

        # JSON 덤프 대신 사람이 읽기 쉬운 status_notes 사용
        # 또는 기본 모드에서도 affected/fixed/under_investigation에 대해 impact_statement 보존
        notes_parts = []
        
        # 버전 범위 subject의 경우 범위 정보만 표시 (impact_statement 중복 없음)
        # impact_statement는 범위가 아닌 버전에만 적용
        has_version_range = len(version_range_notes) > 0
        
        # 수정됨 (CycloneDX 이슈 6): resolved/resolved_with_pedigree의 경우 analysis.detail을 먼저 추가
        if cim.metadata.source_format == DocumentFormat.CYCLONEDX:
            if stmt.status.original_state in ["resolved", "resolved_with_pedigree"]:
                if vuln_data:
                    analysis_detail = get_extension_field(vuln_data, "cyclonedx", "analysis.detail")
                    if analysis_detail:
                        notes_parts.append(analysis_detail + ",")
        
        # analysis.detail 다음에 버전 범위 노트 추가
        notes_parts.extend(version_range_notes)
        
        if self.options.use_free_text_encoding:
            vuln = next((v for v in cim.vulnerabilities if v.id == stmt.vulnerability_id), None)
            if vuln:
                # 원본 CycloneDX 상태 노트 추가 (resolved 제외 - 이미 detail 추가함)
                if stmt.status.original_state:
                    if stmt.status.original_state == "false_positive":
                        notes_parts.append("Note: This was identified as a false positive in the original assessment.")
                    elif stmt.status.original_state == "resolved_with_pedigree":
                        # 실제 detail을 이미 추가했으므로 일반 노트 건너뛰기
                        pass

                # 버전 범위가 아닌 경우에만 impact_statement 추가
                # 버전 범위 subject는 범위 정보만 status_notes에 사용
                # 비범위 subject (수정된 버전)는 detail/impact_statement 가져옴
                if not has_version_range:
                    # AFFECTED 상태의 경우 impact_statement를 status_notes로 보존
                    if stmt.status.value == VulnerabilityStatus.AFFECTED and stmt.status.impact_statement:
                        notes_parts.append(stmt.status.impact_statement)
                    
                    # FIXED 상태의 경우 impact_statement를 status_notes로 보존
                    # 단 analysis.detail에서 이미 추가한 경우 건너뛰기 (CycloneDX resolved)
                    if stmt.status.value == VulnerabilityStatus.FIXED and stmt.status.impact_statement:
                        if stmt.status.original_state not in ["resolved", "resolved_with_pedigree"]:
                            notes_parts.append(stmt.status.impact_statement)
                    
                    # UNDER_INVESTIGATION 상태의 경우 impact_statement를 status_notes로 보존
                    if stmt.status.value == VulnerabilityStatus.UNDER_INVESTIGATION and stmt.status.impact_statement:
                        notes_parts.append(stmt.status.impact_statement)

                # 수정됨 (이슈 4): 파이프 구분 형식 대신 자연어 문장 사용
                # status_notes는 데이터베이스 형식이 아닌 사람이 읽을 수 있는 노트용
                
                # CVSS 요약을 자연어로 추가
                if vuln.ratings:
                    ratings_filtered = filter_placeholder_ratings([{
                        "method": r.method, "score": r.score, "severity": r.severity, "vector": r.vector
                    } for r in vuln.ratings])
                    if ratings_filtered:
                        rating = ratings_filtered[0]
                        severity = (rating.get('severity') or 'unknown').upper()
                        score = rating.get('score') or 'N/A'
                        notes_parts.append(f"This vulnerability has a {severity} severity rating with a CVSS score of {score}.")

                # CWE 요약을 자연어로 추가
                if vuln.cwes:
                    if len(vuln.cwes) == 1:
                        notes_parts.append(f"This vulnerability is classified as CWE-{vuln.cwes[0]}.")
                    elif len(vuln.cwes) <= 3:
                        cwes_str = ", ".join([f"CWE-{c}" for c in vuln.cwes])
                        notes_parts.append(f"Related weaknesses include {cwes_str}.")
                    else:
                        cwes_str = ", ".join([f"CWE-{c}" for c in vuln.cwes[:3]])
                        notes_parts.append(f"Related weaknesses include {cwes_str} and {len(vuln.cwes)-3} others.")

                # 참조 정보를 자연어로 추가
                if vuln.references:
                    # 주요 출처 확인 (category == "source")
                    primary_source = next((r for r in vuln.references if r.category == "source"), None)
                    if primary_source and primary_source.url:
                        source_name = primary_source.summary or "Primary source"
                        notes_parts.append(f"{source_name} is available at {primary_source.url}.")
                    elif len(vuln.references) == 1:
                        ref = vuln.references[0]
                        ref_name = ref.summary or "More information"
                        notes_parts.append(f"{ref_name} is available at {ref.url}.")
                    else:
                        notes_parts.append(f"There are {len(vuln.references)} references available for this vulnerability.")
        else:
            # 기본 모드: affected/fixed/under_investigation에 대해 여전히 impact_statement 보존
            # 버전 범위가 아닌 경우에만
            if not has_version_range:
                if stmt.status.value == VulnerabilityStatus.AFFECTED and stmt.status.impact_statement:
                    notes_parts.append(stmt.status.impact_statement)
                elif stmt.status.value == VulnerabilityStatus.FIXED and stmt.status.impact_statement:
                    if stmt.status.original_state not in ["resolved", "resolved_with_pedigree"]:
                        notes_parts.append(stmt.status.impact_statement)
                elif stmt.status.value == VulnerabilityStatus.UNDER_INVESTIGATION and stmt.status.impact_statement:
                    notes_parts.append(stmt.status.impact_statement)
        
        # CycloneDX 소스에서 not_affected + will_not_fix인 경우 recommendation을 status_notes에 추가
        if cim.metadata.source_format == DocumentFormat.CYCLONEDX:
            if stmt.status.value == VulnerabilityStatus.NOT_AFFECTED:
                # statement의 extension_data에서 will_not_fix response 확인
                # 참고: cyclonedx_response는 namespace 접두사 없이 저장됨
                original_response = stmt.extension_data.get("cyclonedx_response") if hasattr(stmt, 'extension_data') else None
                if original_response:
                    # list 또는 string에 will_not_fix가 포함되어 있는지 확인
                    has_will_not_fix = False
                    if isinstance(original_response, list):
                        has_will_not_fix = "will_not_fix" in original_response
                    elif isinstance(original_response, str):
                        has_will_not_fix = "will_not_fix" in original_response
                    
                    if has_will_not_fix:
                        # vuln의 extension_data에서 recommendation 가져오기 (namespace 포함)
                        recommendation = get_extension_field(vuln_data, "cyclonedx", "recommendation") if vuln_data else None
                        if recommendation:
                            notes_parts.append(f"Recommendation: {recommendation}")
        
        if notes_parts:
            # 수정됨 (이슈 4): 파이프 구분자 대신 자연스러운 문장 흐름 사용
            result["status_notes"] = " ".join(notes_parts)
        
        # OpenVEX extension_data 필드 복원
        # Vulnerability 필드
        if vuln_data:
            vuln_id_ext = get_extension_field(vuln_data, "openvex", "vulnerability.@id")
            if vuln_id_ext:
                result["vulnerability"]["@id"] = vuln_id_ext
            
            aliases = get_extension_field(vuln_data, "openvex", "vulnerability.aliases")
            if aliases:
                result["vulnerability"]["aliases"] = aliases
        
        # Statement 필드
        # status_notes (원본, 생성된 것이 아님)
        # 우선순위: 원본 status_notes 먼저 복원
        status_notes_ext = get_extension_field(stmt, "openvex", "status_notes")
        if status_notes_ext:
            # 원본 status_notes가 우선
            if "status_notes" in result:
                # 원본과 생성된 것을 자연스러운 문장 흐름으로 결합
                result["status_notes"] = status_notes_ext + " " + result["status_notes"]
            else:
                result["status_notes"] = status_notes_ext
        
        # supplier
        supplier = get_extension_field(stmt, "openvex", "supplier")
        if supplier:
            result["supplier"] = supplier
        
        # Product 식별자 복원
        for prod in result.get("products", []):
            prod_id = prod.get("@id")
            if prod_id:
                # 참고: OpenVEX 스펙 v0.2.0은 identifiers 필드를 지원하지 않음
                # Product 식별은 @id를 통해서만 수행됨
                pass

        # OpenVEX 스펙 순서에 맞게 필드 재정렬 (BP 예제)
        # 순서: vulnerability, timestamp, products, status, justification, impact_statement, status_notes, action_statement, action_statement_timestamp, supplier
        field_order = ["vulnerability", "timestamp", "last_updated", "products", "status", "justification", "impact_statement", "status_notes", "action_statement", "action_statement_timestamp", "supplier"]
        ordered_result = {}
        for field in field_order:
            if field in result:
                ordered_result[field] = result[field]
        # 순서 목록에 없는 나머지 필드 추가
        for field in result:
            if field not in ordered_result:
                ordered_result[field] = result[field]

        return ordered_result
    
    def _generate_purl_for_openvex(self, product_id: str, name: str, version: str) -> str:
        """
        PURL이 없는 제품에 대해 PURL 자동 생성
        """
        import re
        
        def normalize(n: str) -> str:
            if not n:
                return ""
            n = n.lower()
            n = re.sub(r':\s*[\d.]+.*$', '', n)
            n = re.sub(r'[^a-z0-9]+', '-', n)
            n = re.sub(r'-+', '-', n)
            return n.strip('-')
        
        source_name = name or product_id or ""
        if not source_name:
            return None
        
        extracted_version = version
        if not extracted_version:
            match = re.search(r'[:\s]+([\d]+\.[\d.]+[a-zA-Z0-9.-]*)$', source_name)
            if match:
                extracted_version = match.group(1)
                source_name = source_name[:match.start()]
        
        normalized = normalize(source_name)
        if not normalized:
            return None
        
        purl = f"pkg:generic/{normalized}"
        
        if extracted_version:
            clean_version = re.sub(r'[^a-zA-Z0-9.\-_+]', '', extracted_version)
            if clean_version:
                purl += f"@{clean_version}"
        
        return purl


class CIMToCycloneDX:
    def __init__(self, options: ConversionOptions, tracking_table: TrackingTable = None):
        self.options = options
        self.tracking_table = tracking_table or TrackingTable()

    def convert(self, cim: CIM) -> Dict:
        # 가능하면 원본 components 복원 (완벽한 복원)
        original_components = get_extension_field(cim.metadata, "cyclonedx", "components")
        
        if original_components and self.options.restore:
            # 완벽한 복원: 원본 components 구조 사용
            components = original_components
            
            # 원본 components에서 ref_mapping 구성
            ref_mapping = {}
            for comp in components:
                bom_ref = comp.get("bom-ref", "")
                if bom_ref:
                    ref_mapping[bom_ref] = bom_ref
            
            print(f"[Restore Mode] Restored {len(components)} original component(s)")
        else:
            # 일반 모드: subjects에서 components 생성
            # subcomponent 처리: parent_ref가 있으면 부모의 components 배열에 추가
            components = []
            parent_components = {}  # ref → component (부모 컴포넌트 매핑)
            child_to_parent = {}    # child_ref → parent_ref (자식-부모 매핑)
            
            # 1단계: 최상위 컴포넌트 (parent_ref 없는 것) 처리
            for s in cim.subjects:
                if not s.parent_ref:
                    comps = self._comp(s)
                    for comp in comps:
                        parent_components[s.ref] = comp
                    components.extend(comps)
                else:
                    child_to_parent[s.ref] = s.parent_ref
            
            # 2단계: 자식 컴포넌트 (subcomponents)를 부모에 추가
            for s in cim.subjects:
                if s.parent_ref:
                    parent_ref = s.parent_ref
                    if parent_ref in parent_components:
                        parent_comp = parent_components[parent_ref]
                        
                        # 부모에 components 배열이 없으면 생성
                        if "components" not in parent_comp:
                            parent_comp["components"] = []
                        
                        # 자식 컴포넌트 생성
                        child_comps = self._comp(s)
                        
                        # PURL에서 type 추론
                        for child_comp in child_comps:
                            if "type" not in child_comp or child_comp["type"] == "library":
                                # PURL에서 type 추론
                                purl = child_comp.get("purl", "")
                                if purl:
                                    child_comp["type"] = _infer_component_type_from_purl(purl)
                        
                        parent_comp["components"].extend(child_comps)
                    else:
                        # 부모가 없으면 최상위에 추가 (폴백)
                        components.extend(self._comp(s))
            
            components, ref_mapping = dedupe_components(components)
        
        # affects에 사용된 모든 base refs 수집 (일반 모드에서만)
        # 이것들은 affects[].ref로 사용되므로 해당 components가 필요함
        if not (original_components and self.options.restore):
            base_refs_in_affects = set()
            for stmt in cim.statements:
                for ref in stmt.subject_refs:
                    # base ref 추출 (_vulns와 동일한 로직)
                    subj = next((s for s in cim.subjects if s.ref == ref), None)
                    if subj and subj.original_id:
                        # base 결정에 original_id 사용
                        base_ref = subj.original_id
                        if ':v' in base_ref:
                            parts = base_ref.split(':v')
                            if len(parts) >= 2:
                                base_ref = parts[0]
                    else:
                        base_ref = ref
                        if ':v' in base_ref:
                            base_ref = ref.split(':v')[0]
                    
                    base_refs_in_affects.add(base_ref)
            
            def collect_all_bom_refs(comps):
                refs = set()
                for c in comps:
                    if c.get("bom-ref"):
                        refs.add(c["bom-ref"])
                    if "components" in c:
                        refs.update(collect_all_bom_refs(c["components"]))
                return refs

            # base ref components가 없으면 추가
            existing_bom_refs = collect_all_bom_refs(components)
            
            for base_ref in base_refs_in_affects:
                if base_ref not in existing_bom_refs:
                    # 이 base ref를 가진 subject 찾기
                    for s in cim.subjects:
                        s_base_ref = s.ref.split(':v')[0] if ':v' in s.ref else s.ref
                        if s_base_ref == base_ref or (s.original_id and s.original_id.split(':v')[0] == base_ref):
                            # base component 생성 (버전 없이)
                            base_name = s.name.split(' ')[0] if s.name else base_ref
                            # 이름에서 버전 접미사 제거
                            for version_marker in [' vers:', ' v', ' 1.', ' 2.', ' 3.', ' 4.', ' 5.']:
                                if version_marker in base_name:
                                    base_name = base_name.split(version_marker)[0]
                                    break
                            
                            comp_type = s.type if s.type else "library"
                            base_comp = {
                                "type": comp_type,
                                "name": base_name,
                                "bom-ref": base_ref
                            }
                            
                            # 가능하면 version 추가
                            version_to_set = s.version
                            
                            # s.version에 없으면 purl에서 버전 추출 시도
                            purl = next((i.value for i in s.identifiers if i.type == "purl"), None)
                            if purl and "@" in purl and not version_to_set:
                                parts = purl.split("@")
                                version_part = parts[1]
                                
                                # range: 형식 처리
                                if version_part.startswith("range:"):
                                    # range:<1.0.1 → vers:semver/<1.0.1
                                    version_to_set = "vers:semver/" + version_part[6:]
                                elif version_part.startswith("vers:"):
                                    # vers:semver/<1.0.1 → 그대로 유지
                                    version_to_set = version_part
                                else:
                                    # 1.0.1 → 그대로 유지
                                    version_to_set = version_part
                            
                            if version_to_set:
                                base_comp["version"] = version_to_set
                            
                            # 가능하면 식별자 추가 (버전 없이)
                            if purl:
                                # PURL에서 버전 제거
                                if "@" in purl:
                                    purl_base = purl.split("@")[0]
                                    base_comp["purl"] = purl_base
                            
                            cpe = next((i.value for i in s.identifiers if i.type == "cpe"), None)
                            if cpe:
                                base_comp["cpe"] = cpe
                            
                            # 가능하면 해시 추가
                            if s.hashes:
                                # CIM 형식을 CycloneDX 형식으로 변환
                                # CIM: [{"algorithm": "sha-256", "value": "..."}]
                                # CDX: [{"alg": "SHA-256", "content": "..."}]
                                cdx_hashes = []
                                for h in s.hashes:
                                    alg = h.get("algorithm", "")
                                    val = h.get("value", "")
                                    if alg and val:
                                        # 알고리즘 이름을 CycloneDX 형식으로 정규화
                                        # 유효한 값: MD5, SHA-1, SHA-256, SHA-384, SHA-512, 
                                        #            SHA3-256, SHA3-384, SHA3-512, BLAKE2b-256 등
                                        alg_normalized = alg.upper()
                                        
                                        # SHA 변형 처리 (SHA256 → SHA-256, sha-256 → SHA-256)
                                        if alg_normalized.startswith("SHA") and "-" not in alg_normalized:
                                            # SHA256 → SHA-256, SHA512 → SHA-512
                                            if alg_normalized.startswith("SHA3"):
                                                # SHA3256 → SHA3-256
                                                alg_normalized = alg_normalized.replace("SHA3", "SHA3-")
                                            else:
                                                # SHA256 → SHA-256
                                                alg_normalized = alg_normalized.replace("SHA", "SHA-")
                                        
                                        cdx_hashes.append({"alg": alg_normalized, "content": val})
                                if cdx_hashes:
                                    base_comp["hashes"] = cdx_hashes
                            
                            components.append(base_comp)
                            existing_bom_refs.add(base_ref)
                            break
        
        # 수정됨 (이슈 1 - 요구사항 #2): original_product_id → [bom_refs] 매핑 구성
        # 동일한 VEX 판정을 모든 패키징 변형에 적용할 수 있게 함
        original_to_variants = {}  # original_product_id → [bom_ref1, bom_ref2, ...]
        for comp in components:
            props = comp.get("properties", [])
            original_id = None
            for prop in props:
                if prop.get("name") == "cdx:csaf:original-product-id":
                    original_id = prop.get("value")
                    break
            
            if original_id:
                if original_id not in original_to_variants:
                    original_to_variants[original_id] = []
                original_to_variants[original_id].append(comp.get("bom-ref"))
        
        vulns = self._vulns(cim, ref_mapping, original_to_variants, components)

        # 수정됨 (CSAF 이슈 3): metadata.timestamp에 initial_release_date 사용
        timestamp_to_use = cim.metadata.created_at
        initial_release_date = get_extension_field(cim.metadata, "csaf", "document.tracking.initial_release_date")
        if initial_release_date:
            try:
                timestamp_to_use = datetime.fromisoformat(initial_release_date.replace('Z', '+00:00'))
            except:
                pass

        # Tool 정보는 VEXCO (변환기 도구)만 포함해야 함
        # 원본 author는 metadata.authors로 이동
        metadata = {
            "timestamp": dt_to_iso_z(timestamp_to_use),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "VEXCO",
                        "version": "1.0.0",
                        "supplier": {
                            "name": "Korea University CCS Lab",
                            "url": ["https://ccs.korea.ac.kr"]
                        }
                    }
                ]
            }
        }
        
        # 원본 author를 metadata.authors에 추가 (tools.supplier가 아님)
        if cim.metadata.publisher.name and cim.metadata.publisher.name != "Unknown":
            metadata["authors"] = [{
                "name": cim.metadata.publisher.name
            }]
        
        # TLP 처리: 공통 TLP 필드 또는 원본 CycloneDX distributionConstraints 사용
        common_tlp_label = get_extension_field(cim.metadata, "common", "tlp.label", None)
        original_dist_constraints = get_extension_field(cim.metadata, "cyclonedx", "metadata.distributionConstraints", None)
        
        if common_tlp_label:
            # CSAF → CycloneDX 변환: TLP 매핑
            # CSAF 2.1: CLEAR, GREEN, AMBER, AMBER+STRICT, RED
            # CycloneDX: CLEAR, GREEN, AMBER, AMBER_AND_STRICT, RED
            tlp_csaf_to_cyclonedx = {
                "CLEAR": "CLEAR",
                "GREEN": "GREEN",
                "AMBER": "AMBER",
                "AMBER+STRICT": "AMBER_AND_STRICT",
                "RED": "RED",
                # CSAF 2.0 레거시 지원
                "WHITE": "CLEAR"
            }
            cdx_tlp_label = tlp_csaf_to_cyclonedx.get(common_tlp_label, common_tlp_label)
            metadata["distributionConstraints"] = {
                "tlp": cdx_tlp_label
            }
        elif original_dist_constraints:
            # 원본 CycloneDX distributionConstraints 복원
            metadata["distributionConstraints"] = original_dist_constraints
        # TLP가 없으면 distributionConstraints 생략 (CycloneDX에서 선택적)
        
        # OpenVEX role을 metadata.properties에 추가 (bom-ref가 아님)
        openvex_role = get_extension_field(cim.metadata, "openvex", "role")
        if openvex_role:
            if "properties" not in metadata:
                metadata["properties"] = []
            metadata["properties"].append({
                "name": "openvex:role",
                "value": openvex_role
            })
        
        # 수정됨 (CSAF 이슈 4): CSAF notes를 CycloneDX properties에 매핑
        csaf_notes = get_extension_field(cim.metadata, "csaf", "document.notes")
        if csaf_notes:
            if "properties" not in metadata:
                metadata["properties"] = []
            for note in csaf_notes:
                note_title = note.get("title", note.get("category", "note"))
                note_text = note.get("text", "")
                if note_text:
                    metadata["properties"].append({
                        "name": f"csaf:note:{note_title}",
                        "value": note_text
                    })
        
        # document.references를 externalReferences에 추가 (가능하면, CSAF에서)
        external_refs = []
        csaf_references = get_extension_field(cim.metadata, "csaf", "document.references")
        if csaf_references:
            for ref in csaf_references:
                ext_ref = {}
                
                # category -> type (CSAF category를 CycloneDX type으로 매핑)
                if ref.get("category"):
                    category = ref["category"]
                    # CSAF categories를 CycloneDX types로 매핑
                    # CycloneDX 1.7은 "advisory"가 아닌 "advisories" (복수형) 사용
                    category_to_type = {
                        "external": "advisories",
                        "self": "advisories",  # CSAF self는 advisory 문서 자체
                        "related": "other"
                    }
                    ext_ref["type"] = category_to_type.get(category, "other")
                else:
                    ext_ref["type"] = "other"
                
                # url -> url
                if ref.get("url"):
                    ext_ref["url"] = ref["url"]
                
                # summary -> comment
                if ref.get("summary"):
                    ext_ref["comment"] = ref["summary"]
                
                if ext_ref.get("url"):
                    external_refs.append(ext_ref)
        
        # 가능하면 원본 metadata.supplier 복원
        if self.options.restore:
            original_supplier = get_extension_field(cim.metadata, "cyclonedx", "metadata.supplier")
            if original_supplier:
                metadata["supplier"] = original_supplier
        
        # metadata.component 복원 (VDR에 중요)
        metadata_component = get_extension_field(cim.metadata, "cyclonedx", "metadata.component")
        if metadata_component:
            metadata["component"] = metadata_component
        
        # 문서 버전 가져오기: CIM 필드 먼저 시도, 그 다음 기본값 1
        doc_version = cim.metadata.document_version if cim.metadata.document_version else 1

        # specVersion 1.7, 필드 순서 수정됨
        # 순서: $schema, bomFormat, specVersion, serialNumber, version, metadata, components, vulnerabilities
        result = {}
        result["$schema"] = "https://cyclonedx.org/schema/bom-1.7.schema.json"
        result["bomFormat"] = "CycloneDX"
        result["specVersion"] = "1.7"
        
        # version 전에 serialNumber 추가
        serial = ensure_urn_uuid(cim.metadata.original_id)
        if serial:
            result["serialNumber"] = serial
        
        result["version"] = doc_version
        result["metadata"] = metadata
        
        # components가 있으면 추가
        if components:
            result["components"] = components
        
        # vulnerabilities 추가
        result["vulnerabilities"] = vulns
        
        # externalReferences는 끝에 추가
        if external_refs:
            result["externalReferences"] = external_refs

        # 가역 모드: 복원을 위한 메타데이터 저장
        if self.options.reversible:
            lost_data = self._collect_lost_data(cim)
            
            # 모든 CIM 엔티티에서 extension_data 수집
            extension_data = {}
            
            # Metadata extension_data
            if cim.metadata.extension_data:
                extension_data["metadata"] = cim.metadata.extension_data
            
            # Subject extension_data
            for idx, subj in enumerate(cim.subjects):
                if subj.extension_data:
                    extension_data[f"subject_{idx}"] = subj.extension_data
            
            # Vulnerability extension_data (인덱스가 아닌 ID를 키로 사용)
            for vuln in cim.vulnerabilities:
                if vuln.extension_data:
                    extension_data[f"vulnerability_{vuln.id}"] = vuln.extension_data
            
            # Statement extension_data
            for idx, stmt in enumerate(cim.statements):
                if stmt.extension_data:
                    extension_data[f"statement_{idx}"] = stmt.extension_data
            
            # subject_mappings 수집 (ref → original_id)
            subject_mappings = {}
            for subj in cim.subjects:
                # original_id가 있으면 항상 저장
                if subj.original_id:
                    subject_mappings[subj.ref] = subj.original_id
                else:
                    # original_id가 없어도 ref → ref 매핑 저장
                    # 복원에 도움됨
                    subject_mappings[subj.ref] = subj.ref
            
            if lost_data or extension_data or subject_mappings:
                conv_meta = ConversionMetadata(
                    version="1.0",
                    source_format="CIM",
                    target_format="CycloneDX",
                    timestamp=dt_to_iso_z(now_utc()),
                    lost_data=lost_data,
                    extension_data=extension_data,
                    subject_mappings=subject_mappings
                )
                encoded = conv_meta.encode()
                
                # result.metadata.properties에 저장 (지역 metadata 변수가 아님)
                if "properties" not in result["metadata"]:
                    result["metadata"]["properties"] = []
                result["metadata"]["properties"].append({
                    "name": "VEXCO.metadata",
                    "value": encoded
                })
                
                items_count = len(lost_data) + len(extension_data) + len(subject_mappings)
                print(f"\n[Reversible Mode] Stored {items_count} item(s) in properties:")
                if lost_data:
                    print(f"  - {len(lost_data)} lost fields (not recoverable)")
                else:
                    print(f"  - 0 lost fields (all data preserved!)")
                if extension_data:
                    print(f"  - {len(extension_data)} extension data entries (recoverable)")
                if subject_mappings:
                    print(f"  - {len(subject_mappings)} subject ID mappings (recoverable)")

        # CycloneDX 1.7 스키마에 따른 필드 순서 적용
        return order_cyclonedx_document(result)
    
    def _collect_lost_data(self, cim: CIM) -> Dict[str, Any]:
        """CycloneDX 변환에서 손실될 데이터 수집"""
        lost = {}
        
        # 개별 statement 상태 수집 (resolved 상태 보존용)
        # 다른 상태를 가진 여러 statement가 같은 CDX vulnerability에 매핑될 때,
        # 어떤 subject가 어떤 상태를 가졌는지 보존 필요
        for stmt in cim.statements:
            # 각 subject_ref에 대한 상태 저장
            for ref in stmt.subject_refs:
                key = f"stmt_status_{ref}_{stmt.vulnerability_id}"
                lost[key] = stmt.status.value.name  # 예: "AFFECTED", "FIXED"
        
        # not_affected 상태에 대한 justification 수집
        for stmt in cim.statements:
            if stmt.status.value == VulnerabilityStatus.NOT_AFFECTED:
                if stmt.status.justification:
                    key = f"stmt_{stmt.id}_justification"
                    lost[key] = justification_enum_to_openvex_str(stmt.status.justification)
                if stmt.status.custom_justification:
                    key = f"stmt_{stmt.id}_custom_justification"
                    lost[key] = stmt.status.custom_justification
        
        # action_statements 수집
        for stmt in cim.statements:
            if stmt.action_statement:
                key = f"stmt_{stmt.id}_action_statement"
                lost[key] = stmt.action_statement
        
        return lost

    def _normalize_hash_algorithm(self, alg: str) -> str:
        """해시 알고리즘 이름을 CycloneDX 형식으로 정규화.
        
        CycloneDX 필요: MD5, SHA-1, SHA-256, SHA-384, SHA-512, 
        SHA3-256, SHA3-384, SHA3-512, BLAKE2b-256 등
        """
        if not alg:
            return alg
        
        # 먼저 대문자로
        alg_upper = alg.upper()
        
        # SHA 변형 처리
        # SHA256 → SHA-256, sha256 → SHA-256
        if alg_upper.startswith("SHA") and "-" not in alg_upper:
            if alg_upper.startswith("SHA3"):
                # SHA3256 → SHA3-256
                return alg_upper.replace("SHA3", "SHA3-")
            else:
                # SHA256 → SHA-256, SHA1 → SHA-1
                # 숫자가 시작하는 위치 찾기
                for i, c in enumerate(alg_upper):
                    if c.isdigit():
                        return alg_upper[:i] + "-" + alg_upper[i:]
                return alg_upper
        
        # BLAKE2b 변형 처리
        # BLAKE2B256 → BLAKE2b-256
        if "BLAKE2" in alg_upper and "-" not in alg_upper:
            return alg_upper.replace("BLAKE2B", "BLAKE2b-").replace("BLAKE2S", "BLAKE2s-")
        
        return alg_upper

    def _comp(self, s: Subject) -> List[Dict]:
        """Subject에서 component 생성.
        subject에 여러 PURL이 있으면 여러 component 반환.
        """
        # 모든 purl 수집
        all_purls = [i.value for i in s.identifiers if i.type == "purl"]
        purl = all_purls[0] if all_purls else None
        
        # @range: 형식 또는 스코프 패키지가 있는 purl 처리
        # pkg:maven/com.acme/product@range:<1.0.1 → purl: pkg:maven/com.acme/product
        # pkg:npm/@scope/package@1.0.0 → purl: pkg:npm/@scope/package@1.0.0 (version: 1.0.0)
        version_from_purl = None
        purl_base = purl
        if purl and "@" in purl:
            # 버전 @ 찾기 (스코프 @가 아님)
            # 스코프 패키지의 경우: pkg:npm/@scope/package@1.0.0
            # 버전 @는 마지막 / 뒤에 위치
            last_slash = purl.rfind("/")
            if last_slash > 0:
                after_slash = purl[last_slash+1:]
                if "@" in after_slash:
                    # 마지막 슬래시 뒤에 버전 구분자 있음
                    at_pos = after_slash.find("@")
                    version_start = last_slash + 1 + at_pos
                    purl_base = purl[:version_start]
                    version_part = purl[version_start+1:]
                else:
                    # 버전 없음, 패키지 이름만 (스코프일 수 있음)
                    purl_base = purl
                    version_part = None
            else:
                # 단순 케이스, 경로에 슬래시 없음
                parts = purl.split("@")
                purl_base = parts[0]
                version_part = parts[1] if len(parts) > 1 else None
            
            if version_part:
                # @range: 또는 @vers:에서 버전 추출
                if version_part.startswith("range:"):
                    # range:<1.0.1 → vers:semver/<1.0.1
                    version_from_purl = "vers:semver/" + version_part[6:]
                    purl = purl_base  # 버전 없이 기본값 사용
                elif version_part.startswith("vers:"):
                    # vers:semver/<1.0.1 → 그대로 유지
                    version_from_purl = version_part
                    purl = purl_base  # 버전 없이 기본값 사용
                else:
                    # 일반 버전 (예: 1.0.0)
                    version_from_purl = version_part
                    # 일반 버전은 purl에 버전 유지
        
        normalized_purl = normalize_purl(purl) if purl else None

        # 기본 이름 추출 (버전 제외)
        if s.name:
            name = s.name
            # 이름에서 버전 접미사 제거 (있는 경우)
            # 예: "product-ABC 2.4" → "product-ABC"
            #           "product-ABC vers:generic/..." → "product-ABC"
            if s.version:
                # 이름에서 " {version}" 또는 " vers:..." 제거
                if s.version.startswith("vers:"):
                    # 이름에서 버전 범위 제거
                    name = name.replace(f" {s.version}", "").strip()
                else:
                    # 이름에서 일반 버전 제거
                    name = name.replace(f" {s.version}", "").strip()
        elif normalized_purl:
            try:
                # PURL에서 이름 추출 (without version)
                # 스코프 패키지 처리: pkg:npm/@scope/package@1.0.0 → package
                last_slash = normalized_purl.rfind("/")
                if last_slash > 0:
                    after_slash = normalized_purl[last_slash+1:]
                    # 버전 제거 (있는 경우)
                    if "@" in after_slash:
                        name = after_slash.split("@")[0]
                    else:
                        name = after_slash
                else:
                    name = normalized_purl.split("/")[-1].split("@")[0].split("?")[0]
            except:
                name = s.ref.split(":")[0] if ":" in s.ref else s.ref
        else:
            # 버전 없는 base ref 사용
            name = s.ref.split(":")[0] if ":" in s.ref else s.ref

        # 식별자와 이름 기반으로 컴포넌트 타입 분류
        comp_type = classify_component_type(
            normalized_purl or s.ref,
            name
        ) if not s.type else s.type

        # 버전 결정: s.version > version_from_purl 우선순위
        version_to_use = s.version or version_from_purl
        
        # CPE 가져오기 (모든 PURL 변형에서 공유)
        cpe = next((i.value for i in s.identifiers if i.type == "cpe"), None)
        
        # 컴포넌트 목록 구성
        components = []
        
        # 수정됨 (이슈 1): 다중 PURL에 pedigree.variants 사용
        # cdx:package:equivalent-to를 가진 별도 컴포넌트 대신,
        # pedigree.variants를 사용하여 동일 제품의 패키징 변형임을 표시
        if len(all_purls) > 1:
            # 다중 PURL - 각각에 대해 pedigree.variants 연결로 별도 컴포넌트 생성
            all_bom_refs = []
            
            # 1차 패스: 모든 bom-ref 생성
            for idx, purl_item in enumerate(all_purls):
                pkg_format = "unknown"
                if purl_item.startswith("pkg:"):
                    format_part = purl_item[4:].split("/")[0]
                    pkg_format = format_part
                
                bom_ref = f"{s.ref}-{pkg_format}" if idx > 0 else s.ref
                all_bom_refs.append(bom_ref)
            
            # 2차 패스: pedigree.variants로 컴포넌트 생성
            for idx, purl_item in enumerate(all_purls):
                is_primary = (idx == 0)
                
                pkg_format = "unknown"
                if purl_item.startswith("pkg:"):
                    format_part = purl_item[4:].split("/")[0]
                    pkg_format = format_part
                
                bom_ref = all_bom_refs[idx]
                
                c = {"type": comp_type, "name": name, "bom-ref": bom_ref}
                
                # 수정됨 (이슈 3): versionRange 필드로 버전 범위 처리
                if version_to_use:
                    if version_to_use.startswith("vers:"):
                        # 버전 범위 - isExternal: true와 함께 versionRange 사용
                        c["isExternal"] = True
                        c["versionRange"] = version_to_use
                    elif version_to_use not in ["unknown", ""]:
                        c["version"] = version_to_use
                
                # 이 PURL 추가
                c["purl"] = normalize_purl(purl_item)
                
                # CPE 추가 (모든 변형에 동일)
                if cpe:
                    c["cpe"] = cpe
                
                # 수정됨 (이슈 1): 관련 패키징 형식 연결을 위해 pedigree.variants 추가
                # 각 변형은 모든 다른 변형을 참조 (자기 자신 제외)
                # CycloneDX는 각 변형 컴포넌트에 type과 name 필요
                other_refs = [ref for ref in all_bom_refs if ref != bom_ref]
                if other_refs:
                    c["pedigree"] = {
                        "variants": [{"bom-ref": ref, "type": comp_type, "name": name} for ref in other_refs]
                    }
                
                # 수정됨 (이슈 1): equivalent-to 대신 cdx:csaf:original-product-id 사용
                c["properties"] = [
                    {"name": "cdx:csaf:original-product-id", "value": s.ref},
                    {"name": "cdx:package:format", "value": pkg_format}
                ]
                
                # primary 표시 추가
                if is_primary:
                    c["properties"].append({"name": "cdx:package:primary", "value": "true"})
                
                # primary 컴포넌트에만 해시 추가
                if is_primary and s.hashes:
                    cdx_hashes = []
                    for h in s.hashes:
                        alg = h.get("algorithm", "")
                        content = h.get("value", "")
                        if alg and content:
                            # CycloneDX 형식으로 정규화: SHA-256, SHA-384, SHA-512 등
                            alg_normalized = self._normalize_hash_algorithm(alg)
                            cdx_hashes.append({"alg": alg_normalized, "content": content})
                    if cdx_hashes:
                        c["hashes"] = cdx_hashes
                
                components.append(c)
        else:
            # 단일 PURL - 단일 컴포넌트 생성
            c = {"type": comp_type, "name": name, "bom-ref": s.ref}
            
            # 수정됨 (이슈 3): versionRange 필드로 버전 범위 처리
            if version_to_use:
                if version_to_use.startswith("vers:"):
                    # 버전 범위 - isExternal: true와 함께 versionRange 사용
                    c["isExternal"] = True
                    c["versionRange"] = version_to_use
                elif version_to_use not in ["unknown", ""]:
                    c["version"] = version_to_use
            
            if normalized_purl:
                c["purl"] = normalized_purl
            if cpe:
                c["cpe"] = cpe
            
            # 가능하면 해시 추가
            if s.hashes:
                cdx_hashes = []
                for h in s.hashes:
                    alg = h.get("algorithm", "")
                    content = h.get("value", "")
                    if alg and content:
                        # CycloneDX 형식으로 정규화: SHA-256, SHA-384, SHA-512 등
                        alg_normalized = self._normalize_hash_algorithm(alg)
                        cdx_hashes.append({"alg": alg_normalized, "content": content})
                if cdx_hashes:
                    c["hashes"] = cdx_hashes
            
            components.append(c)
        
        return components

    def _vulns(self, cim: CIM, ref_mapping: Dict[str, str], 
               original_to_variants: Dict[str, List[str]] = None,
               components: List[Dict] = None) -> List[Dict]:
        """vulnerabilities 배열 생성.
        
        Args:
            cim: CIM 모델
            ref_mapping: bom-ref 매핑
            original_to_variants: 원본 CSAF product_id에서 변형 bom-refs로의 매핑
            components: 생성된 컴포넌트 목록 (빌드 조건 감지용)
        """
        original_to_variants = original_to_variants or {}
        components = components or []
        
        by_vuln = {}
        for st in cim.statements:
            by_vuln.setdefault(st.vulnerability_id, []).append(st)
        vuln_idx = {v.id: v for v in cim.vulnerabilities}
        out = []

        # bomlink 생성을 위한 serial number 가져오기
        serial_number = cim.metadata.original_id or f"urn:uuid:{cim.metadata.id}"

        for vid, stmts in sorted(by_vuln.items()):
            # 버전 정보 수집을 위해 subject별로 statement 그룹화
            by_subject = {}
            for st in stmts:
                for ref in st.subject_refs:
                    if ref not in by_subject:
                        by_subject[ref] = []
                    by_subject[ref].append(st)

            # 완벽한 복원 지원으로 affects 배열 구성
            vv = vuln_idx.get(vid)
            original_affects = get_extension_field(vv, "cyclonedx", "affects") if vv else None
            
            if original_affects and self.options.restore:
                # 완벽한 복원: 원본 affects 구조 사용
                affects = original_affects
                
                self.tracking_table.add(
                    source_field="CIM.vulnerability.extension_data.cyclonedx.affects",
                    source_value=f"{len(original_affects)} affects entries",
                    target_field="vulnerabilities.affects",
                    target_value=f"{len(original_affects)} affects (exact restoration)",
                    rule="Restore original CycloneDX affects structure",
                    status="OK"
                )
            else:
                # 일반 모드: statements에서 affects 재구성
                # 수정됨 (OpenVEX 이슈 5): 각 제품에 대해 별도의 affects 항목 생성
                # 각 버전은 하나의 base ref로 그룹화되지 않고 자신만의 ref를 가져야 함
                affects = []
                
                for st in stmts:
                    for ref in st.subject_refs:
                        # 버전과 original_id를 찾기 위해 subject 가져오기
                        subj = next((s for s in cim.subjects if s.ref == ref), None)
                        if not subj:
                            continue
                        
                        # 가능하면 original_id 사용, 그렇지 않으면 ref 사용
                        if subj.original_id:
                            final_ref = subj.original_id
                        else:
                            final_ref = ref_mapping.get(ref, ref)
                        
                        # 이 ref가 이미 affects에 있는지 확인
                        existing_affect = next((a for a in affects if a.get("ref") == final_ref), None)
                        
                        if existing_affect:
                            # 중복 건너뛰기 - 동일 ref가 이미 추가됨
                            continue
                        
                        # 단일 버전으로 affect 객체 생성
                        affect_obj = {"ref": final_ref}
                        
                        # 버전이 있으면 버전 항목 추가
                        if subj.version:
                            version_entry = {}
                            
                            # 버전이 범위인지 확인
                            if subj.version.startswith("vers:"):
                                version_entry["range"] = subj.version
                            else:
                                version_entry["version"] = subj.version
                            
                            # 상태 매핑
                            if st.status.value == VulnerabilityStatus.AFFECTED:
                                version_entry["status"] = "affected"
                            elif st.status.value == VulnerabilityStatus.NOT_AFFECTED:
                                version_entry["status"] = "unaffected"
                            elif st.status.value == VulnerabilityStatus.FIXED:
                                version_entry["status"] = "unaffected"
                            else:
                                version_entry["status"] = "unknown"
                            
                            affect_obj["versions"] = [version_entry]
                        
                        affects.append(affect_obj)
                
                # 수정됨 (이슈 1 - 요구사항 #2, #3): 모든 패키징 변형에 동일한 VEX 판정 적용
                # 제품이 여러 PURL을 가지면 (예: rpm, deb) 모든 변형에 대해 affects 생성
                expanded_affects = []
                
                # 수정됨 (이슈 1 - 요구사항 #3): 노트/플래그에서 빌드별 조건 확인
                # 빌드별 평가를 나타내는 키워드
                build_condition_keywords = [
                    "build configuration", "compilation flag", "specific environment",
                    "build-specific", "compile-time", "build option", "configuration option",
                    "environment-specific", "platform-specific", "architecture-specific"
                ]
                
                # 원본 평가에 빌드 조건이 언급되어 있는지 확인
                has_build_conditions = False
                for st in stmts:
                    # impact_statement 확인
                    if st.status.impact_statement:
                        stmt_lower = st.status.impact_statement.lower()
                        if any(kw in stmt_lower for kw in build_condition_keywords):
                            has_build_conditions = True
                            break
                    # action_statement 확인
                    if st.action_statement:
                        action_lower = st.action_statement.lower()
                        if any(kw in action_lower for kw in build_condition_keywords):
                            has_build_conditions = True
                            break
                
                for affect_obj in affects:
                    original_ref = affect_obj.get("ref")
                    
                    # 이 ref에 변형이 있는지 확인 (다중 PURL 패키징)
                    variant_refs = original_to_variants.get(original_ref, [])
                    
                    if len(variant_refs) > 1:
                        # 다중 변형 존재 - 각각에 대해 affect 생성
                        for variant_ref in variant_refs:
                            variant_affect = dict(affect_obj)
                            variant_affect["ref"] = variant_ref
                            
                            # 있으면 versions 깊은 복사
                            if "versions" in affect_obj:
                                import copy
                                variant_affect["versions"] = copy.deepcopy(affect_obj["versions"])
                            
                            # 없으면 analysis 초기화
                            if "analysis" not in variant_affect:
                                variant_affect["analysis"] = {}
                            
                            # 수정됨 (요구사항 #3): 빌드 조건이 언급되면 status를 unknown으로 설정
                            if has_build_conditions:
                                # versions status를 unknown으로 설정
                                if "versions" in variant_affect:
                                    for ver in variant_affect["versions"]:
                                        ver["status"] = "unknown"
                                
                                # analysis state를 in_triage로 설정
                                variant_affect["analysis"]["state"] = "in_triage"
                                
                                # variant_ref에서 패키지 형식 가져오기
                                pkg_format = "variant"
                                if "-" in variant_ref:
                                    pkg_format = variant_ref.rsplit("-", 1)[-1]
                                
                                original_detail = variant_affect.get("analysis", {}).get("detail", "")
                                variant_affect["analysis"]["detail"] = (
                                    f"[CSAF product: {original_ref}] Original assessment mentions build-specific conditions. "
                                    f"{pkg_format.upper()} variant status requires separate verification. "
                                    f"Original detail: {original_detail}" if original_detail else 
                                    f"[CSAF product: {original_ref}] Original assessment mentions build-specific conditions. "
                                    f"{pkg_format.upper()} variant status requires separate verification."
                                )
                            else:
                                # 수정됨 (요구사항 #2): detail에 [CSAF product: ...] 접두사 추가
                                original_detail = variant_affect.get("analysis", {}).get("detail", "")
                                if original_detail and not original_detail.startswith("[CSAF product:"):
                                    variant_affect["analysis"]["detail"] = f"[CSAF product: {original_ref}] {original_detail}"
                                elif not original_detail:
                                    variant_affect["analysis"]["detail"] = f"[CSAF product: {original_ref}]"
                            
                            expanded_affects.append(variant_affect)
                    else:
                        # 단일 ref 또는 변형 없음 - 그대로 유지
                        expanded_affects.append(affect_obj)
                
                affects = expanded_affects

            # 우선순위로 상태 결정: affected > fixed > not_affected > under_investigation
            original_state = next((st.status.original_state for st in stmts if st.status.original_state), None)
            statuses = set(st.status.value for st in stmts)

            # 중요: AFFECTED가 존재하면 항상 exploitable 사용
            # 취약한 버전이 여전히 있으므로 original_state보다 우선
            # 취약한 버전이 존재할 때 "resolved"를 표시하는 의미적 오류 방지
            if VulnerabilityStatus.AFFECTED in statuses:
                state = "exploitable"
                self.tracking_table.add(
                    source_field="CIM.statement.status.value",
                    source_value="AFFECTED (exists)",
                    target_field="vulnerabilities.analysis.state",
                    target_value="exploitable",
                    rule="AFFECTED exists → exploitable (overrides original_state)",
                    status="TRANSFORMED"
                )
            elif original_state:
                # AFFECTED 상태가 없을 때만 original_state 사용
                state = original_state
                self.tracking_table.add(
                    source_field="CIM.statement.status.original_state",
                    source_value=original_state,
                    target_field="vulnerabilities.analysis.state",
                    target_value=state,
                    rule="Restore original state (no AFFECTED)",
                    status="OK"
                )
            else:
                # 우선순위로 상태에서 결정
                if VulnerabilityStatus.FIXED in statuses:
                    state = "resolved"
                elif VulnerabilityStatus.NOT_AFFECTED in statuses:
                    state = "not_affected"
                else:
                    state = "in_triage"
                
                source_status = list(statuses)[0] if statuses else "UNDER_INVESTIGATION"
                self.tracking_table.add(
                    source_field="CIM.statement.status.value",
                    source_value=str(source_status),
                    target_field="vulnerabilities.analysis.state",
                    target_value=state,
                    rule=f"Priority: fixed>not_affected>in_triage",
                    status="TRANSFORMED"
                )

            # 수정됨 (OpenVEX 이슈 1): 순서화된 필드로 v_obj 생성:
            # id, source, ratings, cwes, description, analysis, affects
            v_obj = {"id": vid}

            # CVE에 대해 NVD source 추가 (두 번째)
            if vid.startswith("CVE-"):
                v_obj["source"] = {
                    "name": "NVD",
                    "url": f"https://nvd.nist.gov/vuln/detail/{vid}"
                }

            # ratings 추가 (세 번째)
            vv = vuln_idx.get(vid)
            epss_properties = []  # properties용 EPSS 데이터 수집
            vuln_properties = []  # 모든 vulnerability-level properties 수집
            epss_rating = None    # ratings 배열용 EPSS rating
            
            if vv and vv.ratings:
                # EPSS와 일반 ratings 분리
                regular_ratings = []
                for r in vv.ratings:
                    if r.method == "other" and r.vector == "EPSS":
                        # EPSS 데이터 - ratings와 properties 모두에 저장
                        epss_data = get_extension_field(vv, "csaf", "epss")
                        if epss_data:
                            # EPSS 등급 추가
                            epss_rating = {
                                "method": "other",
                                "vector": "EPSS",
                                "score": float(epss_data.get("probability", 0)) if epss_data.get("probability") else None
                            }
                            # 상세 속성 추가
                            if epss_data.get("probability"):
                                epss_properties.append({
                                    "name": "csaf:epss:probability",
                                    "value": str(epss_data["probability"])
                                })
                            if epss_data.get("percentile"):
                                epss_properties.append({
                                    "name": "csaf:epss:percentile",
                                    "value": str(epss_data["percentile"])
                                })
                            if epss_data.get("timestamp"):
                                epss_properties.append({
                                    "name": "csaf:epss:timestamp",
                                    "value": str(epss_data["timestamp"])
                                })
                    else:
                        regular_ratings.append(r)
                
                ratings_data = [self._rating(r) for r in regular_ratings]
                # EPSS 등급 추가 if exists
                if epss_rating and epss_rating.get("score"):
                    ratings_data.append(epss_rating)
                ratings_data = filter_placeholder_ratings(ratings_data)
                ratings_data = dedupe_ratings(ratings_data)
                if ratings_data:
                    v_obj["ratings"] = ratings_data

            # cwes를 4번째로 추가 (description 전에) (OpenVEX 이슈 1)
            if vv and vv.cwes:
                v_obj["cwes"] = unique_list(vv.cwes)
            
            # description을 5번째로 추가 (analysis 전에) (OpenVEX 이슈 1)
            if vv and vv.description:
                v_obj["description"] = vv.description
            
            # aliases를 references 배열에 추가 (properties 아님) (OpenVEX 이슈 4)
            # GHSA-xxxx-yyyy-zzzz 같은 aliases는 구조화된 references여야 함
            vuln_references = []
            if vv:
                # extension_data 경로와 직접 aliases 필드 모두 확인
                aliases = get_extension_field(vv, "openvex", "vulnerability.aliases")
                if not aliases and hasattr(vv, 'aliases') and vv.aliases:
                    aliases = vv.aliases
                if aliases:
                    seen_aliases = set()
                    for alias in aliases:
                        if alias in seen_aliases:
                            continue
                        seen_aliases.add(alias)
                        
                        # alias 타입에 따라 reference 객체 생성
                        ref_obj = {"id": alias}
                        
                        if alias.startswith("GHSA-"):
                            ref_obj["source"] = {
                                "name": "GitHub Advisories",
                                "url": f"https://github.com/advisories/{alias}"
                            }
                        elif alias.startswith("SNYK-"):
                            ref_obj["source"] = {
                                "name": "Snyk Vulnerability Database",
                                "url": f"https://snyk.io/vuln/{alias}"
                            }
                        elif alias.startswith("OSV-"):
                            ref_obj["source"] = {
                                "name": "Open Source Vulnerabilities",
                                "url": f"https://osv.dev/vulnerability/{alias}"
                            }
                        elif alias.startswith("RHSA-") or alias.startswith("RHBA-"):
                            ref_obj["source"] = {
                                "name": "Red Hat Security Advisory",
                                "url": f"https://access.redhat.com/errata/{alias}"
                            }
                        else:
                            # 일반 alias - reference로 추가
                            ref_obj["source"] = {
                                "name": "External Advisory"
                            }
                        
                        vuln_references.append(ref_obj)

            # 6번째로 analysis 추가
            v_obj["analysis"] = {"state": state}
            
            # action_statement_timestamp를 analysis.firstIssued에 매핑 (OpenVEX 이슈 4)
            for st in stmts:
                action_timestamp = get_extension_field(st, "openvex", "action_statement_timestamp")
                if action_timestamp:
                    v_obj["analysis"]["firstIssued"] = action_timestamp
                    break
            
            # extension_data에서 원본 CycloneDX response 복원 (가능한 경우)
            original_response = None
            for st in stmts:
                if st.extension_data and "cyclonedx_response" in st.extension_data:
                    original_response = st.extension_data["cyclonedx_response"]
                    break
            
            if original_response:
                # 원본 response 배열 사용 (["will_not_fix", "update"] 같은 다중 값 보존)
                v_obj["analysis"]["response"] = original_response
            elif state == "exploitable":
                # original response 없는 exploitable 상태의 경우,
                # try to infer response from action_statement
                action_stmt = None
                impact_stmt = None
                for st in stmts:
                    if st.status.value == VulnerabilityStatus.AFFECTED:
                        if st.action_statement:
                            action_stmt = st.action_statement
                        if st.status.impact_statement:
                            impact_stmt = st.status.impact_statement
                        if action_stmt or impact_stmt:
                            break
                
                # action_statement 파싱하여 response 결정
                # 키워드 매칭 전에 부정 확인 (OpenVEX 이슈 3)
                if action_stmt:
                    response_list = []
                    action_lower = action_stmt.lower()
                    
                    # 부정 키워드 확인 헬퍼 함수
                    def is_negated(text: str, keyword: str) -> bool:
                        """키워드가 부정되었는지 확인 ('no', 'not', 'without' 등이 앞에 있는지)"""
                        import re
                        # 패턴: 부정어 + 선택적 단어들 + 키워드
                        negation_patterns = [
                            rf'\bno\s+{keyword}\b',
                            rf'\bnot\s+{keyword}\b',
                            rf'\bwithout\s+{keyword}\b',
                            rf'\b{keyword}\s+not\s+available\b',
                            rf'\b{keyword}\s+unavailable\b',
                            rf'\bno\s+\w+\s+{keyword}\b',  # "no known workaround"
                        ]
                        for pattern in negation_patterns:
                            if re.search(pattern, text):
                                return True
                        return False
                    
                    # 부정 인식과 함께 일반 패턴 확인
                    if "update" in action_lower or "upgrade" in action_lower or "patch" in action_lower:
                        if not is_negated(action_lower, "update") and not is_negated(action_lower, "upgrade") and not is_negated(action_lower, "patch"):
                            response_list.append("update")
                    
                    # 부정되지 않은 경우에만 workaround_available 추가
                    if "workaround" in action_lower:
                        if is_negated(action_lower, "workaround"):
                            # 부정된 workaround - workaround_available 추가하지 않음
                            pass
                        else:
                            response_list.append("workaround_available")
                    
                    if "rollback" in action_lower or "revert" in action_lower:
                        if not is_negated(action_lower, "rollback") and not is_negated(action_lower, "revert"):
                            response_list.append("rollback")
                    
                    if response_list:
                        v_obj["analysis"]["response"] = response_list
                
                # exploitable 상태의 경우 action_statement를 recommendation에 매핑 (OpenVEX 이슈 2)
                if action_stmt and action_stmt != "No remediation information available":
                    v_obj["recommendation"] = action_stmt
            
            # 원본 detail 복원 (가능한 경우, 완벽한 복원)
            # exploitable뿐만 아니라 모든 상태에 적용
            original_detail = get_extension_field(vv, "cyclonedx", "analysis.detail")
            if original_detail and self.options.restore:
                v_obj["analysis"]["detail"] = original_detail
            elif state == "resolved":
                # resolved 상태 (AFFECTED + FIXED)의 경우, 모든 statements에서 status_notes 결합
                # affected와 fixed statements 모두의 정보 보존
                # 형식: "Justification: [justification], Reason: [impact_statement]"
                fixed_stmt = None
                affected_stmt = None
                for st in stmts:
                    if st.status.value == VulnerabilityStatus.FIXED:
                        fixed_stmt = st
                    elif st.status.value == VulnerabilityStatus.AFFECTED:
                        affected_stmt = st
                
                # 모든 statements에서 구조화된 형식으로 status_notes 수집
                detail_parts = []
                
                # 1. FIXED statement 정보를 먼저 추가 (주요 수정 정보)
                if fixed_stmt:
                    just_str = None
                    if fixed_stmt.status.justification:
                        just_str = fixed_stmt.status.justification.value
                    elif fixed_stmt.status.custom_justification:
                        just_str = fixed_stmt.status.custom_justification
                    
                    fixed_notes = get_extension_field(fixed_stmt, "openvex", "status_notes")
                    impact = fixed_stmt.status.impact_statement
                    
                    entry_parts = []
                    entry_parts.append("[FIXED]")
                    if just_str:
                        entry_parts.append(f"Justification: {just_str}")
                    if fixed_notes:
                        entry_parts.append(f"Notes: {fixed_notes}")
                    elif impact:
                        entry_parts.append(f"Reason: {impact}")
                    
                    if len(entry_parts) > 1:
                        detail_parts.append(" ".join(entry_parts))
                
                # 2. Add AFFECTED statement's info (additional context)
                if affected_stmt:
                    just_str = None
                    if affected_stmt.status.justification:
                        just_str = affected_stmt.status.justification.value
                    elif affected_stmt.status.custom_justification:
                        just_str = affected_stmt.status.custom_justification
                    
                    affected_notes = get_extension_field(affected_stmt, "openvex", "status_notes")
                    impact = affected_stmt.status.impact_statement
                    
                    entry_parts = []
                    entry_parts.append("[AFFECTED]")
                    if just_str:
                        entry_parts.append(f"Justification: {just_str}")
                    if affected_notes:
                        entry_parts.append(f"Notes: {affected_notes}")
                    elif impact:
                        entry_parts.append(f"Reason: {impact}")
                    
                    if len(entry_parts) > 1:
                        detail_parts.append(" ".join(entry_parts))
                
                # 모든 부분을 세미콜론 구분자로 결합
                if detail_parts:
                    v_obj["analysis"]["detail"] = "; ".join(detail_parts)
                
                # AFFECTED statement의 action_statement를 recommendation으로 사용
                if affected_stmt and affected_stmt.action_statement:
                    if affected_stmt.action_statement != "No remediation information available":
                        v_obj["recommendation"] = affected_stmt.action_statement
            elif state == "exploitable":
                # FIXED: For exploitable state (AFFECTED + NOT_AFFECTED mix):
                # - analysis.detail: only NOT_AFFECTED statements with format "product_name: impact_statement"
                # - affected content is NOT included in detail (only goes to recommendation)
                # - If only AFFECTED exists (no NOT_AFFECTED), skip analysis.detail entirely
                
                action_stmt = None
                not_affected_details = []
                
                # 상태별로 statements 분리
                for st in stmts:
                    if st.status.value == VulnerabilityStatus.AFFECTED and st.action_statement:
                        if not action_stmt:
                            action_stmt = st.action_statement
                    
                    elif st.status.value == VulnerabilityStatus.NOT_AFFECTED:
                        # subject_refs에서 제품명 가져오기
                        product_name = None
                        if st.subject_refs:
                            # 첫 번째 subject_ref를 제품 식별자로 사용
                            ref = st.subject_refs[0]
                            # PURL에서 의미있는 이름 추출 또는 그대로 사용
                            if "pkg:" in ref:
                                # PURL에서 이름 추출: pkg:type/namespace/name@version
                                parts = ref.split("/")
                                if len(parts) >= 2:
                                    name_part = parts[-1].split("@")[0]
                                    product_name = name_part
                                else:
                                    product_name = ref
                            else:
                                product_name = ref
                        
                        # impact_statement 가져오기
                        impact = st.status.impact_statement
                        if impact and product_name:
                            not_affected_details.append(f"{product_name}: {impact}")
                        elif impact:
                            not_affected_details.append(impact)
                
                # NOT_AFFECTED statements에서만 analysis.detail 생성
                if not_affected_details:
                    v_obj["analysis"]["detail"] = "; ".join(not_affected_details)
                # 참고: not_affected_details 없으면 analysis.detail 의도적으로 생략
                # to avoid duplication with recommendation field
            
            # analysis 타임스탬프 복원 (firstIssued, lastUpdated)
            original_first_issued = get_extension_field(vv, "cyclonedx", "analysis.firstIssued")
            if original_first_issued and self.options.restore:
                v_obj["analysis"]["firstIssued"] = original_first_issued
            
            original_last_updated = get_extension_field(vv, "cyclonedx", "analysis.lastUpdated")
            if original_last_updated and self.options.restore:
                v_obj["analysis"]["lastUpdated"] = original_last_updated
            
            # VDR (Vulnerability Disclosure Report) field restoration
            # detail - detailed description
            detail = get_extension_field(vv, "cyclonedx", "detail")
            if detail:
                v_obj["detail"] = detail
            
            # recommendation - fix recommendations
            recommendation = get_extension_field(vv, "cyclonedx", "recommendation")
            if recommendation:
                v_obj["recommendation"] = recommendation
            
            # workaround - temporary mitigation
            workaround = get_extension_field(vv, "cyclonedx", "workaround")
            if workaround:
                v_obj["workaround"] = workaround
            
            # proofOfConcept - POC
            proof_of_concept = get_extension_field(vv, "cyclonedx", "proofOfConcept")
            if proof_of_concept:
                v_obj["proofOfConcept"] = proof_of_concept
            
            # credits - discoverer information
            credits = get_extension_field(vv, "cyclonedx", "credits")
            if credits:
                v_obj["credits"] = credits

            # 5번째로 affects 추가
            v_obj["affects"] = affects

            # state가 not_affected인 경우에만 justification 추가
            # (justification is only valid for not_affected state in CycloneDX)
            just_enum, custom_just, original_just_str = None, None, None
            for st in stmts:
                # custom_justification 먼저 확인
                if st.status.custom_justification:
                    custom_just = st.status.custom_justification
                    # CycloneDX 형식이면 ("cyclonedx:"로 시작) 유지
                    # OpenVEX 형식이면 enum으로 매핑 시도
                    if not custom_just.startswith("cyclonedx:"):
                        # OpenVEX justification을 enum으로 매핑 시도
                        just_enum = map_openvex_justification_str_to_enum(custom_just)
                        if just_enum:
                            original_just_str = custom_just
                            custom_just = None  # just_enum 사용을 위해 custom_just 초기화
                    break
                elif st.status.justification:
                    just_enum = st.status.justification
                    original_just_str = justification_enum_to_openvex_str(st.status.justification)
                    break

            # state가 "not_affected"인 경우에만 justification 추가
            if state == "not_affected":
                # CycloneDX justification인 경우 custom_just 사용
                if custom_just and custom_just.startswith("cyclonedx:"):
                    cdx_just = custom_just[10:]  # "cyclonedx:" 접두사 제거
                    v_obj["analysis"]["justification"] = cdx_just
                elif just_enum:
                    # FIXED: Use direct mapping according to specification
                    # 키워드 분석 없이 - 사용자 요구사항의 정확한 매핑 사용:
                    # - component_not_present → requires_dependency
                    # - vulnerable_code_not_present → code_not_present
                    # - vulnerable_code_not_in_execute_path → code_not_reachable
                    # - vulnerable_code_cannot_be_controlled_by_adversary → requires_environment
                    # - inline_mitigations_already_exist → protected_by_mitigating_control
                    
                    original_just_str = justification_enum_to_openvex_str(just_enum)
                    
                    # 키워드 분석 없이 직접 매핑
                    direct_mapping = {
                        "component_not_present": "requires_dependency",
                        "vulnerable_code_not_present": "code_not_present",
                        "vulnerable_code_not_in_execute_path": "code_not_reachable",
                        "vulnerable_code_cannot_be_controlled_by_adversary": "requires_environment",
                        "inline_mitigations_already_exist": "protected_by_mitigating_control"
                    }
                    
                    cdx_just = direct_mapping.get(original_just_str)
                    
                    # 매핑되지 않은 값은 표준 매핑으로 폴백
                    if not cdx_just:
                        cdx_just = justification_enum_to_cyclonedx_str(just_enum)
                    
                    if cdx_just:
                        v_obj["analysis"]["justification"] = cdx_just

                        # FIXED (OpenVEX Issue 3): Add properties for original justification mapping
                        # analysis.detail 대신 properties 사용
                        if original_just_str and original_just_str != cdx_just:
                            vuln_properties.append({
                                "name": "cdx:vex:original_justification",
                                "value": original_just_str
                            })
                            
                            # impact_statement를 detail에 추가 (original_justification 접두사 제외)
                            impact_stmt = None
                            for st in stmts:
                                if st.status.impact_statement:
                                    impact_stmt = st.status.impact_statement
                                    break
                            if impact_stmt:
                                v_obj["analysis"]["detail"] = impact_stmt
                    else:
                        # 매핑 불가 justification - properties에 저장
                        if original_just_str:
                            vuln_properties.append({
                                "name": "cdx:vex:original_justification",
                                "value": original_just_str
                            })
                            
                            impact_stmt = None
                            for st in stmts:
                                if st.status.impact_statement:
                                    impact_stmt = st.status.impact_statement
                                    break
                            if impact_stmt:
                                v_obj["analysis"]["detail"] = impact_stmt

            elif custom_just:
                # 커스텀 justification - properties에 저장
                vuln_properties.append({
                    "name": "cdx:vex:original_justification",
                    "value": custom_just
                })
                
                impact_stmt = None
                for st in stmts:
                    if st.status.impact_statement:
                        impact_stmt = st.status.impact_statement
                        break
                if impact_stmt:
                    v_obj["analysis"]["detail"] = impact_stmt

            # 아직 추가되지 않은 경우 impact statement를 detail로 추가
            # 형식: "Justification: [justification], Reason: [impact_statement]"
            # FIXED: Only use FIRST justification and reason to avoid overly long detail
            if "detail" not in v_obj.get("analysis", {}):
                # 첫 번째 유효한 justification과 reason 찾기
                first_just_str = None
                first_reason = None
                
                for st in stmts:
                    # 첫 번째 justification 가져오기
                    if not first_just_str:
                        if st.status.justification:
                            first_just_str = st.status.justification.value
                        elif st.status.custom_justification:
                            first_just_str = st.status.custom_justification
                    
                    # 첫 번째 impact_statement (reason) 가져오기
                    if not first_reason and st.status.impact_statement:
                        first_reason = st.status.impact_statement
                    
                    # 둘 다 있으면 중단
                    if first_just_str and first_reason:
                        break
                
                # 단일 detail 항목 생성
                if first_just_str or first_reason:
                    entry_parts = []
                    if first_just_str:
                        entry_parts.append(f"Justification: {first_just_str}")
                    if first_reason:
                        entry_parts.append(f"Reason: {first_reason}")
                    
                    if entry_parts:
                        v_obj["analysis"]["detail"] = ", ".join(entry_parts)

            # false_positive 노트 추가
            if original_state == "false_positive" and "detail" not in v_obj["analysis"]:
                v_obj["analysis"]["detail"] = "False Positive: This vulnerability does not apply to this component."

            # resolved_with_pedigree 노트 추가
            if original_state == "resolved_with_pedigree" and "detail" not in v_obj["analysis"]:
                v_obj["analysis"]["detail"] = "Resolved with pedigree evidence (commit history, diffs available)."

            # 취약점 세부사항 추가
            if vv:
                # ratings already added above in correct order

                # CSAF notes를 analysis.detail로 매핑
                # extension_data에서 원본 notes 카테고리 복원
                if cim.metadata.source_format == DocumentFormat.CSAF and vv.notes:
                    detail_notes = []
                    
                    # extension_data에 원본 notes 존재 여부 확인
                    original_notes = get_extension_field(vv, "csaf", "notes")
                    
                    for note in vv.notes:
                        category = note.get("category", "")
                        text = note.get("text", "")
                        
                        # extension_data에서 원본 카테고리 찾기
                        original_category = category
                        if original_notes:
                            for orig_note in original_notes:
                                if orig_note.get("text") == text:
                                    original_category = orig_note.get("category", category)
                                    break
                        
                        # "details" 카테고리 notes 포함 (원본 카테고리 기반)
                        if original_category == "details" and text:
                            detail_notes.append(text)
                        # 원래 "details"였던 "summary" 포함 (원본 복원)
                        elif original_category == "details" and category == "summary" and text:
                            detail_notes.append(text)
                        # 기타 비표준 카테고리도 포함
                        elif original_category not in ["description", "summary", "general", "legal_disclaimer"] and text:
                            detail_notes.append(text)
                    
                    if detail_notes:
                        # 순서 유지하면서 detail_notes 중복 제거
                        seen_notes = set()
                        unique_detail_notes = []
                        for note in detail_notes:
                            if note not in seen_notes:
                                seen_notes.add(note)
                                unique_detail_notes.append(note)
                        detail_notes = unique_detail_notes
                        
                        # 기존 detail 있으면 결합
                        if "detail" in v_obj["analysis"]:
                            existing_detail = v_obj["analysis"]["detail"]
                            # 결합 전 중복 확인
                            new_notes = [n for n in detail_notes if n not in existing_detail]
                            if new_notes:
                                combined_detail = existing_detail + " | " + " | ".join(new_notes)
                                v_obj["analysis"]["detail"] = combined_detail
                        else:
                            # notes에서 새 detail 생성
                            v_obj["analysis"]["detail"] = " | ".join(detail_notes)

                # description 별도 유지 (위에서 이미 추가됨)
                # 중복 description/cwes 추가 건너뛰기

                if vv.references:
                    refs_data = []
                    for r in vv.references:
                        # Reference.id 사용 (가능한 경우, CycloneDX에서)
                        ref_id = r.id
                        
                        # FIXED: If no id, extract last part from URL (not full URL)
                        if not ref_id and r.url:
                            if "CVE-" in r.url:
                                # URL에서 CVE-ID 추출
                                import re
                                cve_match = re.search(r'CVE-\d{4}-\d+', r.url)
                                if cve_match:
                                    ref_id = cve_match.group(0)
                            elif "bugzilla.redhat.com" in r.url and "id=" in r.url:
                                # RHBZ# 형식 추출
                                import re
                                bz_match = re.search(r'id=(\d+)', r.url)
                                if bz_match:
                                    ref_id = f"RHBZ#{bz_match.group(1)}"
                            elif "bugzilla" in r.url and "id=" in r.url:
                                # 일반 bugzilla: id=12345 → BZ#12345
                                import re
                                bz_match = re.search(r'id=(\d+)', r.url)
                                if bz_match:
                                    ref_id = f"BZ#{bz_match.group(1)}"
                            else:
                                # FIXED: Extract last path segment from URL
                                # https://security.enterprisedb.com/advisories/EDB-SA-2026-001 → EDB-SA-2026-001
                                try:
                                    from urllib.parse import urlparse
                                    parsed = urlparse(r.url)
                                    path = parsed.path.rstrip('/')
                                    if path:
                                        last_segment = path.split('/')[-1]
                                        if last_segment:
                                            ref_id = last_segment
                                except:
                                    pass

                        # summary가 URL과 같거나 없으면 도메인명 추출
                        name = r.summary or "Ref"
                        if name == r.url or name == "Ref":
                            # URL에서 도메인 추출
                            try:
                                from urllib.parse import urlparse
                                parsed = urlparse(r.url) if r.url else None
                                if parsed:
                                    domain = parsed.netloc
                                    if domain:
                                        # 도메인을 읽기 쉬운 이름으로 변환
                                        if 'nvd.nist.gov' in domain:
                                            name = "NVD"
                                        elif 'cve.org' in domain:
                                            name = "CVE.org"
                                        elif 'github.com' in domain:
                                            name = "GitHub Advisories"
                                        elif 'access.redhat.com' in domain:
                                            name = "Red Hat"
                                        elif 'bugzilla.redhat.com' in domain:
                                            name = "RHBZ"
                                        elif 'bugzilla' in domain:
                                            name = "Bugzilla"
                                        else:
                                            # 도메인을 이름으로 사용
                                            name = domain
                            except:
                                pass

                        # reference 객체 구성
                        ref_obj = {}
                        if ref_id:
                            ref_obj["id"] = ref_id
                        if r.url:
                            if "source" not in ref_obj:
                                ref_obj["source"] = {}
                            ref_obj["source"]["url"] = r.url
                        if name and name != "Ref":
                            if "source" not in ref_obj:
                                ref_obj["source"] = {}
                            ref_obj["source"]["name"] = name
                        
                        if ref_obj:
                            refs_data.append(ref_obj)

                    refs_data = dedupe_references(refs_data)
                    if refs_data:
                        v_obj["references"] = refs_data
                
                # extension_data에서 recommendation 복원
                recommendation = get_extension_field(vv, "cyclonedx", "recommendation")
                if recommendation:
                    v_obj["recommendation"] = recommendation

                # CSAF에서 remediations 처리
                if vv.remediations:
                    # 이 취약점에 대한 모든 remediations 수집
                    # affected뿐만 아니라 모든 product IDs 가져오기
                    # remediations는 모든 상태에 적용 가능 (affected, not_affected, fixed 등)
                    all_pids = set()
                    for st in stmts:
                        for ref in st.subject_refs:
                            mapped_ref = ref_mapping.get(ref, ref)
                            all_pids.add(mapped_ref)

                    response_list = []
                    workaround_list = []
                    recommendation_list = []
                    advisories_list = []  # 새로 추가: remediation URL 수집

                    for rem in vv.remediations:
                        category = rem.get("category", "")
                        details = rem.get("details", "")
                        url = rem.get("url", "")  # advisories용 URL 추출
                        rem_product_ids = set(rem.get("product_ids", []))

                        # 이 remediation이 영향받는 제품에 적용되는지 확인
                        # product_ids가 없으면 모든 영향받는 제품에 적용
                        if rem_product_ids:
                            # product_ids가 지정된 경우에만 교집합 확인
                            if not rem_product_ids.intersection(all_pids):
                                # 어떤 영향받는 제품에도 적용되지 않는 remediations 건너뛰기
                                continue
                        # product_ids 없으면 모든 영향받는 제품에 적용

                        # 1:1 필드 매핑 (접두사 없음, 중복 없음)
                        # vendor_fix → recommendation만
                        # workaround/mitigation → workaround만
                        # url → advisories
                        
                        if category == "vendor_fix":
                            response_list.append("update")
                            # vendor_fix details → recommendation (접두사 없이)
                            if details:
                                recommendation_list.append(details)
                            # advisories용 URL 수집
                            if url:
                                advisories_list.append({
                                    "title": "Vendor Fix URL",
                                    "url": url
                                })
                            # 추적
                            self.tracking_table.add(
                                source_field="vulnerabilities.remediations.category",
                                source_value="vendor_fix",
                                target_field="vulnerabilities.analysis.response",
                                target_value="update",
                                rule="CSAF vendor_fix → CycloneDX update",
                                status="TRANSFORMED"
                            )

                        elif category == "workaround":
                            response_list.append("workaround_available")
                            # workaround details → workaround만 (접두사 없음, recommendation 없음)
                            if details:
                                workaround_list.append(details)
                            # advisories용 URL 수집
                            if url:
                                advisories_list.append({
                                    "title": "Workaround URL",
                                    "url": url
                                })
                            # 추적
                            self.tracking_table.add(
                                source_field="vulnerabilities.remediations.category",
                                source_value="workaround",
                                target_field="vulnerabilities.analysis.response",
                                target_value="workaround_available",
                                rule="CSAF workaround → CycloneDX workaround_available",
                                status="TRANSFORMED"
                            )

                        elif category == "mitigation":
                            # 키워드 확인: rollback 키워드
                            if details and any(kw in details.lower() for kw in ["rollback", "revert", "previous version", "downgrade", "older release"]):
                                response_list.append("rollback")
                            else:
                                response_list.append("workaround_available")
                            # mitigation details → workaround만 (접두사 없음, recommendation 없음)
                            if details:
                                workaround_list.append(details)
                            # advisories용 URL 수집
                            if url:
                                advisories_list.append({
                                    "title": "Mitigation URL",
                                    "url": url
                                })

                        elif category == "no_fix_planned":
                            response_list.append("will_not_fix")
                            # recommendation/workaround에 추가하지 않음
                            # 추적
                            self.tracking_table.add(
                                source_field="vulnerabilities.remediations.category",
                                source_value="no_fix_planned",
                                target_field="vulnerabilities.analysis.response",
                                target_value="will_not_fix",
                                rule="CSAF no_fix_planned → CycloneDX will_not_fix",
                                status="TRANSFORMED"
                            )

                        elif category == "none_available":
                            # CSAF none_available: 
                            # - exploitable 상태면: can_not_fix 추가 (response 있어야 함)
                            # - 그렇지 않으면: response 생략
                            if state == "exploitable":
                                response_list.append("can_not_fix")
                                # 추적
                                self.tracking_table.add(
                                    source_field="vulnerabilities.remediations.category",
                                    source_value="none_available",
                                    target_field="vulnerabilities.analysis.response",
                                    target_value="can_not_fix",
                                    rule="CSAF none_available (exploitable) → CycloneDX can_not_fix",
                                    status="TRANSFORMED"
                                )
                            else:
                                # 추적
                                self.tracking_table.add(
                                    source_field="vulnerabilities.remediations.category",
                                    source_value="none_available",
                                    target_field="vulnerabilities.analysis.response",
                                    target_value="(omitted)",
                                    rule="CSAF none_available (non-exploitable) → CycloneDX response omitted",
                                    status="TRANSFORMED"
                                )

                        elif category == "fix_planned":
                            response_list.append("update")
                            # recommendation/workaround에 추가하지 않음

                        elif category == "optional_patch":
                            response_list.append("update")
                            # recommendation/workaround에 추가하지 않음

                        else:
                            # 알 수 없는 카테고리 - 건너뛰기 (어떤 필드에도 추가 안 함)
                            pass

                    # analysis.detail은 remediation이 아닌 IMPACT STATEMENT만 포함해야 함
                    # threats.details 또는 impact_statement를 사용 가능하면 사용
                    # recommendation/workaround 내용을 여기에 넣지 않음

                    # v_obj에 추가
                    if response_list:
                        # 중복 제거하되 순서 유지
                        seen = set()
                        unique_responses = []
                        for r in response_list:
                            if r not in seen:
                                seen.add(r)
                                unique_responses.append(r)

                        if "response" not in v_obj["analysis"]:
                            v_obj["analysis"]["response"] = unique_responses
                        else:
                            # 기존 responses와 병합
                            existing = v_obj["analysis"]["response"]
                            if not isinstance(existing, list):
                                existing = [existing]
                            for r in unique_responses:
                                if r not in existing:
                                    existing.append(r)
                            v_obj["analysis"]["response"] = existing

                    # workaround 필드 - 다중 항목을 구분자로 연결
                    if workaround_list:
                        v_obj["workaround"] = " | ".join(workaround_list)

                    # recommendation 필드 - 첫 번째 vendor_fix만 (접두사 없이)
                    if recommendation_list:
                        v_obj["recommendation"] = recommendation_list[0]  # 첫 번째 (주요) 수정 사용
                        
                    # advisories 필드 - URL 보존
                    if advisories_list:
                        v_obj["advisories"] = advisories_list

            # 있으면 EPSS properties 추가
            if epss_properties:
                if "properties" not in v_obj:
                    v_obj["properties"] = []
                v_obj["properties"].extend(epss_properties)

            # 수정됨 (OpenVEX 이슈 4): aliases를 references로 추가 (properties가 아님)
            if vuln_references:
                if "references" not in v_obj:
                    v_obj["references"] = []
                # alias references 추가 (중복 방지)
                existing_ids = {r.get("id") for r in v_obj["references"]}
                for ref in vuln_references:
                    if ref.get("id") not in existing_ids:
                        v_obj["references"].append(ref)
                        existing_ids.add(ref.get("id"))

            # 수정됨 (OpenVEX 이슈 2, 3): vulnerability properties 추가 (aliases, original_justification 등)
            if vuln_properties:
                if "properties" not in v_obj:
                    v_obj["properties"] = []
                v_obj["properties"].extend(vuln_properties)

            # CycloneDX 1.7 사양 순서에 맞게 v_obj 필드 재정렬
            # 스키마 순서: bom-ref, id, source, references, ratings, cwes, description, 
            #              detail, recommendation, workaround, proofOfConcept, advisories,
            #              created, published, updated, rejected, credits, tools, analysis, affects, properties
            cyclonedx_vuln_field_order = [
                "bom-ref", "id", "source", "references", "ratings", "cwes", "description",
                "detail", "recommendation", "workaround", "proofOfConcept", "advisories",
                "created", "published", "updated", "rejected", "credits", "tools",
                "analysis", "affects", "properties"
            ]
            ordered_v_obj = {}
            for field in cyclonedx_vuln_field_order:
                if field in v_obj:
                    ordered_v_obj[field] = v_obj[field]
            # 순서 목록에 없는 나머지 필드 추가
            for field in v_obj:
                if field not in ordered_v_obj:
                    ordered_v_obj[field] = v_obj[field]

            out.append(ordered_v_obj)
        return out

    @staticmethod
    def _rating(r: CvssRating) -> Dict:
        o = {}

        # CVSS 계산기 URL과 함께 source를 먼저 추가
        if r.vector and r.method:
            # method에서 CVSS 버전 결정
            version = None
            if "CVSSv3.1" in r.method or "3.1" in r.method:
                version = "3.1"
            elif "CVSSv3.0" in r.method or "3.0" in r.method:
                version = "3.0"
            elif "CVSSv2" in r.method or "2" in r.method:
                version = "2"

            if version and version in ["3.0", "3.1"]:
                # CVSS 계산기 URL 구성
                vector_clean = r.vector
                if vector_clean.startswith("CVSS:"):
                    vector_clean = vector_clean.split("/", 1)[1] if "/" in vector_clean else vector_clean

                calc_url = f"https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector={vector_clean}&version={version}"
                o["source"] = {
                    "name": "NVD",
                    "url": calc_url
                }

        # 순서: score, severity, method, vector (요청된 대로)
        if r.score is not None:
            o["score"] = r.score
        if r.severity:
            # severity를 소문자로 정규화 (CycloneDX 요구사항)
            o["severity"] = r.severity.lower()
        if r.method:
            # method를 CycloneDX 형식으로 정규화
            # CVSSv3.1 → CVSSv31, CVSSv3.0 → CVSSv3, CVSSv2 → CVSSv2
            method = r.method
            if "CVSSv3.1" in method or method == "CVSSv3.1":
                o["method"] = "CVSSv31"
            elif "CVSSv3.0" in method or method == "CVSSv3.0" or method == "CVSSv3":
                o["method"] = "CVSSv3"
            elif "CVSSv2" in method or method == "CVSSv2":
                o["method"] = "CVSSv2"
            elif method in ["CVSSv4", "OWASP", "SSVC", "other"]:
                o["method"] = method
            else:
                # 기본값: 그대로 사용
                o["method"] = method

        # 수정됨 (이슈 2): CVSS vector 문자열 그대로 보존
        # CycloneDX 1.6+는 접두사를 포함한 전체 vector 문자열 필요
        # "CVSS:3.1/" 접두사 제거하지 않음 - 버전 감지에 필요
        if r.vector:
            o["vector"] = r.vector  # 원본 vector 문자열 변경 없이 유지

        return o

class CIMToCSAF:
    def __init__(self, options: ConversionOptions, tracking_table: TrackingTable = None):
        self.options = options
        self.tracking_table = tracking_table or TrackingTable()

    def convert(self, cim: CIM) -> Dict:
        pub = cim.metadata.publisher

        # original_id가 URL이면 namespace 추출
        namespace = pub.namespace

        # namespace에 https:// 접두사 보장
        if namespace and not namespace.startswith(("http://", "https://")):
            namespace = f"https://{namespace}"

        if not namespace and cim.metadata.original_id:
            original_id = cim.metadata.original_id
            if original_id.startswith("http://") or original_id.startswith("https://"):
                # URL에서 도메인 추출: https://openvex.dev/docs/... → https://openvex.dev
                from urllib.parse import urlparse
                parsed = urlparse(original_id)
                namespace = f"{parsed.scheme}://{parsed.netloc}"

        # 깨끗한 author 기반 namespace로 폴백 (.example.com 없이)
        if not namespace:
            if pub.name == "Unknown":
                # 알 수 없는 publisher에 대해 일반 namespace 사용
                namespace = "https://csaf.io/unknown"
            else:
                namespace = f"https://{pub.name.lower().replace(' ', '-')}.com"

        full_product_names = []
        product_id_map = {}  # original_ref → simple_id

        # bomlink 생성을 위한 serial number 가져오기
        serial_number = cim.metadata.original_id or f"urn:uuid:{cim.metadata.id}"

        # branches 구조를 위한 제품 정보 수집
        products_by_vendor = {}  # vendor → {product_name → [versions]}

        for s in cim.subjects:
            # product_id 단순화
            purl = next((i.value for i in s.identifiers if i.type == "purl"), None)
            cpe = next((i.value for i in s.identifiers if i.type == "cpe"), None)

            # 먼저 vendor 추출 (고유 product_id에 필요)
            # vendor 정규화: purl 기반으로 표준화
            vendor = "Unknown Vendor"
            base_product_name = s.name or ""
            version = s.version  # Subject.version으로 시작 (가장 정확)
            product_name = base_product_name
            
            # 이 subject가 CycloneDX에서 버전 범위 정보를 가지는지 확인
            is_version_range = get_extension_field(s, "cyclonedx", "is_version_range")
            version_range = get_extension_field(s, "cyclonedx", "version_range")

            # 먼저 PURL에서 vendor 추출 시도
            if purl:
                try:
                    # PURL 정규화: 쿼리 문자열 제거 (예: repository_url)
                    # pkg:oci/trivy?repository_url=... → pkg:oci/trivy
                    normalized_purl = purl.split("?")[0].split("#")[0]
                    
                    # pkg:type/namespace/name@version 또는 pkg:type/name@version
                    parts = normalized_purl.split("/")
                    
                    if len(parts) >= 3:
                        # pkg:type/namespace/name - namespace가 vendor
                        vendor = parts[1]
                        # 제품 이름 추출
                        name_part = parts[-1].split("@")[0]
                        if name_part:
                            product_name = name_part
                    elif len(parts) == 2:
                        # pkg:type/name - type을 vendor로 사용
                        pkg_type = normalized_purl.split(":")[1].split("/")[0]
                        vendor = pkg_type.capitalize()
                        # 제품 이름 추출
                        name_part = parts[-1].split("@")[0]
                        if name_part:
                            product_name = name_part

                    # s.version이 설정되지 않은 경우에만 purl에서 버전 추출
                    if not version and "@" in normalized_purl:
                        version_part = normalized_purl.split("@")[1]
                        if version_part:
                            version = version_part
                except:
                    pass

            # CPE에서 vendor 추출 시도
            if not vendor or vendor == "Unknown Vendor":
                if cpe:
                    try:
                        # cpe:2.3:a:vendor:product:version:...
                        cpe_parts = cpe.split(":")
                        if len(cpe_parts) >= 4:
                            vendor = cpe_parts[3]
                            if len(cpe_parts) >= 5:
                                product_name = cpe_parts[4]
                            if len(cpe_parts) >= 6:
                                version = cpe_parts[5]
                    except:
                        pass

            # 최종: 항상 product_name 정리 (남은 버전 패턴 제거)
            import re
            if product_name:
                # "vers:..." 패턴 제거: "product-ABC vers:generic/>=1.0|<=2.3" → "product-ABC"
                product_name = re.sub(r'\s+vers:[^\s]+', '', product_name)
                # 후행 버전 제거: " 1.0", " v2.4", " 2.4.1"
                product_name = re.sub(r'\s+v?\d+[\.\d]*.*$', '', product_name)
                # 후행 버전 제거: "-1.0", "-v2.4", "-2.4.1"  
                product_name = re.sub(r'-v?\d+[\.\d]*.*$', '', product_name)
                # 후행 버전 제거: "_1.0", "_v2.4", "_2.4.1"
                product_name = re.sub(r'_v?\d+[\.\d]*.*$', '', product_name)
                # product_name이 버전 번호나 범위만 있으면 제거
                if re.match(r'^v?\d+[\.\d]*$', product_name) or product_name.startswith('vers:'):
                    product_name = "product"  # 폴백 이름
                # 빈 이름 제거
                if not product_name or product_name.strip() == "":
                    product_name = "product"

            # vendor/product 중복 방지 및 정규화
            if vendor and product_name:
                # 같으면 vendor를 Unknown Vendor로 설정
                if vendor.lower() == product_name.lower():
                    vendor = "Unknown Vendor"
                # vendor 표준화 (oci, Oci, OCI → oci)
                vendor = vendor.strip()
                if vendor.lower() == "oci":
                    vendor = "oci"

            # 이제 vendor 접두사와 버전으로 고유한 product_id 생성
            # 이렇게 하면 같은 제품 이름을 가진 다른 vendor가 다른 ID를 갖게 됨
            base_simple_id = simplify_product_id(purl or cpe or s.ref, product_name)

            # vendor를 포함하여 product_id를 고유하게 만듦
            # 우선순위 0 (신규): PURL이 있는 CycloneDX 소스는 PURL을 product_id로 직접 사용
            # 원본 식별자를 보존하고 중복 제품 정의를 방지
            use_purl_as_id = False
            if cim.metadata.source_format == DocumentFormat.CYCLONEDX and purl:
                # CycloneDX의 경우 PURL이 정식 식별자
                use_purl_as_id = True
            
            # 우선순위 1: CSAF에서 original_id가 있고 버전이 일치하면 직접 사용
            # 버전 범위와 다른 버전은 반드시 고유한 product_id를 가져야 함
            use_original_id = False
            if not use_purl_as_id and s.original_id and not s.original_id.startswith("urn:cdx") and not is_version_range:
                # original_id의 버전이 subject 버전과 일치하는지 확인
                # 예: original_id="pkg:npm/@webframe/auth@2.8.0"이지만 version="2.8.1" → 사용 안 함
                if version and version != "unknown":
                    # original_id에 @가 포함되면 버전 추출
                    if "@" in s.original_id:
                        orig_version = s.original_id.split("@")[-1].split("?")[0].split("#")[0]
                        if orig_version == version:
                            use_original_id = True
                    else:
                        # original_id에 버전 없음, 사용 안 함
                        pass
                else:
                    # 버전 미지정, original_id 사용 가능
                    use_original_id = True
            
            if use_purl_as_id:
                # CycloneDX 소스의 경우 PURL을 product_id로 직접 사용
                simple_id = purl
                product_id_map[s.ref] = simple_id
            elif use_original_id:
                # 원본 CSAF product_id 직접 사용 (수정 없이)
                simple_id = s.original_id
                product_id_map[s.ref] = simple_id
            else:
                # 우선순위 2: 새 product_id 생성
                vendor_prefix = vendor.lower().replace(" ", "-").replace(".", "-")[:20]
                if vendor_prefix and vendor_prefix != "unknown-vendor":
                    simple_id = f"{vendor_prefix}-{base_simple_id}"
                else:
                    simple_id = base_simple_id
                
                # 중요: CycloneDX에서 버전 범위 처리
                # 버전 범위는 영향받는 범위 vs 수정된 버전에 대해 별도 제품 생성
                if is_version_range and version_range:
                    # 버전 범위임 (예: vers:semver/<2.8.1)
                    # 범위 접미사로 product_id 생성: auth@range:<2.8.1
                    # 범위 단순화: vers:semver/<2.8.1 → <2.8.1
                    import re
                    range_suffix = version_range
                    # vers:semver/... 형식에서 단순 범위 추출
                    match = re.search(r'vers:[^/]+/(.+)', version_range)
                    if match:
                        range_suffix = match.group(1)
                    simple_id = f"{simple_id}@range:{range_suffix}"
                elif version and version != "unknown":
                    # 일반 버전 - product_id에 포함
                    if version not in simple_id and not simple_id.endswith(version):
                        simple_id = f"{simple_id}@{version}"
                else:
                    # 버전 없음 또는 unknown: 아직 없으면 ":unknown" 추가
                    if not simple_id.endswith(":unknown"):
                        simple_id = f"{simple_id}:unknown"

                product_id_map[s.ref] = simple_id

            # 계층 구조에 저장
            if vendor not in products_by_vendor:
                products_by_vendor[vendor] = {}

            if product_name not in products_by_vendor[vendor]:
                products_by_vendor[vendor][product_name] = []

            # 포괄적인 제품 식별 헬퍼 생성
            pih = create_product_identification_helper(s, serial_number)

            # 추가 전에 중복 product_id 확인
            existing_ids = [v["product_id"] for v in products_by_vendor[vendor][product_name]]
            if simple_id not in existing_ids:
                products_by_vendor[vendor][product_name].append({
                    "product_id": simple_id,
                    "name": product_name,  # 제품 이름만, 버전 없이
                    "version": version,
                    "pih": pih,
                    "subject": s
                })

        # tracking ID 생성
        # 먼저 extension_data에서 복원 시도
        tracking_id = get_extension_field(cim.metadata, "csaf", "tracking.id")
        
        if not tracking_id:
            # URL이 아니면 original_id로 폴백
            if cim.metadata.original_id and not cim.metadata.original_id.startswith(("http://", "https://")):
                tracking_id = cim.metadata.original_id.strip()
            else:
                # 새 tracking ID 생성: CSAF-YYYYMMDD-NNNN
                from datetime import datetime
                date_str = datetime.now().strftime("%Y%m%d")
                tracking_id = f"CSAF-{date_str}-{cim.metadata.id[:8]}"

        # 먼저 extension_data에서 원본 branches 복원 시도
        original_branches = get_extension_field(cim.metadata, "csaf", "product_tree.branches")
        
        if original_branches:
            # 원본 branches 구조 사용, 단 CSAF 2.0 준수를 위해 purl → purls 변환
            def convert_purl_to_purls(branch):
                """branches에서 'purl' (단일)을 'purls' (배열)로 재귀 변환"""
                if "product" in branch:
                    pih = branch["product"].get("product_identification_helper", {})
                    if pih and "purl" in pih and "purls" not in pih:
                        # 단일 purl을 purls 배열로 변환
                        pih["purls"] = [pih["purl"]]
                        del pih["purl"]
                
                # 하위 branches 재귀 처리
                if "branches" in branch:
                    for sub_branch in branch["branches"]:
                        convert_purl_to_purls(sub_branch)
                
                return branch
            
            # 모든 branches 변환
            branches = [convert_purl_to_purls(b.copy()) for b in original_branches]
        else:
            # branches 구조 구성: vendor -> product_name -> product_version
            # product_tree에 버전 범위 포함
            # 버전 범위는 vulnerabilities에서 참조될 수 있는 유효한 제품
            branches = []
            for vendor, products in sorted(products_by_vendor.items()):
                product_branches = []

                for product_name, versions in sorted(products.items()):
                    version_branches = []
                    
                    # 중복 방지를 위해 이미 추가된 버전 추적
                    added_product_ids = set()

                    for v_info in versions:
                        version = v_info["version"]
                        product_id = v_info["product_id"]
                    
                        # 버전 없는 subject 건너뛰기 (version이 None 또는 빈 값)
                        if not version or version in ["unknown", ""]:
                            continue
                        
                        # product_id가 이미 추가되었으면 건너뛰기 (중복 방지)
                        if product_id in added_product_ids:
                            continue
                        added_product_ids.add(product_id)

                        # 버전 범위인지 결정
                        is_range = version.startswith("vers:") or ">=" in version or "<" in version or "|" in version
                        
                        # 수정됨 (CDX 이슈 2): vers 표기법이 있는 버전 범위에 product_version_range 사용
                        if is_range:
                            import re
                            category = "product_version_range"
                            
                            # name 필드용 vers 표기법 구성
                            if version.startswith("vers:"):
                                name = version
                            else:
                                # 가능하면 purl에서 패키지 타입 가져오기
                                purl = None
                                if v_info.get("subject") and v_info["subject"].identifiers:
                                    for ident in v_info["subject"].identifiers:
                                        if ident.type == "purl" and ident.value:
                                            purl = ident.value
                                            break
                                
                                pkg_type = "generic"
                                if purl:
                                    match = re.match(r'pkg:([^/]+)/', purl)
                                    if match:
                                        pkg_type = match.group(1)
                                
                                name = f"vers:{pkg_type}/{version}"
                        else:
                            category = "product_version"
                            name = version

                        # 전체 제품 이름 구성: "Vendor Product Version"
                        full_name_parts = []
                        if vendor and vendor != "Unknown Vendor":
                            full_name_parts.append(vendor)
                        full_name_parts.append(product_name)
                        if is_range:
                            # 제품 이름용 단순화된 표시 버전
                            import re
                            display_range = version
                            match = re.search(r'vers:[^/]+/(.+)', version)
                            if match:
                                display_range = match.group(1)
                            full_name_parts.append(f"(range: {display_range})")
                        elif version:
                            full_name_parts.append(version)

                        full_product_name = " ".join(full_name_parts)
                    
                        # 제품 이름이 product_id와 다른지 확인
                        product_display_name = full_product_name
                        if product_display_name == product_id:
                            if version and version != "unknown":
                                product_display_name = f"{product_name} {version}"
                            else:
                                product_display_name = f"{product_name} (unversioned)"
                        
                        # product identification helper 생성
                        # 버전 범위의 경우 특정 PURL이 있는 PIH 포함하지 않음
                        pih = v_info.get("pih")
                        if is_range:
                            # 범위에 PURL 포함하지 않음 (PURL에 범위 불가)
                            pih = None

                        version_branch = {
                            "category": category,
                            "name": name,
                            "product": {
                                "product_id": product_id,
                                "name": product_display_name
                            }
                        }

                        if pih:
                            version_branch["product"]["product_identification_helper"] = pih

                        version_branches.append(version_branch)

                    # version_branches가 있는 경우에만 product_branch 추가
                    if version_branches:
                        product_branch = {
                            "category": "product_name",
                            "name": product_name,
                            "branches": version_branches
                        }
                        product_branches.append(product_branch)

                # product_branches가 있는 경우에만 vendor_branch 추가
                if product_branches:
                    vendor_branch = {
                        "category": "vendor",
                        "name": vendor,
                        "branches": product_branches
                    }
                    branches.append(vendor_branch)

        # branches에 있는 제품 확인
        products_in_branches = set()
        for vendor_branch in branches:
            for product_branch in vendor_branch.get("branches", []):
                for version_branch in product_branch.get("branches", []):
                    if "product" in version_branch:
                        products_in_branches.add(version_branch["product"]["product_id"])
        
        # CHANGED: Always use branches structure only (not full_product_names)
        # 일반 모드와 복원 모드 간 일관성 보장
        # 모든 제품은 이미 branches에 있어야 함
        full_product_names = []
        
        # product_tree 구성
        pt = {}
        
        # 빈 branches를 재귀적으로 제거하는 헬퍼 함수
        def remove_empty_branches(branch):
            """
            branch 구조에서 빈 branches 배열을 재귀적으로 제거.
            CSAF는 branches가 존재하면 비어있지 않아야 함.
            """
            if "branches" in branch:
                # 빈 또는 None branches 필터링
                non_empty = [
                    remove_empty_branches(b) 
                    for b in branch["branches"] 
                    if b is not None
                ]
                
                if non_empty:
                    # 비어있지 않은 branches 유지
                    branch["branches"] = non_empty
                else:
                    # 빈 branches 필드 완전히 제거
                    del branch["branches"]
            
            return branch
        
        # branches가 비어있지 않으면 추가
        if branches:
            # 빈 branches 재귀적으로 정리
            cleaned_branches = []
            for vb in branches:
                if vb.get("branches"):  # 제품 branches가 있음
                    cleaned_vb = remove_empty_branches(vb.copy())
                    # 정리 후에도 branches가 있으면 추가
                    if "branches" in cleaned_vb or "product" in cleaned_vb:
                        cleaned_branches.append(cleaned_vb)
            
            if cleaned_branches:
                pt["branches"] = cleaned_branches
        
        # branches에 없는 제품이 있으면 full_product_names에 추가
        if full_product_names:
            pt["full_product_names"] = full_product_names
        
        # 중요: product_tree에 최소 하나의 제품 정의가 있어야 함
        # CSAF는 product_tree에 최소 하나의 제품이 필요함
        if not pt:
            # branches도 없고 full_product_names도 없음 - 오류 상황
            # 폴백으로 모든 subjects를 full_product_names에 추가
            full_product_names = []
            for s in cim.subjects:
                product_id = product_id_map.get(s.ref, s.ref)
                product_name = s.name or product_id
                pih = create_product_identification_helper(s, serial_number)
                
                fpn = {
                    "product_id": product_id,
                    "name": product_name
                }
                
                if pih:
                    fpn["product_identification_helper"] = pih
                
                full_product_names.append(fpn)
            
            if full_product_names:
                pt["full_product_names"] = full_product_names
        
        # CycloneDX metadata.component 처리 - product_family 카테고리 사용
        # vendor → product_family → product_name → product_version 구조 생성
        metadata_component = get_extension_field(cim.metadata, "cyclonedx", "metadata.component")
        root_product_id = None
        
        if cim.metadata.source_format == DocumentFormat.CYCLONEDX and metadata_component:
            # metadata.component 필드 추출
            mc_name = metadata_component.get("name", "Unknown Product")
            mc_version = metadata_component.get("version", "")
            mc_bom_ref = metadata_component.get("bom-ref", mc_name.lower().replace(" ", "-"))
            mc_supplier = metadata_component.get("supplier", {})
            mc_supplier_name = mc_supplier.get("name", "Unknown Vendor") if mc_supplier else "Unknown Vendor"
            
            # 루트 제품 ID
            root_product_id = mc_bom_ref
            
            # vendor → product_family → product_name → product_version 구조 생성
            # 컴포넌트 branches 수집 (product_name → product_version)
            component_branches = []
            seen_components = set()
            
            for s in cim.subjects:
                comp_purl = None
                if s.identifiers:
                    for ident in s.identifiers:
                        if ident.type == "purl" and ident.value:
                            comp_purl = ident.value
                            break
                
                if not comp_purl:
                    comp_purl = s.ref
                
                # 중복 건너뛰기
                if comp_purl in seen_components:
                    continue
                seen_components.add(comp_purl)
                
                # 루트 제품 자체는 건너뛰기
                if comp_purl == root_product_id:
                    continue
                
                comp_name = s.name or ""
                comp_version = s.version or ""
                
                # 컴포넌트 이름 정리 (@webframe/ 같은 네임스페이스 접두사 제거)
                display_name = comp_name
                if display_name.startswith("@") and "/" in display_name:
                    display_name = display_name.split("/")[-1]
                elif "/" in display_name:
                    display_name = display_name.split("/")[-1]
                
                if not display_name:
                    # PURL에서 추출
                    if comp_purl.startswith("pkg:"):
                        parts = comp_purl.split("/")
                        if len(parts) >= 2:
                            last_part = parts[-1]
                            if "@" in last_part:
                                display_name = last_part.split("@")[0]
                            else:
                                display_name = last_part
                
                if not display_name:
                    display_name = comp_purl
                
                # product_identification_helper 생성
                pih = {}
                if comp_purl.startswith("pkg:"):
                    pih["purls"] = [comp_purl]
                
                # CPE가 있으면 추가
                if s.identifiers:
                    for ident in s.identifiers:
                        if ident.type == "cpe" and ident.value:
                            if ident.value.startswith("cpe:2.3:"):
                                pih["cpe"] = ident.value
                            break
                
                # product 객체 생성
                product_obj = {
                    "name": f"{display_name} {comp_version}" if comp_version else display_name,
                    "product_id": comp_purl
                }
                if pih:
                    product_obj["product_identification_helper"] = pih
                
                # product_name → product_version branch 생성
                comp_branch = {
                    "category": "product_name",
                    "name": display_name,
                    "branches": [{
                        "category": "product_version",
                        "name": comp_version if comp_version else "1.0",
                        "product": product_obj
                    }]
                }
                component_branches.append(comp_branch)
            
            # 전체 구조 생성: vendor → product_family → [component branches]
            family_branch = {
                "category": "vendor",
                "name": mc_supplier_name,
                "branches": [{
                    "category": "product_family",
                    "name": mc_name,
                    "branches": component_branches
                }]
            }
            
            # Replace existing branches with new structure
            # (don't append, replace to avoid duplicate product definitions)
            pt["branches"] = [family_branch]
        
        # ========================================
        # subcomponent → relationships 매핑
        # OpenVEX의 subcomponent를 CSAF의 relationships로 변환
        # ========================================
        relationships = []
        combined_product_map = {}  # (child_ref, parent_ref) → combined_product_id
        
        for subj in cim.subjects:
            if subj.parent_ref:
                # subcomponent가 있는 경우 relationship 생성
                child_id = product_id_map.get(subj.ref, subj.ref)
                parent_id = product_id_map.get(subj.parent_ref, subj.parent_ref)
                
                # 결합된 product ID 생성 (예: "CSAFPID-CHILD-IN-PARENT")
                combined_id = f"CSAFPID-{_sanitize_product_id(subj.ref)}-IN-{_sanitize_product_id(subj.parent_ref)}"
                combined_product_map[(subj.ref, subj.parent_ref)] = combined_id
                
                # 이름 생성
                child_name = subj.name or _extract_name_from_purl(subj.ref)
                parent_subj = next((s for s in cim.subjects if s.ref == subj.parent_ref), None)
                parent_name = parent_subj.name if parent_subj else _extract_name_from_purl(subj.parent_ref)
                combined_name = f"{child_name} in {parent_name}"
                
                # product_identification_helper 생성
                pih = {}
                if subj.ref.startswith("pkg:"):
                    pih["purls"] = [subj.ref]
                
                rel = {
                    "category": "installed_on",
                    "full_product_name": {
                        "name": combined_name,
                        "product_id": combined_id
                    },
                    "product_reference": child_id,
                    "relates_to_product_reference": parent_id
                }
                
                if pih:
                    rel["full_product_name"]["product_identification_helper"] = pih
                
                relationships.append(rel)
        
        if relationships:
            pt["relationships"] = relationships
            # 결합된 product_id를 product_id_map에 추가 (vulnerabilities에서 참조하기 위해)
            for (child_ref, parent_ref), combined_id in combined_product_map.items():
                # 기존 child_ref 매핑을 combined_id로 업데이트
                # (취약점 영향은 "라이브러리"가 아닌 "라이브러리를 포함한 서비스"에 적용)
                product_id_map[child_ref] = combined_id
        
        # extension_data에서 product_tree.relationships 복원 (CSAF → CSAF만)
        restored_relationships = get_extension_field(cim.metadata, "csaf", "product_tree.relationships")
        if restored_relationships:
            # relationships에서 purl → purls 변환
            for rel in restored_relationships:
                fpn = rel.get("full_product_name", {})
                pih = fpn.get("product_identification_helper", {})
                if pih and "purl" in pih and "purls" not in pih:
                    pih["purls"] = [pih["purl"]]
                    del pih["purl"]
            pt["relationships"] = restored_relationships
        
        vulns = self._vulns(cim, product_id_map)

        # 자주 사용되는 제품 집합에 대한 product_groups 생성 (일관성을 위해 선택적)
        if self.options.use_csaf_product_groups:
            product_groups = self._create_product_groups(vulns, product_id_map)
            if product_groups:
                pt["product_groups"] = product_groups

        # 소스 형식과 취약점에 따라 제목 설정
        # 제목은 정규 이름이거나 충분히 고유해야 함
        vuln_count = len(set(st.vulnerability_id for st in cim.statements))
        product_count = len(cim.subjects)

        if cim.metadata.source_format == DocumentFormat.CYCLONEDX:
            title = f"CSAF VEX Document for {vuln_count} CVEs across {product_count} Products (CycloneDX-derived)"
        elif cim.metadata.source_format == DocumentFormat.OPENVEX:
            title = f"CSAF VEX Document for {vuln_count} CVEs across {product_count} Products (OpenVEX-derived)"
        else:
            title = f"CSAF VEX Document for {vuln_count} CVEs across {product_count} Products"

        result = {
            "$schema": "https://docs.oasis-open.org/csaf/csaf/v2.1/schema/csaf.json",
            "document": self._build_document(cim, pub, namespace, tracking_id, title),
            "product_tree": pt,
            "vulnerabilities": vulns
        }
        
        # Reversible mode: store metadata in document.notes
        if self.options.reversible:
            lost_data = self._collect_lost_data(cim)
            
            # extension_data 수집
            extension_data = {}
            if cim.metadata.extension_data:
                extension_data["metadata"] = cim.metadata.extension_data
            for idx, subj in enumerate(cim.subjects):
                if subj.extension_data:
                    extension_data[f"subject_{idx}"] = subj.extension_data
            for vuln in cim.vulnerabilities:
                if vuln.extension_data:
                    extension_data[f"vulnerability_{vuln.id}"] = vuln.extension_data
            for idx, stmt in enumerate(cim.statements):
                if stmt.extension_data:
                    extension_data[f"statement_{idx}"] = stmt.extension_data
            
            # subject_mappings 수집
            subject_mappings = {}
            for subj in cim.subjects:
                if subj.original_id:
                    subject_mappings[subj.ref] = subj.original_id
                else:
                    subject_mappings[subj.ref] = subj.ref
            
            if lost_data or extension_data or subject_mappings:
                conv_meta = ConversionMetadata(
                    version="1.0",
                    source_format="CIM",
                    target_format="CSAF",
                    timestamp=dt_to_iso_z(now_utc()),
                    lost_data=lost_data,
                    extension_data=extension_data,
                    subject_mappings=subject_mappings
                )
                encoded = conv_meta.encode()
                
                # Store in document.notes
                if "notes" not in result["document"]:
                    result["document"]["notes"] = []
                
                result["document"]["notes"].insert(0, {
                    "category": "general",
                    "title": "VEXCO Conversion Metadata",
                    "text": encoded
                })
                
                items_count = len(lost_data) + len(extension_data) + len(subject_mappings)
                print(f"\n[Reversible Mode] Stored {items_count} item(s) in document.notes:")
                if lost_data:
                    print(f"  - {len(lost_data)} lost fields (not recoverable)")
                else:
                    print(f"  - 0 lost fields (all data preserved!)")
                if extension_data:
                    print(f"  - {len(extension_data)} extension data entries (recoverable)")
                if subject_mappings:
                    print(f"  - {len(subject_mappings)} subject ID mappings (recoverable)")
        
        # CSAF 2.1 스키마에 따른 필드 순서 적용
        return order_csaf_document(result)
    
    def _collect_lost_data(self, cim: CIM) -> Dict[str, Any]:
        """CSAF 변환에서 손실될 데이터 수집"""
        lost = {}
        
        # CSAF에 매핑되지 않는 OpenVEX/CycloneDX 전용 필드 수집
        # (대부분의 CIM 필드가 CSAF에 매핑되므로 lost_data는 최소)
        
        return lost

    def _build_document(self, cim: CIM, pub: Publisher, namespace: str, tracking_id: str, title: str) -> Dict:
        """extension_data 복원과 함께 CSAF document 섹션 구성"""
        
        # 수정됨 (CycloneDX 이슈 6): CycloneDX/OpenVEX에서 원본 publisher 사용
        # CycloneDX: metadata.component.supplier 또는 metadata.component.manufacturer 사용
        # OpenVEX: author 사용
        # CSAF 복원: 원본 publisher 사용
        
        publisher_name = pub.name
        publisher_namespace = namespace
        publisher_category = "vendor"  # 기본 category
        
        if cim.metadata.source_format == DocumentFormat.CYCLONEDX:
            # metadata.component.supplier 또는 manufacturer에서 publisher 가져오기
            metadata_component = get_extension_field(cim.metadata, "cyclonedx", "metadata.component")
            if metadata_component:
                # 우선순위: supplier.name > manufacturer.name > publisher.name
                supplier = metadata_component.get("supplier", {})
                manufacturer = metadata_component.get("manufacturer", {})
                
                if supplier and supplier.get("name"):
                    publisher_name = supplier["name"]
                    if supplier.get("url"):
                        url_list = supplier["url"]
                        publisher_namespace = url_list[0] if isinstance(url_list, list) else url_list
                elif manufacturer and manufacturer.get("name"):
                    publisher_name = manufacturer["name"]
                    if manufacturer.get("url"):
                        url_list = manufacturer["url"]
                        publisher_namespace = url_list[0] if isinstance(url_list, list) else url_list
        elif cim.metadata.source_format == DocumentFormat.OPENVEX:
            # author를 publisher로 사용
            if pub.name and pub.name != "Unknown":
                publisher_name = pub.name
                if pub.namespace:
                    publisher_namespace = pub.namespace
            
            # 수정됨 (OpenVEX 이슈 1): OpenVEX role을 CSAF publisher.category에 매핑
            # OpenVEX role 값: vendor, coordinator, discoverer, other, user, aggregator
            # CSAF category 값: vendor, coordinator, discoverer, user, other, multiplier, translator
            openvex_role = get_extension_field(cim.metadata, "openvex", "role")
            if openvex_role:
                role_lower = openvex_role.lower()
                # 직접 매핑
                if role_lower in ["vendor", "coordinator", "discoverer", "user", "other"]:
                    publisher_category = role_lower
                # vendor에 매핑되는 역할 설명
                elif any(kw in role_lower for kw in ["psirt", "security incident response", "security team", "product security"]):
                    publisher_category = "vendor"
                # Aggregator/multiplier
                elif role_lower in ["aggregator", "multiplier"]:
                    publisher_category = "multiplier"
                # Document Creator는 기본 vendor
                elif role_lower == "document creator":
                    publisher_category = "vendor"
                # 기본 폴백
                else:
                    publisher_category = "vendor"
        else:
            # CSAF 소스 - 원본 publisher 복원
            original_category = get_extension_field(cim.metadata, "csaf", "document.publisher.category")
            original_name = get_extension_field(cim.metadata, "csaf", "document.publisher.name")
            original_namespace = get_extension_field(cim.metadata, "csaf", "document.publisher.namespace")
            
            if original_category:
                publisher_category = original_category
            if original_name:
                publisher_name = original_name
            if original_namespace:
                publisher_namespace = original_namespace
        
        # TLP 처리: 공통 TLP 필드 또는 원본 CSAF distribution 사용
        distribution = None
        common_tlp_label = get_extension_field(cim.metadata, "common", "tlp.label", None)
        common_tlp_url = get_extension_field(cim.metadata, "common", "tlp.url", "https://www.first.org/tlp/")
        
        if common_tlp_label:
            # CycloneDX → CSAF 변환: TLP 매핑
            # CycloneDX: CLEAR, GREEN, AMBER, AMBER_AND_STRICT, RED
            # CSAF 2.1: CLEAR, GREEN, AMBER, AMBER+STRICT, RED
            tlp_cyclonedx_to_csaf = {
                "CLEAR": "CLEAR",
                "GREEN": "GREEN",
                "AMBER": "AMBER",
                "AMBER_AND_STRICT": "AMBER+STRICT",
                "RED": "RED"
            }
            csaf_tlp_label = tlp_cyclonedx_to_csaf.get(common_tlp_label, common_tlp_label)
            distribution = {
                "tlp": {
                    "label": csaf_tlp_label,
                    "url": common_tlp_url
                }
            }
        else:
            # 원본 CSAF distribution 또는 기본값
            distribution = get_extension_field(cim.metadata, "csaf", "document.distribution", {
                "tlp": {
                    "label": "CLEAR",
                    "url": "https://www.first.org/tlp/"
                }
            })
        
        doc = {
            "category": get_extension_field(cim.metadata, "csaf", "document.category", "csaf_vex"),
            "csaf_version": "2.1",
            "distribution": distribution,
            "publisher": {
                "category": publisher_category,
                "name": publisher_name,
                "namespace": publisher_namespace
            },
            "title": get_extension_field(cim.metadata, "csaf", "document.title", title),
            "tracking": {
                "id": tracking_id,
                # CycloneDX 소스는 "interim" 사용 (CycloneDX에는 document status 개념 없음)
                "status": get_extension_field(cim.metadata, "csaf", "document.tracking.status", 
                         "interim" if cim.metadata.source_format == DocumentFormat.CYCLONEDX else "final"),
                "version": None,  # 아래에서 revision_history 구성 후 설정됨
                # revision_history는 아래에서 설정됨
                "revision_history": None,
                "initial_release_date": dt_to_iso_z(cim.metadata.created_at),
                "current_release_date": None,  # 아래에서 설정됨
                "generator": {
                    "engine": {
                        "name": "VEXCO Engine",
                        "version": "1.0.0"
                    },
                    "date": dt_to_iso_z(now_utc())
                }
            }
        }
        
        # current_release_date가 initial_release_date보다 이전이 아닌지 확인
        initial_dt = cim.metadata.created_at
        current_dt = now_utc()
        
        # CIM.metadata.last_updated 먼저 시도
        if cim.metadata.last_updated:
            current_dt = cim.metadata.last_updated
        
        # 현재 시간이 초기 시간보다 이전인 경우 (타임존 문제로 발생 가능),
        # 초기 시간을 현재 시간으로 사용
        if current_dt < initial_dt:
            current_dt = initial_dt
        
        # extension_data에 저장된 current_release_date 확인 (폴백)
        if not cim.metadata.last_updated:
            stored_current_date = get_extension_field(cim.metadata, "csaf", "document.tracking.current_release_date")
            if stored_current_date:
                # 저장된 날짜 파싱
                try:
                    stored_dt = datetime.fromisoformat(stored_current_date.replace('Z', '+00:00'))
                    # 저장된 날짜가 초기 날짜보다 이전이 아닌 경우에만 사용
                    if stored_dt >= initial_dt:
                        current_dt = stored_dt
                except:
                    pass  # 계산된 current_dt 사용
        
        doc["tracking"]["current_release_date"] = dt_to_iso_z(current_dt)
        
        # ===== REVISION_HISTORY 생성 =====
        # 소스에 이미 revision_history가 있는지 확인 (CSAF → CSAF)
        existing_revision_history = get_extension_field(cim.metadata, "csaf", "document.tracking.revision_history")
        
        if existing_revision_history and cim.metadata.source_format == DocumentFormat.CSAF:
            # CSAF → CSAF: 기존 revision_history 사용하고 새 항목 추가
            revision_history = list(existing_revision_history)  # 복사
            
            # 마지막 버전 번호 가져오기
            last_version = 1
            for rev in revision_history:
                try:
                    ver_num = int(rev.get("number", "1"))
                    if ver_num > last_version:
                        last_version = ver_num
                except (ValueError, TypeError):
                    pass
            
            # VEXCO 변환 항목 추가
            new_version = last_version + 1
            revision_history.append({
                "date": dt_to_iso_z(now_utc()),
                "number": str(new_version),
                "summary": "Converted/processed by VEXCO Engine"
            })
            
            doc["tracking"]["revision_history"] = revision_history
            doc["tracking"]["version"] = str(new_version)
        else:
            # OpenVEX/CycloneDX → CSAF: 소스 버전에서 revision_history 생성
            source_version = cim.metadata.document_version or 1
            
            # source_version이 정수인지 확인
            try:
                source_version = int(source_version)
            except (ValueError, TypeError):
                source_version = 1
            
            revision_history = []
            
            if source_version == 1:
                # 소스가 버전 1: 단일 항목 + VEXCO 항목 생성
                revision_history.append({
                    "date": dt_to_iso_z(cim.metadata.created_at),
                    "number": "1",
                    "summary": f"Initial release (original {cim.metadata.source_format.value} document)"
                })
                revision_history.append({
                    "date": dt_to_iso_z(now_utc()),
                    "number": "2",
                    "summary": f"Converted to CSAF from {cim.metadata.source_format.value} by VEXCO Engine"
                })
                doc["tracking"]["version"] = "2"
            else:
                # Source version > 1: Generate placeholder history from 1 to source_version
                # Then add VEXCO conversion as next version
                
                # Calculate time interval for placeholder revisions
                # Distribute between created_at and now
                time_span = (now_utc() - cim.metadata.created_at).total_seconds()
                if time_span <= 0:
                    time_span = 86400  # Default 1 day if timestamps are same
                
                interval = time_span / (source_version + 1)  # +1 for VEXCO entry
                
                for ver in range(1, source_version + 1):
                    # Calculate revision date (distribute evenly)
                    if ver == 1:
                        rev_date = cim.metadata.created_at
                    else:
                        rev_date = cim.metadata.created_at + timedelta(seconds=interval * (ver - 1))
                    
                    if ver == 1:
                        summary = f"Initial release (original {cim.metadata.source_format.value} v1)"
                    elif ver == source_version:
                        summary = f"Version {ver} (original {cim.metadata.source_format.value} document)"
                    else:
                        summary = f"Version {ver} (inferred from original document)"
                    
                    revision_history.append({
                        "date": dt_to_iso_z(rev_date),
                        "number": str(ver),
                        "summary": summary
                    })
                
                # 다음 버전으로 VEXCO 변환 항목 추가
                new_version = source_version + 1
                revision_history.append({
                    "date": dt_to_iso_z(now_utc()),
                    "number": str(new_version),
                    "summary": f"Converted to CSAF from {cim.metadata.source_format.value} by VEXCO Engine"
                })
                
                doc["tracking"]["version"] = str(new_version)
            
            doc["tracking"]["revision_history"] = revision_history
        
        # extension_data에서 선택적 CSAF 필드 복원
        
        # aggregate_severity
        aggregate_severity = get_extension_field(cim.metadata, "csaf", "document.aggregate_severity")
        if aggregate_severity:
            doc["aggregate_severity"] = aggregate_severity
        
        # lang
        lang = get_extension_field(cim.metadata, "csaf", "document.lang")
        if lang:
            doc["lang"] = lang
        
        # source_lang
        source_lang = get_extension_field(cim.metadata, "csaf", "document.source_lang")
        if source_lang:
            doc["source_lang"] = source_lang
        
        # publisher 추가 필드 (CSAF 소스에서 복원)
        contact_details = get_extension_field(cim.metadata, "csaf", "document.publisher.contact_details")
        if contact_details:
            doc["publisher"]["contact_details"] = contact_details
        
        issuing_authority = get_extension_field(cim.metadata, "csaf", "document.publisher.issuing_authority")
        if issuing_authority:
            doc["publisher"]["issuing_authority"] = issuing_authority
        
        # tracking 추가 필드
        aliases = get_extension_field(cim.metadata, "csaf", "document.tracking.aliases")
        if aliases:
            doc["tracking"]["aliases"] = aliases
        
        # references
        references = get_extension_field(cim.metadata, "csaf", "document.references")
        if not references:
            references = []
        
        # 원본 advisory 참조를 첫 번째 요소로 추가 (CSAF 2.1 요구사항)
        # 변환된 문서의 경우 원본 문서 참조가 첫 번째여야 함
        original_id = get_extension_field(cim.metadata, "openvex", "@id")
        if original_id and original_id.startswith("http"):
            # URL에서 문서 ID 추출
            doc_id = original_id.rstrip('/').split('/')[-1]
            original_ref = {
                "category": "external",
                "summary": f"Original OpenVEX Advisory ({doc_id})",
                "url": original_id
            }
            # 시작 부분에 삽입 (CSAF 2.1 요구사항)
            references.insert(0, original_ref)
        
        if references:
            doc["references"] = references
        
        # notes
        notes = get_extension_field(cim.metadata, "csaf", "document.notes")
        if not notes:
            notes = []
        
        # 원본 도구 정보를 notes에 추가 (CycloneDX 이슈 6)
        # 원본 도구 정보 보존
        source_format = cim.metadata.source_format.value if cim.metadata.source_format else "Unknown"
        original_author = pub.name if pub.name and pub.name != "Unknown" else None
        
        if source_format == "CycloneDX":
            # 도구 정보를 위한 올바른 extension_data 키 사용
            tool_name = get_extension_field(cim.metadata, "cyclonedx", "tool_name")
            tool_version = None
            
            # 폴백: 저장된 metadata.tools에서 추출 시도
            tools_data = get_extension_field(cim.metadata, "cyclonedx", "metadata.tools")
            if tools_data:
                if isinstance(tools_data, dict):
                    components = tools_data.get("components", [])
                    if components:
                        first_tool = components[0]
                        if not tool_name:
                            tool_name = first_tool.get("name")
                        tool_version = first_tool.get("version")
                elif isinstance(tools_data, list) and tools_data:
                    first_tool = tools_data[0]
                    if not tool_name:
                        tool_name = first_tool.get("name")
                    tool_version = first_tool.get("version")
            
            if tool_name:
                tool_text = f"This document was derived from a CycloneDX VEX generated by {tool_name}"
                if tool_version:
                    tool_text += f" {tool_version}"
                tool_text += "."
                
                notes.insert(0, {
                    "category": "other",
                    "title": "Original Analysis Tool",
                    "text": tool_text
                })
        elif source_format == "OpenVEX" and original_author:
            tool_name = get_extension_field(cim.metadata, "openvex", "tooling")
            role = get_extension_field(cim.metadata, "openvex", "role")
            
            text_parts = [f"This document was converted from an OpenVEX document authored by '{original_author}'"]
            if role:
                text_parts.append(f"(Role: {role})")
            if tool_name:
                text_parts.append(f", generated by '{tool_name}'")
            
            notes.insert(0, {
                "category": "other",
                "title": "Original Tooling Information",
                "text": " ".join(text_parts) + "."
            })
        
        # notes 추가 from CycloneDX metadata (if not already from CSAF)
        # metadata.component.description -> notes (category: description)
        component_desc = get_extension_field(cim.metadata, "cyclonedx", "metadata.component")
        if component_desc and isinstance(component_desc, dict) and component_desc.get("description"):
            notes.append({
                "category": "description",
                "title": "Product Description",
                "text": component_desc["description"]
            })
        
        # metadata.licenses -> notes (category: legal_disclaimer)
        licenses = get_extension_field(cim.metadata, "cyclonedx", "metadata.licenses")
        if licenses and isinstance(licenses, list):
            license_texts = []
            for lic in licenses:
                if isinstance(lic, dict) and lic.get("license"):
                    license_obj = lic["license"]
                    if license_obj.get("text"):
                        license_texts.append(license_obj["text"])
                    elif license_obj.get("name"):
                        license_texts.append(license_obj["name"])
            if license_texts:
                notes.append({
                    "category": "legal_disclaimer",
                    "title": "License",
                    "text": "\n\n".join(license_texts)
                })
        
        # annotations -> notes (category: general)
        annotations = get_extension_field(cim.metadata, "cyclonedx", "annotations")
        if annotations and isinstance(annotations, list):
            annotation_texts = []
            for ann in annotations:
                if isinstance(ann, dict):
                    text_parts = []
                    if ann.get("text"):
                        text_parts.append(ann["text"])
                    if ann.get("subjects") and isinstance(ann["subjects"], list):
                        text_parts.append(f"Subjects: {', '.join(str(s) for s in ann['subjects'])}")
                    if text_parts:
                        annotation_texts.append(" - ".join(text_parts))
            if annotation_texts:
                notes.append({
                    "category": "general",
                    "title": "General Security Recommendations",
                    "text": "\n".join(annotation_texts)
                })
        
        if notes:
            doc["notes"] = notes
        
        # acknowledgments
        acknowledgments = get_extension_field(cim.metadata, "csaf", "document.acknowledgments")
        if acknowledgments:
            doc["acknowledgments"] = acknowledgments
        
        # 문서 필드 재정렬 (OpenVEX 이슈 3)
        # 필수 순서: category, csaf_version, distribution, publisher, title, tracking, notes
        ordered_doc = {}
        doc_field_order = ["category", "csaf_version", "distribution", "publisher", "title", "tracking", "notes", "references", "acknowledgments"]
        for field in doc_field_order:
            if field in doc:
                ordered_doc[field] = doc[field]
        # 정렬된 목록에 없는 나머지 필드 추가
        for field, value in doc.items():
            if field not in ordered_doc:
                ordered_doc[field] = value
        
        # tracking 필드 재정렬
        # 필수 순서: id, status, version, initial_release_date, current_release_date, revision_history, generator
        if "tracking" in ordered_doc:
            tracking = ordered_doc["tracking"]
            ordered_tracking = {}
            tracking_field_order = ["id", "status", "version", "initial_release_date", "current_release_date", "revision_history", "generator"]
            for field in tracking_field_order:
                if field in tracking:
                    ordered_tracking[field] = tracking[field]
            # 나머지 필드 추가
            for field, value in tracking.items():
                if field not in ordered_tracking:
                    ordered_tracking[field] = value
            ordered_doc["tracking"] = ordered_tracking
        
        return ordered_doc

    def _vulns(self, cim: CIM, product_id_map: Dict[str, str]) -> List[Dict]:
        by_vuln = {}
        for st in cim.statements:
            by_vuln.setdefault(st.vulnerability_id, []).append(st)
        vuln_idx = {v.id: v for v in cim.vulnerabilities}
        out = []

        for vid, stmts in sorted(by_vuln.items()):
            # Store original statements for perfect restoration
            vv = vuln_idx.get(vid)
            if vv and self.options.reversible:
                # Serialize statements to dict format for storage
                stmt_data = []
                for st in stmts:
                    stmt_dict = {
                        "subject_refs": st.subject_refs,
                        "status": {
                            "value": st.status.value.name,
                            "justification": st.status.justification.value if st.status.justification else None,
                            "custom_justification": st.status.custom_justification,
                            "impact_statement": st.status.impact_statement,
                            "original_state": st.status.original_state
                        },
                        "action_statement": st.action_statement,
                        "timestamp": st.timestamp.isoformat() if st.timestamp else None
                    }
                    stmt_data.append(stmt_dict)
                
                set_extension_field(vv, "csaf", "original_statements", stmt_data)
            
            # Apply product status priority to prevent duplicates
            if self.options.apply_csaf_product_priority:
                ps = self._apply_product_priority(stmts, product_id_map)
            else:
                ps = self._collect_product_statuses(stmts, product_id_map)

            # Only add flags for products that are actually in known_not_affected
            not_affected_products = set(ps.get("known_not_affected", []))

            # CSAF VEX: Add flags with justification labels for NOT_AFFECTED products
            # EXCEPTION: false_positive products use threats section instead of flags
            flags = []
            flags_by_label = {}  # label → [product_ids]
            
            # Track which products have flags
            products_with_flags = set()
            
            # Track false_positive products (they go to threats, not flags)
            false_positive_products = {}  # product_id → detail text

            for st in stmts:
                # Check if this is a false_positive statement
                is_false_positive = st.status.original_state == "false_positive"
                
                if st.status.value == VulnerabilityStatus.NOT_AFFECTED:
                    mapped_pids = [product_id_map.get(pid, pid) for pid in st.subject_refs]
                    
                    if is_false_positive:
                        # false_positive: collect for threats section
                        detail = st.status.impact_statement or "This vulnerability was incorrectly identified"
                        for pid in mapped_pids:
                            false_positive_products[pid] = detail
                        products_with_flags.update(mapped_pids)  # Mark as handled
                    elif st.status.justification:
                        # Normal NOT_AFFECTED with justification: add to flags
                        label = justification_enum_to_csaf_flag(st.status.justification)
                        if label:
                            if label not in flags_by_label:
                                flags_by_label[label] = []
                            flags_by_label[label].extend(mapped_pids)
                            products_with_flags.update(mapped_pids)
                            
                            # Track justification conversion
                            self.tracking_table.add(
                                source_field="CIM.statement.status.justification",
                                source_value=str(st.status.justification),
                                target_field="flags.label",
                                target_value=label,
                                rule=f"Justification → CSAF flag label",
                                status="TRANSFORMED"
                            )
            
            # IMPORTANT: For known_not_affected products without flags,
            # add default flag to satisfy CSAF validator
            # (CSAF requires either flag or threat for known_not_affected products)
            not_affected_without_flags = not_affected_products - products_with_flags
            if not_affected_without_flags:
                # Add default "vulnerable_code_not_present" flag
                # (more accurate than "component_not_present" which means the component itself is absent)
                default_label = "vulnerable_code_not_present"
                if default_label not in flags_by_label:
                    flags_by_label[default_label] = []
                flags_by_label[default_label].extend(list(not_affected_without_flags))

            # Build flags array
            for label, pids in flags_by_label.items():
                flags.append({
                    "label": label,
                    "product_ids": unique_list(pids)
                })

            # vulnerability ID가 CVE 형식인지 확인
            import re
            is_cve = bool(re.match(r'^CVE-\d{4}-\d{4,}$', vid))
            
            if is_cve:
                v_obj = {"cve": vid}
            else:
                # 비-CVE ID는 ids 필드로 매핑
                # 첫 번째 하이픈 앞 문자열을 system_name으로 사용
                system_name = vid.split("-")[0] if "-" in vid else vid
                
                v_obj = {
                    "ids": [{
                        "system_name": system_name,
                        "text": vid
                    }]
                }
            
            # Get vulnerability index for this CVE
            vv = vuln_idx.get(vid)
            
            # aliases를 CSAF ids 필드에 매핑
            if vv and vv.aliases:
                existing_ids = v_obj.get("ids", [])
                existing_texts = {item["text"] for item in existing_ids}
                
                for alias in vv.aliases:
                    # 이미 추가된 것은 건너뛰기
                    if alias in existing_texts or alias == vid:
                        continue
                    
                    if alias.startswith("CVE-"):
                        # CVE는 cve 필드에 추가 (기존에 없는 경우에만)
                        if "cve" not in v_obj:
                            v_obj["cve"] = alias
                        continue
                    
                    # 첫 번째 하이픈 앞 문자열을 system_name으로 사용
                    system_name = alias.split("-")[0] if "-" in alias else alias
                    
                    existing_ids.append({
                        "system_name": system_name,
                        "text": alias
                    })
                    existing_texts.add(alias)
                
                if existing_ids:
                    v_obj["ids"] = existing_ids
            
            # Restore title from extension_data or extract from description
            vv = vuln_idx.get(vid)
            if vv:
                # Try to get original title from extension_data first
                vuln_title = get_extension_field(vv, "csaf", "vulnerabilities.title")
                
                # If no stored title, try to extract from description
                if not vuln_title and vv.description:
                    desc = vv.description
                    # Check if description is in "title, description" format
                    if ", " in desc:
                        parts = desc.split(", ", 1)
                        if len(parts) == 2 and len(parts[0]) < 200:
                            vuln_title = parts[0]
                    
                    # If still no title, use description if it's short enough
                    if not vuln_title and len(desc) < 200:
                        vuln_title = desc
                    # If description is too long, truncate for title
                    elif not vuln_title:
                        vuln_title = desc[:197] + "..."
                
                # Fallback to CVE ID as title
                if not vuln_title:
                    vuln_title = vid
                
                v_obj["title"] = vuln_title
            
            # CWE information should be in notes, not as a separate field in CSAF
            # CSAF schema does not have a cwe field at vulnerabilities level

            # Remove empty arrays from product_status
            ps_cleaned = {k: v for k, v in ps.items() if v}
            if ps_cleaned:
                v_obj["product_status"] = ps_cleaned

            # Add flags if present
            if flags:
                v_obj["flags"] = flags

            vv = vuln_idx.get(vid)
            if vv:
                notes = []
                
                # Restore original notes with their categories
                if vv.notes:
                    for note in vv.notes:
                        note_obj = {}
                        if note.get("category"):
                            note_obj["category"] = note["category"]
                        if note.get("text"):
                            note_obj["text"] = note["text"]
                        if note.get("title"):
                            note_obj["title"] = note["title"]
                        if note_obj:
                            notes.append(note_obj)
                
                # Add description as a note if not already in notes
                if vv.description:
                    # FIXED: Use description text directly (title is stored separately in extension_data)
                    desc_text = vv.description
                    
                    # Check if description is already in notes
                    desc_exists = any(n.get("text") == desc_text for n in notes)
                    if not desc_exists and desc_text:
                        notes.insert(0, {"category": "description", "text": desc_text, "title": "Vulnerability description"})
                else:
                    # If no description, add impact_statement/action_statement to notes
                    # (they will be excluded from threats.details below)
                    for st in stmts:
                        # NOT_AFFECTED: impact_statement → notes
                        if st.status.value == VulnerabilityStatus.NOT_AFFECTED and st.status.impact_statement:
                            if st.status.impact_statement not in [n.get("text") for n in notes]:
                                notes.append({
                                    "category": "summary",
                                    "text": st.status.impact_statement,
                                    "title": "Vulnerability Summary"
                                })
                        
                        # AFFECTED: action_statement → notes
                        elif st.status.value == VulnerabilityStatus.AFFECTED and st.action_statement:
                            if st.action_statement not in [n.get("text") for n in notes]:
                                notes.append({
                                    "category": "general",
                                    "text": st.action_statement,
                                    "title": "Recommended Action"
                                })
                        
                        # UNDER_INVESTIGATION: detail → notes
                        elif st.status.value == VulnerabilityStatus.UNDER_INVESTIGATION:
                            detail_text = get_extension_field(st, "cyclonedx", "analysis.detail")
                            if detail_text and detail_text not in [n.get("text") for n in notes]:
                                notes.append({
                                    "category": "general",
                                    "text": detail_text,
                                    "title": "Analysis Details"
                                })
                
                # Add recommendation as general note if available
                recommendation = get_extension_field(vv, "cyclonedx", "recommendation")
                if not recommendation:
                    # Fallback to vuln-level recommendation
                    vuln = vuln_idx.get(vid)
                    if vuln:
                        recommendation = get_extension_field(vuln, "cyclonedx", "recommendation")
                
                if recommendation:
                    # Check if already exists to avoid duplicates
                    rec_exists = any(
                        n.get("text") == recommendation and 
                        n.get("title") == "General Security Recommendations"
                        for n in notes
                    )
                    if not rec_exists:
                        notes.append({
                            "category": "general",
                            "text": recommendation,
                            "title": "General Security Recommendations"
                        })

                # Collect impact_statements that will go into threats
                threat_impact_statements = set()
                for st in stmts:
                    if st.status.value == VulnerabilityStatus.NOT_AFFECTED and st.status.impact_statement:
                        threat_impact_statements.add(st.status.impact_statement)

                # FIXED (CycloneDX Issue 3): Do NOT add AFFECTED products' impact_statement to notes
                # analysis.detail (stored as impact_statement) should only go to remediations.details
                # This prevents the same text appearing in notes, threats, AND remediations
                # 
                # Role separation:
                # - notes: vulnerability description (from vv.description)
                # - threats: impact for FIXED/NOT_AFFECTED products only
                # - remediations: action/response for AFFECTED products (includes detail)

                # notes 추가 for CycloneDX special states
                has_false_positive = any(st.status.original_state == "false_positive" for st in stmts)
                has_pedigree = any(st.status.original_state == "resolved_with_pedigree" for st in stmts)

                if has_false_positive:
                    notes.append({
                        "category": "summary",
                        "text": "Note: Some affected products were identified as false positives in the original assessment."
                    })

                if has_pedigree:
                    # FIXED (Issue 6): Improved pedigree note handling
                    # Check if actual pedigree data exists in components
                    pedigree_data_exists = False
                    components_data = get_extension_field(cim.metadata, "cyclonedx", "components")
                    if components_data:
                        for comp in components_data:
                            pedigree = comp.get("pedigree", {})
                            if pedigree and (pedigree.get("commits") or pedigree.get("patches")):
                                pedigree_data_exists = True
                                break
                    
                    # FIXED (CycloneDX Issue 4): Use analysis.detail for pedigree context
                    pedigree_context = None
                    if vv:
                        analysis_detail = get_extension_field(vv, "cyclonedx", "analysis.detail")
                        if analysis_detail:
                            pedigree_context = analysis_detail
                    
                    # Also check statement-level detail
                    if not pedigree_context:
                        for st in stmts:
                            if st.status.original_state == "resolved_with_pedigree":
                                if st.status.impact_statement:
                                    pedigree_context = st.status.impact_statement
                                    break
                    
                    if pedigree_data_exists:
                        notes.append({
                            "category": "summary",
                            "text": "Note: Resolution includes pedigree information with commit history and code diffs. See references section for detailed links."
                        })
                    elif pedigree_context:
                        # FIXED: Use actual pedigree context from analysis.detail
                        notes.append({
                            "category": "summary",
                            "text": f"Resolved with pedigree: {pedigree_context}"
                        })
                    else:
                        # No pedigree context available
                        notes.append({
                            "category": "summary",
                            "text": "Resolved with pedigree evidence. See analysis details for verification information."
                        })
                
                if notes:
                    # Auto-bind product_ids to notes based on content matching
                    # CSAF spec: If a note is specific to a product or product group,
                    # it MUST be bound via product_ids
                    
                    # Build product name mapping: name/version → product_id
                    product_name_map = {}
                    for st in stmts:
                        for ref in st.subject_refs:
                            # Get mapped product_id
                            pid = product_id_map.get(ref, ref)
                            
                            # Get subject
                            subj = next((s for s in cim.subjects if s.ref == ref), None)
                            if subj:
                                # Add name variations
                                if subj.name:
                                    product_name_map[subj.name.lower()] = pid
                                if subj.version:
                                    product_name_map[subj.version.lower()] = pid
                                    if subj.name:
                                        # name + version
                                        product_name_map[f"{subj.name} {subj.version}".lower()] = pid
                                
                                # Add identifier values
                                for ident in subj.identifiers:
                                    if ident.value:
                                        # Extract product name from purl or cpe
                                        if ident.type == "purl" and "/" in ident.value:
                                            parts = ident.value.split("/")
                                            if parts:
                                                prod_name = parts[-1].split("@")[0]
                                                product_name_map[prod_name.lower()] = pid
                    
                    # Match notes to products
                    for note in notes:
                        if "product_ids" in note:
                            # Already has product_ids, skip
                            continue
                        
                        # Check title and text for product mentions
                        search_text = ""
                        if note.get("title"):
                            search_text += note["title"].lower() + " "
                        if note.get("text"):
                            search_text += note["text"].lower()
                        
                        if not search_text:
                            continue
                        
                        # Find matching products
                        matched_pids = set()
                        for prod_name, pid in product_name_map.items():
                            if prod_name in search_text:
                                matched_pids.add(pid)
                        
                        # Add product_ids if matches found
                        if matched_pids:
                            note["product_ids"] = sorted(list(matched_pids))
                    
                    v_obj["notes"] = notes
                
                # CSAF VEX Profile: Add notes from remediations if no notes exist
                # This satisfies CSAF-VEX-NOTES-001 validator requirement
                if not notes and vv and vv.remediations:
                    notes_from_remed = []
                    for rem in vv.remediations:
                        if rem.get("details"):
                            notes_from_remed.append({
                                "category": "general",
                                "text": rem["details"],
                                "title": f"Remediation: {rem.get('category', 'unknown').replace('_', ' ').title()}"
                            })
                    if notes_from_remed:
                        v_obj["notes"] = notes_from_remed
                
                # Add CWEs (CSAF format: array of objects with mandatory id, name, version)
                # Priority: restore original CWE objects > use CWE ID only
                # If name is not available in original, mark as "[User Input Required]"
                if vv.cwes:
                    # Try to restore original CWE objects from extension_data
                    original_cwes = get_extension_field(vv, "csaf", "cwes_original")
                    
                    if original_cwes:
                        # Use original CWE objects (faithful restoration)
                        v_obj["cwes"] = original_cwes
                    else:
                        # Build CWE objects from CWE IDs only
                        # FIXED (CycloneDX Issue 5): Use actual CWE names from CWE_NAMES mapping
                        cwes_list = []
                        for cwe in vv.cwes:
                            # Extract CWE number
                            if isinstance(cwe, int):
                                cwe_num = str(cwe)
                                cwe_id = f"CWE-{cwe}"
                            else:
                                cwe_id = cwe if cwe.startswith("CWE-") else f"CWE-{cwe}"
                                cwe_num = cwe_id.replace("CWE-", "")
                            
                            # CSAF requires id, name, and version (all mandatory)
                            # FIXED: Use get_cwe_name() for actual CWE name
                            cwe_name = get_cwe_name(cwe_num)
                            
                            # version must match pattern: ^[1-9]\d*\.([0-9]|([1-9]\d+))(\.\d+)?$
                            cwe_obj = {
                                "id": cwe_id,
                                "name": cwe_name,
                                "version": "4.14"  # Latest CWE version as of 2024
                            }
                            cwes_list.append(cwe_obj)
                        
                        if cwes_list:
                            v_obj["cwes"] = cwes_list

                # Add CVSS metrics (CSAF format: metrics not scores)
                if vv.ratings:
                    metrics_list = []
                    for rating in vv.ratings:
                        metric_obj = {}
                        
                        # CVSS 버전 결정
                        if rating.method and "3.1" in rating.method:
                            cvss_key = "cvss_v3"
                            version = "3.1"
                        elif rating.method and "3.0" in rating.method:
                            cvss_key = "cvss_v3"
                            version = "3.0"
                        elif rating.method and "2" in rating.method:
                            cvss_key = "cvss_v2"
                            version = "2.0"
                        else:
                            cvss_key = "cvss_v3"
                            version = "3.1"
                        
                        # Build CVSS object
                        cvss_obj = {}
                        if version:
                            cvss_obj["version"] = version
                        if rating.vector:
                            cvss_obj["vectorString"] = rating.vector
                        if rating.score is not None:
                            cvss_obj["baseScore"] = rating.score
                        if rating.severity:
                            cvss_obj["baseSeverity"] = rating.severity.upper()
                        
                        if cvss_obj:
                            # CSAF requires "content" wrapper
                            metric_obj["content"] = {cvss_key: cvss_obj}
                            
                            # Add products (all products affected by this vulnerability)
                            product_ids = []
                            for st in stmts:
                                for ref in st.subject_refs:
                                    pid = product_id_map.get(ref, ref)
                                    if pid not in product_ids:
                                        product_ids.append(pid)
                            
                            if product_ids:
                                metric_obj["products"] = product_ids
                            
                            metrics_list.append(metric_obj)
                    
                    if metrics_list:
                        v_obj["metrics"] = metrics_list

                # FIXED (OpenVEX Issue 2): Parse CVSS from status_notes and add to metrics
                # This should NOT call NVD API - only use data from the original document
                for st in stmts:
                    status_notes = get_extension_field(st, "openvex", "status_notes")
                    if status_notes and "CVSS" in status_notes:
                        import re
                        # Parse CVSS vector: CVSS:3.1/AV:N/AC:L/...
                        cvss_match = re.search(r'(CVSS:\d+\.\d+/[^\s]+)', status_notes)
                        # Parse score: (Score: 7.5)
                        score_match = re.search(r'\(Score:\s*([\d.]+)\)', status_notes)
                        
                        if cvss_match:
                            vector_string = cvss_match.group(1)
                            
                            # Extract version from vector
                            version_match = re.match(r'CVSS:(\d+\.\d+)', vector_string)
                            version = version_match.group(1) if version_match else "3.1"
                            cvss_key = "cvss_v3" if version.startswith("3") else "cvss_v2"
                            
                            # Extract base score
                            base_score = None
                            if score_match:
                                base_score = float(score_match.group(1))
                            
                            # Determine severity from score
                            severity = None
                            if base_score is not None:
                                if base_score >= 9.0:
                                    severity = "CRITICAL"
                                elif base_score >= 7.0:
                                    severity = "HIGH"
                                elif base_score >= 4.0:
                                    severity = "MEDIUM"
                                elif base_score > 0:
                                    severity = "LOW"
                                else:
                                    severity = "NONE"
                            
                            # Build CVSS object
                            cvss_obj = {
                                "version": version,
                                "vectorString": vector_string
                            }
                            if base_score is not None:
                                cvss_obj["baseScore"] = base_score
                            if severity:
                                cvss_obj["baseSeverity"] = severity
                            
                            # Get product IDs for this statement
                            metric_pids = [product_id_map.get(ref, ref) for ref in st.subject_refs]
                            
                            # Add to metrics
                            metric_obj = {
                                "content": {cvss_key: cvss_obj},
                                "products": metric_pids
                            }
                            
                            if "metrics" not in v_obj:
                                v_obj["metrics"] = []
                            v_obj["metrics"].append(metric_obj)
                            break  # Only add once per vulnerability

                # Add threats with impact details - GROUP BY DETAILS
                # FIXED (Issue 5): CSAF VEX Profile 6.1.27.9 requires known_not_affected or fixed products
                # to have justification in threats[] (category: "impact") or flags section
                threats_by_details = {}
                
                # FIXED (CycloneDX Issue 3): Collect AFFECTED products' impact_statement to avoid duplication
                # analysis.detail is shared across all statuses in CycloneDX, but should only appear
                # in remediations for AFFECTED products, not in threats for FIXED/NOT_AFFECTED
                affected_impact_statements = set()
                for st in stmts:
                    if st.status.value == VulnerabilityStatus.AFFECTED and st.status.impact_statement:
                        affected_impact_statements.add(st.status.impact_statement)
                
                # Also track texts used in notes
                texts_used_in_notes = set()
                for note in notes:
                    if note.get("text"):
                        texts_used_in_notes.add(note["text"])
                
                # FIRST: Add false_positive products to threats
                # false_positive uses threats instead of flags (CSAF has no false_positive flag)
                for pid, detail in false_positive_products.items():
                    fp_details = f"False Positive: {detail}"
                    if fp_details not in threats_by_details:
                        threats_by_details[fp_details] = []
                    threats_by_details[fp_details].append(pid)
                
                # FIXED (Issue 5): Track products that need impact statements
                fixed_products = set(ps_cleaned.get("fixed", []))
                not_affected_products_set = set(ps_cleaned.get("known_not_affected", []))
                
                for st in stmts:
                    # Skip false_positive statements (already handled above)
                    if st.status.original_state == "false_positive":
                        continue
                    
                    # Add threats for NOT_AFFECTED, UNDER_INVESTIGATION, and FIXED products ONLY
                    # AFFECTED products' impact goes to remediations, not threats
                    if st.status.value in [VulnerabilityStatus.NOT_AFFECTED, VulnerabilityStatus.UNDER_INVESTIGATION, VulnerabilityStatus.FIXED]:
                        details_parts = []
                        mapped_pids = [product_id_map.get(pid, pid) for pid in st.subject_refs]

                        # FIXED (Issue 5): For FIXED products, add impact statement
                        if st.status.value == VulnerabilityStatus.FIXED:
                            # FIXED (CycloneDX Issue 3): Skip if same as AFFECTED's impact (to avoid duplication)
                            if st.status.impact_statement and st.status.impact_statement not in affected_impact_statements:
                                details_parts.append(st.status.impact_statement)
                            else:
                                # Use default message instead of duplicating AFFECTED's detail
                                details_parts.append("This vulnerability has been fixed in this version.")
                        
                        # For NOT_AFFECTED, add impact statement
                        elif st.status.value == VulnerabilityStatus.NOT_AFFECTED:
                            # FIXED (CycloneDX Issue 3): Skip if same as AFFECTED's impact
                            if st.status.impact_statement and st.status.impact_statement not in affected_impact_statements:
                                details_parts.append(st.status.impact_statement)
                            # FIXED (Issue 5): If no impact_statement but has justification, include it
                            elif st.status.justification:
                                justification_text = st.status.justification.value if hasattr(st.status.justification, 'value') else str(st.status.justification)
                                details_parts.append(f"Product is not affected: {justification_text}")
                            else:
                                details_parts.append("This product is not affected by this vulnerability.")
                        
                        # For UNDER_INVESTIGATION, add detail
                        elif st.status.value == VulnerabilityStatus.UNDER_INVESTIGATION:
                            # FIXED (CDX Issue 5): Check multiple sources for detail
                            detail_text = get_extension_field(st, "cyclonedx", "analysis.detail")
                            
                            # Fallback to impact_statement
                            if not detail_text and st.status.impact_statement:
                                detail_text = st.status.impact_statement
                            
                            # Fallback to action_statement  
                            if not detail_text and st.action_statement:
                                detail_text = st.action_statement
                            
                            if detail_text and detail_text not in affected_impact_statements:
                                details_parts.append(detail_text)
                            elif not detail_text:
                                details_parts.append("Investigation is ongoing to determine the impact of this vulnerability.")

                        # Build details string
                        if details_parts:
                            details = ". ".join(details_parts)
                            if details not in threats_by_details:
                                threats_by_details[details] = []
                            threats_by_details[details].extend(mapped_pids)

                threats = []
                for details, pids in threats_by_details.items():
                    threats.append({
                        "category": "impact",
                        "details": details,
                        "product_ids": unique_list(pids)
                    })

                if threats:
                    v_obj["threats"] = threats

                # Add remediations (REQUIRED for affected products in csaf_vex)
                remediations = []

                # Collect action statements from AFFECTED products
                # Priority order for categories: vendor_fix > mitigation > workaround > fix_planned > no_fix_planned > optional_patch > none_available
                category_priority = {
                    "vendor_fix": 1,
                    "mitigation": 2,
                    "workaround": 3,
                    "fix_planned": 4,
                    "no_fix_planned": 5,
                    "optional_patch": 6,
                    "none_available": 7
                }
                
                action_statements_by_category = {}
                for st in stmts:
                    if st.status.value == VulnerabilityStatus.AFFECTED:
                        mapped_pids = [product_id_map.get(pid, pid) for pid in st.subject_refs]
                        
                        # Use action_statement as details (primary)
                        # Fallback to impact_statement if no action_statement
                        if st.action_statement:
                            details = st.action_statement
                        elif st.status.impact_statement:
                            details = st.status.impact_statement
                        else:
                            details = "No remediation information available"
                        
                        # FIXED (OpenVEX Issue 1): Append status_notes to details
                        status_notes = get_extension_field(st, "openvex", "status_notes")
                        if status_notes:
                            # Remove CVSS part from status_notes (will be handled separately in metrics)
                            import re
                            cvss_pattern = r'CVSS:\d+\.\d+/[^\s]+'
                            non_cvss_parts = re.split(cvss_pattern, status_notes)
                            # Clean up parts
                            clean_notes_parts = []
                            for part in non_cvss_parts:
                                part = part.strip()
                                # Remove score pattern like "(Score: 7.5)"
                                part = re.sub(r'\(Score:\s*[\d.]+\)\.?', '', part).strip()
                                # Remove leading/trailing punctuation
                                part = part.strip(' .')
                                if part:
                                    clean_notes_parts.append(part)
                            
                            clean_status_notes = ". ".join(clean_notes_parts)
                            if clean_status_notes:
                                details = f"{details} {clean_status_notes}"

                        # Try to extract category from action_statement with priority
                        categories_found = []
                        if st.action_statement:
                            action_lower = st.action_statement.lower()
                            
                            # Check for explicit category format
                            if "," in st.action_statement and st.action_statement.split(",")[0] in [
                                "vendor_fix", "workaround", "mitigation", "no_fix_planned", 
                                "none_available", "fix_planned", "optional_patch"
                            ]:
                                parts = st.action_statement.split(",", 1)
                                categories_found.append(parts[0].strip())
                            else:
                                # Check for keywords and collect all applicable categories
                                if "update" in action_lower or "patch" in action_lower or "upgrade" in action_lower:
                                    categories_found.append("vendor_fix")
                                if "will not fix" in action_lower or "wont fix" in action_lower:
                                    categories_found.append("no_fix_planned")
                                if "workaround" in action_lower:
                                    categories_found.append("workaround")
                                if "mitigation" in action_lower or "mitigate" in action_lower:
                                    categories_found.append("mitigation")
                        
                        # Use highest priority category
                        if categories_found:
                            category = min(categories_found, key=lambda c: category_priority.get(c, 99))
                        else:
                            category = "vendor_fix"  # Default

                        key = (category, details)
                        if key not in action_statements_by_category:
                            action_statements_by_category[key] = []
                        action_statements_by_category[key].extend(mapped_pids)

                # Build remediations
                # FIXED (Issue 2, 3): Properly handle recommendation, workaround, and multiple responses
                # Each should be a separate remediation entry per CSAF VEX Profile requirements
                
                recommendation = get_extension_field(vv, "cyclonedx", "recommendation") if vv else None
                workaround_text = get_extension_field(vv, "cyclonedx", "workaround") if vv else None
                
                # Helper function: Determine remediation category from text using keyword analysis
                def determine_remediation_category(text: str) -> str:
                    """텍스트를 분석하여 가장 적합한 CSAF remediation 카테고리 결정"""
                    if not text:
                        return "vendor_fix"
                    
                    text_lower = text.lower()
                    
                    # Check for negative patterns first (no_fix_planned, none_available)
                    negative_patterns = [
                        ("no fix", "no_fix_planned"),
                        ("will not fix", "no_fix_planned"),
                        ("wont fix", "no_fix_planned"),
                        ("won't fix", "no_fix_planned"),
                        ("orphaned", "no_fix_planned"),
                        ("end-of-life", "no_fix_planned"),
                        ("eol", "no_fix_planned"),
                        ("none available", "none_available"),
                        ("not yet ready", "none_available"),
                        ("no remediation available", "none_available"),
                        ("no patch available", "none_available"),
                        ("upgrade is not possible", "none_available"),
                    ]
                    for pattern, category in negative_patterns:
                        if pattern in text_lower:
                            return category
                    
                    # Check for workaround keywords
                    workaround_keywords = ["configuration", "disable", "restrict", "avoid", "temporary", "bypass", "scenario", "workaround", "do not use"]
                    for keyword in workaround_keywords:
                        if keyword in text_lower:
                            return "workaround"
                    
                    # Check for mitigation keywords
                    mitigation_keywords = ["reduce risk", "access control", "external device", "compensating", "hardening", "mitigation", "mitigate"]
                    for keyword in mitigation_keywords:
                        if keyword in text_lower:
                            return "mitigation"
                    
                    # Check for vendor_fix keywords
                    vendor_fix_keywords = ["upgrade", "patch", "update", "fixed", "resolved", "new release", "official fix"]
                    for keyword in vendor_fix_keywords:
                        if keyword in text_lower:
                            return "vendor_fix"
                    
                    # Default to vendor_fix
                    return "vendor_fix"
                
                # Get affected products for remediation binding
                affected_pids = ps_cleaned.get("known_affected", [])
                
                # FIXED (CycloneDX Issue 2): Get response array from statements
                # Note: response is stored directly as "cyclonedx_response" key, not with namespace prefix
                response_array = []
                for st in stmts:
                    if hasattr(st, 'extension_data') and st.extension_data:
                        stmt_response = st.extension_data.get("cyclonedx_response")
                        if stmt_response:
                            if isinstance(stmt_response, list):
                                response_array.extend(stmt_response)
                            else:
                                response_array.append(stmt_response)
                response_array = list(set(response_array))  # Deduplicate
                
                # FIXED (CycloneDX Issue 1): Get timestamps for remediation.date
                first_issued = get_extension_field(vv, "cyclonedx", "analysis.firstIssued") if vv else None
                last_updated = get_extension_field(vv, "cyclonedx", "analysis.lastUpdated") if vv else None
                
                # Determine remediation date based on verification keywords
                # FIXED: Check ALL statements (including FIXED/resolved_with_pedigree) for verification keywords
                remediation_date = None
                detail_text = ""
                for st in stmts:
                    if st.status.impact_statement:
                        detail_text = st.status.impact_statement.lower()
                        # Found detail, no need to continue
                        break
                    # Also check extension_data for original detail
                    ext_detail = get_extension_field(st, "cyclonedx", "analysis.detail")
                    if ext_detail:
                        detail_text = ext_detail.lower()
                        break
                
                # Also check vulnerability-level detail
                if not detail_text and vv:
                    vuln_detail = get_extension_field(vv, "cyclonedx", "analysis.detail")
                    if vuln_detail:
                        detail_text = vuln_detail.lower()
                
                verification_keywords = ["audit", "verified", "confirmed", "reviewed", "validated", "approved"]
                has_verification = any(kw in detail_text for kw in verification_keywords)
                
                if last_updated and has_verification:
                    remediation_date = last_updated
                elif first_issued:
                    remediation_date = first_issued
                
                # PRIORITY 1: Use original CSAF remediations if this is restore mode
                if vv and vv.remediations and cim.metadata.source_format == DocumentFormat.CSAF:
                    for rem in vv.remediations:
                        rem_obj = {}
                        if rem.get("category"):
                            rem_obj["category"] = rem["category"]
                        if rem.get("details"):
                            rem_obj["details"] = rem["details"]
                        if rem.get("product_ids"):
                            mapped_pids = [product_id_map.get(pid, pid) for pid in rem["product_ids"]]
                            rem_obj["product_ids"] = unique_list(mapped_pids)
                        if rem.get("date"):
                            rem_obj["date"] = rem["date"]
                        
                        if rem_obj and rem_obj.get("category"):
                            remediations.append(rem_obj)
                
                # PRIORITY 2: Build from CycloneDX response array (MAIN LOGIC)
                # FIXED (CycloneDX Issue 2, 3): 
                # - Each response generates separate remediation
                # - will_not_fix for NOT_AFFECTED means "no fix needed" (product not vulnerable), NOT "won't fix vulnerability"
                # - Only create remediations for AFFECTED products
                if not remediations and response_array and affected_pids:
                    # FIXED: Only generate remediations for AFFECTED products
                    target_pids = affected_pids
                    
                    # Response to CSAF category mapping (CORRECTED per user spec)
                    response_to_category = {
                        "update": "vendor_fix",
                        "workaround_available": "workaround", 
                        "can_not_fix": "none_available",
                        "will_not_fix": "no_fix_planned",
                        "rollback": "mitigation",
                    }
                    
                    # FIXED (CycloneDX Issue 3): Skip will_not_fix for NOT_AFFECTED products
                    # will_not_fix for NOT_AFFECTED means "product is not vulnerable, no fix needed"
                    # This is semantically different from "vendor won't fix a vulnerability"
                    # Check if all statements with this response are NOT_AFFECTED
                    not_affected_responses = set()
                    for st in stmts:
                        if st.status.value == VulnerabilityStatus.NOT_AFFECTED:
                            # extension_data에서 response 가져오기
                            cdx_response = st.extension_data.get("cyclonedx_response", []) if st.extension_data else []
                            for r in cdx_response:
                                not_affected_responses.add(r.lower() if isinstance(r, str) else r)
                    
                    # 상호 배타성 규칙
                    mutually_exclusive = {
                        "vendor_fix": {"none_available", "fix_planned", "no_fix_planned", "optional_patch"},
                        "none_available": {"vendor_fix", "workaround", "mitigation", "fix_planned", "no_fix_planned", "optional_patch"},
                        "optional_patch": {"vendor_fix", "workaround", "mitigation", "none_available", "fix_planned", "no_fix_planned"},
                        "fix_planned": {"vendor_fix", "none_available", "no_fix_planned", "optional_patch"},
                        "no_fix_planned": {"vendor_fix", "none_available", "fix_planned", "optional_patch"},
                    }
                    
                    added_categories = set()
                    
                    def can_add_category(new_cat: str) -> bool:
                        excluded = mutually_exclusive.get(new_cat, set())
                        return not (excluded & added_categories)
                    
                    # remediation을 위한 detail 텍스트 가져오기 (use once, not repeated)
                    base_detail = ""
                    for st in stmts:
                        if st.status.impact_statement:
                            base_detail = st.status.impact_statement
                            break
                    
                    for resp in response_array:
                        resp_lower = resp.lower() if isinstance(resp, str) else ""
                        
                        # FIXED (CycloneDX Issue 3): Skip will_not_fix if it's for NOT_AFFECTED products
                        # 잘못된 "no_fix_planned" remediation 방지 for products that aren't vulnerable
                        if resp_lower == "will_not_fix" and resp_lower in not_affected_responses:
                            continue
                        
                        resp_category = response_to_category.get(resp_lower)
                        
                        if not resp_category:
                            continue
                        
                        # 상호 배타성 확인
                        if not can_add_category(resp_category):
                            continue
                        
                        if resp_category in added_categories:
                            continue
                        
                        # FIXED (CDX Issue 1): Generate category-specific details WITHOUT duplication
                        # base_detail을 workaround와 비workaround 부분으로 분리
                        workaround_parts = []
                        non_workaround_parts = []
                        if base_detail:
                            sentences = base_detail.replace(". ", ".|").split("|")
                            for s in sentences:
                                s = s.strip()
                                if not s:
                                    continue
                                if "workaround" in s.lower():
                                    workaround_parts.append(s)
                                else:
                                    non_workaround_parts.append(s)
                        
                        if resp_lower == "update":
                            # vendor_fix gets non-workaround parts only
                            if non_workaround_parts:
                                resp_details = " ".join(non_workaround_parts)
                            elif base_detail:
                                resp_details = base_detail
                            else:
                                resp_details = "Update to the latest version to resolve this vulnerability."
                        elif resp_lower == "workaround_available":
                            # workaround gets only workaround-specific sentences
                            if workaround_parts:
                                resp_details = " ".join(workaround_parts)
                            else:
                                resp_details = "A workaround is available. See vulnerability details."
                        elif resp_lower == "can_not_fix":
                            resp_details = "This vulnerability cannot be fixed in the current product version."
                        elif resp_lower == "will_not_fix":
                            # FIXED (CycloneDX Issue 3): This code path only reached for AFFECTED products
                            # NOT_AFFECTED 제품의 경우 위에서 will_not_fix 건너뜀
                            if base_detail:
                                resp_details = base_detail
                            else:
                                resp_details = "No fix is planned for this vulnerability in this product version."
                        elif resp_lower == "rollback":
                            resp_details = "Roll back to a previous version that is not affected."
                        else:
                            resp_details = f"Response: {resp}"
                        
                        rem_obj = {
                            "category": resp_category,
                            "details": resp_details,
                            "product_ids": target_pids
                        }
                        if remediation_date:
                            rem_obj["date"] = remediation_date
                        
                        remediations.append(rem_obj)
                        added_categories.add(resp_category)
                
                # 폴백: 아직 remediations 없으면 action_statements에서 구성
                if not remediations and action_statements_by_category:
                    for (category, details), pids in action_statements_by_category.items():
                        final_details = details
                        if recommendation and (
                            "No remediation" in details or
                            details == "No remediation information available"
                        ):
                            final_details = recommendation
                        
                        rem_obj = {
                            "category": category,
                            "details": final_details,
                            "product_ids": unique_list(pids)
                        }
                        # FIXED (CycloneDX Issue 1): Add date if available
                        if remediation_date:
                            rem_obj["date"] = remediation_date
                        
                        remediations.append(rem_obj)
                        
                        self.tracking_table.add(
                            source_field="CIM.statement.action_statement",
                            source_value=f"{category}, {final_details[:30]}..." if len(final_details) > 30 else f"{category}, {final_details}",
                            target_field="remediations",
                            target_value=f"category: {category}",
                            rule="action_statement → CSAF remediation",
                            status="TRANSFORMED"
                        )

                # 최종 폴백: affected 제품에 기본 remediation 추가
                if affected_pids and not remediations:
                    default_details = recommendation if recommendation else "No remediation information available"
                    default_rem = {
                        "category": "vendor_fix",
                        "details": default_details,
                        "product_ids": affected_pids
                    }
                    # FIXED (CycloneDX Issue 1): Add date if available
                    if remediation_date:
                        default_rem["date"] = remediation_date
                    remediations.append(default_rem)
                
                # FIXED (CycloneDX Issue 3): Do NOT create remediation for fixed products
                # CSAF spec: remediations are only for known_affected products
                # fixed products already have the fix applied, no remediation needed
                # resolved_with_pedigree 로직이 잘못 remediation 추가했음 for fixed products

                if remediations:
                    v_obj["remediations"] = remediations
                
                # references 추가 (categories 보존)
                references = []
                if vv and vv.references:
                    for ref in vv.references:
                        ref_obj = {"url": ref.url}
                        if ref.summary:
                            ref_obj["summary"] = ref.summary
                        if ref.category:
                            ref_obj["category"] = ref.category
                        else:
                            ref_obj["category"] = "external"  # Default
                        references.append(ref_obj)
                
                # FIXED (Issue 6): Extract pedigree information to references
                # resolved_with_pedigree 상태 확인 및 pedigree 링크 추가
                has_pedigree = any(st.status.original_state == "resolved_with_pedigree" for st in stmts)
                if has_pedigree:
                    # components에서 pedigree 데이터 가져오기 시도
                    pedigree_refs_added = False
                    components_data = get_extension_field(cim.metadata, "cyclonedx", "components")
                    if components_data:
                        for comp in components_data:
                            pedigree = comp.get("pedigree", {})
                            if pedigree:
                                # commits 추출
                                commits = pedigree.get("commits", [])
                                for commit in commits:
                                    commit_url = commit.get("url")
                                    if commit_url:
                                        references.append({
                                            "category": "external",
                                            "summary": f"Pedigree commit: {commit.get('uid', 'Unknown')}",
                                            "url": commit_url
                                        })
                                        pedigree_refs_added = True
                                
                                # patches 추출
                                patches = pedigree.get("patches", [])
                                for patch in patches:
                                    patch_url = patch.get("url") or patch.get("resolves", [{}])[0].get("url")
                                    if patch_url:
                                        references.append({
                                            "category": "external",
                                            "summary": f"Pedigree patch: {patch.get('type', 'fix')}",
                                            "url": patch_url
                                        })
                                        pedigree_refs_added = True
                    
                    # pedigree references 없으면 노트 추가
                    # (handled in notes section below)
                
                if references:
                    v_obj["references"] = references

                # metrics(CVSS) 추가 - 올바른 CSAF 구조
                if vv.ratings:
                    metrics = []
                    seen_metrics = set()  # Track unique metrics
                    
                    for rating in vv.ratings:
                        if rating.vector and rating.score is not None:
                            # CVSS 버전 결정
                            version = "3.1"
                            if rating.method:
                                if "3.0" in rating.method:
                                    version = "3.0"
                                elif "2" in rating.method:
                                    version = "2.0"

                            # vector string 구성
                            # CSAF requires:
                            #   - CVSS v3: vectorString WITH prefix (CVSS:3.1/...)
                            #   - CVSS v2: vectorString WITHOUT prefix (AV:N/AC:L/...)
                            vector = rating.vector
                            if version.startswith("3"):
                                # CVSS v3: add prefix if missing
                                if not vector.startswith("CVSS:"):
                                    vector = f"CVSS:{version}/{vector}"
                            elif version.startswith("2"):
                                # CVSS v2: remove prefix if present
                                if vector.startswith("CVSS:"):
                                    vector = vector.replace("CVSS:2.0/", "")

                            cvss_obj = {
                                "version": version,
                                "vectorString": vector,
                                "baseScore": rating.score
                            }

                            if rating.severity:
                                # CSAF requires baseSeverity in uppercase
                                cvss_obj["baseSeverity"] = rating.severity.upper()

                            # 이 vulnerability의 모든 products 가져오기
                            all_pids = []
                            for key, pids in ps_cleaned.items():
                                all_pids.extend(pids)

                            # content와 products로 metric 구성
                            metric = {
                                "content": {},
                                "products": unique_list(all_pids)
                            }

                            # 버전에 따라 cvss_v3 또는 cvss_v2 추가
                            if version.startswith("3"):
                                metric["content"]["cvss_v3"] = cvss_obj
                            elif version.startswith("2"):
                                metric["content"]["cvss_v2"] = cvss_obj
                            
                            # 중복 제거를 위한 고유 키 생성
                            # vector와 products를 키로 사용
                            metric_key = (vector, tuple(sorted(metric["products"])))
                            
                            if metric_key not in seen_metrics:
                                seen_metrics.add(metric_key)
                                metrics.append(metric)

                    if metrics:
                        v_obj["metrics"] = metrics

                if vv.references:
                    refs_data = []
                    for r in vv.references:
                        # category를 CSAF 허용값('external' 또는 'self')으로 매핑
                        category = r.category
                        if category not in ['external', 'self']:
                            category = 'external'  # Default to external
                        
                        refs_data.append({
                            "category": category,
                            "summary": r.summary or "Ref",
                            "url": r.url
                        })
                    
                    refs_data = dedupe_references(refs_data)
                    if refs_data:
                        v_obj["references"] = refs_data

            # FIXED (OpenVEX Issue 3): Reorder vulnerability fields
            # 필수 순서: cve, title, notes, product_status, flags, references, metrics, cwes, threats, remediations
            ordered_v_obj = {}
            field_order = ["cve", "title", "notes", "product_status", "flags", "references", "metrics", "cwes", "threats", "remediations", "ids"]
            for field in field_order:
                if field in v_obj:
                    ordered_v_obj[field] = v_obj[field]
            # 정렬된 목록에 없는 나머지 필드 추가
            for field, value in v_obj.items():
                if field not in ordered_v_obj:
                    ordered_v_obj[field] = value
            
            out.append(ordered_v_obj)
        return out

    def _apply_product_priority(self, stmts: List[VEXStatement], product_id_map: Dict[str, str]) -> Dict[str, List[str]]:
        """
        Apply priority rules to prevent same product in multiple statuses.
        Priority: fixed > not_affected > affected > under_investigation
        """
        ps = {"known_not_affected": [], "known_affected": [], "fixed": [], "under_investigation": []}

        # 제품별 그룹화
        by_product = {}
        for st in stmts:
            for pid in st.subject_refs:
                simple_pid = product_id_map.get(pid, pid)
                if simple_pid not in by_product:
                    by_product[simple_pid] = []
                by_product[simple_pid].append(st.status.value)

        # 각 제품에 우선순위 적용
        priority = {
            VulnerabilityStatus.FIXED: 4,
            VulnerabilityStatus.NOT_AFFECTED: 3,
            VulnerabilityStatus.AFFECTED: 2,
            VulnerabilityStatus.UNDER_INVESTIGATION: 1
        }

        for pid, statuses in by_product.items():
            # 가장 높은 우선순위 상태 가져오기
            highest = max(statuses, key=lambda s: priority.get(s, 0))

            if highest == VulnerabilityStatus.NOT_AFFECTED:
                ps["known_not_affected"].append(pid)
                # Track conversion
                self.tracking_table.add(
                    source_field="CIM.statement.status.value",
                    source_value=str(highest),
                    target_field="product_status.known_not_affected",
                    target_value=pid,
                    rule="NOT_AFFECTED → known_not_affected",
                    status="TRANSFORMED"
                )
            elif highest == VulnerabilityStatus.AFFECTED:
                ps["known_affected"].append(pid)
                # Track conversion
                self.tracking_table.add(
                    source_field="CIM.statement.status.value",
                    source_value=str(highest),
                    target_field="product_status.known_affected",
                    target_value=pid,
                    rule="AFFECTED → known_affected",
                    status="TRANSFORMED"
                )
            elif highest == VulnerabilityStatus.FIXED:
                ps["fixed"].append(pid)
                # Track conversion
                self.tracking_table.add(
                    source_field="CIM.statement.status.value",
                    source_value=str(highest),
                    target_field="product_status.fixed",
                    target_value=pid,
                    rule="FIXED → fixed",
                    status="TRANSFORMED"
                )
            else:
                ps["under_investigation"].append(pid)
                # Track conversion
                self.tracking_table.add(
                    source_field="CIM.statement.status.value",
                    source_value=str(highest),
                    target_field="product_status.under_investigation",
                    target_value=pid,
                    rule="UNDER_INVESTIGATION → under_investigation",
                    status="TRANSFORMED"
                )

        for k in ps:
            ps[k] = unique_list(ps[k])

        return ps

    def _collect_product_statuses(self, stmts: List[VEXStatement], product_id_map: Dict[str, str]) -> Dict[str, List[str]]:
        """우선순위 없이 제품 상태 수집 (중복 있을 수 있음)"""
        ps = {"known_not_affected": [], "known_affected": [], "fixed": [], "under_investigation": []}

        for st in stmts:
            for pid in st.subject_refs:
                simple_pid = product_id_map.get(pid, pid)
                if st.status.value == VulnerabilityStatus.NOT_AFFECTED:
                    ps["known_not_affected"].append(simple_pid)
                elif st.status.value == VulnerabilityStatus.AFFECTED:
                    ps["known_affected"].append(simple_pid)
                elif st.status.value == VulnerabilityStatus.FIXED:
                    ps["fixed"].append(simple_pid)
                else:
                    ps["under_investigation"].append(simple_pid)

        for k in ps:
            ps[k] = unique_list(ps[k])

        return ps

    def _create_product_groups(self, vulns: List[Dict], product_id_map: Dict[str, str]) -> List[Dict]:
        """
        Create product_groups for frequently repeated product sets.
        AGGRESSIVE: Group any set with 2+ products that appears 2+ times.
        This drastically reduces document size.
        """
        # Collect all product ID sets from vulnerabilities
        product_sets = []

        for v in vulns:
            # Collect from product_status (ANY status)
            if "product_status" in v:
                for status, pids in v["product_status"].items():
                    if isinstance(pids, list) and len(pids) >= 2:  # 2+ products
                        product_sets.append(frozenset(pids))

            # Collect from remediations
            if "remediations" in v:
                for rem in v["remediations"]:
                    pids = rem.get("product_ids", [])
                    if len(pids) >= 2:
                        product_sets.append(frozenset(pids))

            # Collect from threats
            if "threats" in v:
                for threat in v["threats"]:
                    pids = threat.get("product_ids", [])
                    if len(pids) >= 2:
                        product_sets.append(frozenset(pids))

            # Collect from metrics
            if "metrics" in v:
                for metric in v["metrics"]:
                    pids = metric.get("products", [])
                    if len(pids) >= 2:
                        product_sets.append(frozenset(pids))

        # Count frequency of each set
        from collections import Counter
        set_counts = Counter(product_sets)

        # Create candidate groups
        # Group if: repeated 2+ times OR has 5+ products (even if used once)
        candidate_groups = []

        for pids_set, count in sorted(set_counts.items(), key=lambda x: (-len(x[0]), -x[1])):
            # AGGRESSIVE: 2+ repetitions OR 5+ products
            if count >= 2 or len(pids_set) >= 5:
                candidate_groups.append(pids_set)

        # Remove subsets: if group A is a subset of group B, remove A
        # This prevents duplicate product IDs across groups
        filtered_groups = []
        for i, group_a in enumerate(candidate_groups):
            is_subset = False
            for j, group_b in enumerate(candidate_groups):
                if i != j and group_a < group_b:  # A is proper subset of B
                    is_subset = True
                    break
            if not is_subset:
                filtered_groups.append(group_a)

        # Create final product_groups with group_ids
        product_groups = []
        group_map = {}  # frozenset → group_id

        for idx, pids_set in enumerate(filtered_groups, 1):
            group_id = f"CSAFGID-{idx:04d}"
            group_map[pids_set] = group_id

            product_groups.append({
                "group_id": group_id,
                "product_ids": sorted(list(pids_set))
            })

        # Replace product_ids with group_ids in vulnerabilities
        if product_groups:
            for v in vulns:
                # Replace in product_status
                if "product_status" in v:
                    for status in list(v["product_status"].keys()):
                        pids = v["product_status"][status]
                        if isinstance(pids, list) and len(pids) > 0:
                            pids_set = frozenset(pids)
                            if pids_set in group_map:
                                # CSAF allows product_group_ids in product_status
                                v["product_status"][status] = [group_map[pids_set]]

                # Replace in remediations
                if "remediations" in v:
                    for rem in v["remediations"]:
                        pids = rem.get("product_ids", [])
                        if pids:
                            pids_set = frozenset(pids)
                            if pids_set in group_map:
                                rem["product_group_ids"] = [group_map[pids_set]]
                                del rem["product_ids"]

                # Replace in threats
                if "threats" in v:
                    for threat in v["threats"]:
                        pids = threat.get("product_ids", [])
                        if pids:
                            pids_set = frozenset(pids)
                            if pids_set in group_map:
                                threat["product_group_ids"] = [group_map[pids_set]]
                                del threat["product_ids"]

                # Replace in metrics
                if "metrics" in v:
                    for metric in v["metrics"]:
                        pids = metric.get("products", [])
                        if pids:
                            pids_set = frozenset(pids)
                            if pids_set in group_map:
                                metric["product_group_ids"] = [group_map[pids_set]]
                                del metric["products"]

        return product_groups
# ===== VALIDATION =====