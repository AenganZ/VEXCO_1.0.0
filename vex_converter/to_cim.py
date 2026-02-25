"""
형식 → CIM 변환기
OpenVEX, CycloneDX, CSAF에서 CIM(Common Information Model)으로 변환
"""
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from .models import (
    CIM, Metadata, Publisher, Subject, Vulnerability, VEXStatement,
    StatusInfo, Identifier, CvssRating, Reference, DocumentFormat,
    VulnerabilityStatus, Justification, ConversionOptions, ConversionMetadata
)
from .utils import (
    dt_to_iso_z, now_utc, safe_str, decode_structured_text,
    set_extension_field, get_extension_field, dedupe_ratings,
    filter_placeholder_ratings, dedupe_references, unique_list
)
from .constants import (
    MAPPING_TABLE, map_openvex_justification_str_to_enum,
    map_cyclonedx_justification_to_enum, csaf_flag_to_justification_enum
)


class OpenVEXToCIM:
    """OpenVEX → CIM 변환기"""
    
    def __init__(self, options: ConversionOptions = None):
        self.options = options or ConversionOptions()
        
    def convert(self, data: Dict) -> CIM:
        # 복원 모드: 첫 번째 statement의 status_notes에서 메타데이터 추출
        restore_metadata = None
        if self.options.restore:
            statements_data = data.get("statements", [])
            if statements_data:
                first_stmt = statements_data[0]
                status_notes = first_stmt.get("status_notes", "")
                if status_notes and status_notes.startswith("[VEXCONV:v1]"):
                    # 메타데이터 부분 추출 (첫 번째 | 앞)
                    meta_part = status_notes.split(" | ")[0]
                    restore_metadata = ConversionMetadata.decode(meta_part)
                    if restore_metadata:
                        print(f"[Restore Mode] Found conversion metadata from {restore_metadata.source_format}")
                        print(f"  Timestamp: {restore_metadata.timestamp}")
                        if restore_metadata.lost_data:
                            print(f"  Lost data fields: {len(restore_metadata.lost_data)}")
        
        doc_id = data.get("@id", f"openvex-{uuid.uuid4()}")
        author = data.get("author", "Unknown")
        timestamp_str = data.get("timestamp", dt_to_iso_z(now_utc()))
        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        
        # last_updated 파싱
        last_updated = None
        last_updated_str = data.get("last_updated")
        if last_updated_str:
            last_updated = datetime.fromisoformat(last_updated_str.replace('Z', '+00:00'))
        
        # version 파싱
        doc_version = data.get("version")

        metadata = Metadata(
            id=str(uuid.uuid4()),
            publisher=Publisher(name=author),
            created_at=timestamp,
            source_format=DocumentFormat.OPENVEX,
            original_id=doc_id,
            document_version=doc_version,
            last_updated=last_updated
        )
        
        # 복원용으로 OpenVEX @id를 extension_data에 저장
        if doc_id:
            set_extension_field(metadata, "openvex", "@id", doc_id)
        
        # OpenVEX 전용 문서 필드를 extension_data에 저장
        # @context 저장
        if data.get("@context"):
            set_extension_field(metadata, "openvex", "@context", data["@context"])
        
        # version (가역 변환용으로 extension_data에도 저장)
        if data.get("version"):
            set_extension_field(metadata, "openvex", "version", data["version"])
        
        # role 저장
        if data.get("role"):
            set_extension_field(metadata, "openvex", "role", data["role"])
        
        # last_updated (가역 변환용으로 extension_data에도 저장)
        if data.get("last_updated"):
            set_extension_field(metadata, "openvex", "last_updated", data["last_updated"])
        
        # tooling 저장
        if data.get("tooling"):
            set_extension_field(metadata, "openvex", "tooling", data["tooling"])

        subjects_idx = {}
        statements = []
        vulns_idx = {}

        for stmt_idx, stmt_data in enumerate(data.get("statements", [])):
            vuln = stmt_data.get("vulnerability", {})
            vuln_id = vuln.get("name", f"VULN-{stmt_idx}")

            if vuln_id not in vulns_idx:
                vuln_obj = Vulnerability(id=vuln_id)
                
                # OpenVEX 취약점 필드를 extension_data에 저장
                # vulnerability.@id 저장
                if vuln.get("@id"):
                    set_extension_field(vuln_obj, "openvex", "vulnerability.@id", vuln["@id"])
                
                # vulnerability.description 저장
                if vuln.get("description"):
                    vuln_obj.description = vuln["description"]
                
                # vulnerability.aliases - CIM aliases 필드에 저장
                if vuln.get("aliases"):
                    vuln_obj.aliases = vuln["aliases"]
                    # 하위 호환성을 위해 extension_data에도 유지
                    set_extension_field(vuln_obj, "openvex", "vulnerability.aliases", vuln["aliases"])
                
                vulns_idx[vuln_id] = vuln_obj

            status_str = stmt_data.get("status", "under_investigation")
            status_enum = {
                "affected": VulnerabilityStatus.AFFECTED,
                "not_affected": VulnerabilityStatus.NOT_AFFECTED,
                "fixed": VulnerabilityStatus.FIXED,
                "under_investigation": VulnerabilityStatus.UNDER_INVESTIGATION
            }.get(status_str, VulnerabilityStatus.UNDER_INVESTIGATION)

            justification_str = stmt_data.get("justification", "").strip()
            just_enum = map_openvex_justification_str_to_enum(justification_str) if justification_str else None
            # 원본 justification 항상 보존 (enum으로 매핑되더라도)
            custom_just = justification_str if justification_str else None

            status_notes = stmt_data.get("status_notes", "").strip()
            
            impact = stmt_data.get("impact_statement", "").strip() or None
            
            # impact_statement 없고 status_notes 있으면 status_notes에서 추출
            # status_notes 형식: "[VEXCONV:v1]{...} | text | more text"
            # 비메타데이터 텍스트를 impact_statement로 추출
            if not impact and status_notes:
                # 메타데이터 부분 제거
                notes_text = status_notes
                if notes_text.startswith("[VEXCONV:v1]"):
                    parts = notes_text.split(" | ", 1)
                    if len(parts) > 1:
                        notes_text = parts[1]  # 첫 번째 " | " 이후의 모든 내용
                
                # 실제 impact statement 추출 (before CVSS/CWE/References)
                # " | "로 분할하고 부분 추출 that are not CVSS/CWE/References
                impact_parts = []
                for part in notes_text.split(" | "):
                    # 메타데이터 형태의 부분 건너뛰기
                    if part.startswith("CVSS:") or part.startswith("CWEs:") or part.startswith("References:"):
                        break
                    if part.startswith("Note:"):
                        continue
                    impact_parts.append(part)
                
                if impact_parts:
                    impact = " | ".join(impact_parts)

            embedded_data = decode_structured_text(status_notes) if status_notes else {}
            
            # original_state 힌트를 위해 status_notes 파싱
            if status_notes and not embedded_data.get("original_state"):
                if "false positive" in status_notes.lower():
                    embedded_data["original_state"] = "false_positive"
                elif "resolved_with_pedigree" in status_notes.lower() or "pedigree" in status_notes.lower():
                    embedded_data["original_state"] = "resolved_with_pedigree"

            if embedded_data.get("cvss_ratings"):
                for rating_data in embedded_data["cvss_ratings"]:
                    vulns_idx[vuln_id].ratings.append(CvssRating(**rating_data))

            if embedded_data.get("cwes"):
                vulns_idx[vuln_id].cwes.extend(embedded_data["cwes"])

            if embedded_data.get("references"):
                for ref_data in embedded_data["references"]:
                    vulns_idx[vuln_id].references.append(Reference(**ref_data))

            subject_refs = []
            for prod in stmt_data.get("products", []):
                prod_id = prod.get("@id", "").strip()
                if not prod_id: continue
                
                # PURL 정규화: 중복 제거를 위해 repository_url 제거
                # pkg:oci/trivy?repository_url=... → pkg:oci/trivy
                normalized_id = prod_id
                if prod_id.startswith("pkg:"):
                    normalized_id = prod_id.split("?")[0].split("#")[0]

                # 항상 메인 제품을 subject로 등록
                if normalized_id not in subjects_idx:
                    id_type = "purl" if normalized_id.startswith("pkg:") else ("cpe" if normalized_id.startswith("cpe:") else "product_id")
                    
                    # identifiers 목록 구성
                    identifiers = [Identifier(type=id_type, value=normalized_id)]
                    
                    # OpenVEX identifiers 필드에서 추가 식별자 추출
                    prod_identifiers = prod.get("identifiers", {})
                    if prod_identifiers:
                        # purl 처리
                        if prod_identifiers.get("purl") and prod_identifiers["purl"] != normalized_id:
                            identifiers.append(Identifier(type="purl", value=prod_identifiers["purl"]))
                        # CPE 처리 (cpe23 or cpe)
                        cpe_value = prod_identifiers.get("cpe23") or prod_identifiers.get("cpe")
                        if cpe_value:
                            identifiers.append(Identifier(type="cpe", value=cpe_value))
                    
                    # @id에서 버전 추출 - handle scoped packages properly
                    # 예시:
                    # - pkg:maven/com.acme/product-zeta@1.0.1 → version: 1.0.1
                    # - pkg:npm/@webframe/auth@2.0.0 → version: 2.0.0 (scoped package)
                    # - pkg:maven/com.acme/product-zeta@range:>=2.0.0|<2.3.0 → version: vers:semver/>=2.0.0|<2.3.0
                    version = None
                    name = None
                    if "@" in normalized_id:
                        # 버전 구분자인 마지막 @ 찾기 (not scoped package @)
                        # 스코프 패키지의 경우 pkg:npm/@webframe/auth@2.0.0
                        # 마지막 / 뒤의 @를 찾아야 함 /
                        last_slash = normalized_id.rfind("/")
                        if last_slash > 0:
                            after_slash = normalized_id[last_slash+1:]
                            if "@" in after_slash:
                                # 버전 @가 마지막 / 뒤에 있음 /
                                at_in_after = after_slash.find("@")
                                version_start = last_slash + 1 + at_in_after
                                base_part = normalized_id[:version_start]
                                version_part = normalized_id[version_start+1:]
                                name = after_slash[:at_in_after]
                            else:
                                # 버전 없음, 스코프 패키지만
                                base_part = normalized_id
                                version_part = None
                                name = after_slash
                        else:
                            # 단순 케이스: pkg:type/ 뒤에 슬래시 없음/
                            parts = normalized_id.split("@")
                            base_part = parts[0]
                            version_part = parts[1] if len(parts) > 1 else None
                            if "/" in base_part:
                                name = base_part.split("/")[-1]
                        
                        if version_part:
                            # 다양한 버전 형식 처리
                            if version_part.startswith("range:"):
                                # range:>=2.0.0|<2.3.0 → vers:semver 변환/>=2.0.0|<2.3.0
                                version = "vers:semver/" + version_part[6:]
                            elif version_part.startswith("vers:"):
                                # vers:semver/<1.0.1 → 그대로 유지
                                version = version_part
                            else:
                                # 1.0.1 → 그대로 유지
                                version = version_part
                    
                    # 해시 존재 시 추출
                    hashes = prod.get("hashes")
                    hashes_list = None
                    if hashes:
                        # OpenVEX 해시 형식을 CIM 형식으로 변환
                        hashes_list = []
                        for alg, value in hashes.items():
                            hashes_list.append({
                                "algorithm": alg,
                                "value": value
                            })
                    
                    subj = Subject(
                        ref=normalized_id, 
                        identifiers=identifiers,
                        original_id=prod_id,  # 가역 변환용 원본 @id 저장
                        hashes=hashes_list,  # 해시 저장
                        version=version,  # 추출된 버전 저장
                        name=name  # 추출된 이름 저장
                    )
                    
                    subjects_idx[normalized_id] = subj

                subcomps = prod.get("subcomponents", [])
                if subcomps:
                    # subcomponent가 있으면 subject_refs에 추가 (실제 영향받는 컴포넌트)
                    for sub in subcomps:
                        sub_id = sub.get("@id", "").strip()
                        if sub_id:
                            # subcomponent PURL도 정규화
                            normalized_sub = sub_id
                            if sub_id.startswith("pkg:"):
                                normalized_sub = sub_id.split("?")[0].split("#")[0]
                            
                            if normalized_sub not in subjects_idx:
                                subj_sub = Subject(
                                    ref=normalized_sub, 
                                    identifiers=[Identifier(
                                        type="purl" if normalized_sub.startswith("pkg:") else "product_id", 
                                        value=normalized_sub
                                    )],
                                    original_id=sub_id,
                                    parent_ref=normalized_id  # 부모 product 참조 설정
                                )
                                
                                subjects_idx[normalized_sub] = subj_sub
                            else:
                                # 이미 존재하는 subject에 parent_ref 설정
                                if subjects_idx[normalized_sub].parent_ref is None:
                                    subjects_idx[normalized_sub].parent_ref = normalized_id
                            subject_refs.append(normalized_sub)
                else:
                    # subcomponent 없음: 메인 product 자체가 영향받음
                    subject_refs.append(normalized_id)

            stmt_ts = stmt_data.get("timestamp")
            stmt_dt = datetime.fromisoformat(stmt_ts.replace('Z', '+00:00')) if stmt_ts else timestamp

            action = stmt_data.get("action_statement", "").strip() or None

            # 원본 CycloneDX state 존재 시 복원
            original_state = embedded_data.get("original_state")

            stmt = VEXStatement(
                id=f"stmt-{stmt_idx}",
                subject_refs=unique_list(subject_refs),
                vulnerability_id=vuln_id,
                status=StatusInfo(
                    value=status_enum,
                    justification=just_enum,
                    custom_justification=custom_just,
                    impact_statement=impact,
                    original_state=original_state
                ),
                timestamp=stmt_dt,
                action_statement=action
            )
            
            # OpenVEX statement 필드를 extension_data에 저장
            # status_notes (원시 값, embedded_data 아님)
            if status_notes:
                set_extension_field(stmt, "openvex", "status_notes", status_notes)
            
            # 수정: action_statement_timestamp 저장 for CycloneDX firstIssued mapping
            action_ts = stmt_data.get("action_statement_timestamp")
            if action_ts:
                set_extension_field(stmt, "openvex", "action_statement_timestamp", action_ts)
            
            # supplier 저장
            if stmt_data.get("supplier"):
                set_extension_field(stmt, "openvex", "supplier", stmt_data["supplier"])
            
            statements.append(stmt)
        
        # 복원 모드: extension_data와 subject_mappings 적용
        if self.options.restore and restore_metadata:
            extension_data = restore_metadata.extension_data
            subject_mappings = restore_metadata.subject_mappings
            restored_count = 0
            
            # extension_data 복원
            if extension_data:
                # Metadata extension_data 복원
                if "metadata" in extension_data:
                    metadata.extension_data = extension_data["metadata"]
                    restored_count += 1
                
                # Subject extension_data 복원
                for idx, subj in enumerate(subjects_idx.values()):
                    key = f"subject_{idx}"
                    if key in extension_data:
                        subj.extension_data = extension_data[key]
                        restored_count += 1
                
                # Vulnerability extension_data 복원 (use ID as key, not index)
                for vuln in vulns_idx.values():
                    key = f"vulnerability_{vuln.id}"
                    if key in extension_data:
                        vuln_ext = extension_data[key]
                        vuln.extension_data = vuln_ext
                        restored_count += 1
                        
                        # extension_data에서 references 복원
                        if "references" in vuln_ext:
                            for ref_dict in vuln_ext["references"]:
                                vuln.references.append(Reference(
                                    url=ref_dict.get("url", ""),
                                    summary=ref_dict.get("summary"),
                                    category=ref_dict.get("category"),
                                    id=ref_dict.get("id")
                                ))
                        
                        # extension_data에서 ratings 복원
                        if "ratings" in vuln_ext:
                            for rating_dict in vuln_ext["ratings"]:
                                vuln.ratings.append(CvssRating(
                                    method=rating_dict.get("method"),
                                    score=rating_dict.get("score"),
                                    severity=rating_dict.get("severity"),
                                    vector=rating_dict.get("vector")
                                ))
                        
                        # extension_data에서 cwes 복원
                        if "cwes" in vuln_ext:
                            vuln.cwes = vuln_ext["cwes"]
                
                # Statement extension_data 복원
                for idx, stmt in enumerate(statements):
                    key = f"statement_{idx}"
                    if key in extension_data:
                        stmt.extension_data = extension_data[key]
                        restored_count += 1
            
            # subject_mappings에서 original_id 복원
            if subject_mappings:
                for subj in subjects_idx.values():
                    if subj.ref in subject_mappings:
                        subj.original_id = subject_mappings[subj.ref]
                        restored_count += 1
            
            if restored_count > 0:
                print(f"[Restore Mode] Restored {restored_count} field(s) from metadata")

        return CIM(
            metadata=metadata,
            subjects=list(subjects_idx.values()),
            vulnerabilities=list(vulns_idx.values()),
            statements=statements
        )

class CycloneDXToCIM:
    def __init__(self, options: ConversionOptions = None):
        self.options = options or ConversionOptions()
        
    def convert(self, data: Dict) -> CIM:
        # 복원 모드: 메타데이터 존재 시 추출
        restore_metadata = None
        if self.options.restore:
            metadata_section = data.get("metadata", {})
            properties = metadata_section.get("properties", [])
            for prop in properties:
                if prop.get("name") == "VEXCO.metadata":
                    restore_metadata = ConversionMetadata.decode(prop.get("value", ""))
                    if restore_metadata:
                        print(f"\n[Restore Mode] Found conversion metadata from {restore_metadata.source_format}")
                        print(f"  Timestamp: {restore_metadata.timestamp}")
                        print(f"  Lost data fields: {len(restore_metadata.lost_data)}")
                    break
        
        metadata_data = data.get("metadata", {})
        timestamp_str = metadata_data.get("timestamp", dt_to_iso_z(now_utc()))
        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        
        # 문서 버전 가져오기
        doc_version = data.get("version")

        # tools 또는 manufacturer에서 publisher 정보 추출
        # 이전(리스트)과 새로운(components 객체) tools 형식 모두 지원
        tools_field = metadata_data.get("tools", [])
        vendor = "Unknown"
        
        if isinstance(tools_field, dict):
            # 새 형식: {"components": [...]}
            tool_components = tools_field.get("components", [])
            if tool_components:
                first_tool = tool_components[0]
                # supplier.name 먼저 시도, 없으면 name
                supplier = first_tool.get("supplier", {})
                if isinstance(supplier, dict) and supplier.get("name"):
                    vendor = supplier["name"]
                elif first_tool.get("name"):
                    vendor = first_tool["name"]
        elif isinstance(tools_field, list) and tools_field:
            # 이전 형식: [{"vendor": "...", "name": "..."}]
            first_tool = tools_field[0]
            vendor = first_tool.get("vendor", first_tool.get("name", "Unknown"))
        
        # components에서 manufacturer 정보 가져오기 시도 (최우선)
        manufacturer_name = None
        manufacturer_url = None
        components = data.get("components", [])
        if components:
            # manufacturer 정보가 있는 첫 번째 component에서 manufacturer 가져오기
            for comp in components:
                manufacturer = comp.get("manufacturer", {})
                if manufacturer:
                    if manufacturer.get("name"):
                        manufacturer_name = manufacturer["name"]
                    if manufacturer.get("url"):
                        manufacturer_url = manufacturer["url"]
                    if manufacturer_name or manufacturer_url:
                        break  # manufacturer 정보 찾음
        
        # manufacturer 있으면 사용, 없으면 tools의 vendor 사용
        publisher_name = manufacturer_name if manufacturer_name else vendor
        publisher_namespace = manufacturer_url if manufacturer_url else None

        metadata = Metadata(
            id=str(uuid.uuid4()),
            publisher=Publisher(
                name=publisher_name,
                namespace=publisher_namespace
            ),
            created_at=timestamp,
            source_format=DocumentFormat.CYCLONEDX,
            original_id=data.get("serialNumber"),
            document_version=doc_version
        )
        
        # 수정 (CycloneDX 이슈 3): 취약점에서 lastUpdated 추출하여 metadata.last_updated에 사용
        # OpenVEX last_updated 필드에 사용됨
        latest_last_updated = None
        for v in data.get("vulnerabilities", []):
            analysis = v.get("analysis", {})
            last_updated_str = analysis.get("lastUpdated")
            if last_updated_str:
                try:
                    last_updated_dt = datetime.fromisoformat(last_updated_str.replace('Z', '+00:00'))
                    if latest_last_updated is None or last_updated_dt > latest_last_updated:
                        latest_last_updated = last_updated_dt
                except:
                    pass
        
        if latest_last_updated:
            metadata.last_updated = latest_last_updated
        
        # 완벽한 복원을 위해 원본 components 저장
        if self.options.reversible:
            original_components = data.get("components", [])
            if original_components:
                set_extension_field(metadata, "cyclonedx", "components", original_components)
            
            # 완벽한 복원을 위해 metadata.supplier 저장
            metadata_supplier = metadata_data.get("supplier")
            if metadata_supplier:
                set_extension_field(metadata, "cyclonedx", "metadata.supplier", metadata_supplier)
        
        # metadata.component 저장 (VDR에 중요)
        metadata_component = metadata_data.get("component")
        if metadata_component:
            set_extension_field(metadata, "cyclonedx", "metadata.component", metadata_component)
        
        # 수정 (이슈 7): tools 정보 저장 for accurate restoration in CSAF notes
        if tools_field:
            set_extension_field(metadata, "cyclonedx", "metadata.tools", tools_field)
            # tool name/supplier도 명시적으로 추출하여 저장 for easy access
            tool_name = None
            tool_supplier = None
            if isinstance(tools_field, dict):
                tool_components = tools_field.get("components", [])
                if tool_components:
                    first_tool = tool_components[0]
                    tool_name = first_tool.get("name")
                    supplier = first_tool.get("supplier", {})
                    if isinstance(supplier, dict):
                        tool_supplier = supplier.get("name")
            elif isinstance(tools_field, list) and tools_field:
                first_tool = tools_field[0]
                tool_name = first_tool.get("name")
                tool_supplier = first_tool.get("vendor")
            
            if tool_name:
                set_extension_field(metadata, "cyclonedx", "tool_name", tool_name)
            if tool_supplier:
                set_extension_field(metadata, "cyclonedx", "tool_supplier", tool_supplier)
        
        # CycloneDX 1.7+ distributionConstraints.tlp 파싱
        distribution_constraints = metadata_data.get("distributionConstraints", {})
        if distribution_constraints:
            set_extension_field(metadata, "cyclonedx", "metadata.distributionConstraints", distribution_constraints)
            # TLP 정보를 공통 필드로 저장 (CSAF 변환 시 사용)
            tlp_label = distribution_constraints.get("tlp")
            if tlp_label:
                # CycloneDX TLP → 정규화된 TLP (CIM 공통)
                # CycloneDX: CLEAR, GREEN, AMBER, AMBER_AND_STRICT, RED
                set_extension_field(metadata, "common", "tlp.label", tlp_label)

        subjects_idx = {}
        for comp in data.get("components", []):
            ref = comp.get("bom-ref", "").strip()
            if not ref: continue

            identifiers = []
            if comp.get("purl"): identifiers.append(Identifier(type="purl", value=comp["purl"]))
            if comp.get("cpe"): identifiers.append(Identifier(type="cpe", value=comp["cpe"]))
            
            # CycloneDX 해시를 CIM 형식으로 변환
            hashes = None
            cdx_hashes = comp.get("hashes", [])
            if cdx_hashes:
                # CDX 형식: [{"alg": "SHA-256", "content": "..."}]
                # CIM 형식: [{"algorithm": "sha-256", "value": "..."}]
                hashes = []
                for h in cdx_hashes:
                    alg = h.get("alg", "")
                    content = h.get("content", "")
                    if alg and content:
                        # 알고리즘 이름 변환: SHA-256 → sha-256
                        alg_lower = alg.lower()
                        hashes.append({"algorithm": alg_lower, "value": content})

            subjects_idx[ref] = Subject(
                ref=ref,
                identifiers=identifiers,
                name=comp.get("name"),
                version=comp.get("version"),
                type=comp.get("type", "library"),
                original_id=ref,  # 원본 URN 형식 보존 (예: urn:cdx:...)
                hashes=hashes  # 해시 추가
            )

        # components 없는 affects refs에 대해 가상 subjects 생성
        all_affect_refs = set()
        for v in data.get("vulnerabilities", []):
            for a in v.get("affects", []):
                ref = a.get("ref")
                if ref: all_affect_refs.add(ref)

        for ref in all_affect_refs:
            if ref not in subjects_idx:
                name = self._extract_name_from_ref(ref)
                id_type = "purl" if ref.startswith("pkg:") else ("cpe" if ref.startswith("cpe:") else "product_id")
                
                # 복원 모드에서 원본 ID 찾기 시도
                determined_original_id = None
                if restore_metadata and restore_metadata.subject_mappings:
                    # 정확한 일치 시도
                    if ref in restore_metadata.subject_mappings:
                        determined_original_id = restore_metadata.subject_mappings[ref]
                    # urn:cdx 접두사 제거하여 찾기 시도
                    elif "#" in ref:
                        # urn:cdx:xxx#pkg:apk/alpine/busybox:vunknown → pkg:apk/alpine/busybox
                        clean_ref = ref.split("#")[1] if "#" in ref else ref
                        # :vunknown 접미사 제거
                        if ":vunknown" in clean_ref:
                            clean_ref = clean_ref.replace(":vunknown", "")
                        # 매핑에서 찾기 시도
                        if clean_ref in restore_metadata.subject_mappings:
                            determined_original_id = restore_metadata.subject_mappings[clean_ref]
                
                subjects_idx[ref] = Subject(
                    ref=ref,
                    identifiers=[Identifier(type=id_type, value=ref)],
                    name=name,
                    type="library",
                    original_id=determined_original_id
                )

        statements = []
        vulns_idx = {}

        for vidx, v in enumerate(data.get("vulnerabilities", [])):
            vuln_id = v.get("id", f"VULN-{vidx}")

            if vuln_id not in vulns_idx:
                vuln = Vulnerability(id=vuln_id, description=v.get("description"))

                for r in v.get("ratings", []):
                    vuln.ratings.append(CvssRating(
                        method=r.get("method"),
                        score=r.get("score"),
                        severity=r.get("severity"),
                        vector=r.get("vector")
                    ))

                vuln.cwes = v.get("cwes", [])

                # source를 참조로 추가 (취약점 정보의 주요 출처)
                source = v.get("source", {})
                if source and source.get("url"):
                    vuln.references.append(Reference(
                        url=source.get("url", ""),
                        summary=source.get("name", "Primary Source"),
                        category="source"
                    ))

                # 추가 참조 추가
                for ref in v.get("references", []):
                    source_obj = ref.get("source", {})
                    ref_id = ref.get("id")
                    ref_url = source_obj.get("url", "")
                    
                    # id가 실제로 유효한 URL 형식인 경우에만 URL로 사용
                    if not ref_url and ref_id:
                        # id가 URL처럼 보이는지 확인 (http:// 또는 https://로 시작)
                        if ref_id.startswith(("http://", "https://")):
                            ref_url = ref_id
                        # 그렇지 않으면 id를 URL로 사용 안 함
                    
                    # 참조 생성하려면 유효한 URL 필수
                    if ref_url:
                        vuln.references.append(Reference(
                            url=ref_url,
                            summary=source_obj.get("name"),
                            category="external",
                            id=ref_id if ref_id and not ref_id.startswith(("http://", "https://")) else None
                        ))
                
                # CSAF notes용 recommendation을 extension_data에 저장
                recommendation = v.get("recommendation")
                if recommendation:
                    set_extension_field(vuln, "cyclonedx", "recommendation", recommendation)
                
                # VDR (취약점 공개 보고서) 필드 처리
                # detail - 상세 설명
                detail = v.get("detail")
                if detail:
                    set_extension_field(vuln, "cyclonedx", "detail", detail)
                
                # workaround - 임시 완화책
                workaround = v.get("workaround")
                if workaround:
                    set_extension_field(vuln, "cyclonedx", "workaround", workaround)
                
                # proofOfConcept - 개념 증명
                proof_of_concept = v.get("proofOfConcept")
                if proof_of_concept:
                    set_extension_field(vuln, "cyclonedx", "proofOfConcept", proof_of_concept)
                
                # credits - 발견자 정보
                credits = v.get("credits")
                if credits:
                    set_extension_field(vuln, "cyclonedx", "credits", credits)
                
                # 수정됨 (CycloneDX 이슈 1): analysis 타임스탬프 항상 저장
                # reversible 옵션에 관계없이 remediation.date 매핑에 필요
                original_first_issued = v.get("analysis", {}).get("firstIssued")
                if original_first_issued:
                    set_extension_field(vuln, "cyclonedx", "analysis.firstIssued", original_first_issued)
                
                original_last_updated = v.get("analysis", {}).get("lastUpdated")
                if original_last_updated:
                    set_extension_field(vuln, "cyclonedx", "analysis.lastUpdated", original_last_updated)
                
                # analysis.detail 항상 저장 (OpenVEX status_notes에 필요)
                original_detail = v.get("analysis", {}).get("detail")
                if original_detail:
                    set_extension_field(vuln, "cyclonedx", "analysis.detail", original_detail)
                
                # 완벽한 복원을 위해 원본 affects 저장
                if self.options.reversible:
                    original_affects = v.get("affects", [])
                    if original_affects:
                        set_extension_field(vuln, "cyclonedx", "affects", original_affects)

                vulns_idx[vuln_id] = vuln

            analysis = v.get("analysis", {})
            state_str = analysis.get("state", "in_triage")
            just_raw = safe_str(analysis.get("justification")).strip() or None

            detail_text = safe_str(analysis.get("detail", "")).strip()
            embedded_data = decode_structured_text(detail_text) if detail_text else {}

            original_just = embedded_data.get("original_justification")
            custom_just = embedded_data.get("custom_justification")

            just_enum = None
            if original_just:
                just_enum = map_openvex_justification_str_to_enum(original_just)
                if not just_enum:
                    custom_just = original_just
            elif just_raw:
                just_enum = map_cyclonedx_justification_to_enum(just_raw)
                # 보존을 위해 원본 CycloneDX justification 저장
                if just_enum and just_raw:
                    # 매핑 성공 시 CSAF 출력용으로 원본을 custom으로 저장
                    custom_just = f"cyclonedx:{just_raw}"
                elif not just_enum:
                    custom_just = just_raw

            # 모든 CycloneDX 상태에 대해 원본 상태 저장 (완벽한 복원용)
            # exploitable, in_triage, resolved 등 포함
            original_cdx_state = state_str if state_str else None

            status_str = MAPPING_TABLE["cyclonedx_state_to_openvex_status"].get(state_str, "under_investigation")
            status_enum = {
                "affected": VulnerabilityStatus.AFFECTED,
                "not_affected": VulnerabilityStatus.NOT_AFFECTED,
                "fixed": VulnerabilityStatus.FIXED,
                "under_investigation": VulnerabilityStatus.UNDER_INVESTIGATION
            }.get(status_str, VulnerabilityStatus.UNDER_INVESTIGATION)

            # affects 처리 전에 impact_statement 추출
            # resolved/resolved_with_pedigree 상태의 경우 detail을 impact_statement로 사용
            if state_str in ["resolved", "resolved_with_pedigree"] and detail_text:
                impact_stmt = detail_text
            elif state_str == "false_positive" and detail_text:
                # false_positive의 경우 detail이 왜 거짓 양성인지 설명
                impact_stmt = detail_text
            elif "impact_statement" in embedded_data:
                impact_stmt = embedded_data.get("impact_statement")
            elif detail_text and status_str == "not_affected":
                # not_affected의 경우에도 detail을 impact_statement로 사용
                impact_stmt = detail_text
            elif state_str == "in_triage" and detail_text:
                # in_triage의 경우에도 detail을 impact_statement로 사용
                impact_stmt = detail_text
            elif state_str == "exploitable" and detail_text:
                # exploitable의 경우에도 detail을 impact_statement로 사용
                impact_stmt = detail_text
            else:
                impact_stmt = None

            # false_positive의 경우 justification 추가
            if state_str == "false_positive":
                if not just_enum:
                    # false_positive의 기본 justification
                    just_enum = Justification.VULNERABLE_CODE_NOT_PRESENT
                    if not custom_just:
                        custom_just = "false_positive"

            # action_statement 추출 (recommendation 먼저, 그 다음 detail, response 순)
            action_parts = []
            
            # AFFECTED 상태의 경우
            if status_enum == VulnerabilityStatus.AFFECTED:
                # 1. recommendation (최우선 - 구체적인 개선 조언)
                recommendation = v.get("recommendation")
                if recommendation:
                    action_parts.append(recommendation)
                
                # 2. analysis.detail (워크어라운드 등 상세 정보 포함)
                detail_text = analysis.get("detail")
                if detail_text:
                    action_parts.append(detail_text)
                elif not recommendation:
                    # 3. recommendation과 detail이 없는 경우에만 response를 텍스트로 변환
                    response = analysis.get("response")
                    if response:
                        response_texts = []
                        if isinstance(response, list):
                            for r in response:
                                response_texts.append(self._response_to_text(r))
                        else:
                            response_texts.append(self._response_to_text(response))

                        # and로 연결
                        if response_texts:
                            action_parts.append(" and ".join(response_texts))

                # 4. 다른 것이 없으면 기본 메시지
                if not action_parts:
                    action_parts.append("No remediation information available")

                # workaround 가져오기 (명시적 필드가 있는 경우)
                workaround = v.get("workaround")
                if workaround:
                    action_parts.append(f"Workaround: {workaround}")
            
            # FIXED 상태의 경우 (resolved_with_pedigree 포함)
            elif status_enum == VulnerabilityStatus.FIXED:
                # response 정보 포함
                response = analysis.get("response")
                if response:
                    response_texts = []
                    if isinstance(response, list):
                        for r in response:
                            response_texts.append(self._response_to_text(r))
                    else:
                        response_texts.append(self._response_to_text(response))
                    if response_texts:
                        action_parts.append(" and ".join(response_texts))
                # FIXED 상태용 workaround 가져오기
                workaround = v.get("workaround")
                if workaround:
                    action_parts.append(f"Workaround: {workaround}")

            action_statement = " | ".join(action_parts) if action_parts else None

            # 보존을 위해 원본 response 저장
            original_response = analysis.get("response")
            stmt_extension_data = {}
            if original_response:
                stmt_extension_data["cyclonedx_response"] = original_response
            
            affect_refs = []
            
            # 버전 범위 분석하여 fixed 상태 감지
            # 조건: range: vers:semver/<X.Y.Z + version: X.Y.Z unaffected + response: update
            # 결과: 버전 X.Y.Z는 FIXED (단순 unaffected가 아님)
            version_fixes = {}  # version_val → is_fixed
            
            for a in v.get("affects", []):
                versions = a.get("versions", [])
                if len(versions) >= 2:
                    # range + fixed 버전 패턴 확인
                    for i in range(len(versions) - 1):
                        curr_ver = versions[i]
                        next_ver = versions[i + 1]
                        
                        # 현재가 affected range이고 다음이 unaffected 버전인지 확인
                        curr_range = curr_ver.get("range", "")
                        curr_status = curr_ver.get("status", "")
                        next_version = next_ver.get("version", "")
                        next_status = next_ver.get("status", "")
                        
                        # 패턴: range: vers:semver/<1.0.1 + affected
                        #      + version: 1.0.1 + unaffected
                        #      + response: update
                        # → 버전 1.0.1은 FIXED
                        if (curr_range.startswith("vers:") and "affected" in curr_status and
                            next_version and ("unaffected" in next_status or "not_affected" in next_status)):
                            # range에서 경계 버전 추출
                            # vers:semver/<1.0.1 → 1.0.1
                            import re
                            match = re.search(r'<([0-9.]+)', curr_range)
                            if match:
                                boundary_version = match.group(1)
                                # next_version이 경계와 일치하는지 확인
                                if next_version == boundary_version:
                                    # response에 "update" 포함 여부 확인
                                    response = analysis.get("response", [])
                                    if isinstance(response, list) and "update" in response:
                                        version_fixes[next_version] = True
                                    elif response == "update":
                                        version_fixes[next_version] = True
            
            # statement 병합을 위해 상태별 버전 그룹화
            # 키: (status, action_statement, justification)
            # 값: version_refs 리스트
            version_groups = {}
            
            for a in v.get("affects", []):
                ref = a.get("ref", "").strip()
                if not ref:
                    continue

                versions = a.get("versions", [])
                if versions:
                    # 상태별로 버전 그룹화
                    for version_info in versions:
                        version_val = version_info.get("version")
                        range_val = version_info.get("range")
                        version_status = version_info.get("status")
                        
                        # 버전인지 범위인지 결정
                        is_version_range = False
                        if range_val and not version_val:
                            version_val = range_val
                            is_version_range = True

                        if not version_val:
                            continue

                        # 버전별 ref 생성
                        # 버전 범위의 경우 고유한 ref 생성을 위해 해시 사용
                        # (PURL 형식 문자열에 범위를 직접 넣지 않음)
                        if is_version_range:
                            # 고유성을 위한 해시 기반 ref 생성
                            range_hash = hashlib.md5(f"{ref}:{range_val}".encode()).hexdigest()[:8]
                            version_ref = f"{ref}:range:{range_hash}"
                        else:
                            version_ref = f"{ref}:v{version_val}"

                        # 버전별 subject가 없으면 생성
                        if version_ref not in subjects_idx:
                            base_subject = subjects_idx.get(ref)
                            
                            # 이 버전의 original_id 결정
                            # 복원 모드에서 subject_mappings에서 원본 ID 찾기 시도
                            determined_original_id = None
                            if restore_metadata and restore_metadata.subject_mappings:
                                # 먼저 정확한 일치 시도
                                if version_ref in restore_metadata.subject_mappings:
                                    determined_original_id = restore_metadata.subject_mappings[version_ref]
                                # 버전 접미사 없이 시도
                                elif ref in restore_metadata.subject_mappings:
                                    determined_original_id = restore_metadata.subject_mappings[ref]
                            
                            if base_subject:
                                # 수정됨 (CycloneDX 이슈 2): identifier purl 버전을 version_val과 일치하도록 업데이트
                                new_identifiers = []
                                for ident in base_subject.identifiers:
                                    if ident.type == "purl" and ident.value and '@' in ident.value:
                                        # 범위가 아니면 purl 버전 업데이트
                                        if not version_val.startswith("vers:") and not is_version_range:
                                            # 기본 purl 추출 및 버전 업데이트
                                            last_at = ident.value.rfind('@')
                                            slash_after_at = ident.value.find('/', last_at) if last_at >= 0 else -1
                                            if slash_after_at == -1 or slash_after_at < last_at:
                                                # @가 버전 구분자 - 교체
                                                base_purl = ident.value[:last_at]
                                                updated_purl = f"{base_purl}@{version_val}"
                                                new_identifiers.append(Identifier(type="purl", value=updated_purl))
                                            else:
                                                new_identifiers.append(Identifier(type=ident.type, value=ident.value))
                                        else:
                                            new_identifiers.append(Identifier(type=ident.type, value=ident.value))
                                    else:
                                        new_identifiers.append(Identifier(type=ident.type, value=ident.value))
                                
                                new_subject = Subject(
                                    ref=version_ref,
                                    identifiers=new_identifiers,
                                    name=f"{base_subject.name} {version_val}" if base_subject.name else version_val,
                                    version=version_val,
                                    type=base_subject.type,
                                    original_id=determined_original_id or base_subject.original_id,
                                    hashes=base_subject.hashes  # 기본 subject에서 해시 복사
                                )
                                # 버전 범위 정보를 extension_data에 저장
                                if is_version_range:
                                    set_extension_field(new_subject, "cyclonedx", "is_version_range", True)
                                    set_extension_field(new_subject, "cyclonedx", "version_range", version_val)
                                    # PURL 생성을 위한 기본 ref 저장
                                    set_extension_field(new_subject, "cyclonedx", "base_ref", ref)
                                    # 수정됨 (CycloneDX 이슈 2): 올바른 status_notes를 위해 버전 상태 저장
                                    set_extension_field(new_subject, "cyclonedx", "version_status", version_status)
                                subjects_idx[version_ref] = new_subject
                            else:
                                new_subject = Subject(
                                    ref=version_ref,
                                    identifiers=[Identifier(type="product_id", value=version_ref)],
                                    name=version_val,
                                    version=version_val,
                                    type="library",
                                    original_id=determined_original_id
                                )
                                if is_version_range:
                                    set_extension_field(new_subject, "cyclonedx", "is_version_range", True)
                                    set_extension_field(new_subject, "cyclonedx", "version_range", version_val)
                                    set_extension_field(new_subject, "cyclonedx", "base_ref", ref)
                                    # 수정됨 (CycloneDX 이슈 2): 올바른 status_notes를 위해 버전 상태 저장
                                    set_extension_field(new_subject, "cyclonedx", "version_status", version_status)
                                subjects_idx[version_ref] = new_subject

                        # 버전 상태를 VulnerabilityStatus로 매핑
                        # 이 버전이 fixed로 식별되었는지 확인
                        if version_val in version_fixes and version_fixes[version_val]:
                            # 이 버전은 FIXED (패치가 사용 가능한 경계 버전)
                            version_status_enum = VulnerabilityStatus.FIXED
                        elif version_status == "affected":
                            version_status_enum = VulnerabilityStatus.AFFECTED
                        elif version_status in ["unaffected", "not_affected"]:
                            # 특수 케이스: analysis.state가 "resolved" 또는 "resolved_with_pedigree"이고
                            # response에 "update"가 포함되면, unaffected 버전은 FIXED
                            if state_str in ["resolved", "resolved_with_pedigree"]:
                                response = analysis.get("response", [])
                                if (isinstance(response, list) and "update" in response) or response == "update":
                                    version_status_enum = VulnerabilityStatus.FIXED
                                else:
                                    version_status_enum = VulnerabilityStatus.NOT_AFFECTED
                                    # resolved 상태에서 NOT_AFFECTED에 대한 기본 justification 추가
                                    if not just_enum:
                                        just_enum = Justification.VULNERABLE_CODE_NOT_PRESENT
                                        if not custom_just:
                                            custom_just = "fixed_in_this_version"
                            else:
                                version_status_enum = VulnerabilityStatus.NOT_AFFECTED
                        elif version_status == "unknown":
                            version_status_enum = VulnerabilityStatus.UNDER_INVESTIGATION
                        elif version_status is None:
                            version_status_enum = status_enum
                        else:
                            version_status_enum = status_enum

                        # (status, action_statement, justification, detail_text)로 그룹화
                        # 다른 detail을 가진 다른 제품을 분리하기 위해 detail_text 포함
                        group_key = (
                            version_status_enum,
                            action_statement,
                            just_enum,
                            custom_just,
                            impact_stmt if isinstance(impact_stmt, str) else None,
                            original_cdx_state,
                            detail_text if detail_text and not embedded_data else None  # 제품 분리를 위해 detail_text 추가
                        )
                        
                        if group_key not in version_groups:
                            version_groups[group_key] = []
                        version_groups[group_key].append(version_ref)
                else:
                    # 버전 정보 없음, ref 직접 사용
                    # 복원 모드에서 이 ref에 대한 원본 상태가 있는지 확인
                    if restore_metadata and restore_metadata.lost_data:
                        status_key = f"stmt_status_{ref}_{vuln_id}"
                        original_status_name = restore_metadata.lost_data.get(status_key)
                        if original_status_name:
                            # 원본 상태 복원
                            try:
                                restored_status = VulnerabilityStatus[original_status_name]
                                # 원본 상태와 함께 이 ref에 대한 별도 statement 생성
                                statements.append(VEXStatement(
                                    id=f"stmt-{vidx}-{ref}",
                                    subject_refs=[ref],
                                    vulnerability_id=vuln_id,
                                    status=StatusInfo(
                                        value=restored_status,
                                        justification=just_enum,
                                        custom_justification=custom_just,
                                        impact_statement=impact_stmt,
                                        original_state=original_cdx_state
                                    ),
                                    timestamp=timestamp,
                                    action_statement=action_statement,
                                    extension_data=stmt_extension_data.copy()
                                ))
                                continue  # affect_refs에 추가 건너뛰기
                            except KeyError:
                                pass  # 기본 처리로 이동
                    
                    # 기본: 일괄 처리를 위해 affect_refs에 추가
                    affect_refs.append(ref)

            # 그룹화된 버전들로부터 병합된 statement 생성
            for idx, (group_key, version_refs) in enumerate(version_groups.items()):
                status_enum_val, action_stmt, just_enum_val, custom_just_val, impact_stmt_val, original_state_val, detail_text_val = group_key
                
                statements.append(VEXStatement(
                    id=f"stmt-{vidx}-group{idx}",
                    subject_refs=unique_list(version_refs),
                    vulnerability_id=vuln_id,
                    status=StatusInfo(
                        value=status_enum_val,
                        justification=just_enum_val,
                        custom_justification=custom_just_val,
                        impact_statement=impact_stmt_val,
                        original_state=original_state_val
                    ),
                    timestamp=timestamp,
                    action_statement=action_stmt,
                    extension_data=stmt_extension_data.copy()
                ))

            # 버전 정보 없는 affects에 대한 statement 생성
            if affect_refs:
                statements.append(VEXStatement(
                    id=f"stmt-{vidx}",
                    subject_refs=unique_list(affect_refs),
                    vulnerability_id=vuln_id,
                    status=StatusInfo(
                        value=status_enum,
                        justification=just_enum,
                        custom_justification=custom_just,
                        impact_statement=impact_stmt if isinstance(impact_stmt, str) else None,
                        original_state=original_cdx_state
                    ),
                    timestamp=timestamp,
                    action_statement=action_statement,
                    extension_data=stmt_extension_data.copy()
                ))

        # 복원 모드: 메타데이터에서 손실된 데이터 적용
        if self.options.restore and restore_metadata:
            lost_data = restore_metadata.lost_data
            extension_data = restore_metadata.extension_data
            subject_mappings = restore_metadata.subject_mappings
            restored_count = 0
            
            for stmt in statements:
                # justification 복원
                just_key = f"stmt_{stmt.id}_justification"
                if just_key in lost_data:
                    stmt.status.justification = map_openvex_justification_str_to_enum(lost_data[just_key])
                    restored_count += 1
                
                custom_just_key = f"stmt_{stmt.id}_custom_justification"
                if custom_just_key in lost_data:
                    stmt.status.custom_justification = lost_data[custom_just_key]
                    restored_count += 1
                
                # action_statement 복원
                action_key = f"stmt_{stmt.id}_action_statement"
                if action_key in lost_data:
                    stmt.action_statement = lost_data[action_key]
                    restored_count += 1
            
            # extension_data 복원
            if extension_data:
                # Metadata extension_data 복원
                if "metadata" in extension_data:
                    metadata.extension_data = extension_data["metadata"]
                    restored_count += 1
                
                # Subject extension_data 복원
                for idx, subj in enumerate(subjects_idx.values()):
                    key = f"subject_{idx}"
                    if key in extension_data:
                        subj.extension_data = extension_data[key]
                        restored_count += 1
                
                # Vulnerability extension_data 복원
                for idx, vuln in enumerate(vulns_idx.values()):
                    key = f"vulnerability_{idx}"
                    if key in extension_data:
                        vuln.extension_data = extension_data[key]
                        restored_count += 1
                        
                        # extension_data에서 notes 복원
                        notes = get_extension_field(vuln, "csaf", "notes")
                        if notes:
                            vuln.notes = notes
                            restored_count += 1
                
                # Statement extension_data 복원
                for idx, stmt in enumerate(statements):
                    key = f"statement_{idx}"
                    if key in extension_data:
                        stmt.extension_data = extension_data[key]
                        restored_count += 1
            
            # subject_mappings에서 original_id 복원
            if subject_mappings:
                for subj in subjects_idx.values():
                    if subj.ref in subject_mappings:
                        subj.original_id = subject_mappings[subj.ref]
                        restored_count += 1
            
            if restored_count > 0:
                print(f"[Restore Mode] Restored {restored_count} field(s) from metadata")

        return CIM(
            metadata=metadata,
            subjects=list(subjects_idx.values()),
            vulnerabilities=list(vulns_idx.values()),
            statements=statements
        )

    def _response_to_text(self, response):
        """CycloneDX response enum을 텍스트로 변환"""
        mapping = {
            "update": "Update to a different revision or release",
            "workaround_available": "There is a workaround available",
            "rollback": "Revert to a previous revision or release",
            "will_not_fix": "Will not fix",
            "can_not_fix": "Can not fix"
        }
        return mapping.get(response, response)

    @staticmethod
    def _extract_name_from_ref(ref: str) -> str:
        """컴포넌트 참조에서 의미 있는 이름 추출"""
        ref = ref.strip()

        # PURL 형식: pkg:type/namespace/name@version
        if ref.startswith("pkg:"):
            try:
                parts = ref.split("/")
                if len(parts) >= 2:
                    name_part = parts[-1].split("@")[0].split("?")[0]
                    return name_part
            except: pass

        # fragment가 있는 URN: urn:cdx:...#product-ABC
        if "#" in ref:
            return ref.split("#")[-1]

        # CPE 형식: cpe:2.3:a:vendor:product:...
        if ref.startswith("cpe:"):
            try:
                parts = ref.split(":")
                if len(parts) >= 5:
                    return parts[4]  # 제품 이름
            except: pass

        # 경로 형식: .../product-ABC
        if "/" in ref:
            return ref.split("/")[-1]

        # 콜론 구분: prefix:product-ABC
        if ":" in ref:
            return ref.split(":")[-1]

        # 폴백: ref 자체 사용 (너무 길면 자르기)
        return ref[:100] if len(ref) <= 100 else ref[:100]

class CSAFToCIM:
    def __init__(self, options: ConversionOptions = None):
        self.options = options or ConversionOptions()
        
    def convert(self, data: Dict) -> CIM:
        # 복원 모드: document.notes에서 메타데이터 추출
        restore_metadata = None
        if self.options.restore:
            doc = data.get("document", {})
            notes = doc.get("notes", [])
            for note in notes:
                if note.get("title") == "VEXCO Conversion Metadata":
                    text = note.get("text", "")
                    if text.startswith("[VEXCONV:v1]"):
                        restore_metadata = ConversionMetadata.decode(text)
                        if restore_metadata:
                            print(f"[Restore Mode] Found conversion metadata from {restore_metadata.source_format}")
                            print(f"  Timestamp: {restore_metadata.timestamp}")
                            if restore_metadata.lost_data:
                                print(f"  Lost data fields: {len(restore_metadata.lost_data)}")
                        break
        
        doc = data.get("document", {})
        tracking = doc.get("tracking", {})
        publisher_data = doc.get("publisher", {})

        timestamp_str = tracking.get("initial_release_date", dt_to_iso_z(now_utc()))
        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        
        # last_updated 파싱 (current_release_date)
        last_updated = None
        current_release_str = tracking.get("current_release_date")
        if current_release_str:
            last_updated = datetime.fromisoformat(current_release_str.replace('Z', '+00:00'))
        
        # version 파싱 (CSAF uses string like "1.0.0", try to extract major version as int)
        doc_version = None
        version_str = tracking.get("version")
        if version_str:
            try:
                # 먼저 직접 int 변환 시도 (예: "1" → 1)
                doc_version = int(version_str)
            except ValueError:
                # semver에서 major 버전 추출 시도 (예: "1.0.0" → 1)
                try:
                    doc_version = int(version_str.split('.')[0])
                except (ValueError, IndexError):
                    pass

        metadata = Metadata(
            id=str(uuid.uuid4()),
            publisher=Publisher(
                name=publisher_data.get("name", "Unknown"),
                namespace=publisher_data.get("namespace"),
                role=publisher_data.get("category")
            ),
            created_at=timestamp,
            source_format=DocumentFormat.CSAF,
            original_id=tracking.get("id"),
            document_version=doc_version,
            last_updated=last_updated
        )
        
        # 복원을 위해 CSAF tracking.id를 extension_data에 저장
        if tracking.get("id"):
            set_extension_field(metadata, "csaf", "tracking.id", tracking["id"])
        
        # CSAF 전용 문서 필드를 extension_data에 저장
        # aggregate_severity (심각도 집계)
        if doc.get("aggregate_severity"):
            set_extension_field(metadata, "csaf", "document.aggregate_severity", doc["aggregate_severity"])
        
        # distribution (배포)
        if doc.get("distribution"):
            distribution = doc["distribution"]
            
            # CSAF 2.0 TLP 레이블을 CSAF 2.1 형식으로 변환
            if "tlp" in distribution and "label" in distribution["tlp"]:
                tlp_label = distribution["tlp"]["label"]
                
                # CSAF 2.0 → 2.1 매핑
                tlp_2_0_to_2_1 = {
                    "WHITE": "CLEAR",
                    "AMBER": "AMBER",
                    "GREEN": "GREEN",
                    "RED": "RED"
                }
                
                normalized_label = tlp_2_0_to_2_1.get(tlp_label, tlp_label)
                
                if tlp_label in tlp_2_0_to_2_1:
                    # 원본 수정 방지를 위해 복사본 생성
                    distribution = distribution.copy()
                    distribution["tlp"] = distribution["tlp"].copy()
                    distribution["tlp"]["label"] = normalized_label
                
                # TLP 정보를 공통 필드로 저장 (CycloneDX 변환 시 사용)
                # CSAF 2.1: CLEAR, GREEN, AMBER, AMBER+STRICT, RED
                set_extension_field(metadata, "common", "tlp.label", normalized_label)
                
                # TLP URL도 저장
                tlp_url = distribution["tlp"].get("url")
                if tlp_url:
                    set_extension_field(metadata, "common", "tlp.url", tlp_url)
            
            set_extension_field(metadata, "csaf", "document.distribution", distribution)
        
        # lang (언어)
        if doc.get("lang"):
            set_extension_field(metadata, "csaf", "document.lang", doc["lang"])
        
        # source_lang (원본 언어)
        if doc.get("source_lang"):
            set_extension_field(metadata, "csaf", "document.source_lang", doc["source_lang"])
        
        # category (카테고리)
        if doc.get("category"):
            set_extension_field(metadata, "csaf", "document.category", doc["category"])
        
        # title (제목)
        if doc.get("title"):
            set_extension_field(metadata, "csaf", "document.title", doc["title"])
        
        # publisher 추가 필드
        if publisher_data.get("contact_details"):
            set_extension_field(metadata, "csaf", "document.publisher.contact_details", publisher_data["contact_details"])
        
        if publisher_data.get("issuing_authority"):
            set_extension_field(metadata, "csaf", "document.publisher.issuing_authority", publisher_data["issuing_authority"])
        
        # tracking 추가 필드
        if tracking.get("status"):
            set_extension_field(metadata, "csaf", "document.tracking.status", tracking["status"])
        
        if tracking.get("version"):
            set_extension_field(metadata, "csaf", "document.tracking.version", tracking["version"])
        
        if tracking.get("revision_history"):
            set_extension_field(metadata, "csaf", "document.tracking.revision_history", tracking["revision_history"])
        
        # OpenVEX statements.timestamp용 initial_release_date 저장
        if tracking.get("initial_release_date"):
            set_extension_field(metadata, "csaf", "document.tracking.initial_release_date", tracking["initial_release_date"])
        
        if tracking.get("current_release_date"):
            set_extension_field(metadata, "csaf", "document.tracking.current_release_date", tracking["current_release_date"])
        
        if tracking.get("generator"):
            set_extension_field(metadata, "csaf", "document.tracking.generator", tracking["generator"])
        
        if tracking.get("aliases"):
            set_extension_field(metadata, "csaf", "document.tracking.aliases", tracking["aliases"])
        
        # document references (문서 참조)
        if doc.get("references"):
            set_extension_field(metadata, "csaf", "document.references", doc["references"])
        
        # document notes (최상위 노트)
        if doc.get("notes"):
            set_extension_field(metadata, "csaf", "document.notes", doc["notes"])
        
        # document acknowledgments (감사의 글)
        if doc.get("acknowledgments"):
            set_extension_field(metadata, "csaf", "document.acknowledgments", doc["acknowledgments"])

        pt = data.get("product_tree", {})
        
        # product_tree.relationships를 extension_data에 저장
        if pt.get("relationships"):
            set_extension_field(metadata, "csaf", "product_tree.relationships", pt["relationships"])
        
        # 완전한 복원을 위해 원본 branches 구조 저장
        if pt.get("branches"):
            set_extension_field(metadata, "csaf", "product_tree.branches", pt["branches"])
        
        subjects_idx = {}

        # full_product_names 처리 (단순 형식)
        for p in pt.get("full_product_names", []):
            pid = p.get("product_id", "").strip()
            if not pid: continue

            pih = p.get("product_identification_helper", {})
            identifiers = []

            # 표준 식별자
            if pih.get("purls"):
                for purl in pih["purls"]:
                    identifiers.append(Identifier(type="purl", value=purl))
            elif pih.get("purl"):
                identifiers.append(Identifier(type="purl", value=pih["purl"]))

            if pih.get("cpe"):
                identifiers.append(Identifier(type="cpe", value=pih["cpe"]))

            # CSAF 2.1 해시 형식을 CIM 형식으로 변환
            hashes_csaf = pih.get("hashes")
            hashes = None
            if hashes_csaf:
                hashes = []
                for hash_entry in hashes_csaf:
                    file_hashes = hash_entry.get("file_hashes", [])
                    for fh in file_hashes:
                        alg = fh.get("algorithm")
                        val = fh.get("value")
                        if alg and val:
                            if alg.startswith("sha") and not alg.startswith("sha-"):
                                alg = alg.replace("sha", "sha-")
                            hashes.append({"algorithm": alg, "value": val})
            
            model_numbers = pih.get("model_numbers")
            sbom_urls = pih.get("sbom_urls")
            serial_numbers = pih.get("serial_numbers")
            skus = pih.get("skus")

            # product_id에서 버전 먼저 추출 (우선순위)
            version = None
            if ":v" in pid:
                parts = pid.split(":v", 1)
                if len(parts) == 2:
                    version = parts[1]
            
            # product_id에 버전 없으면 purl에서 추출 시도
            if not version:
                for ident in identifiers:
                    if ident.type == "purl" and "@" in ident.value:
                        try:
                            version = ident.value.split("@")[1].split("?")[0].split("#")[0]
                            break
                        except:
                            pass
            
            # PURL이 없으면 제품 이름에서 자동 생성
            if not any(ident.type == "purl" for ident in identifiers):
                product_name = p.get("name", "")
                generated_purl = self._generate_purl_from_product(
                    vendor=None,
                    product=None,
                    version=version,
                    product_name=product_name
                )
                if generated_purl:
                    identifiers.append(Identifier(type="purl", value=generated_purl))
            
            subjects_idx[pid] = Subject(
                ref=pid,
                identifiers=identifiers,
                name=p.get("name", pid),
                version=version,
                hashes=hashes,
                model_numbers=model_numbers,
                sbom_urls=sbom_urls,
                serial_numbers=serial_numbers,
                skus=skus
            )

        # branches 처리 (Red Hat 스타일)
        branches_products = self._extract_from_branches(pt.get("branches", []))
        for pid, prod_info in branches_products.items():
            if pid not in subjects_idx:
                identifiers = []
                # 모든 purl 추가 (첫 번째만 아님)
                if prod_info.get("purls"):
                    for purl in prod_info["purls"]:
                        identifiers.append(Identifier(type="purl", value=purl))
                elif prod_info.get("purl"):
                    identifiers.append(Identifier(type="purl", value=prod_info["purl"]))
                if prod_info.get("cpe"): 
                    identifiers.append(Identifier(type="cpe", value=prod_info["cpe"]))
                
                # prod_info에 없으면 product_id에서 버전 추출
                version = prod_info.get("version")
                if not version and ":v" in pid:
                    parts = pid.split(":v", 1)
                    if len(parts) == 2:
                        version = parts[1]

                subjects_idx[pid] = Subject(
                    ref=pid,
                    identifiers=identifiers,
                    name=prod_info.get("name", pid),
                    version=version,
                    hashes=prod_info.get("hashes")
                )

        # relationships 처리 (복합 product ID 생성)
        # remediation용 composite_pid → comp_ref 매핑도 생성
        composite_to_comp = {}
        for rel in pt.get("relationships", []):
            fpn = rel.get("full_product_name", {})
            composite_pid = fpn.get("product_id", "").strip()
            comp_ref = rel.get("product_reference", "")
            
            # 매핑 저장
            if composite_pid and comp_ref:
                composite_to_comp[composite_pid] = comp_ref
            
            if composite_pid and composite_pid not in subjects_idx:
                # 컴포넌트 제품에서 식별자 상속
                parent_ref = rel.get("relates_to_product_reference", "")

                identifiers = []
                name = fpn.get("name", composite_pid)

                # 컴포넌트에서 purl/cpe 상속 시도
                if comp_ref in subjects_idx:
                    identifiers = subjects_idx[comp_ref].identifiers.copy()

                subjects_idx[composite_pid] = Subject(
                    ref=composite_pid,
                    identifiers=identifiers,
                    name=name
                )

        statements = []
        vulns_idx = {}

        # 1단계: 먼저 모든 취약점 생성
        for vidx, v in enumerate(data.get("vulnerabilities", [])):
            vuln_id = v.get("cve", f"VULN-{vidx}")

            if vuln_id not in vulns_idx:
                vuln = Vulnerability(id=vuln_id)

                # 모든 notes 추출
                for note in v.get("notes", []):
                    note_entry = {}
                    if note.get("category"):
                        note_entry["category"] = note["category"]
                    if note.get("text"):
                        note_entry["text"] = note["text"]
                    if note.get("title"):
                        note_entry["title"] = note["title"]
                    if note_entry:
                        vuln.notes.append(note_entry)
                
                # 가역 변환을 위해 notes를 extension_data에 저장
                if self.options.reversible and vuln.notes:
                    set_extension_field(vuln, "csaf", "notes", vuln.notes)

                # CSAF 취약점 title 추출
                vuln_title = v.get("title")
                if vuln_title:
                    set_extension_field(vuln, "csaf", "vulnerabilities.title", vuln_title)

                # description 추출
                # 1순위: category가 "description"인 note
                # 2순위: category가 "details"인 note
                # 3순위: title
                # 4순위: category가 "summary"인 note
                desc_text = None
                details_text = None
                summary_text = None
                
                for note in v.get("notes", []):
                    cat = note.get("category")
                    if cat == "description" and not desc_text:
                        desc_text = note.get("text")
                    elif cat == "details" and not details_text:
                        details_text = note.get("text")
                    elif cat == "summary" and not summary_text:
                        summary_text = note.get("text")
                
                if desc_text:
                    vuln.description = desc_text
                elif details_text:
                    vuln.description = details_text
                elif vuln_title:
                    vuln.description = vuln_title
                elif summary_text:
                    vuln.description = summary_text

                # CWE 추출 (CSAF 2.0/2.1 호환성을 위해 단수 "cwe"와 복수 "cwes" 모두 지원)
                cwe = v.get("cwe", {})
                if cwe and cwe.get("id"):
                    cwe_id = cwe["id"].replace("CWE-", "")
                    try:
                        vuln.cwes.append(int(cwe_id))
                    except ValueError:
                        pass
                
                # "cwes" 배열도 지원 (CSAF 2.1 이상)
                cwes = v.get("cwes", [])
                for cwe_obj in cwes:
                    if cwe_obj and cwe_obj.get("id"):
                        cwe_id = cwe_obj["id"].replace("CWE-", "")
                        try:
                            cwe_int = int(cwe_id)
                            if cwe_int not in vuln.cwes:
                                vuln.cwes.append(cwe_int)
                        except ValueError:
                            pass
                
                # 완전한 복원을 위해 원본 CWE 객체를 extension_data에 저장
                if cwes:
                    set_extension_field(vuln, "csaf", "cwes_original", cwes)

                # CVSS 등급 추출 (CSAF 2.0: scores, CSAF 2.1: metrics)
                # metrics 먼저 시도 (CSAF 2.1 형식)
                metrics = v.get("metrics", [])
                for metric_obj in metrics:
                    content = metric_obj.get("content", {})
                    cvss3 = content.get("cvss_v3")
                    cvss2 = content.get("cvss_v2")
                    epss = content.get("epss")
                    
                    if cvss3:
                        version = cvss3.get("version", "3.1")
                        method = f"CVSSv{version}"
                        vuln.ratings.append(CvssRating(
                            method=method,
                            score=cvss3.get("baseScore"),
                            severity=cvss3.get("baseSeverity"),
                            vector=cvss3.get("vectorString")
                        ))
                    if cvss2:
                        vuln.ratings.append(CvssRating(
                            method="CVSSv2",
                            score=cvss2.get("baseScore"),
                            severity=cvss2.get("baseSeverity"),
                            vector=cvss2.get("vectorString")
                        ))
                    
                    # EPSS 데이터 추출 및 extension_data에 저장
                    if epss:
                        epss_data = {
                            "probability": epss.get("probability"),
                            "percentile": epss.get("percentile"),
                            "timestamp": epss.get("timestamp")
                        }
                        set_extension_field(vuln, "csaf", "epss", epss_data)
                        # CycloneDX 변환을 위해 ratings에도 추가
                        vuln.ratings.append(CvssRating(
                            method="other",
                            score=float(epss.get("probability", 0)) if epss.get("probability") else None,
                            severity=None,
                            vector="EPSS"
                        ))

                # CSAF 2.0 "scores" 형식도 시도
                scores = v.get("scores", [])
                for score_obj in scores:
                    cvss3 = score_obj.get("cvss_v3")
                    cvss2 = score_obj.get("cvss_v2")
                    
                    if cvss3:
                        version = cvss3.get("version", "3.1")
                        method = f"CVSSv{version}"
                        vuln.ratings.append(CvssRating(
                            method=method,
                            score=cvss3.get("baseScore"),
                            severity=cvss3.get("baseSeverity"),
                            vector=cvss3.get("vectorString")
                        ))
                    if cvss2:
                        vuln.ratings.append(CvssRating(
                            method="CVSSv2",
                            score=cvss2.get("baseScore"),
                            severity=cvss2.get("baseSeverity"),
                            vector=cvss2.get("vectorString")
                        ))

                # 참조 추출
                for ref_obj in v.get("references", []):
                    ref_url = ref_obj.get("url")
                    if ref_url:
                        vuln.references.append(Reference(
                            url=ref_url,
                            summary=ref_obj.get("summary"),
                            category=ref_obj.get("category", "external")
                        ))

                # remediation 추출
                for rem_obj in v.get("remediations", []):
                    rem_entry = {
                        "category": rem_obj.get("category", ""),
                        "details": rem_obj.get("details", "")
                    }
                    if rem_obj.get("url"):
                        rem_entry["url"] = rem_obj["url"]
                    vuln.remediations.append(rem_entry)

                vulns_idx[vuln_id] = vuln

        # 2단계: 취약점의 extension_data 복원 (복원 모드인 경우)
        if self.options.restore and restore_metadata:
            extension_data = restore_metadata.extension_data
            if extension_data:
                # 취약점 ID를 키로 사용 (인덱스가 아님)
                for v in data.get("vulnerabilities", []):
                    vuln_id = v.get("cve", "")
                    if vuln_id:
                        vuln = vulns_idx.get(vuln_id)
                        if vuln:
                            key = f"vulnerability_{vuln_id}"
                            if key in extension_data:
                                vuln.extension_data = extension_data[key]
                                print(f"[Restore Mode] Restored extension_data for vulnerability {vuln_id}")

        # 3단계: statement 생성 (이제 extension_data 사용 가능)
        for vidx, v in enumerate(data.get("vulnerabilities", [])):
            vuln_id = v.get("cve", f"VULN-{vidx}")

            # 사용 가능하면 원본 statements 복원 (완벽한 복원)
            vuln = vulns_idx.get(vuln_id)
            original_statements = get_extension_field(vuln, "csaf", "original_statements") if vuln else None
            
            if original_statements and self.options.restore:
                # 완벽한 복원: 저장된 데이터로부터 statements 재생성
                for stmt_dict in original_statements:
                    # StatusInfo 재구성
                    status_data = stmt_dict.get("status", {})
                    status_value_name = status_data.get("value", "UNDER_INVESTIGATION")
                    status_enum = {
                        "AFFECTED": VulnerabilityStatus.AFFECTED,
                        "NOT_AFFECTED": VulnerabilityStatus.NOT_AFFECTED,
                        "FIXED": VulnerabilityStatus.FIXED,
                        "UNDER_INVESTIGATION": VulnerabilityStatus.UNDER_INVESTIGATION
                    }.get(status_value_name, VulnerabilityStatus.UNDER_INVESTIGATION)
                    
                    # justification 재구성
                    just_value = status_data.get("justification")
                    just_enum = None
                    if just_value:
                        just_enum = map_openvex_justification_str_to_enum(just_value.lower())
                    
                    status_info = StatusInfo(
                        value=status_enum,
                        justification=just_enum,
                        custom_justification=status_data.get("custom_justification"),
                        impact_statement=status_data.get("impact_statement"),
                        original_state=status_data.get("original_state")
                    )
                    
                    # timestamp 재구성
                    timestamp_str = stmt_dict.get("timestamp")
                    timestamp_obj = None
                    if timestamp_str:
                        try:
                            timestamp_obj = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                        except:
                            pass
                    
                    # statement 생성
                    statements.append(VEXStatement(
                        id=f"stmt-{vidx}-restored-{len(statements)}",
                        subject_refs=stmt_dict.get("subject_refs", []),
                        vulnerability_id=vuln_id,
                        status=status_info,
                        timestamp=timestamp_obj,
                        action_statement=stmt_dict.get("action_statement")
                    ))
                
                # 일반 처리 건너뛰기
                continue
            
            # 일반 처리 (저장된 statements 없음)
            ps = v.get("product_status", {})
            flags_map = {}
            for fl in v.get("flags", []):
                lbl = safe_str(fl.get("label")).strip()
                for pid in fl.get("product_ids", []):
                    flags_map[safe_str(pid).strip()] = lbl

            # threats에서 impact statement 추출
            threats_map = {}
            for threat in v.get("threats", []):
                if threat.get("category") == "impact":
                    details = threat.get("details", "")
                    for pid in threat.get("product_ids", []):
                        pid_clean = safe_str(pid).strip()
                        if pid_clean and details:
                            threats_map[pid_clean] = details
            
            # details notes를 impact_statement로 추출
            # category가 "details"인 notes는 impact_statement에 매핑되어야 함
            details_notes_map = {}
            for note in v.get("notes", []):
                if note.get("category") == "details":
                    note_text = note.get("text", "")
                    if note_text:
                        # product_status의 모든 제품에 적용
                        for status_key in ["known_not_affected", "known_affected", "under_investigation"]:
                            for pid in ps.get(status_key, []):
                                pid_clean = safe_str(pid).strip()
                                if pid_clean and pid_clean not in details_notes_map:
                                    details_notes_map[pid_clean] = note_text
            
            # remediation에서 action statement 추출
            remediations_map = {}
            remediations_seen = {}  # 중복 방지를 위해 pid별 본 내용 추적
            
            for rem in v.get("remediations", []):
                category = rem.get("category", "")
                details = rem.get("details", "")
                if details:
                    for pid in rem.get("product_ids", []):
                        pid_clean = safe_str(pid).strip()
                        if pid_clean:
                            # 형식: "category: details" 또는 그냥 details
                            if category:
                                action_text = f"{category}: {details}"
                            else:
                                action_text = details
                            
                            # 정규화된 내용으로 중복 확인
                            # 핵심 details 추출 (category 접두사 제외)하여 정규화
                            normalized_details = details.strip().lower()
                            
                            if pid_clean not in remediations_seen:
                                remediations_seen[pid_clean] = set()
                            
                            # 이 details 내용이 본 적 없으면만 추가
                            if normalized_details not in remediations_seen[pid_clean]:
                                remediations_seen[pid_clean].add(normalized_details)
                                
                                # 기존 action에 추가 (있는 경우)
                                if pid_clean in remediations_map:
                                    remediations_map[pid_clean] += "\n" + action_text
                                else:
                                    remediations_map[pid_clean] = action_text

            # CSAF product status를 VulnerabilityStatus로 매핑
            status_mapping = [
                ("known_not_affected", VulnerabilityStatus.NOT_AFFECTED),
                ("known_affected", VulnerabilityStatus.AFFECTED),
                ("first_affected", VulnerabilityStatus.AFFECTED),
                ("last_affected", VulnerabilityStatus.AFFECTED),
                ("fixed", VulnerabilityStatus.FIXED),
                ("first_fixed", VulnerabilityStatus.FIXED),
                ("recommended", VulnerabilityStatus.FIXED),
                ("under_investigation", VulnerabilityStatus.UNDER_INVESTIGATION)
            ]

            for key, status_value in status_mapping:
                for pid in ps.get(key, []):
                    pid = safe_str(pid).strip()
                    if not pid: continue

                    if pid not in subjects_idx:
                        subjects_idx[pid] = Subject(ref=pid, name=pid, identifiers=[
                            Identifier(type="product_id", value=pid)
                        ])

                    flag_label = flags_map.get(pid)
                    just_enum = csaf_flag_to_justification_enum(flag_label) if flag_label else None
                    custom_just = flag_label if flag_label and not just_enum else None

                    # impact statement 가져오기: threats 먼저, 그 다음 details notes
                    impact_stmt = threats_map.get(pid)
                    if not impact_stmt:
                        impact_stmt = details_notes_map.get(pid)
                    
                    # remediation에서 action statement 가져오기
                    action_stmt = remediations_map.get(pid)

                    statements.append(VEXStatement(
                        id=f"stmt-{vidx}-{pid}",
                        subject_refs=[pid],
                        vulnerability_id=vuln_id,
                        status=StatusInfo(
                            value=status_value,
                            justification=just_enum,
                            custom_justification=custom_just,
                            impact_statement=impact_stmt
                        ),
                        action_statement=action_stmt,
                        timestamp=timestamp
                    ))
        
        # 복원 모드: extension_data와 subject_mappings 적용
        if self.options.restore and restore_metadata:
            extension_data = restore_metadata.extension_data
            subject_mappings = restore_metadata.subject_mappings
            restored_count = 0
            
            # extension_data 복원
            if extension_data:
                # Metadata extension_data 복원
                if "metadata" in extension_data:
                    metadata.extension_data = extension_data["metadata"]
                    restored_count += 1
                
                # Subject extension_data 복원
                for idx, subj in enumerate(subjects_idx.values()):
                    key = f"subject_{idx}"
                    if key in extension_data:
                        subj.extension_data = extension_data[key]
                        restored_count += 1
                
                # Vulnerability extension_data 복원
                for idx, vuln in enumerate(vulns_idx.values()):
                    key = f"vulnerability_{idx}"
                    if key in extension_data:
                        vuln.extension_data = extension_data[key]
                        restored_count += 1
                
                # Statement extension_data 복원
                for idx, stmt in enumerate(statements):
                    key = f"statement_{idx}"
                    if key in extension_data:
                        stmt.extension_data = extension_data[key]
                        restored_count += 1
            
            # subject_mappings에서 original_id 복원
            if subject_mappings:
                for subj in subjects_idx.values():
                    if subj.ref in subject_mappings:
                        subj.original_id = subject_mappings[subj.ref]
                        restored_count += 1
            
            if restored_count > 0:
                print(f"[Restore Mode] Restored {restored_count} field(s) from metadata")

        return CIM(
            metadata=metadata,
            subjects=list(subjects_idx.values()),
            vulnerabilities=list(vulns_idx.values()),
            statements=statements
        )

    def _extract_from_branches(self, branches: List[Dict], parent_vendor: str = None, parent_product: str = None) -> Dict[str, Dict]:
        """
        branches에서 제품 정보를 재귀적으로 추출
        """
        products = {}

        for branch in branches:
            category = branch.get("category", "")
            branch_name = branch.get("name", "")
            
            # vendor/product 정보 추적
            current_vendor = parent_vendor
            current_product = parent_product
            
            if category == "vendor":
                current_vendor = branch_name
            elif category == "product_name" or category == "product_family":
                current_product = branch_name
            
            # 이 branch에 product가 있는지 확인
            prod = branch.get("product", {})
            if prod and prod.get("product_id"):
                pid = prod["product_id"]
                pih = prod.get("product_identification_helper", {})
                
                # CSAF 2.0은 "purls" (배열) 사용, 호환성을 위해 "purl"도 확인
                purl_value = None
                all_purls = []
                if pih.get("purls"):
                    all_purls = pih["purls"]
                    purl_value = all_purls[0] if all_purls else None
                elif pih.get("purl"):
                    purl_value = pih["purl"]
                    all_purls = [purl_value]
                
                # product_id에서 버전 먼저 추출 (우선순위)
                # 형식: base-id:vversion
                version = None
                if ":v" in pid:
                    parts = pid.split(":v", 1)
                    if len(parts) == 2:
                        version = parts[1]
                
                # product_id에 버전 없으면 category/name 또는 purl에서 추출
                if not version:
                    if category == "product_version":
                        version = branch_name
                    elif category == "product_version_range":
                        version = branch_name
                    elif purl_value and "@" in purl_value:
                        try:
                            version = purl_value.split("@")[1].split("?")[0].split("#")[0]
                        except:
                            pass
                
                # PURL이 없으면 vendor/product/version 정보로 자동 생성
                generated_purl = None
                if not purl_value:
                    generated_purl = self._generate_purl_from_product(
                        vendor=current_vendor,
                        product=current_product,
                        version=version,
                        product_name=prod.get("name", "")
                    )
                    if generated_purl:
                        purl_value = generated_purl
                        all_purls = [generated_purl]
                
                # CSAF 2.1 형식에서 해시 추출
                hashes_csaf = pih.get("hashes")
                hashes = None
                if hashes_csaf:
                    hashes = []
                    for hash_entry in hashes_csaf:
                        file_hashes = hash_entry.get("file_hashes", [])
                        for fh in file_hashes:
                            alg = fh.get("algorithm")
                            val = fh.get("value")
                            if alg and val:
                                if alg.startswith("sha") and not alg.startswith("sha-"):
                                    alg = alg.replace("sha", "sha-")
                                hashes.append({"algorithm": alg, "value": val})
                
                products[pid] = {
                    "name": prod.get("name", pid),
                    "purl": purl_value,
                    "purls": all_purls,
                    "cpe": pih.get("cpe"),
                    "version": version,
                    "hashes": hashes,
                    "generated_purl": generated_purl is not None
                }

            # 하위 branches 재귀 처리
            sub_branches = branch.get("branches", [])
            if sub_branches:
                sub_products = self._extract_from_branches(sub_branches, current_vendor, current_product)
                products.update(sub_products)

        return products
    
    def _generate_purl_from_product(self, vendor: str, product: str, version: str, product_name: str) -> str:
        """
        PURL이 없는 CSAF 제품에서 PURL 생성
        """
        import re
        
        def normalize(name: str) -> str:
            if not name:
                return ""
            name = name.lower()
            name = re.sub(r':\s*[\d.]+.*$', '', name)
            name = re.sub(r'[^a-z0-9]+', '-', name)
            name = re.sub(r'-+', '-', name)
            return name.strip('-')
        
        namespace = normalize(vendor) if vendor else None
        name = normalize(product) if product else None
        extracted_version = version
        
        if not name and product_name:
            if not extracted_version:
                match = re.search(r'[:\s]+([\d]+\.[\d.]+[a-zA-Z0-9.-]*)$', product_name)
                if match:
                    extracted_version = match.group(1)
                    product_name = product_name[:match.start()]
            name = normalize(product_name)
        
        if not name:
            return None
        
        purl = "pkg:generic/"
        if namespace:
            purl += f"{namespace}/"
        purl += name
        
        if extracted_version:
            clean_version = re.sub(r'[^a-zA-Z0-9.\-_+]', '', extracted_version)
            if clean_version:
                purl += f"@{clean_version}"
        
        return purl

# ===== CIM에서 변환하는 CONVERTERS =====