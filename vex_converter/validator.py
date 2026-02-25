"""
검증기 및 손실 분석기
"""
import json
from typing import Dict, List, Any, Set, Optional
from .models import CIM, TrackingTable, DocumentFormat
from .constants import MAPPING_TABLE
from .utils import extract_all_fields, normalize_field_path

class Validator:
    @staticmethod
    def validate_input(data: Dict, format_name: str):
        if format_name == "OpenVEX":
            if "@context" not in data:
                raise ValidationError("Missing @context in OpenVEX document")
            if "statements" not in data:
                raise ValidationError("Missing statements in OpenVEX document")

        elif format_name == "CycloneDX":
            if "bomFormat" not in data or data["bomFormat"] != "CycloneDX":
                raise ValidationError("Invalid CycloneDX document")
            if "vulnerabilities" not in data:
                raise ValidationError("Missing vulnerabilities in CycloneDX document")

        elif format_name == "CSAF":
            if "document" not in data:
                raise ValidationError("Missing document in CSAF")
            if "product_tree" not in data:
                raise ValidationError("Missing product_tree in CSAF")
            if "vulnerabilities" not in data:
                raise ValidationError("Missing vulnerabilities in CSAF")

# ===== 손실 분석기 =====

class LossAnalyzer:
    # 각 형식의 표준 필드 정의
    STANDARD_FIELDS = {
        "OpenVEX": {
            "document": ["@context", "@id", "author", "timestamp", "version", "statements"],
            "statement": ["vulnerability", "timestamp", "products", "status", "justification", 
                         "impact_statement", "action_statement", "status_notes"]
        },
        "CycloneDX": {
            "document": ["bomFormat", "specVersion", "serialNumber", "version", "metadata", "components", "vulnerabilities"],
            "vulnerability": ["id", "affects", "analysis", "description", "ratings", "cwes", "references"]
        },
        "CSAF": {
            "document": ["document", "product_tree", "vulnerabilities"],
            "vulnerability": ["cve", "product_status", "flags", "notes", "references"]
        }
    }

    def analyze(self, source_data: Dict, source_format: str, cim: CIM, result: Dict, target_format: str, use_free_text: bool) -> Dict:
        analysis = {
            "source": source_format,
            "target": target_format,
            "summary": {
                "source_subjects": 0,
                "source_vulnerabilities": 0,
                "source_statements": 0,
                "cim_subjects": len(cim.subjects),
                "cim_vulnerabilities": len(cim.vulnerabilities),
                "cim_statements": len(cim.statements),
                "output_subjects": 0,
                "output_vulnerabilities": 0,
                "output_statements": 0
            },
            "details": [],
            "has_data_loss": False
        }

        # 소스 데이터 개수
        source_counts = self._count_source_data(source_data, source_format)
        analysis["summary"]["source_subjects"] = source_counts["subjects"]
        analysis["summary"]["source_vulnerabilities"] = source_counts["vulnerabilities"]
        analysis["summary"]["source_statements"] = source_counts["statements"]

        # 출력 데이터 개수
        output_counts = self._count_source_data(result, target_format)
        analysis["summary"]["output_subjects"] = output_counts["subjects"]
        analysis["summary"]["output_vulnerabilities"] = output_counts["vulnerabilities"]
        analysis["summary"]["output_statements"] = output_counts["statements"]

        # 소스 -> CIM 변환 비교
        if source_counts["vulnerabilities"] != len(cim.vulnerabilities):
            loss = source_counts["vulnerabilities"] - len(cim.vulnerabilities)
            if loss > 0:
                analysis["has_data_loss"] = True
                analysis["details"].append({
                    "severity": "CRITICAL",
                    "category": "vulnerability_loss_in_parsing",
                    "count": loss,
                    "message": f"Lost {loss} vulnerabilities during {source_format} -> CIM conversion"
                })

        if source_counts["subjects"] != len(cim.subjects):
            loss = source_counts["subjects"] - len(cim.subjects)
            if loss > 0:
                analysis["has_data_loss"] = True
                analysis["details"].append({
                    "severity": "CRITICAL",
                    "category": "subject_loss_in_parsing",
                    "count": loss,
                    "message": f"Lost {loss} subjects during {source_format} -> CIM conversion"
                })

        # CIM -> 출력 변환 비교
        if len(cim.vulnerabilities) != output_counts["vulnerabilities"]:
            loss = len(cim.vulnerabilities) - output_counts["vulnerabilities"]
            if loss > 0:
                analysis["has_data_loss"] = True
                analysis["details"].append({
                    "severity": "CRITICAL",
                    "category": "vulnerability_loss_in_output",
                    "count": loss,
                    "message": f"Lost {loss} vulnerabilities during CIM -> {target_format} conversion"
                })

        if len(cim.subjects) != output_counts["subjects"]:
            loss = len(cim.subjects) - output_counts["subjects"]
            if loss > 0:
                # CycloneDX는 의도적으로 중복 PURL/CPE를 병합하는 dedupe_components 사용
                # OpenVEX는 statement 기반: statement에 언급된 제품만 출력에 나타남
                if target_format == "CycloneDX":
                    analysis["details"].append({
                        "severity": "INFO",
                        "category": "component_deduplication",
                        "count": loss,
                        "message": f"Merged {loss} duplicate components (same PURL/CPE)"
                    })
                elif target_format == "OpenVEX":
                    analysis["details"].append({
                        "severity": "INFO",
                        "category": "statement_driven_filtering",
                        "count": loss,
                        "message": f"Excluded {loss} products not referenced in any statement (OpenVEX is statement-driven)"
                    })
                else:
                    analysis["has_data_loss"] = True
                    analysis["details"].append({
                        "severity": "CRITICAL",
                        "category": "subject_loss_in_output",
                        "count": loss,
                        "message": f"Lost {loss} subjects during CIM -> {target_format} conversion"
                    })

        # 팬텀 컴포넌트 확인
        explicit_subjects = {s.ref for s in cim.subjects if any(
            i.type in ("purl", "cpe") for i in s.identifiers
        )}
        phantom_subjects = {s.ref for s in cim.subjects if s.ref not in explicit_subjects}

        if phantom_subjects:
            analysis["details"].append({
                "severity": "LOW",
                "category": "phantom_components",
                "count": len(phantom_subjects),
                "message": "Component details inferred from affects refs (no explicit components in source)"
            })

        # CycloneDX 특수 상태 확인
        special_states = [st for st in cim.statements if st.status.original_state in ["false_positive", "resolved_with_pedigree"]]
        if special_states:
            analysis["details"].append({
                "severity": "INFO",
                "category": "cyclonedx_special_states",
                "count": len(special_states),
                "message": f"CycloneDX special states preserved: {', '.join(set(st.status.original_state for st in special_states))}"
            })

        # 매핑 불가능한 justification 확인
        custom_justs = [st for st in cim.statements if st.status.custom_justification]
        if custom_justs:
            analysis["details"].append({
                "severity": "MEDIUM",
                "category": "custom_justifications",
                "count": len(custom_justs),
                "message": "Custom justifications that don't map to standard enums"
            })

        # 비표준 필드 손실 감지
        non_standard_fields = self._detect_non_standard_fields(source_data, source_format)
        if non_standard_fields:
            for field_info in non_standard_fields:
                field_name = field_info['field'].replace('statements.', '')
                analysis["details"].append({
                    "severity": "MEDIUM",
                    "category": "non_standard_field_loss",
                    "count": 1,
                    "message": f"{field_name}: Lost (non-standard field)"
                })
                analysis["has_data_loss"] = True

        # 표준 필드 손실 감지 (예: action_statement)
        standard_field_losses = self._detect_standard_field_loss(cim, target_format)
        if standard_field_losses:
            for loss_info in standard_field_losses:
                analysis["details"].append({
                    "severity": "MEDIUM",
                    "category": "standard_field_loss",
                    "count": loss_info["count"],
                    "message": f"{loss_info['field']}: Lost (no corresponding field in {target_format})"
                })
                analysis["has_data_loss"] = True

        # 필드 레벨 손실 감지 (상세 정보 손실)
        field_level_losses = self._detect_field_level_loss(source_data, source_format, result, target_format, cim)
        if field_level_losses:
            analysis["lost_fields"] = field_level_losses
            analysis["has_data_loss"] = True

        return analysis

    def _detect_non_standard_fields(self, data: Dict, format_name: str) -> List[Dict]:
        """손실될 비표준 필드 감지"""
        non_standard = []
        seen_fields = set()

        if format_name == "OpenVEX":
            # 문서 레벨 비표준 필드 확인
            doc_standard = self.STANDARD_FIELDS["OpenVEX"]["document"]
            for key in data.keys():
                if key not in doc_standard and key not in seen_fields:
                    non_standard.append({
                        "field": key,
                        "reason": "Non-standard OpenVEX document field"
                    })
                    seen_fields.add(key)

            # statement 레벨 비표준 필드 확인
            stmt_standard = self.STANDARD_FIELDS["OpenVEX"]["statement"]
            for stmt in data.get("statements", []):
                for key in stmt.keys():
                    field_name = f"statements.{key}"
                    if key not in stmt_standard and field_name not in seen_fields:
                        non_standard.append({
                            "field": field_name,
                            "reason": "Non-standard OpenVEX statement field"
                        })
                        seen_fields.add(field_name)

        elif format_name == "CycloneDX":
            # 비표준 CycloneDX 필드 확인
            for vuln in data.get("vulnerabilities", []):
                analysis = vuln.get("analysis", {})
                for key in analysis.keys():
                    field_name = f"vulnerabilities.analysis.{key}"
                    if key not in ["state", "justification", "detail", "response", "ratings", "firstIssued", "lastUpdated"] and field_name not in seen_fields:
                        non_standard.append({
                            "field": field_name,
                            "reason": "Non-standard CycloneDX analysis field"
                        })
                        seen_fields.add(field_name)

        return non_standard

    def _detect_standard_field_loss(self, cim: CIM, target_format: str) -> List[Dict]:
        """대상 형식에서 손실될 표준 필드 감지"""
        losses = []

        # action_statement 손실 확인
        action_statements = [st for st in cim.statements if st.action_statement]
        if action_statements and target_format in ["CycloneDX", "CSAF"]:
            losses.append({
                "field": "action_statement",
                "count": len(action_statements),
                "reason": f"No corresponding field in {target_format} format"
            })

        return losses

    # 형식 간 필드 매핑 (소스 → 대상)
    FIELD_MAPPINGS = {
        ("CSAF", "CycloneDX"): {
            # 문서 레벨 매핑
            "document.publisher.name": "metadata.tools.vendor",
            "document.tracking.initial_release_date": "metadata.timestamp",
            "document.tracking.id": "serialNumber",  # 재생성되지만 개념적으로 매핑됨

            # 제품 매핑
            "product_tree": "components",  # 다른 구조지만 매핑됨
            "product_tree.branches": "components",
            "product_tree.relationships": "components",  # 관계가 다르게 표현됨

            # 취약점 매핑
            "vulnerabilities.cve": "vulnerabilities.id",
            "vulnerabilities.cwe.id": "vulnerabilities.cwes",
            "vulnerabilities.cwe.name": "vulnerabilities.cwes",  # ID만, name 손실
            "vulnerabilities.notes": "vulnerabilities.description",  # description note만
            "vulnerabilities.scores.cvss_v3": "vulnerabilities.ratings",
            "vulnerabilities.scores.cvss_v3.baseScore": "vulnerabilities.ratings.score",
            "vulnerabilities.scores.cvss_v3.baseSeverity": "vulnerabilities.ratings.severity",
            "vulnerabilities.scores.cvss_v3.vectorString": "vulnerabilities.ratings.vector",
            "vulnerabilities.scores.cvss_v3.attackComplexity": "vulnerabilities.ratings.vector",  # vector 내
            "vulnerabilities.scores.cvss_v3.attackVector": "vulnerabilities.ratings.vector",
            "vulnerabilities.scores.cvss_v3.availabilityImpact": "vulnerabilities.ratings.vector",
            "vulnerabilities.scores.cvss_v3.confidentialityImpact": "vulnerabilities.ratings.vector",
            "vulnerabilities.scores.cvss_v3.integrityImpact": "vulnerabilities.ratings.vector",
            "vulnerabilities.scores.cvss_v3.privilegesRequired": "vulnerabilities.ratings.vector",
            "vulnerabilities.scores.cvss_v3.scope": "vulnerabilities.ratings.vector",
            "vulnerabilities.scores.cvss_v3.userInteraction": "vulnerabilities.ratings.vector",
            "vulnerabilities.scores.products": "vulnerabilities.ratings",  # 구조에 암시됨
            "vulnerabilities.references": "vulnerabilities.references",
            "vulnerabilities.references.url": "vulnerabilities.references.source.url",
            "vulnerabilities.references.summary": "vulnerabilities.references.source.name",
            "vulnerabilities.references.category": "vulnerabilities.references",  # 구조에 보존됨
            "vulnerabilities.product_status.known_affected": "vulnerabilities.affects",
        },
        ("CSAF", "OpenVEX"): {
            # 문서 레벨 매핑
            "document.publisher.name": "author",
            "document.tracking.initial_release_date": "timestamp",

            # 제품 매핑 - OpenVEX는 statement 기반
            "product_tree": "statements.products",

            # 취약점 매핑
            "vulnerabilities.cve": "statements.vulnerability.name",
            "vulnerabilities.notes": "statements",  # description이 impact_statement로 감
            "vulnerabilities.product_status": "statements.status",
        },
        ("OpenVEX", "CycloneDX"): {
            "@context": "bomFormat",  # 형식 식별자
            "@id": "serialNumber",  # 문서 ID
            "author": "metadata.tools.vendor",
            "timestamp": "metadata.timestamp",
            "statements": "vulnerabilities",
            "statements.vulnerability": "vulnerabilities",
            "statements.vulnerability.name": "vulnerabilities.id",
            "statements.status": "vulnerabilities.analysis.state",
            "statements.justification": "vulnerabilities.analysis.justification",
            "statements.impact_statement": "vulnerabilities.analysis.detail",
            "statements.action_statement": "vulnerabilities.analysis.response",
            "statements.products": "vulnerabilities.affects",
        },
        ("OpenVEX", "CSAF"): {
            "@context": "document.category",  # 형식 식별자
            "@id": "document.tracking.id",
            "author": "document.publisher.name",
            "timestamp": "document.tracking.initial_release_date",
            "statements": "vulnerabilities",
            "statements.vulnerability": "vulnerabilities",
            "statements.vulnerability.name": "vulnerabilities.cve",
            "statements.status": "vulnerabilities.product_status",
            "statements.justification": "vulnerabilities.flags",
            "statements.impact_statement": "vulnerabilities.notes",
            "statements.action_statement": "vulnerabilities.remediations",
            "statements.products": "vulnerabilities.product_status",
        },
        ("CycloneDX", "OpenVEX"): {
            "metadata.tools": "author",  # 도구 vendor가 author가 됨
            "metadata.tools.vendor": "author",
            "metadata.tools.name": "author",
            "components": "statements.products",
            "vulnerabilities.id": "statements.vulnerability.name",
            "vulnerabilities.source": "statements",  # 소스 정보가 CIM references로 감
            "vulnerabilities.source.url": "statements",  # references의 일부
            "vulnerabilities.source.name": "statements",  # references의 일부
            "vulnerabilities.description": "statements",  # impact_statement로 감
            "vulnerabilities.affects": "statements.products",
            "vulnerabilities.analysis.state": "statements.status",
            "vulnerabilities.analysis.justification": "statements.justification",
            "vulnerabilities.analysis.detail": "statements.impact_statement",
            "vulnerabilities.analysis.response": "statements",  # 손실 - response 필드 없음
            "vulnerabilities.ratings": "statements.status_notes",  # status_notes에 요약됨
            "vulnerabilities.ratings.method": "statements.status_notes",
            "vulnerabilities.ratings.score": "statements.status_notes",
            "vulnerabilities.ratings.severity": "statements.status_notes",
            "vulnerabilities.ratings.vector": "statements.status_notes",
        },
        ("CycloneDX", "CSAF"): {
            # 문서 레벨 매핑 (CSAF → CycloneDX의 역)
            "metadata.tools": "document.publisher",
            "metadata.tools.vendor": "document.publisher.name",
            "metadata.tools.name": "document.publisher",  # 부분 매핑
            "metadata.timestamp": "document.tracking.initial_release_date",
            "serialNumber": "document.tracking.id",
            "bomFormat": "document.category",
            "specVersion": "document.csaf_version",

            # 제품 매핑
            "components": "product_tree.full_product_names",

            # 취약점 매핑 (역)
            "vulnerabilities": "vulnerabilities",
            "vulnerabilities.id": "vulnerabilities.cve",
            "vulnerabilities.cwes": "vulnerabilities.cwe.id",
            "vulnerabilities.description": "vulnerabilities.notes",
            "vulnerabilities.affects": "vulnerabilities.product_status",
            "vulnerabilities.analysis": "vulnerabilities.product_status",
            "vulnerabilities.analysis.state": "vulnerabilities.product_status",
            "vulnerabilities.analysis.justification": "vulnerabilities.flags",
            "vulnerabilities.analysis.detail": "vulnerabilities.notes",
            "vulnerabilities.analysis.response": "vulnerabilities.remediations",
            "vulnerabilities.ratings": "vulnerabilities.scores.cvss_v3",
            "vulnerabilities.ratings.score": "vulnerabilities.scores.cvss_v3.baseScore",
            "vulnerabilities.ratings.severity": "vulnerabilities.scores.cvss_v3.baseSeverity",
            "vulnerabilities.ratings.vector": "vulnerabilities.scores.cvss_v3.vectorString",
            "vulnerabilities.ratings.method": "vulnerabilities.scores",
            "vulnerabilities.references": "vulnerabilities.references",
            "vulnerabilities.references.source.url": "vulnerabilities.references.url",
            "vulnerabilities.references.source.name": "vulnerabilities.references.summary",
        },
    }

    def _get_mapped_field(self, source_field: str, source_format: str, target_format: str) -> Optional[str]:
        """source_field가 매핑되는 대상 필드 가져오기 (있는 경우)"""
        key = (source_format, target_format)
        if key not in self.FIELD_MAPPINGS:
            return None

        mappings = self.FIELD_MAPPINGS[key]

        # 정확한 일치 확인
        if source_field in mappings:
            return mappings[source_field]

        # 접두사 일치 확인 (예: vulnerabilities.scores.cvss_v3.* → vulnerabilities.ratings)
        for source_pattern, target_field in mappings.items():
            if source_field.startswith(source_pattern + "."):
                return target_field

        return None

    def _detect_field_level_loss(self, source_data: Dict, source_format: str, result: Dict, target_format: str, cim: CIM) -> List[str]:
        """모든 필드를 비교하여 변환 중 손실되는 특정 필드 감지"""

        # 소스와 대상에서 모든 필드 추출
        source_fields = extract_all_fields(source_data)
        target_fields = extract_all_fields(result)

        # 소스에 있지만 대상에 없는 필드 찾기
        lost_fields = source_fields - target_fields

        # 변경이 예상되는 필드 건너뛰기 (도구 생성 필드)
        skip_patterns = [
            '@context',  # OpenVEX 컨텍스트 URL
            '@id',  # 재생성될 수 있음
            'serialNumber',  # CycloneDX가 새로 생성
            'version',  # 문서 버전이 변경될 수 있음
            'bomFormat',  # 대상 형식 식별자
            'specVersion',  # 대상 스펙 버전
            'metadata.timestamp',  # 타임스탬프 업데이트됨
            'timestamp',  # 타임스탬프 업데이트됨
            'author',  # publisher에서 매핑될 수 있음
            'tracking.current_release_date',  # 도구가 업데이트함
            'tracking.generator',  # 도구별, 보존 안 됨
            'tracking.revision_history',  # 재생성될 수 있음
        ]

        # 중요한 손실 필터링
        significant_losses = []
        for field in sorted(lost_fields):
            # 예상되는 변경 건너뛰기
            if any(pattern in field for pattern in skip_patterns):
                continue

            # 이 필드가 대상 형식에 매핑되는지 확인
            mapped_field = self._get_mapped_field(field, source_format, target_format)
            if mapped_field:
                # 필드가 매핑됨, 손실 아님
                continue

            # 중복 부모 경로 건너뛰기 (리프 필드만 원함)
            # 예: "document.notes.text"가 있으면 "document.notes"는 보고 안 함
            is_parent = any(other.startswith(field + '.') for other in lost_fields)
            if not is_parent:
                significant_losses.append(field)

        return significant_losses

    def _count_source_data(self, data: Dict, format_name: str) -> Dict:
        counts = {"subjects": 0, "vulnerabilities": 0, "statements": 0}

        if format_name == "OpenVEX":
            # 모든 statement에서 고유 제품 수
            unique_products = set()
            for stmt in data.get("statements", []):
                for prod in stmt.get("products", []):
                    prod_id = prod.get("@id", "").strip()
                    if prod_id:
                        unique_products.add(prod_id)
                    # subcomponent도 확인
                    for sub in prod.get("subcomponents", []):
                        sub_id = sub.get("@id", "").strip()
                        if sub_id:
                            unique_products.add(sub_id)
            counts["subjects"] = len(unique_products)
            counts["vulnerabilities"] = len(set(s.get("vulnerability", {}).get("name") for s in data.get("statements", [])))
            counts["statements"] = len(data.get("statements", []))

        elif format_name == "CycloneDX":
            counts["subjects"] = len(data.get("components", []))

            # 고유 취약점 ID 수 (항목이 아닌, 같은 CVE가 여러 제품에 영향 줄 수 있음)
            unique_vuln_ids = set()
            for v in data.get("vulnerabilities", []):
                vuln_id = v.get("id", "")
                if vuln_id:
                    unique_vuln_ids.add(vuln_id)
            counts["vulnerabilities"] = len(unique_vuln_ids)

            # affects를 확장하여 statement 수
            stmt_count = 0
            for v in data.get("vulnerabilities", []):
                stmt_count += len(v.get("affects", []))
            counts["statements"] = stmt_count

        elif format_name == "CSAF":
            pt = data.get("product_tree", {})

            # full_product_names에서 수
            fpn_count = len(pt.get("full_product_names", []))

            # branches에서 수 (재귀)
            def count_branches(branches):
                count = 0
                for branch in branches:
                    if branch.get("product", {}).get("product_id"):
                        count += 1
                    count += count_branches(branch.get("branches", []))
                return count

            branches_count = count_branches(pt.get("branches", []))

            # relationships에서 수
            relationships_count = len(pt.get("relationships", []))

            # 총 고유 subject
            counts["subjects"] = fpn_count + branches_count + relationships_count
            counts["vulnerabilities"] = len(data.get("vulnerabilities", []))

            # product_status에서 statement 수
            stmt_count = 0
            for v in data.get("vulnerabilities", []):
                ps = v.get("product_status", {})
                for status_list in ps.values():
                    stmt_count += len(status_list)
            counts["statements"] = stmt_count

        return counts

# ===== MAIN CONVERTER =====