"""
VEX Converter 데이터 모델
"""
import json
import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any
from enum import Enum

class DocumentFormat(Enum):
    OPENVEX = "OpenVEX"
    CYCLONEDX = "CycloneDX"
    CSAF = "CSAF"

class VulnerabilityStatus(Enum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"

class Justification(Enum):
    COMPONENT_NOT_PRESENT = "component_not_present"
    VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present"
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY = "vulnerable_code_cannot_be_controlled_by_adversary"
    INLINE_MITIGATIONS_ALREADY_EXIST = "inline_mitigations_already_exist"

# ===== 변환 추적 및 가역성 =====

@dataclass
class MappingRecord:
    """변환 중 단일 필드 매핑 기록"""
    source_field: str
    source_value: Any
    target_field: str
    target_value: Any
    rule: str  # 매핑 규칙 설명
    status: str  # "OK", "LOSSY", "TRANSFORMED", "MERGED"
    loss_description: Optional[str] = None

class TrackingTable:
    """표시 및 분석을 위한 변환 중 필드 매핑 추적"""
    
    def __init__(self):
        self.records: List[MappingRecord] = []
    
    def add(self, source_field: str, source_value: Any, 
            target_field: str, target_value: Any,
            rule: str, status: str = "OK", loss_description: Optional[str] = None):
        """매핑 기록 추가"""
        self.records.append(MappingRecord(
            source_field=source_field,
            source_value=self._format_value(source_value),
            target_field=target_field,
            target_value=self._format_value(target_value),
            rule=rule,
            status=status,
            loss_description=loss_description
        ))
    
    def _format_value(self, value: Any) -> str:
        """표시용 값 포맷"""
        if value is None:
            return "null"
        elif isinstance(value, (list, dict)):
            s = json.dumps(value, ensure_ascii=False)
            if len(s) > 60:
                return s[:57] + "..."
            return s
        else:
            s = str(value)
            if len(s) > 60:
                return s[:57] + "..."
            return s
    
    def print_table(self, source_format: str, target_format: str):
        """터미널에 매핑 테이블 출력 (간소화된 형식)"""
        if not self.records:
            print("\nNo field mappings tracked.")
            return
        
        print(f"\nCONVERSION MAPPING: {source_format} → {target_format}")
        
        for rec in self.records:
            # 더 깔끔한 표시를 위해 CIM 중간 레이어 제거
            display_source_field = rec.source_field
            display_source_field = display_source_field.replace("CIM.statement.", "")
            display_source_field = display_source_field.replace("CIM.vulnerability.", "")
            display_source_field = display_source_field.replace("CIM.metadata.", "")
            display_source_field = display_source_field.replace("CIM.subject.", "")
            display_source_field = display_source_field.replace("CIM.", "")
            
            # 간단한 형식: source → target (status)
            # OK가 아닌 경우에만 status 표시
            if rec.status == "OK":
                print(f"  {display_source_field} → {rec.target_field}")
            else:
                status_color = {
                    "LOSSY": "\033[93m",  # Yellow
                    "TRANSFORMED": "\033[96m",  # Cyan
                    "MERGED": "\033[95m"  # Magenta
                }.get(rec.status, "")
                reset = "\033[0m" if status_color else ""
                print(f"  {display_source_field} → {rec.target_field} {status_color}({rec.status}){reset}")
        
        # 요약
        status_counts = {}
        for rec in self.records:
            status_counts[rec.status] = status_counts.get(rec.status, 0) + 1
        
        print(f"\nSummary: {sum(status_counts.values())} mappings")
        if status_counts.get("TRANSFORMED", 0) > 0:
            print(f"  Transformed: {status_counts['TRANSFORMED']}")
        if status_counts.get("LOSSY", 0) > 0:
            print(f"  Lossy: {status_counts['LOSSY']}")
        if status_counts.get("MERGED", 0) > 0:
            print(f"  Merged: {status_counts['MERGED']}")
        print()

@dataclass
class ConversionMetadata:
    """가역 변환을 위한 메타데이터"""
    version: str = "1.0"
    source_format: str = ""
    target_format: str = ""
    timestamp: str = ""
    lost_data: Dict[str, Any] = field(default_factory=dict)
    # CIM의 Extension 데이터 (모든 형식별 필드)
    extension_data: Dict[str, Any] = field(default_factory=dict)
    # Subject ID 매핑: original_ref → modified_ref
    # 예: {"pkg:apk/alpine/busybox": "pkg:apk/alpine/busybox:vunknown"}
    subject_mappings: Dict[str, str] = field(default_factory=dict)
    
    def encode(self) -> str:
        """메타데이터를 서명이 있는 일반 JSON 문자열로 인코딩"""
        data = {
            "version": self.version,
            "source_format": self.source_format,
            "target_format": self.target_format,
            "timestamp": self.timestamp,
            "lost_data": self.lost_data,
            "extension_data": self.extension_data,
            "subject_mappings": self.subject_mappings
        }
        json_str = json.dumps(data, ensure_ascii=False, separators=(',', ':'))
        return f"[VEXCONV:v1]{json_str}"
    
    @staticmethod
    def decode(encoded: str) -> Optional['ConversionMetadata']:
        """일반 JSON 서명에서 메타데이터 디코딩"""
        if not encoded or not encoded.startswith("[VEXCONV:v1]"):
            return None
        
        try:
            # 서명 뒤의 JSON 부분 추출
            json_str = encoded[len("[VEXCONV:v1]"):]
            # 일반 JSON과 base64 모두 처리 (하위 호환성)
            if json_str.startswith("{"):
                # 일반 JSON
                data = json.loads(json_str)
            else:
                # 레거시 base64 형식 (하위 호환성)
                b64 = json_str.rstrip("]")
                json_str = base64.b64decode(b64).decode('utf-8')
                data = json.loads(json_str)
            
            return ConversionMetadata(
                version=data.get("version", "1.0"),
                source_format=data.get("source_format", ""),
                target_format=data.get("target_format", ""),
                timestamp=data.get("timestamp", ""),
                lost_data=data.get("lost_data", {}),
                extension_data=data.get("extension_data", {}),
                subject_mappings=data.get("subject_mappings", {})
            )
        except Exception:
            return None

    INLINE_MITIGATIONS_ALREADY_EXIST = "inline_mitigations_already_exist"

@dataclass
class ConversionOptions:
    use_free_text_encoding: bool = True
    preserve_cyclonedx_special_states: bool = True  # false_positive, resolved_with_pedigree
    consolidate_duplicate_statements: bool = True   # OpenVEX 출력용
    apply_csaf_product_priority: bool = True        # 중복 제품 상태 방지
    use_csaf_product_groups: bool = False           # CSAF에서 product_groups 사용 (일관성을 위해 기본 비활성화)
    enable_nvd_enrichment: bool = False             # NVD API에서 CWE, CVSS 가져오기
    nvd_api_key: Optional[str] = None               # NVD API 키 (선택, 속도 제한 증가)
    reversible: bool = False                        # 가역 변환 활성화 (복원용 메타데이터 저장)
    restore: bool = False                           # 가역 변환에서 복원
    show_mapping_table: bool = True                 # 변환 중 필드 매핑 테이블 표시
    input_vdr: bool = False                         # 입력 CycloneDX를 VDR(취약점 공개 보고서)로 처리

class ValidationError(Exception):
    pass

@dataclass
class Identifier:
    type: str
    value: str

@dataclass
class Subject:
    ref: str
    identifiers: List[Identifier] = field(default_factory=list)
    name: Optional[str] = None
    version: Optional[str] = None
    type: Optional[str] = None
    # 확장된 CSAF product_identification_helper 필드
    hashes: Optional[List[Dict]] = None  # {algorithm, value, filename} 목록
    model_numbers: Optional[List[str]] = None
    sbom_urls: Optional[List[str]] = None
    serial_numbers: Optional[List[str]] = None
    skus: Optional[List[str]] = None
    # 형식별 필드용 Extension 데이터
    # 키: "cyclonedx.<field>", "openvex.<field>", "csaf.<field>"
    extension_data: Dict[str, Any] = field(default_factory=dict)
    # 원본 형식의 원본 ID (가역 변환용)
    # 예: "pkg:apk/alpine/busybox" → OpenVEX의 원본 @id 보존
    original_id: Optional[str] = None
    # 부모 제품 참조 (OpenVEX subcomponents, CSAF relationships 용)
    parent_ref: Optional[str] = None

@dataclass
class StatusInfo:
    value: VulnerabilityStatus
    justification: Optional[Justification] = None
    custom_justification: Optional[str] = None
    impact_statement: Optional[str] = None
    original_state: Optional[str] = None  # CycloneDX false_positive, resolved_with_pedigree용

@dataclass
class VEXStatement:
    id: str
    subject_refs: List[str]
    vulnerability_id: str
    status: StatusInfo
    timestamp: datetime
    action_statement: Optional[str] = None
    # 형식별 필드용 Extension 데이터
    extension_data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class CvssRating:
    method: Optional[str] = None
    score: Optional[float] = None
    severity: Optional[str] = None
    vector: Optional[str] = None

@dataclass
class Reference:
    url: str
    summary: Optional[str] = None
    category: Optional[str] = None
    id: Optional[str] = None  # CycloneDX reference id용

@dataclass
class Vulnerability:
    id: str
    description: Optional[str] = None
    aliases: List[str] = field(default_factory=list)  # OpenVEX aliases → CSAF ids
    ratings: List[CvssRating] = field(default_factory=list)
    cwes: List[int] = field(default_factory=list)
    references: List[Reference] = field(default_factory=list)
    notes: List[Dict[str, str]] = field(default_factory=list)  # CSAF notes용
    remediations: List[Dict[str, Any]] = field(default_factory=list)  # CSAF remediations용
    # 형식별 필드용 Extension 데이터
    extension_data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Publisher:
    name: str
    namespace: Optional[str] = None
    role: Optional[str] = None

@dataclass
class Metadata:
    id: str
    publisher: Publisher
    created_at: datetime
    source_format: DocumentFormat
    original_id: Optional[str] = None
    document_version: Optional[int] = None  # 문서 버전 (OpenVEX, CycloneDX, CSAF)
    last_updated: Optional[datetime] = None  # 마지막 업데이트 타임스탬프 (OpenVEX last_updated, CSAF current_release_date)
    # 형식별 문서 레벨 필드용 Extension 데이터
    # 예: "csaf.document.aggregate_severity": {"namespace": "...", "text": "..."}
    extension_data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class CIM:
    """Extension 데이터 지원이 있는 공통 중간 모델
    
    Extension 데이터 형식:
    - 네임스페이스: "cyclonedx.", "openvex.", "csaf."
    - 중첩 필드: "csaf.document.aggregate_severity" → {"namespace": "...", "text": "..."}
    - --reversible 모드에서 보존되고 --restore 모드에서 복원됨
    """
    metadata: Metadata
    subjects: List[Subject]
    vulnerabilities: List[Vulnerability]
    statements: List[VEXStatement]
    # metadata에 맞지 않는 문서 레벨 필드용 전역 Extension 데이터
    extension_data: Dict[str, Any] = field(default_factory=dict)