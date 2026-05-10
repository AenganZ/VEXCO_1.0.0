"""
validation_common.py
Cross-document validation용 공통 타입 정의.
기존 integrated_validators 패키지의 코드를 변경하지 않는다.
루트 레벨에 배치하여 cross_validator.py에서 import한다.
"""
from dataclasses import dataclass, field, asdict
from typing import Optional


# ---------------------------------------------------------------------------
# Enums (str 상속으로 JSON 직렬화 호환)
# ---------------------------------------------------------------------------
class MatchStrength:
    """근거의 강도. strong/weak는 매칭에 사용된 식별자의 신뢰도를 의미한다.
    매칭 자체가 실패한 경우(unresolved) NONE을 사용한다."""
    STRONG = "strong"   # purl exact, cpe exact, component_ref == product_ref
    WEAK = "weak"       # name + version exact match
    NONE = "none"       # 매칭 실패 (unresolved)


class MatchStatus:
    """결과 상태. matched/ambiguous/unresolved는 매칭 결과의 확정성을 의미한다.
    strength와 status는 독립 축이다. (예: weak+matched, strong+ambiguous 모두 가능)"""
    MATCHED = "matched"       # 1:1 대응 성공
    AMBIGUOUS = "ambiguous"   # 1:N 후보 존재
    UNRESOLVED = "unresolved" # 어떤 매칭도 실패


class Verdict:
    VALID = "valid"
    WARNING = "warning"
    UNVERIFIABLE = "unverifiable"
    INVALID = "invalid"


# ---------------------------------------------------------------------------
# Internal Representation (IR)
# ---------------------------------------------------------------------------
@dataclass
class IRVulnerability:
    """Core IR - 취약점 단위 최소 표현"""
    vuln_id: str
    aliases: list = field(default_factory=list)
    cwes: list = field(default_factory=list)


@dataclass
class IRProduct:
    """Core IR - 제품/컴포넌트 단위 최소 표현
    name, version: weak matching에 사용.
      원문에 name이 없으면 purl/identifier에서 파싱하여 보조 채움.
    purl, cpe: strong matching에 사용.
    """
    identifier: str
    name: str = ""
    version: str = ""
    purl: str = ""
    cpe: str = ""


@dataclass
class IRStatement:
    """Core IR - VEX 문(statement) 단위 최소 표현"""
    vulnerability: IRVulnerability = None
    products: list = field(default_factory=list)   # list[IRProduct]
    status: str = ""
    justification: str = ""
    timestamp: str = ""


@dataclass
class IRDocument:
    """VEX 문서의 validation용 최소 내부 표현 (core + extended).
    원문 전체 복제가 아니라, cross-document 매칭에 필요한 필드만 추출한다.
    extended dict 사용 예:
      - extended["containment"]: CSAF product tree의 parent->child 관계
        형식: { parent_id: [child_id, ...] }
        scope rule 보조 입력으로만 사용
    """
    format_type: str = ""
    format_version: str = ""
    doc_id: str = ""
    timestamp: str = ""
    author: str = ""
    statements: list = field(default_factory=list)   # list[IRStatement]
    extended: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# BOM IR
# ---------------------------------------------------------------------------
@dataclass
class BOMComponent:
    """BOM 컴포넌트 최소 표현
    name, version: weak matching에 사용 (name + version 기반)
    purl, cpe, bom_ref: strong matching에 사용 (exact match)
    """
    name: str = ""
    version: str = ""
    purl: str = ""
    cpe: str = ""
    bom_ref: str = ""


@dataclass
class BOMDocument:
    """BOM 문서 최소 표현
    extended dict 사용 예:
      - extended["containment"]: BOM 내 parent->child 관계
        CycloneDX: metadata.component -> components, nested components
        형식: { parent_ref: [child_ref, ...] }
    """
    format_type: str = ""
    format_version: str = ""
    serial: str = ""
    components: list = field(default_factory=list)   # list[BOMComponent]
    extended: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Cross-Document Match Result
#
# strength (MatchStrength): 근거의 강도
# status (MatchStatus):     결과 상태
# 이 둘은 독립 축이다.
# ---------------------------------------------------------------------------
@dataclass
class MatchResult:
    vex_product_id: str       # VEX 문서 내 product 식별자
    bom_component_id: str     # BOM 문서 내 component 식별자
    strength: str             # 근거의 강도 (strong / weak / none)
    status: str               # 결과 상태 (matched / ambiguous / unresolved)
    matching_basis: str = ""  # 매칭에 사용된 필드 (purl / cpe / ref / name+version)
    match_field: str = ""     # 실제 매칭 값 요약
    detail: str = ""          # 사람이 읽을 수 있는 상세 설명
    vuln_id: str = ""         # 이 매칭이 속한 취약점 ID (statement-level 추적)
    statement_index: int = -1 # VEX 문서 내 statement 인덱스 (0-based)

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Cross-doc Validation Rule Result (통일 반환 포맷)
# ---------------------------------------------------------------------------
@dataclass
class CrossRuleResult:
    rule_id: str
    rule_name: str
    severity: str       # "error" | "warning" | "info"
    passed: bool
    message: str
    context: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)