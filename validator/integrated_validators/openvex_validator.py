"""
OpenVEX 시맨틱 검증기 v2.0
OpenVEX 명세 v0.2.0 기반

검증 흐름:
  1단계: JSON 스키마 검증(구조적)
  2단계: 시맨틱 검증(명세 도출 규칙)

네이밍 규칙:
  스키마 규칙   : SCHEMA_OPENVEX_{NNN}
  시맨틱 MUST   : OPENVEX_SEMANTIC_{CATEGORY}_{DESCRIPTION}  (severity=error)
  시맨틱 SHOULD : OPENVEX_SEMANTIC_{CATEGORY}_{DESCRIPTION}  (severity=warning)
"""

import re
from typing import Dict, Any, List, Tuple
from datetime import datetime

try:
    from jsonschema import Draft7Validator
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False


# PURL 패턴 (Package URL)
PURL_PATTERN = re.compile(r'^pkg:[a-z]+/.+')

# OpenVEX 유효 상태값
VALID_STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}

# OpenVEX 유효 justification 라벨
VALID_JUSTIFICATIONS = {
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "vulnerable_code_not_in_execute_path",
    "inline_mitigations_already_exist"
}


# ========================================================================
# 1단계: 스키마 검증 (Schema Validation Phase)
# ========================================================================

def _run_schema_validation(data: Dict[str, Any], schema: Dict[str, Any],
                           errors: List[Dict[str, Any]]) -> bool:
    """
    JSON Schema 기반 구조 검증을 수행한다.
    필수 필드, enum 멤버십, 타입 체크 등 구조적 규칙은 이 단계에서 처리된다.

    Returns:
        True이면 스키마 검증 통과 (시맨틱 검증 진행 가능)
    """
    if not schema or not HAS_JSONSCHEMA:
        # 스키마가 없으면 시맨틱 검증으로 바로 진행
        return True

    try:
        validator = Draft7Validator(schema)
        validation_errors = sorted(validator.iter_errors(data), key=lambda e: e.path)

        for error in validation_errors:
            path = "/" + "/".join(str(p) for p in error.path) if error.path else "/"
            errors.append({
                "path": path,
                "message": f"JSON Schema validation failed: {error.message}",
                "schema_path": "/" + "/".join(str(p) for p in error.schema_path) if error.schema_path else "/",
                "severity": "error",
                "rule_id": "SCHEMA_OPENVEX_001"
            })
    except Exception as e:
        errors.append({
            "path": "/",
            "message": f"Schema validation error: {str(e)}",
            "schema_path": "/",
            "severity": "error",
            "rule_id": "SCHEMA_OPENVEX_000"
        })
        # 스키마 엔진 자체 오류 시 시맨틱 검증 중단
        return False

    return True


# ========================================================================
# 2단계: 시맨틱 검증 (Semantic Validation Phase)
# 스키마 검증이 완료된 상태를 전제로 실행된다.
# ========================================================================

def _run_semantic_validation(data: Dict[str, Any],
                             errors: List[Dict[str, Any]]):
    """
    OpenVEX 명세에서 도출한 시맨틱 규칙을 검증한다.
    조건부 필수, 교차 필드 정합성, 의미 기반 제약 등을 검사한다.
    스키마 검증이 이미 완료되었다고 가정한다.
    """
    # 문서 수준 시맨틱 규칙
    _validate_document_semantic(data, errors)

    # Statement 수준 시맨틱 규칙
    if "statements" in data and isinstance(data["statements"], list):
        for idx, statement in enumerate(data["statements"]):
            _validate_statement_semantic(statement, idx, data, errors)

        # 교차 Statement 시맨틱 규칙
        _validate_cross_statement_rules(data["statements"], data, errors)


def _validate_document_semantic(data: Dict[str, Any],
                                errors: List[Dict[str, Any]]):
    """
    문서 수준 시맨틱 규칙 검증

    명세 참조:
    - @context: OpenVEX 네임스페이스 URL 형식 (MUST)
    - @id: 비어있지 않은 IRI (MUST)
    - author: 개인 또는 조직을 식별할 수 있는 주체 (MUST)
    - version: 1 이상 (MUST), 변경 시 증가 (MUST)
    """

    # --- MUST 규칙 ---

    # OPENVEX_SEMANTIC_DOC_CONTEXT_FORMAT: @context URL 형식 검증
    # 명세: "OpenVEX 문서는 반드시 https://openvex.dev/ns/v[version] 형식의 @context를 사용해야 한다"
    if "@context" in data:
        context = data["@context"]
        if not isinstance(context, str) or not context.startswith("https://openvex.dev/ns/"):
            errors.append({
                "path": "/@context",
                "message": "@context SHOULD use OpenVEX namespace format (https://openvex.dev/ns/...) for JSON-LD interoperability",
                "schema_path": "/@context",
                "severity": "warning",
                "rule_id": "OPENVEX_SEMANTIC_DOC_CONTEXT_FORMAT"
            })

    # OPENVEX_SEMANTIC_DOC_ID_NONEMPTY: @id 비어있지 않아야 함
    # 명세: "VEX 문서 식별 IRI는 반드시 존재하고 고유해야 한다"
    if "@id" in data:
        doc_id = data["@id"]
        if isinstance(doc_id, str) and len(doc_id.strip()) == 0:
            errors.append({
                "path": "/@id",
                "message": "@id MUST NOT be empty",
                "schema_path": "/@id",
                "severity": "error",
                "rule_id": "OPENVEX_SEMANTIC_DOC_ID_NONEMPTY"
            })

    # OPENVEX_SEMANTIC_DOC_VERSION_MINIMUM: version은 1 이상
    # 명세: "문서 버전 번호는 최소 1 이상이어야 한다"
    if "version" in data:
        version = data["version"]
        if isinstance(version, int) and version < 1:
            errors.append({
                "path": "/version",
                "message": "version MUST be >= 1",
                "schema_path": "/version",
                "severity": "error",
                "rule_id": "OPENVEX_SEMANTIC_DOC_VERSION_MINIMUM"
            })

    # OPENVEX_SEMANTIC_DOC_AUTHOR_IDENTITY: author는 개인 또는 조직을 식별 가능해야 함
    # 명세(MUST): "author 필드는 반드시 개인(individual) 또는 조직(organization)을
    #             식별할 수 있는 주체여야 한다"
    if "author" in data:
        author = data["author"]
        if isinstance(author, str):
            # 단순 문자열인 경우: 빈 문자열이거나 식별 불가능하면 오류
            if len(author.strip()) == 0:
                errors.append({
                    "path": "/author",
                    "message": "author MUST identify an individual or organization and MUST NOT be empty",
                    "schema_path": "/author",
                    "severity": "error",
                    "rule_id": "OPENVEX_SEMANTIC_DOC_AUTHOR_IDENTITY"
                })

    # --- SHOULD/RECOMMENDED 규칙 ---

    # OPENVEX_SEMANTIC_DOC_AUTHOR_MACHINE_READABLE: author에 기계 판독 가능 식별자 권장
    # 명세(RECOMMENDED): "IRI, 이메일 주소 등 기계가 식별할 수 있는 형식을 사용하는 것이 좋다"
    if "author" in data:
        author = data["author"]
        if isinstance(author, str) and len(author.strip()) > 0:
            # IRI(http/https), 이메일, URI 형식인지 간이 검사
            is_machine_readable = (
                author.startswith("http://") or
                author.startswith("https://") or
                "@" in author or
                author.startswith("urn:")
            )
            if not is_machine_readable:
                errors.append({
                    "path": "/author",
                    "message": "author SHOULD use a machine-readable identifier (IRI, email, URN)",
                    "schema_path": "/author",
                    "severity": "warning",
                    "rule_id": "OPENVEX_SEMANTIC_DOC_AUTHOR_MACHINE_READABLE"
                })

    # OPENVEX_SEMANTIC_TS_DOC_FORMAT: 문서 타임스탬프 ISO 8601 형식 권장
    if "timestamp" in data:
        ts_result = _validate_timestamp(data["timestamp"], "document timestamp")
        if not ts_result["valid"]:
            errors.append({
                "path": "/timestamp",
                "message": ts_result["reason"],
                "schema_path": "/timestamp",
                "severity": "warning",
                "rule_id": "OPENVEX_SEMANTIC_TS_DOC_FORMAT"
            })

    # OPENVEX_SEMANTIC_TS_LASTUPDATED_FORMAT: last_updated ISO 8601 형식 권장
    if "last_updated" in data:
        lu_result = _validate_timestamp(data["last_updated"], "last_updated")
        if not lu_result["valid"]:
            errors.append({
                "path": "/last_updated",
                "message": lu_result["reason"],
                "schema_path": "/last_updated",
                "severity": "warning",
                "rule_id": "OPENVEX_SEMANTIC_TS_LASTUPDATED_FORMAT"
            })


def _validate_statement_semantic(statement: Dict[str, Any], idx: int,
                                 doc: Dict[str, Any],
                                 errors: List[Dict[str, Any]]):
    """
    개별 OpenVEX Statement 시맨틱 규칙 검증

    명세 참조 - Statement 요소:
    - vulnerability: 필수 (고유 ID 문자열 반드시 존재)
    - status: 필수 - not_affected, affected, fixed, under_investigation
    - justification: not_affected일 때 필수 (또는 impact_statement)
    - impact_statement: not_affected일 때 필수 (또는 justification)
    - action_statement: affected일 때 필수
    - products: 식별 가능(Addressable)해야 함
    - timestamp: Statement 타임스탬프가 문서 타임스탬프보다 우선
    """
    path_prefix = f"/statements/{idx}"
    status = statement.get("status")

    # ==================================================================
    # 상태 기반 조건부 필수 규칙 (MUST)
    # ==================================================================

    # OPENVEX_SEMANTIC_STMT_STATUS_NOTAFFECTED_JUSTIFICATION: not_affected → justification/impact_statement 필수
    # 명세(MUST): "status가 not_affected일 때 justification과 impact_statement 중 최소 하나가
    #             반드시 존재해야 한다"
    if status == "not_affected":
        has_justification = "justification" in statement
        has_impact = "impact_statement" in statement

        if not has_justification and not has_impact:
            errors.append({
                "path": path_prefix,
                "message": "status 'not_affected' MUST have either 'justification' or 'impact_statement'",
                "schema_path": f"{path_prefix}/status",
                "severity": "error",
                "rule_id": "OPENVEX_SEMANTIC_STMT_STATUS_NOTAFFECTED_JUSTIFICATION"
            })

        # OPENVEX_SEMANTIC_STMT_NOTAFFECTED_JUSTIFICATION_PREFERRED: justification 라벨 우선 사용 권장
        # 명세(SHOULD): "not_affected 상태일 때, 자유 양식의 impact_statement보다는
        #               표준화된 justification 레이블을 우선적으로 사용해야 한다"
        if has_impact and not has_justification:
            errors.append({
                "path": f"{path_prefix}/justification",
                "message": "not_affected status SHOULD prefer standardized justification label over free-form impact_statement for machine processing",
                "schema_path": f"{path_prefix}/justification",
                "severity": "warning",
                "rule_id": "OPENVEX_SEMANTIC_STMT_NOTAFFECTED_JUSTIFICATION_PREFERRED"
            })

        # OPENVEX_SEMANTIC_STMT_NOTAFFECTED_IMPACT_DETAIL: justification과 함께 impact_statement 권장
        # 명세(SHOULD): "justification이 있을 때 impact_statement도 함께 제공하면 더 나은 기술적 세부사항 전달 가능"
        if has_justification and not has_impact:
            errors.append({
                "path": f"{path_prefix}/impact_statement",
                "message": "Including 'impact_statement' with 'justification' provides additional technical details",
                "schema_path": f"{path_prefix}/impact_statement",
                "severity": "warning",
                "rule_id": "OPENVEX_SEMANTIC_STMT_NOTAFFECTED_IMPACT_DETAIL"
            })

        # justification 값이 있으면 유효한 레이블인지 검사 (시맨틱 레벨)
        if has_justification:
            justification_val = statement["justification"]
            if isinstance(justification_val, str) and justification_val not in VALID_JUSTIFICATIONS:
                errors.append({
                    "path": f"{path_prefix}/justification",
                    "message": f"Invalid justification value '{justification_val}'. Valid values: {', '.join(sorted(VALID_JUSTIFICATIONS))}",
                    "schema_path": f"{path_prefix}/justification",
                    "severity": "error",
                    "rule_id": "OPENVEX_SEMANTIC_STMT_JUSTIFICATION_INVALID_VALUE"
                })

    # OPENVEX_SEMANTIC_STMT_STATUS_AFFECTED_ACTION: affected → action_statement 필수
    # 명세(MUST): "status가 affected일 때 action_statement가 반드시 존재해야 한다"
    elif status == "affected":
        if "action_statement" not in statement:
            errors.append({
                "path": path_prefix,
                "message": "status 'affected' MUST have 'action_statement'",
                "schema_path": f"{path_prefix}/status",
                "severity": "error",
                "rule_id": "OPENVEX_SEMANTIC_STMT_STATUS_AFFECTED_ACTION"
            })
        else:
            # OPENVEX_SEMANTIC_STMT_AFFECTED_ACTION_SPECIFIC: action_statement 구체적 조치 포함 권장
            # 명세(SHOULD): "action_statement는 단순히 존재하기만 해서는 안 되며
            #               취약점 해결을 위한 구체적인 조치나 완화 방법을 설명해야 한다"
            action = statement["action_statement"]
            if isinstance(action, str) and len(action.strip()) < 10:
                errors.append({
                    "path": f"{path_prefix}/action_statement",
                    "message": "action_statement SHOULD describe specific mitigation or remediation steps, not just exist",
                    "schema_path": f"{path_prefix}/action_statement",
                    "severity": "warning",
                    "rule_id": "OPENVEX_SEMANTIC_STMT_AFFECTED_ACTION_SPECIFIC"
                })

    # ==================================================================
    # 취약점 시맨틱 규칙
    # ==================================================================

    if "vulnerability" in statement:
        vuln = statement["vulnerability"]
        if isinstance(vuln, dict):
            # OPENVEX_SEMANTIC_STMT_VULN_NAME_NONEMPTY: vulnerability name 비어있지 않아야 함
            # 명세(MUST): "취약점을 지칭할 수 있는 고유한 ID 문자열이 반드시 존재해야 한다"
            if "name" in vuln:
                name = vuln["name"]
                if isinstance(name, str) and len(name.strip()) == 0:
                    errors.append({
                        "path": f"{path_prefix}/vulnerability/name",
                        "message": "vulnerability name MUST NOT be empty",
                        "schema_path": f"{path_prefix}/vulnerability/name",
                        "severity": "error",
                        "rule_id": "OPENVEX_SEMANTIC_STMT_VULN_NAME_NONEMPTY"
                    })

            # OPENVEX_SEMANTIC_STMT_VULN_CVE_RECOMMENDED: CVE ID 사용 권장
            # 명세(SHOULD): "취약점 식별 시 가급적 CVE ID와 같은 전역적으로 공인된
            #               식별 체계를 사용해야 한다"
            if "name" in vuln:
                name = vuln["name"]
                if isinstance(name, str) and len(name.strip()) > 0:
                    cve_pattern = re.compile(r'^CVE-\d{4}-\d{4,}$')
                    if not cve_pattern.match(name.strip()):
                        errors.append({
                            "path": f"{path_prefix}/vulnerability/name",
                            "message": "vulnerability name SHOULD use a globally recognized identifier such as CVE ID (e.g., CVE-2024-12345)",
                            "schema_path": f"{path_prefix}/vulnerability/name",
                            "severity": "warning",
                            "rule_id": "OPENVEX_SEMANTIC_STMT_VULN_CVE_RECOMMENDED"
                        })

    # ==================================================================
    # 제품 시맨틱 규칙
    # ==================================================================

    if "products" in statement and isinstance(statement["products"], list):
        for prod_idx, product in enumerate(statement["products"]):
            if isinstance(product, dict):
                prod_path = f"{path_prefix}/products/{prod_idx}"

                # OPENVEX_SEMANTIC_STMT_PROD_ADDRESSABLE: 제품 식별 가능성 검증
                # 명세(MUST): "Statement의 대상이 되는 제품은 반드시 OpenVEX에서 제공하는
                #             식별 기작(ID, Identifiers, Hashes 중 하나 이상)을 통해
                #             식별 가능(Addressable)해야 한다"
                if not _is_addressable_entity(product):
                    errors.append({
                        "path": prod_path,
                        "message": "Product MUST be addressable via at least one of: @id, identifiers, or hashes",
                        "schema_path": prod_path,
                        "severity": "error",
                        "rule_id": "OPENVEX_SEMANTIC_STMT_PROD_ADDRESSABLE"
                    })

                # OPENVEX_SEMANTIC_STMT_PROD_PURL_FORMAT: PURL 사용 권장
                # 명세(RECOMMENDED): "제품 식별 시 가장 권장되는 방식은 purl을 사용하는 것이다"
                if "@id" in product:
                    pid = product["@id"]
                    if isinstance(pid, str) and len(pid.strip()) > 0 and not PURL_PATTERN.match(pid):
                        errors.append({
                            "path": f"{prod_path}/@id",
                            "message": "Product @id SHOULD use Package URL (PURL) format (e.g., pkg:npm/express@4.18.0)",
                            "schema_path": f"{prod_path}/@id",
                            "severity": "warning",
                            "rule_id": "OPENVEX_SEMANTIC_STMT_PROD_PURL_FORMAT"
                        })

                # subcomponents 시맨틱 규칙
                if "subcomponents" in product and isinstance(product["subcomponents"], list):
                    for sub_idx, subcomp in enumerate(product["subcomponents"]):
                        if isinstance(subcomp, dict):
                            sub_path = f"{prod_path}/subcomponents/{sub_idx}"
                            
                            if not _is_addressable_entity(subcomp):
                                errors.append({
                                    "path": sub_path,
                                    "message": "subcomponent MUST be addressable via at least one of: @id, identifiers, or hashes",
                                    "schema_path": sub_path,
                                    "severity": "error",
                                    "rule_id": "OPENVEX_SEMANTIC_STMT_SUBCOMP_ADDRESSABLE"
                                })


                            # OPENVEX_SEMANTIC_STMT_SUBCOMP_PURL_FORMAT: subcomponent PURL 사용 권장
                            # 명세(SHOULD): "subcomponents는 소프트웨어 식별자를 포함해야 하며,
                            #               해당 제품의 SBOM에 기재된 내용과 일치하는 것이 권장된다"
                            if "@id" in subcomp:
                                sid = subcomp["@id"]
                                if isinstance(sid, str) and len(sid.strip()) > 0 and not PURL_PATTERN.match(sid):
                                    errors.append({
                                        "path": f"{sub_path}/@id",
                                        "message": "subcomponent @id SHOULD use PURL format",
                                        "schema_path": f"{sub_path}/@id",
                                        "severity": "warning",
                                        "rule_id": "OPENVEX_SEMANTIC_STMT_SUBCOMP_PURL_FORMAT"
                                    })

    # OPENVEX_SEMANTIC_TS_STMT_FORMAT: Statement 타임스탬프 형식 권장
    if "timestamp" in statement:
        ts_result = _validate_timestamp(statement["timestamp"], "statement timestamp")
        if not ts_result["valid"]:
            errors.append({
                "path": f"{path_prefix}/timestamp",
                "message": ts_result["reason"],
                "schema_path": f"{path_prefix}/timestamp",
                "severity": "warning",
                "rule_id": "OPENVEX_SEMANTIC_TS_STMT_FORMAT"
            })

    # ==================================================================
    # Statement 유효성 검증 (상속 포함)
    # ==================================================================

    # OPENVEX_SEMANTIC_STMT_COMPLETENESS: Statement 4대 필수 요소 검증
    # 명세(MUST): "최종적으로 도출되는 데이터에는 반드시 제품(products), 상태(status),
    #             취약점(vulnerability), 타임스탬프(timestamp) 이 4가지 요소가
    #             모두 포함되어야 한다."
    # 상속 로직: Statement에 없으면 문서 레벨에서 상속
    has_products = bool(statement.get("products"))
    has_status = bool(statement.get("status"))
    has_vulnerability = bool(statement.get("vulnerability"))

    # 타임스탬프: Statement에 없으면 문서 레벨에서 상속
    has_timestamp = bool(statement.get("timestamp")) or bool(doc.get("timestamp"))

    missing_elements = []
    if not has_products:
        missing_elements.append("products")
    if not has_status:
        missing_elements.append("status")
    if not has_vulnerability:
        missing_elements.append("vulnerability")
    if not has_timestamp:
        missing_elements.append("timestamp")

    if missing_elements:
        errors.append({
            "path": path_prefix,
            "message": f"Statement MUST have all four required elements (including via inheritance). Missing: {', '.join(missing_elements)}",
            "schema_path": path_prefix,
            "severity": "error",
            "rule_id": "OPENVEX_SEMANTIC_STMT_COMPLETENESS"
        })


def _validate_cross_statement_rules(statements: List[Dict[str, Any]],
                                    doc: Dict[str, Any],
                                    errors: List[Dict[str, Any]]):
    """
    교차 Statement 시맨틱 규칙 검증
    여러 Statement 간의 정합성을 검사한다.
    """

    # OPENVEX_SEMANTIC_CROSS_DUPLICATE_JUSTIFICATION: 동일 제품에 중복 justification 금지
    # 명세(MUST): 동일한 제품(@id)에 대해 서로 다른 justification이 있으면 안 됨
    product_justifications: Dict[tuple, List[tuple]] = {}

    for stmt_idx, statement in enumerate(statements):
        status = statement.get("status")
        justification = statement.get("justification")

        # not_affected 상태이고 justification이 있는 경우만 검사
        if status != "not_affected" or not justification:
            continue

        # products에서 제품 ID 수집
        products = statement.get("products", [])
        vuln = statement.get("vulnerability", {})
        vuln_name = vuln.get("name", "").strip() if isinstance(vuln, dict) else ""
        effective_ts = statement.get("timestamp") or doc.get("timestamp") or ""

        for product in products:
            if isinstance(product, dict):
                prod_id = product.get("@id", "").strip()
                if prod_id:
                    key = (prod_id, vuln_name, effective_ts)
                    if key not in product_justifications:
                        product_justifications[key] = []
                    product_justifications[key].append((stmt_idx, justification))

                # subcomponents도 확인
                subcomponents = product.get("subcomponents", [])
                for subcomp in subcomponents:
                    if isinstance(subcomp, dict):
                        sub_id = subcomp.get("@id", "").strip()
                        if sub_id:
                            key = (sub_id, vuln_name, effective_ts)
                            if key not in product_justifications:
                                product_justifications[key] = []
                            product_justifications[key].append((stmt_idx, justification))


    # 동일 product+vulnerability+effective_timestamp에 대해 justification 충돌 검사
    for (prod_id, vuln_name, effective_ts), just_list in product_justifications.items():
        if len(just_list) > 1:
            unique_justifications = set(j for _, j in just_list)
            if len(unique_justifications) > 1:
                stmt_indices = [idx for idx, _ in just_list]
                justifications = list(unique_justifications)
                errors.append({
                    "path": "/statements",
                    "message": f"Conflicting justifications for product '{prod_id}', vulnerability '{vuln_name}' at effective timestamp '{effective_ts}': {', '.join(justifications)}",
                    "schema_path": "/statements",
                    "severity": "warning",
                    "rule_id": "OPENVEX_SEMANTIC_CROSS_DUPLICATE_JUSTIFICATION",
                    "detail": f"Statement indices: {stmt_indices}"
                })



# ========================================================================
# 유틸리티 함수
# ========================================================================
def _has_nonempty_identifier_field(value: Any) -> bool:
    if isinstance(value, str):
        return len(value.strip()) > 0
    if isinstance(value, list) or isinstance(value, dict):
        return len(value) > 0
    return bool(value)

def _is_addressable_entity(entity: Dict[str, Any]) -> bool:
    return (
        _has_nonempty_identifier_field(entity.get("@id")) or
        _has_nonempty_identifier_field(entity.get("identifiers")) or
        _has_nonempty_identifier_field(entity.get("hashes"))
    )

def _validate_timestamp(value: Any, context: str) -> Dict[str, Any]:
    """타임스탬프 형식 검증 (ISO 8601)"""
    if not isinstance(value, str):
        return {
            "valid": False,
            "reason": f"{context} SHOULD be an ISO 8601 formatted string",
        }

    dt = _parse_datetime(value)
    if not dt:
        return {
            "valid": False,
            "reason": f"{context} SHOULD be in ISO 8601 date-time format (e.g., '2024-01-15T10:00:00Z')",
        }

    return {"valid": True, "reason": ""}


def _parse_datetime(value: str) -> datetime:
    """ISO 8601 형식 파싱"""
    formats = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%d"
    ]

    for fmt in formats:
        try:
            if fmt.endswith("Z"):
                test_value = value.replace("+00:00", "Z").replace("-00:00", "Z")
                return datetime.strptime(test_value.replace("Z", "+0000"), fmt.replace("Z", "%z")).replace(tzinfo=None)
            else:
                return datetime.strptime(value, fmt)
        except ValueError:
            continue

    return None


# ========================================================================
# 공개 검증 인터페이스
# ========================================================================

def validate_openvex(data: Dict[str, Any], schema: Dict[str, Any]) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    OpenVEX validation entry point.
    Runs schema validation first, then semantic validation.

    Returns:
        (is_valid, errors) - errors include severity and rule_id
    """
    errors = []

    # 1단계: 스키마 검증
    schema_ok = _run_schema_validation(data, schema, errors)

    # 2단계: 시맨틱 검증 (스키마 검증 후 실행)
    if schema_ok:
        _run_semantic_validation(data, errors)

    # 전체 유효성 판단 (error severity만 유효성에 영향)
    has_errors = any(e["severity"] == "error" for e in errors)
    return not has_errors, errors


# ========================================================================
# UI용 규칙 문서 (통합 네이밍)
# ========================================================================

VALIDATION_RULES = {
    "schema": [
        {"id": "SCHEMA_OPENVEX_001", "severity": "error",
         "desc": "[Schema] JSON Schema validation failed"},
    ],
    "must": [
        {"id": "OPENVEX_SEMANTIC_DOC_ID_NONEMPTY", "severity": "error",
         "desc": "[MUST] @id MUST NOT be empty"},
        {"id": "OPENVEX_SEMANTIC_DOC_VERSION_MINIMUM", "severity": "error",
         "desc": "[MUST] version MUST be >= 1"},
        {"id": "OPENVEX_SEMANTIC_DOC_AUTHOR_IDENTITY", "severity": "error",
         "desc": "[MUST] author MUST identify an individual or organization"},
        {"id": "OPENVEX_SEMANTIC_STMT_STATUS_NOTAFFECTED_JUSTIFICATION", "severity": "error",
         "desc": "[MUST] not_affected requires justification OR impact_statement"},
        {"id": "OPENVEX_SEMANTIC_STMT_JUSTIFICATION_INVALID_VALUE", "severity": "error",
         "desc": "[MUST] justification MUST be a valid OpenVEX justification label"},
        {"id": "OPENVEX_SEMANTIC_STMT_STATUS_AFFECTED_ACTION", "severity": "error",
         "desc": "[MUST] affected requires action_statement"},
        {"id": "OPENVEX_SEMANTIC_STMT_VULN_NAME_NONEMPTY", "severity": "error",
         "desc": "[MUST] vulnerability name MUST NOT be empty"},
        {"id": "OPENVEX_SEMANTIC_STMT_PROD_ADDRESSABLE", "severity": "error",
         "desc": "[MUST] Product MUST be addressable via @id, identifiers, or hashes"},
        {"id": "OPENVEX_SEMANTIC_STMT_COMPLETENESS", "severity": "error",
         "desc": "[MUST] Statement MUST have products, status, vulnerability, and timestamp (including via inheritance)"},
        {"id": "OPENVEX_SEMANTIC_STMT_SUBCOMP_ADDRESSABLE", "severity": "error",
         "desc": "[MUST] subcomponent MUST be addressable via @id, identifiers, or hashes"},
    ],
    "should": [
        {"id": "OPENVEX_SEMANTIC_CROSS_DUPLICATE_JUSTIFICATION", "severity": "warning",
         "desc": "[SHOULD] Conflicting justifications for same product+vulnerability at same effective timestamp should be avoided"},
        {"id": "OPENVEX_SEMANTIC_DOC_AUTHOR_MACHINE_READABLE", "severity": "warning",
         "desc": "[RECOMMENDED] author SHOULD use machine-readable identifier (IRI, email, URN)"},
        {"id": "OPENVEX_SEMANTIC_DOC_CONTEXT_FORMAT", "severity": "warning",
         "desc": "[SHOULD] @context SHOULD use OpenVEX namespace format for JSON-LD interoperability"},
        {"id": "OPENVEX_SEMANTIC_STMT_NOTAFFECTED_JUSTIFICATION_PREFERRED", "severity": "warning",
         "desc": "[SHOULD] not_affected SHOULD prefer standardized justification label over free-form impact_statement"},
        {"id": "OPENVEX_SEMANTIC_STMT_NOTAFFECTED_IMPACT_DETAIL", "severity": "warning",
         "desc": "[SHOULD] impact_statement recommended alongside justification for technical detail"},
        {"id": "OPENVEX_SEMANTIC_STMT_AFFECTED_ACTION_SPECIFIC", "severity": "warning",
         "desc": "[SHOULD] action_statement SHOULD describe specific mitigation steps"},
        {"id": "OPENVEX_SEMANTIC_STMT_PROD_PURL_FORMAT", "severity": "warning",
         "desc": "[RECOMMENDED] Product @id SHOULD use PURL format"},
        {"id": "OPENVEX_SEMANTIC_STMT_SUBCOMP_PURL_FORMAT", "severity": "warning",
         "desc": "[SHOULD] subcomponent @id SHOULD use PURL format"},
        {"id": "OPENVEX_SEMANTIC_STMT_VULN_CVE_RECOMMENDED", "severity": "warning",
         "desc": "[SHOULD] vulnerability name SHOULD use globally recognized ID (e.g., CVE)"},
        {"id": "OPENVEX_SEMANTIC_TS_DOC_FORMAT", "severity": "warning",
         "desc": "[SHOULD] document timestamp SHOULD be in ISO 8601 format"},
        {"id": "OPENVEX_SEMANTIC_TS_LASTUPDATED_FORMAT", "severity": "warning",
         "desc": "[SHOULD] last_updated SHOULD be in ISO 8601 format"},
        {"id": "OPENVEX_SEMANTIC_TS_STMT_FORMAT", "severity": "warning",
         "desc": "[SHOULD] statement timestamp SHOULD be in ISO 8601 format"},
    ]
}