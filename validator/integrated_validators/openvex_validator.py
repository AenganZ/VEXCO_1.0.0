#!/usr/bin/env python3
"""
OpenVEX Validator v1.0.0
OpenVEX 명세 v0.2.0 기반 검증기
https://github.com/openvex/spec
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


def validate_openvex(data: Dict[str, Any], schema: Dict[str, Any]) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    OpenVEX 명세 v0.2.0 기반 검증
    
    Returns:
        (is_valid, errors) - errors에는 severity와 rule_id 포함
    """
    errors = []
    
    # ========================================
    # 1단계: JSON Schema 검증 (MUST)
    # ========================================
    if schema and HAS_JSONSCHEMA:
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
                    "rule_id": "SCHEMA-OVX-001"
                })
        except Exception as e:
            errors.append({
                "path": "/",
                "message": f"Schema validation error: {str(e)}",
                "schema_path": "/",
                "severity": "error",
                "rule_id": "SCHEMA-OVX-000"
            })
            return False, errors
    
    # ========================================
    # 2단계: OpenVEX 명세 규칙 검증
    # ========================================
    
    # 문서 수준 검증
    _validate_document_fields(data, errors)
    
    # Statement 수준 검증
    if "statements" in data and isinstance(data["statements"], list):
        for idx, statement in enumerate(data["statements"]):
            _validate_statement(statement, idx, errors)
        
        # OVX-JUST-DUP-001: 동일 제품에 대해 중복된 justification 체크 (MUST)
        _validate_no_duplicate_justifications(data["statements"], errors)
    
    # 전체 유효성 판단 (error가 없으면 valid)
    has_errors = any(e["severity"] == "error" for e in errors)
    return not has_errors, errors


def _validate_document_fields(data: Dict[str, Any], errors: List[Dict[str, Any]]):
    """
    문서 수준 OpenVEX 요구사항 검증
    
    명세 참조 - Document 필드:
    - @context: 필수 - OpenVEX 컨텍스트 URL
    - @id: 필수 - VEX 문서 식별 IRI
    - author: 필수 - 작성자 식별자
    - timestamp: 필수 - 문서 발행 시각
    - version: 필수 - 문서 버전 (변경 시 증가)
    - statements: 필수 - Statement 목록
    """
    
    # OVX-CTX-001: @context 형식 검증 (MUST)
    if "@context" in data:
        context = data["@context"]
        if not isinstance(context, str) or not context.startswith("https://openvex.dev/ns/"):
            errors.append({
                "path": "/@context",
                "message": "@context MUST start with 'https://openvex.dev/ns/' (e.g., 'https://openvex.dev/ns/v0.2.0')",
                "schema_path": "/@context",
                "severity": "error",
                "rule_id": "OVX-CTX-001"
            })
    
    # OVX-ID-001: @id는 비어있으면 안 됨 (MUST)
    if "@id" in data:
        doc_id = data["@id"]
        if isinstance(doc_id, str) and len(doc_id.strip()) == 0:
            errors.append({
                "path": "/@id",
                "message": "@id MUST NOT be empty",
                "schema_path": "/@id",
                "severity": "error",
                "rule_id": "OVX-ID-001"
            })
    
    # OVX-TS-001: timestamp 형식 검증 (SHOULD - 스펙에 형식 MUST 명시 없음)
    if "timestamp" in data:
        ts_result = _validate_timestamp(data["timestamp"], "document timestamp")
        if not ts_result["valid"]:
            errors.append({
                "path": "/timestamp",
                "message": ts_result['reason'],
                "schema_path": "/timestamp",
                "severity": ts_result["severity"],
                "rule_id": "OVX-TS-001"
            })
    
    # OVX-TS-002: last_updated 형식 검증 (선택 필드)
    if "last_updated" in data:
        lu_result = _validate_timestamp(data["last_updated"], "last_updated")
        if not lu_result["valid"]:
            errors.append({
                "path": "/last_updated",
                "message": lu_result['reason'],
                "schema_path": "/last_updated",
                "severity": lu_result["severity"],
                "rule_id": "OVX-TS-002"
            })
    
    # OVX-VER-001: version은 1 이상 (MUST)
    if "version" in data:
        version = data["version"]
        if isinstance(version, int) and version < 1:
            errors.append({
                "path": "/version",
                "message": "version MUST be >= 1",
                "schema_path": "/version",
                "severity": "error",
                "rule_id": "OVX-VER-001"
            })


def _validate_statement(statement: Dict[str, Any], idx: int, errors: List[Dict[str, Any]]):
    """
    개별 OpenVEX Statement 검증
    
    명세 참조 - Statement 필드:
    - vulnerability: 필수
    - status: 필수 - not_affected, affected, fixed, under_investigation 중 하나
    - justification: not_affected일 때 필수 (또는 impact_statement)
    - impact_statement: not_affected일 때 필수 (또는 justification)
    - action_statement: affected일 때 필수
    """
    path_prefix = f"/statements/{idx}"
    status = statement.get("status")
    
    # ========================================
    # status별 MUST 규칙
    # ========================================
    
    # OVX-STATE-001: not_affected는 justification OR impact_statement 필수 (MUST)
    if status == "not_affected":
        has_justification = "justification" in statement
        has_impact = "impact_statement" in statement
        
        if not has_justification and not has_impact:
            errors.append({
                "path": path_prefix,
                "message": "status 'not_affected' MUST have either 'justification' or 'impact_statement'",
                "schema_path": f"{path_prefix}/status",
                "severity": "error",
                "rule_id": "OVX-STATE-001"
            })
        
        # OVX-SHOULD-001: justification 있을 때 impact_statement도 권장 (SHOULD)
        if has_justification and not has_impact:
            errors.append({
                "path": f"{path_prefix}/impact_statement",
                "message": "Including 'impact_statement' with 'justification' provides additional technical details",
                "schema_path": f"{path_prefix}/impact_statement",
                "severity": "warning",
                "rule_id": "OVX-SHOULD-001"
            })
    
    # OVX-STATE-002: affected는 action_statement 필수 (MUST)
    elif status == "affected":
        if "action_statement" not in statement:
            errors.append({
                "path": path_prefix,
                "message": "status 'affected' MUST have 'action_statement'",
                "schema_path": f"{path_prefix}/status",
                "severity": "error",
                "rule_id": "OVX-STATE-002"
            })
    
    # OVX-STATUS-001: status 값 검증 (MUST)
    if status:
        valid_statuses = {"not_affected", "affected", "fixed", "under_investigation"}
        if status not in valid_statuses:
            errors.append({
                "path": f"{path_prefix}/status",
                "message": f"Invalid status value '{status}'. Allowed values: {', '.join(sorted(valid_statuses))}",
                "schema_path": f"{path_prefix}/status",
                "severity": "error",
                "rule_id": "OVX-STATUS-001"
            })
    
    # ========================================
    # vulnerability 검증
    # ========================================
    
    # OVX-VULN-001: vulnerability에 name 필수 (MUST)
    if "vulnerability" in statement:
        vuln = statement["vulnerability"]
        if isinstance(vuln, dict):
            if "name" not in vuln:
                errors.append({
                    "path": f"{path_prefix}/vulnerability",
                    "message": "vulnerability MUST have 'name' field",
                    "schema_path": f"{path_prefix}/vulnerability/name",
                    "severity": "error",
                    "rule_id": "OVX-VULN-001"
                })
            elif "name" in vuln:
                name = vuln["name"]
                if isinstance(name, str) and len(name.strip()) == 0:
                    errors.append({
                        "path": f"{path_prefix}/vulnerability/name",
                        "message": "vulnerability name MUST NOT be empty",
                        "schema_path": f"{path_prefix}/vulnerability/name",
                        "severity": "error",
                        "rule_id": "OVX-VULN-002"
                    })
    
    # ========================================
    # products 검증
    # ========================================
    
    if "products" in statement and isinstance(statement["products"], list):
        for prod_idx, product in enumerate(statement["products"]):
            if isinstance(product, dict):
                prod_path = f"{path_prefix}/products/{prod_idx}"
                
                # OVX-PROD-001: Product에 @id 필수 (MUST)
                if "@id" not in product:
                    errors.append({
                        "path": prod_path,
                        "message": "Product MUST have '@id' field",
                        "schema_path": f"{prod_path}/@id",
                        "severity": "error",
                        "rule_id": "OVX-PROD-001"
                    })
                else:
                    prod_id = product["@id"]
                    
                    # OVX-PROD-002: @id 비어있으면 안 됨 (MUST)
                    if isinstance(prod_id, str) and len(prod_id.strip()) == 0:
                        errors.append({
                            "path": f"{prod_path}/@id",
                            "message": "Product @id MUST NOT be empty",
                            "schema_path": f"{prod_path}/@id",
                            "severity": "error",
                            "rule_id": "OVX-PROD-002"
                        })
                    
                    # OVX-SHOULD-002: PURL 사용 권장 (SHOULD)
                    elif isinstance(prod_id, str) and not PURL_PATTERN.match(prod_id):
                        errors.append({
                            "path": f"{prod_path}/@id",
                            "message": "Product @id SHOULD use Package URL (PURL) format (e.g., pkg:npm/express@4.18.0)",
                            "schema_path": f"{prod_path}/@id",
                            "severity": "warning",
                            "rule_id": "OVX-SHOULD-002"
                        })
                
                # ========================================
                # subcomponents 검증 (SHOULD)
                # ========================================
                
                if "subcomponents" in product and isinstance(product["subcomponents"], list):
                    for sub_idx, subcomp in enumerate(product["subcomponents"]):
                        if isinstance(subcomp, dict):
                            sub_path = f"{prod_path}/subcomponents/{sub_idx}"
                            
                            # OVX-SUB-001: subcomponent에 @id 필수 (MUST)
                            if "@id" not in subcomp:
                                errors.append({
                                    "path": sub_path,
                                    "message": "subcomponent MUST have '@id' field",
                                    "schema_path": f"{sub_path}/@id",
                                    "severity": "error",
                                    "rule_id": "OVX-SUB-001"
                                })
                            else:
                                sub_id = subcomp["@id"]
                                
                                # OVX-SHOULD-003: subcomponent에도 PURL 권장 (SHOULD)
                                if isinstance(sub_id, str) and not PURL_PATTERN.match(sub_id):
                                    errors.append({
                                        "path": f"{sub_path}/@id",
                                        "message": "subcomponent @id SHOULD use PURL format",
                                        "schema_path": f"{sub_path}/@id",
                                        "severity": "warning",
                                        "rule_id": "OVX-SHOULD-003"
                                    })
    
    # OVX-TS-003: Statement timestamp 형식 (선택 필드)
    if "timestamp" in statement:
        ts_result = _validate_timestamp(statement["timestamp"], "statement timestamp")
        if not ts_result["valid"]:
            errors.append({
                "path": f"{path_prefix}/timestamp",
                "message": ts_result['reason'],
                "schema_path": f"{path_prefix}/timestamp",
                "severity": ts_result["severity"],
                "rule_id": "OVX-TS-003"
            })


def _validate_timestamp(value: Any, context: str) -> Dict[str, Any]:
    """타임스탬프 형식 검증 (ISO 8601) - SHOULD 규칙 (스펙에 형식 MUST 명시 없음)"""
    
    if not isinstance(value, str):
        return {
            "valid": False,
            "reason": f"{context} SHOULD be an ISO 8601 formatted string",
            "severity": "warning"
        }
    
    dt = _parse_datetime(value)
    if not dt:
        return {
            "valid": False,
            "reason": f"{context} SHOULD be in ISO 8601 date-time format (e.g., '2024-01-15T10:00:00Z')",
            "severity": "warning"
        }
    
    return {"valid": True, "reason": "", "severity": ""}


def _validate_no_duplicate_justifications(statements: List[Dict[str, Any]], errors: List[Dict[str, Any]]):
    """
    동일 제품에 대해 중복된 justification이 존재하는지 검증 (MUST)
    
    동일한 제품(@id)에 대해 서로 다른 justification이 있으면 안 됨.
    예: openssl-1.0.1f에 대해 component_not_present와 vulnerable_code_not_present가 동시에 존재하면 오류
    """
    from typing import Dict, Set, List
    
    # product_id -> [(statement_idx, justification)] 매핑
    product_justifications: Dict[str, List[tuple]] = {}
    
    for stmt_idx, statement in enumerate(statements):
        status = statement.get("status")
        justification = statement.get("justification")
        
        # not_affected 상태이고 justification이 있는 경우만 검사
        if status != "not_affected" or not justification:
            continue
        
        # products에서 제품 ID 수집
        products = statement.get("products", [])
        for product in products:
            if isinstance(product, dict):
                prod_id = product.get("@id", "")
                if prod_id:
                    if prod_id not in product_justifications:
                        product_justifications[prod_id] = []
                    product_justifications[prod_id].append((stmt_idx, justification))
                
                # subcomponents도 확인
                subcomponents = product.get("subcomponents", [])
                for subcomp in subcomponents:
                    if isinstance(subcomp, dict):
                        sub_id = subcomp.get("@id", "")
                        if sub_id:
                            if sub_id not in product_justifications:
                                product_justifications[sub_id] = []
                            product_justifications[sub_id].append((stmt_idx, justification))
    
    # 동일 제품에 대해 서로 다른 justification이 있는지 검사
    for prod_id, just_list in product_justifications.items():
        if len(just_list) > 1:
            # 서로 다른 justification이 있는지 확인
            unique_justifications = set(j for _, j in just_list)
            if len(unique_justifications) > 1:
                stmt_indices = [idx for idx, _ in just_list]
                justifications = list(unique_justifications)
                errors.append({
                    "path": "/statements",
                    "message": f"Product '{prod_id}' has multiple different justifications: {', '.join(justifications)}",
                    "schema_path": "/statements",
                    "severity": "error",
                    "rule_id": "OVX-JUST-DUP-001",
                    "detail": f"Statement indices: {stmt_indices}"
                })


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


# ========================================
# UI용 규칙 문서
# ========================================

VALIDATION_RULES = {
    'must': [
        {'id': 'SCHEMA-OVX-001', 'severity': 'error', 'desc': '[MUST] JSON Schema validation failed'},
        {'id': 'OVX-CTX-001', 'severity': 'error', 'desc': '[MUST] @context must start with https://openvex.dev/ns/'},
        {'id': 'OVX-ID-001', 'severity': 'error', 'desc': '[MUST] @id cannot be empty'},
        {'id': 'OVX-VER-001', 'severity': 'error', 'desc': '[MUST] version must be >= 1'},
        {'id': 'OVX-STATE-001', 'severity': 'error', 'desc': '[MUST] not_affected requires justification or impact_statement'},
        {'id': 'OVX-STATE-002', 'severity': 'error', 'desc': '[MUST] affected requires action_statement'},
        {'id': 'OVX-STATUS-001', 'severity': 'error', 'desc': '[MUST] status must be a valid value'},
        {'id': 'OVX-VULN-001', 'severity': 'error', 'desc': '[MUST] vulnerability requires name field'},
        {'id': 'OVX-VULN-002', 'severity': 'error', 'desc': '[MUST] vulnerability name cannot be empty'},
        {'id': 'OVX-PROD-001', 'severity': 'error', 'desc': '[MUST] Product requires @id field'},
        {'id': 'OVX-PROD-002', 'severity': 'error', 'desc': '[MUST] Product @id cannot be empty'},
        {'id': 'OVX-SUB-001', 'severity': 'error', 'desc': '[MUST] subcomponent requires @id field'},
        {'id': 'OVX-JUST-DUP-001', 'severity': 'error', 'desc': '[MUST] Same product cannot have multiple different justifications'},
    ],
    'should': [
        {'id': 'OVX-TS-001', 'severity': 'warning', 'desc': '[SHOULD] timestamp should be in ISO 8601 format'},
        {'id': 'OVX-TS-002', 'severity': 'warning', 'desc': '[SHOULD] last_updated should be in ISO 8601 format'},
        {'id': 'OVX-TS-003', 'severity': 'warning', 'desc': '[SHOULD] statement timestamp should be in ISO 8601 format'},
        {'id': 'OVX-SHOULD-001', 'severity': 'warning', 'desc': '[SHOULD] impact_statement recommended with justification'},
        {'id': 'OVX-SHOULD-002', 'severity': 'warning', 'desc': '[SHOULD] Product @id should use PURL format'},
        {'id': 'OVX-SHOULD-003', 'severity': 'warning', 'desc': '[SHOULD] subcomponent @id should use PURL format'},
    ]
}