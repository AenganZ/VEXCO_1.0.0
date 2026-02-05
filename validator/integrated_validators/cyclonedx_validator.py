#!/usr/bin/env python3
"""
CycloneDX Enhanced Validator v2.0
Complete implementation of all CycloneDX VEX business rules
"""

import json
import re
from jsonschema import Draft7Validator
from typing import Dict, Any, List, Tuple, Set
from datetime import datetime


def validate_cyclonedx(data: Dict[str, Any], schema: Dict[str, Any]) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Complete CycloneDX validation with all VEX business rules
    
    Returns:
        (is_valid, errors) - where errors include severity and rule_id
    """
    errors = []
    
    # ============ STEP 1: JSON Schema Validation ============
    try:
        validator = Draft7Validator(schema)
        validation_errors = sorted(validator.iter_errors(data), key=lambda e: e.path)
        
        for error in validation_errors:
            path = "/" + "/".join(str(p) for p in error.path) if error.path else "/"
            schema_path = "/" + "/".join(str(p) for p in error.schema_path) if error.schema_path else "/"
            
            errors.append({
                "path": path,
                "message": f"[Schema] {error.message}",
                "schema_path": schema_path,
                "severity": "error",
                "rule_id": "SCHEMA-001"
            })
    except Exception as e:
        errors.append({
            "path": "/",
            "message": f"[Schema] Validation failed: {str(e)}",
            "schema_path": "/",
            "severity": "error",
            "rule_id": "SCHEMA-000"
        })
        return False, errors
    
    # ============ STEP 2: CycloneDX VEX Business Rules ============
    
    # Document-level validations
    _validate_document_metadata(data, errors)
    
    # Deprecated fields validation
    _validate_deprecated_fields(data, errors)
    
    # Collect bom-refs for reference validation
    bom_refs = _collect_bom_refs(data)
    
    # CDX-BOMREF-DUP-001: Validate bom-ref uniqueness
    _validate_bomref_uniqueness(data, errors)
    
    # Validate vulnerabilities
    if "vulnerabilities" in data and isinstance(data["vulnerabilities"], list):
        for idx, vuln in enumerate(data["vulnerabilities"]):
            _validate_vulnerability(vuln, idx, bom_refs, errors)
    
    # Determine overall validity
    has_errors = any(e["severity"] == "error" for e in errors)
    return not has_errors, errors


def _validate_document_metadata(data: Dict[str, Any], errors: List[Dict[str, Any]]):
    """Validate CycloneDX document metadata requirements"""
    
    # CDX-FORMAT-001: bomFormat must be "CycloneDX"
    if "bomFormat" in data:
        if data["bomFormat"] != "CycloneDX":
            errors.append({
                "path": "/bomFormat",
                "message": "[VEX-CycloneDX] bomFormat MUST be 'CycloneDX'",
                "schema_path": "/bomFormat",
                "severity": "error",
                "rule_id": "CDX-FORMAT-001"
            })
    
    # CDX-VERSION-001: version must be >= 1
    if "version" in data:
        version = data["version"]
        if isinstance(version, int) and version < 1:
            errors.append({
                "path": "/version",
                "message": "[VEX-CycloneDX] version MUST be greater than or equal to 1",
                "schema_path": "/version",
                "severity": "error",
                "rule_id": "CDX-VERSION-001"
            })


def _validate_bomref_uniqueness(data: Dict[str, Any], errors: List[Dict[str, Any]]):
    """Validate that all bom-ref values are unique"""
    
    bomrefs = {}  # bom-ref -> path
    
    # Collect from components
    if "components" in data and isinstance(data["components"], list):
        for idx, comp in enumerate(data["components"]):
            if isinstance(comp, dict) and "bom-ref" in comp:
                ref = comp["bom-ref"]
                if ref in bomrefs:
                    errors.append({
                        "path": f"/components/{idx}/bom-ref",
                        "message": f"[VEX-CycloneDX] bom-ref '{ref}' appears multiple times (first at {bomrefs[ref]}) - all bom-refs MUST be unique",
                        "schema_path": f"/components/{idx}/bom-ref",
                        "severity": "error",
                        "rule_id": "CDX-BOMREF-DUP-001"
                    })
                else:
                    bomrefs[ref] = f"/components/{idx}"
    
    # Collect from services
    if "services" in data and isinstance(data["services"], list):
        for idx, svc in enumerate(data["services"]):
            if isinstance(svc, dict) and "bom-ref" in svc:
                ref = svc["bom-ref"]
                if ref in bomrefs:
                    errors.append({
                        "path": f"/services/{idx}/bom-ref",
                        "message": f"[VEX-CycloneDX] bom-ref '{ref}' appears multiple times (first at {bomrefs[ref]}) - all bom-refs MUST be unique",
                        "schema_path": f"/services/{idx}/bom-ref",
                        "severity": "error",
                        "rule_id": "CDX-BOMREF-DUP-001"
                    })
                else:
                    bomrefs[ref] = f"/services/{idx}"
    
    # Collect from metadata.component
    if "metadata" in data and isinstance(data["metadata"], dict):
        if "component" in data["metadata"] and isinstance(data["metadata"]["component"], dict):
            if "bom-ref" in data["metadata"]["component"]:
                ref = data["metadata"]["component"]["bom-ref"]
                if ref in bomrefs:
                    errors.append({
                        "path": "/metadata/component/bom-ref",
                        "message": f"[VEX-CycloneDX] bom-ref '{ref}' appears multiple times (first at {bomrefs[ref]}) - all bom-refs MUST be unique",
                        "schema_path": "/metadata/component/bom-ref",
                        "severity": "error",
                        "rule_id": "CDX-BOMREF-DUP-001"
                    })
                else:
                    bomrefs[ref] = "/metadata/component"


def _collect_bom_refs(data: Dict[str, Any]) -> Set[str]:
    """Collect all bom-ref values from components, services, etc."""
    refs = set()
    
    # From components
    if "components" in data and isinstance(data["components"], list):
        for comp in data["components"]:
            if isinstance(comp, dict) and "bom-ref" in comp:
                refs.add(comp["bom-ref"])
    
    # From services
    if "services" in data and isinstance(data["services"], list):
        for svc in data["services"]:
            if isinstance(svc, dict) and "bom-ref" in svc:
                refs.add(svc["bom-ref"])
    
    # From metadata.component
    if "metadata" in data and isinstance(data["metadata"], dict):
        if "component" in data["metadata"] and isinstance(data["metadata"]["component"], dict):
            if "bom-ref" in data["metadata"]["component"]:
                refs.add(data["metadata"]["component"]["bom-ref"])
    
    return refs


def _validate_deprecated_fields(data: Dict[str, Any], errors: List[Dict[str, Any]]):
    """Validate deprecated/legacy fields in CycloneDX 1.7"""
    
    # CDX-DEPRECATED-001: metadata.tools[] (legacy)
    if "metadata" in data and isinstance(data["metadata"], dict):
        if "tools" in data["metadata"]:
            tools = data["metadata"]["tools"]
            if isinstance(tools, list) and len(tools) > 0:
                errors.append({
                    "path": "/metadata/tools",
                    "message": "[VEX-CycloneDX] 'metadata.tools[]' is DEPRECATED in CycloneDX 1.7. Use 'metadata.tools' (object) with 'components' or 'services' arrays instead",
                    "schema_path": "/metadata/tools",
                    "severity": "warning",
                    "rule_id": "CDX-DEPRECATED-001"
                })
    
    # CDX-DEPRECATED-002: components[].modified
    if "components" in data and isinstance(data["components"], list):
        for idx, comp in enumerate(data["components"]):
            if isinstance(comp, dict) and "modified" in comp:
                errors.append({
                    "path": f"/components/{idx}/modified",
                    "message": "[VEX-CycloneDX] 'component.modified' is deprecated (still valid but not recommended). May be removed in future versions. Consider using 'component.pedigree' instead",
                    "schema_path": f"/components/{idx}/modified",
                    "severity": "warning",
                    "rule_id": "CDX-DEPRECATED-002"
                })
    
    # CDX-DEPRECATED-003: vulnerabilities[].tools[] (legacy)
    if "vulnerabilities" in data and isinstance(data["vulnerabilities"], list):
        for idx, vuln in enumerate(data["vulnerabilities"]):
            if isinstance(vuln, dict):
                if "tools" in vuln:
                    tools = vuln["tools"]
                    if isinstance(tools, list) and len(tools) > 0:
                        errors.append({
                            "path": f"/vulnerabilities/{idx}/tools",
                            "message": "[VEX-CycloneDX] 'vulnerability.tools[]' is DEPRECATED in CycloneDX 1.7. Use 'vulnerability.tools' (object) with 'components' or 'services' arrays instead",
                            "schema_path": f"/vulnerabilities/{idx}/tools",
                            "severity": "warning",
                            "rule_id": "CDX-DEPRECATED-003"
                        })
    
    # CDX-DEPRECATED-004: formulation[].components[].identities[] (deprecated)
    if "formulation" in data and isinstance(data["formulation"], list):
        for f_idx, formula in enumerate(data["formulation"]):
            if isinstance(formula, dict) and "components" in formula:
                components = formula["components"]
                if isinstance(components, list):
                    for c_idx, comp in enumerate(components):
                        if isinstance(comp, dict) and "identities" in comp:
                            errors.append({
                                "path": f"/formulation/{f_idx}/components/{c_idx}/identities",
                                "message": "[VEX-CycloneDX] 'identities' field is deprecated (still valid but not recommended). May be removed in future versions. Consider using 'evidence.identity' instead",
                                "schema_path": f"/formulation/{f_idx}/components/{c_idx}/identities",
                                "severity": "warning",
                                "rule_id": "CDX-DEPRECATED-004"
                            })
    
    # CDX-DEPRECATED-005: Check Tool objects (deprecated type)
    # Check in metadata.toolChoice
    if "metadata" in data and isinstance(data["metadata"], dict):
        if "toolChoice" in data["metadata"]:
            tool_choice = data["metadata"]["toolChoice"]
            if isinstance(tool_choice, dict):
                for tool_array_key in ["toolReferences", "toolChoice"]:
                    if tool_array_key in tool_choice:
                        tool_array = tool_choice[tool_array_key]
                        if isinstance(tool_array, list):
                            for t_idx, tool_item in enumerate(tool_array):
                                if isinstance(tool_item, dict):
                                    # Check if it's using deprecated 'tool' structure
                                    if "vendor" in tool_item and "name" in tool_item and "bom-ref" not in tool_item:
                                        errors.append({
                                            "path": f"/metadata/toolChoice/{tool_array_key}/{t_idx}",
                                            "message": "[VEX-CycloneDX] Deprecated 'tool' object structure (still valid but not recommended). Consider using 'component' or 'service' objects instead",
                                            "schema_path": f"/metadata/toolChoice/{tool_array_key}/{t_idx}",
                                            "severity": "warning",
                                            "rule_id": "CDX-DEPRECATED-005"
                                        })


def _validate_vulnerability(vuln: Dict[str, Any], idx: int, bom_refs: Set[str], errors: List[Dict[str, Any]]):
    """Validate CycloneDX vulnerability with all VEX business rules"""
    path_prefix = f"/vulnerabilities/{idx}"
    
    # CDX-ID-001: Vulnerability ID should be present
    if "id" not in vuln:
        errors.append({
            "path": path_prefix,
            "message": "[VEX-CycloneDX] vulnerability SHOULD have an 'id' field to identify the vulnerability (e.g., CVE-2024-1234)",
            "schema_path": f"{path_prefix}/id",
            "severity": "warning",
            "rule_id": "CDX-ID-001"
        })
    elif "id" in vuln:
        vuln_id = vuln["id"]
        if isinstance(vuln_id, str):
            if len(vuln_id.strip()) == 0:
                errors.append({
                    "path": f"{path_prefix}/id",
                    "message": "[VEX-CycloneDX] vulnerability id should not be empty",
                    "schema_path": f"{path_prefix}/id",
                    "severity": "error",
                    "rule_id": "CDX-ID-002"
                })
            elif not _is_valid_vuln_id(vuln_id):
                errors.append({
                    "path": f"{path_prefix}/id",
                    "message": f"[VEX-CycloneDX] vulnerability id '{vuln_id}' should follow standard format (CVE-YYYY-NNNNN, GHSA-xxxx-xxxx-xxxx, etc.)",
                    "schema_path": f"{path_prefix}/id",
                    "severity": "warning",
                    "rule_id": "CDX-ID-003"
                })
    
    # Validate analysis if present
    if "analysis" in vuln:
        analysis = vuln["analysis"]
        if isinstance(analysis, dict):
            _validate_analysis(analysis, path_prefix, errors)
    
    # CDX-REF-001: Validate affects array
    if "affects" in vuln:
        affects = vuln["affects"]
        if isinstance(affects, list):
            for aff_idx, affect in enumerate(affects):
                _validate_affect(affect, f"{path_prefix}/affects/{aff_idx}", bom_refs, errors)


def _validate_analysis(analysis: Dict[str, Any], vuln_path: str, errors: List[Dict[str, Any]]):
    """CDX-AN-STATE-001: Validate analysis object with VEX-specific rules"""
    analysis_path = f"{vuln_path}/analysis"
    
    state = analysis.get("state")
    
    # State-specific requirements
    if state == "not_affected":
        # SHOULD have justification (machine-readable)
        if "justification" not in analysis:
            errors.append({
                "path": analysis_path,
                "message": "[VEX-CycloneDX] analysis with state 'not_affected' SHOULD include 'justification' field (machine-readable reason)",
                "schema_path": f"{analysis_path}/state",
                "severity": "warning",
                "rule_id": "CDX-AN-STATE-001"
            })
        
        # SHOULD have detail (human-readable)
        if "detail" not in analysis:
            errors.append({
                "path": analysis_path,
                "message": "[VEX-CycloneDX] analysis with state 'not_affected' SHOULD include 'detail' field (human-readable explanation)",
                "schema_path": f"{analysis_path}/state",
                "severity": "warning",
                "rule_id": "CDX-AN-STATE-002"
            })
        elif "detail" in analysis:
            detail = analysis["detail"]
            if isinstance(detail, str) and len(detail.strip()) == 0:
                errors.append({
                    "path": f"{analysis_path}/detail",
                    "message": "[VEX-CycloneDX] detail field should provide meaningful explanation",
                    "schema_path": f"{analysis_path}/detail",
                    "severity": "warning",
                    "rule_id": "CDX-AN-STATE-003"
                })
    
    elif state == "exploitable":
        # SHOULD have response
        if "response" not in analysis:
            errors.append({
                "path": analysis_path,
                "message": "[VEX-CycloneDX] analysis with state 'exploitable' SHOULD include 'response' field describing remediation actions",
                "schema_path": f"{analysis_path}/state",
                "severity": "warning",
                "rule_id": "CDX-AN-STATE-004"
            })
        
        # SHOULD have detail about exploitability
        if "detail" not in analysis:
            errors.append({
                "path": analysis_path,
                "message": "[VEX-CycloneDX] analysis with state 'exploitable' SHOULD include 'detail' field describing exploitation scenario",
                "schema_path": f"{analysis_path}/state",
                "severity": "warning",
                "rule_id": "CDX-AN-STATE-005"
            })
    
    elif state == "in_triage":
        if "detail" not in analysis:
            errors.append({
                "path": analysis_path,
                "message": "[VEX-CycloneDX] analysis with state 'in_triage' SHOULD include 'detail' field describing investigation status",
                "schema_path": f"{analysis_path}/state",
                "severity": "warning",
                "rule_id": "CDX-AN-STATE-006"
            })
    
    elif state == "false_positive":
        if "detail" not in analysis:
            errors.append({
                "path": analysis_path,
                "message": "[VEX-CycloneDX] analysis with state 'false_positive' SHOULD include 'detail' field explaining why it's a false positive",
                "schema_path": f"{analysis_path}/state",
                "severity": "warning",
                "rule_id": "CDX-AN-STATE-007"
            })
    
    # CDX-JUST-VAL-001: Validate justification values
    if "justification" in analysis:
        justification = analysis["justification"]
        valid_justifications = {
            "code_not_present",
            "code_not_reachable",
            "requires_configuration",
            "requires_dependency",
            "requires_environment",
            "protected_by_compiler",
            "protected_at_runtime",
            "protected_at_perimeter",
            "protected_by_mitigating_control"
        }
        
        if justification not in valid_justifications:
            errors.append({
                "path": f"{analysis_path}/justification",
                "message": f"[VEX-CycloneDX] Invalid justification value '{justification}'. Must be one of: {', '.join(sorted(valid_justifications))}",
                "schema_path": f"{analysis_path}/justification",
                "severity": "error",
                "rule_id": "CDX-JUST-VAL-001"
            })
    
    # CDX-RESP-VAL-001: Validate response values
    if "response" in analysis:
        responses = analysis["response"]
        if isinstance(responses, list):
            valid_responses = {
                "can_not_fix",
                "will_not_fix",
                "update",
                "rollback",
                "workaround_available"
            }
            
            for resp_idx, response in enumerate(responses):
                if response not in valid_responses:
                    errors.append({
                        "path": f"{analysis_path}/response/{resp_idx}",
                        "message": f"[VEX-CycloneDX] Invalid response value '{response}'. Must be one of: {', '.join(sorted(valid_responses))}",
                        "schema_path": f"{analysis_path}/response",
                        "severity": "error",
                        "rule_id": "CDX-RESP-VAL-001"
                    })
    
    # CDX-TIMESTAMP-001: Validate timestamp logic
    if "firstIssued" in analysis:
        fi_result = _validate_timestamp(analysis["firstIssued"], "firstIssued")
        if not fi_result["valid"]:
            errors.append({
                "path": f"{analysis_path}/firstIssued",
                "message": f"[VEX-CycloneDX] {fi_result['reason']}",
                "schema_path": f"{analysis_path}/firstIssued",
                "severity": fi_result["severity"],
                "rule_id": "CDX-TIMESTAMP-001"
            })
    
    if "lastUpdated" in analysis:
        lu_result = _validate_timestamp(analysis["lastUpdated"], "lastUpdated")
        if not lu_result["valid"]:
            errors.append({
                "path": f"{analysis_path}/lastUpdated",
                "message": f"[VEX-CycloneDX] {lu_result['reason']}",
                "schema_path": f"{analysis_path}/lastUpdated",
                "severity": lu_result["severity"],
                "rule_id": "CDX-TIMESTAMP-002"
            })
        
        # Check firstIssued < lastUpdated
        if "firstIssued" in analysis:
            try:
                fi = _parse_datetime(analysis["firstIssued"])
                lu = _parse_datetime(analysis["lastUpdated"])
                if fi and lu and lu < fi:
                    errors.append({
                        "path": f"{analysis_path}/lastUpdated",
                        "message": "[VEX-CycloneDX] lastUpdated cannot be earlier than firstIssued",
                        "schema_path": f"{analysis_path}/lastUpdated",
                        "severity": "warning",
                        "rule_id": "CDX-TIMESTAMP-003"
                    })
            except:
                pass


def _validate_affect(affect: Dict[str, Any], path: str, bom_refs: Set[str], errors: List[Dict[str, Any]]):
    """CDX-REF-001 & CDX-VERSIONS-001: Validate affects entry"""
    
    # CDX-REF-001: ref must point to valid bom-ref
    if "ref" not in affect:
        errors.append({
            "path": path,
            "message": "[VEX-CycloneDX] affect entry MUST have 'ref' field to identify the affected component",
            "schema_path": f"{path}/ref",
            "severity": "error",
            "rule_id": "CDX-REF-001"
        })
    elif "ref" in affect:
        ref = affect["ref"]
        if isinstance(ref, str):
            if len(ref.strip()) == 0:
                errors.append({
                    "path": f"{path}/ref",
                    "message": "[VEX-CycloneDX] ref should not be empty",
                    "schema_path": f"{path}/ref",
                    "severity": "error",
                    "rule_id": "CDX-REF-002"
                })
            elif ref not in bom_refs:
                errors.append({
                    "path": f"{path}/ref",
                    "message": f"[VEX-CycloneDX] ref '{ref}' does not match any component bom-ref in this BOM. Referenced component must exist in components[], services[], or metadata.component.",
                    "schema_path": f"{path}/ref",
                    "severity": "error",
                    "rule_id": "CDX-REF-003"
                })
    
    # CDX-VERSIONS-001: Validate versions array
    if "versions" in affect and isinstance(affect["versions"], list):
        for ver_idx, version in enumerate(affect["versions"]):
            if isinstance(version, dict):
                has_version = "version" in version
                has_range = "range" in version
                
                if not has_version and not has_range:
                    errors.append({
                        "path": f"{path}/versions/{ver_idx}",
                        "message": "[VEX-CycloneDX] version entry MUST have either 'version' (single version) or 'range' (version range)",
                        "schema_path": f"{path}/versions/{ver_idx}",
                        "severity": "error",
                        "rule_id": "CDX-VERSIONS-001"
                    })


def _validate_timestamp(value: Any, context: str) -> Dict[str, Any]:
    """Validate timestamp format and logic"""
    
    if not isinstance(value, str):
        return {
            "valid": False,
            "reason": f"{context} must be a string in ISO 8601 format",
            "severity": "error"
        }
    
    dt = _parse_datetime(value)
    if not dt:
        return {
            "valid": False,
            "reason": f"{context} must be in ISO 8601 date-time format",
            "severity": "error"
        }
    
    # Future date check removed - not part of official CycloneDX 1.7 spec
    return {"valid": True}


def _parse_datetime(value: str) -> datetime:
    """Parse ISO 8601 datetime"""
    formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
    ]
    
    test_value = value.replace("+00:00", "Z")
    
    for fmt in formats:
        try:
            if "Z" in fmt:
                return datetime.strptime(test_value.replace("Z", "+0000"), fmt.replace("Z", "%z")).replace(tzinfo=None)
            else:
                return datetime.strptime(test_value, fmt)
        except ValueError:
            continue
    
    return None


def _is_valid_vuln_id(vuln_id: str) -> bool:
    """Check if vulnerability ID follows standard patterns"""
    patterns = [
        r'^CVE-\d{4}-\d{4,}$',
        r'^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$',
        r'^PYSEC-\d{4}-\d+$',
        r'^RUSTSEC-\d{4}-\d+$',
        r'^OSV-\d{4}-\d+$',
        r'^GO-\d{4}-\d+$',
    ]
    
    return any(re.match(pattern, vuln_id, re.IGNORECASE) for pattern in patterns)


def load_schema(schema_path: str) -> Dict[str, Any]:
    """Load JSON schema from file"""
    with open(schema_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def load_document(doc_path: str) -> Dict[str, Any]:
    """Load JSON document from file"""
    with open(doc_path, 'r', encoding='utf-8') as f:
        return json.load(f)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 3:
        print("Usage: python cyclonedx_validator.py <schema.json> <document.json>")
        sys.exit(1)
    
    schema = load_schema(sys.argv[1])
    document = load_document(sys.argv[2])
    
    is_valid, errors = validate_cyclonedx(document, schema)
    
    if is_valid:
        print("✓ Valid CycloneDX document")
        print("  - JSON Schema: ✓")
        print("  - CycloneDX VEX Rules: ✓")
    else:
        error_items = [e for e in errors if e["severity"] == "error"]
        warning_items = [e for e in errors if e["severity"] == "warning"]
        
        print(f"✗ Invalid CycloneDX document")
        if error_items:
            print(f"\n  Errors ({len(error_items)}):")
            for error in error_items:
                print(f"    [{error['rule_id']}] {error['path']}")
                print(f"      {error['message']}")
        
        if warning_items:
            print(f"\n  Warnings ({len(warning_items)}):")
            for warning in warning_items:
                print(f"    [{warning['rule_id']}] {warning['path']}")
                print(f"      {warning['message']}")
    
    sys.exit(0 if is_valid else 1)