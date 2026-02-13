#!/usr/bin/env python3
"""
CycloneDX Validator v2.1
Based on CycloneDX Specification v1.7
https://cyclonedx.org/docs/1.7/json/

Only validates rules explicitly stated in the official specification.
"""

import json
import re
from jsonschema import Draft7Validator
from typing import Dict, Any, List, Tuple, Set
from datetime import datetime


def validate_cyclonedx(data: Dict[str, Any], schema: Dict[str, Any]) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    CycloneDX validation based on official specification v1.7
    
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
    
    # ============ STEP 2: CycloneDX Specification Rules ============
    # Reference: https://cyclonedx.org/docs/1.7/json/
    
    # Document-level validations
    _validate_document_metadata(data, errors)
    
    # Deprecated fields validation
    _validate_deprecated_fields(data, errors)
    
    # Collect bom-refs for reference validation
    bom_refs = _collect_bom_refs(data)
    
    # CDX-BOMREF-DUP-001: Validate bom-ref uniqueness
    # Spec: "Every bom-ref must be unique within the BOM"
    _validate_bomref_uniqueness(data, errors)
    
    # Validate vulnerabilities
    if "vulnerabilities" in data and isinstance(data["vulnerabilities"], list):
        for idx, vuln in enumerate(data["vulnerabilities"]):
            _validate_vulnerability(vuln, idx, bom_refs, errors)
    
    # Determine overall validity
    has_errors = any(e["severity"] == "error" for e in errors)
    return not has_errors, errors


def _validate_document_metadata(data: Dict[str, Any], errors: List[Dict[str, Any]]):
    """
    Validate CycloneDX document metadata requirements
    
    Spec Reference:
    - bomFormat: MUST be "CycloneDX"
    - version: Value must be greater or equal to 1
    """
    
    # CDX-FORMAT-001: bomFormat must be "CycloneDX"
    # Spec: "This value must be 'CycloneDX'"
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
    # Spec: "Value must be greater or equal to 1"
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
    """
    Validate that all bom-ref values are unique
    
    Spec: "Every bom-ref must be unique within the BOM"
    """
    
    bomrefs = {}  # bom-ref -> path
    
    # Collect from components
    if "components" in data and isinstance(data["components"], list):
        _collect_bomrefs_recursive(data["components"], "/components", bomrefs, errors)
    
    # Collect from services
    if "services" in data and isinstance(data["services"], list):
        for idx, svc in enumerate(data["services"]):
            if isinstance(svc, dict) and "bom-ref" in svc:
                ref = svc["bom-ref"]
                if ref in bomrefs:
                    errors.append({
                        "path": f"/services/{idx}/bom-ref",
                        "message": f"[VEX-CycloneDX] bom-ref '{ref}' is duplicated (first at {bomrefs[ref]}) - all bom-refs MUST be unique",
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
                        "message": f"[VEX-CycloneDX] bom-ref '{ref}' is duplicated (first at {bomrefs[ref]}) - all bom-refs MUST be unique",
                        "schema_path": "/metadata/component/bom-ref",
                        "severity": "error",
                        "rule_id": "CDX-BOMREF-DUP-001"
                    })
                else:
                    bomrefs[ref] = "/metadata/component"


def _collect_bomrefs_recursive(components: List, path_prefix: str, bomrefs: Dict, errors: List):
    """Recursively collect bom-refs from nested components"""
    for idx, comp in enumerate(components):
        if isinstance(comp, dict):
            if "bom-ref" in comp:
                ref = comp["bom-ref"]
                current_path = f"{path_prefix}/{idx}"
                if ref in bomrefs:
                    errors.append({
                        "path": f"{current_path}/bom-ref",
                        "message": f"[VEX-CycloneDX] bom-ref '{ref}' is duplicated (first at {bomrefs[ref]}) - all bom-refs MUST be unique",
                        "schema_path": f"{current_path}/bom-ref",
                        "severity": "error",
                        "rule_id": "CDX-BOMREF-DUP-001"
                    })
                else:
                    bomrefs[ref] = current_path
            
            # Check nested components
            if "components" in comp and isinstance(comp["components"], list):
                _collect_bomrefs_recursive(comp["components"], f"{path_prefix}/{idx}/components", bomrefs, errors)


def _collect_bom_refs(data: Dict[str, Any]) -> Set[str]:
    """Collect all bom-ref values from components, services, etc."""
    refs = set()
    
    def collect_from_components(components: List):
        for comp in components:
            if isinstance(comp, dict):
                if "bom-ref" in comp:
                    refs.add(comp["bom-ref"])
                if "components" in comp and isinstance(comp["components"], list):
                    collect_from_components(comp["components"])
    
    # From components
    if "components" in data and isinstance(data["components"], list):
        collect_from_components(data["components"])
    
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
    """
    Validate deprecated/legacy fields in CycloneDX 1.7
    
    Spec Reference: "Tools (legacy) Deprecated"
    """
    
    # CDX-DEPRECATED-001: metadata.tools[] (legacy)
    # Spec: "Tools (legacy) Deprecated"
    if "metadata" in data and isinstance(data["metadata"], dict):
        if "tools" in data["metadata"]:
            tools = data["metadata"]["tools"]
            if isinstance(tools, list) and len(tools) > 0:
                errors.append({
                    "path": "/metadata/tools",
                    "message": "[VEX-CycloneDX] 'metadata.tools[]' array format is DEPRECATED in CycloneDX 1.7. Use 'metadata.tools' object with 'components' or 'services' arrays instead",
                    "schema_path": "/metadata/tools",
                    "severity": "warning",
                    "rule_id": "CDX-DEPRECATED-001"
                })


def _validate_vulnerability(vuln: Dict[str, Any], idx: int, bom_refs: Set[str], errors: List[Dict[str, Any]]):
    """
    Validate CycloneDX vulnerability with specification rules
    
    Spec Reference - analysis:
    - state: enum values defined
    - justification: enum values defined, "should be specified for all not_affected cases"
    - response: enum values defined
    """
    path_prefix = f"/vulnerabilities/{idx}"
    
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
    """
    Validate analysis object with specification rules
    
    Spec Reference:
    - state: Must be one of the defined enum values
    - justification: Must be one of the defined enum values
    - response: Must be one of the defined enum values
    - not_affected: "Justification should be specified for all not_affected cases" (SHOULD)
    """
    analysis_path = f"{vuln_path}/analysis"
    
    state = analysis.get("state")
    
    # CDX-STATE-VAL-001: Validate state values
    # Spec: enum values defined in specification
    if state:
        valid_states = {
            "resolved",
            "resolved_with_pedigree",
            "exploitable",
            "in_triage",
            "false_positive",
            "not_affected"
        }
        
        if state not in valid_states:
            errors.append({
                "path": f"{analysis_path}/state",
                "message": f"[VEX-CycloneDX] Invalid state value '{state}'. Must be one of: {', '.join(sorted(valid_states))}",
                "schema_path": f"{analysis_path}/state",
                "severity": "error",
                "rule_id": "CDX-STATE-VAL-001"
            })
    
    # CDX-JUST-SHOULD-001: not_affected SHOULD have justification
    # Spec: "Justification should be specified for all not_affected cases"
    if state == "not_affected":
        if "justification" not in analysis:
            errors.append({
                "path": analysis_path,
                "message": "[VEX-CycloneDX] analysis with state 'not_affected' SHOULD include 'justification' field",
                "schema_path": f"{analysis_path}/state",
                "severity": "warning",
                "rule_id": "CDX-JUST-SHOULD-001"
            })
    
    # CDX-JUST-VAL-001: Validate justification values
    # Spec: enum values defined in specification
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
    # Spec: enum values defined in specification
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
    
    # CDX-TS-001: Validate timestamp format
    if "firstIssued" in analysis:
        fi_result = _validate_timestamp(analysis["firstIssued"], "firstIssued")
        if not fi_result["valid"]:
            errors.append({
                "path": f"{analysis_path}/firstIssued",
                "message": f"[VEX-CycloneDX] {fi_result['reason']}",
                "schema_path": f"{analysis_path}/firstIssued",
                "severity": fi_result["severity"],
                "rule_id": "CDX-TS-001"
            })
    
    if "lastUpdated" in analysis:
        lu_result = _validate_timestamp(analysis["lastUpdated"], "lastUpdated")
        if not lu_result["valid"]:
            errors.append({
                "path": f"{analysis_path}/lastUpdated",
                "message": f"[VEX-CycloneDX] {lu_result['reason']}",
                "schema_path": f"{analysis_path}/lastUpdated",
                "severity": lu_result["severity"],
                "rule_id": "CDX-TS-002"
            })


def _validate_affect(affect: Dict[str, Any], path: str, bom_refs: Set[str], errors: List[Dict[str, Any]]):
    """
    Validate affects entry
    
    Spec Reference:
    - ref: References a component or service by bom-ref (required)
    - versions: Must have either 'version' or 'range'
    """
    
    # CDX-REF-001: ref must be present
    # Spec: "References a component or service by the objects bom-ref"
    if "ref" not in affect:
        errors.append({
            "path": path,
            "message": "[VEX-CycloneDX] affect entry MUST have 'ref' field",
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
                    "message": "[VEX-CycloneDX] ref MUST NOT be empty",
                    "schema_path": f"{path}/ref",
                    "severity": "error",
                    "rule_id": "CDX-REF-002"
                })
            elif ref not in bom_refs:
                errors.append({
                    "path": f"{path}/ref",
                    "message": f"[VEX-CycloneDX] ref '{ref}' does not match any bom-ref in this BOM",
                    "schema_path": f"{path}/ref",
                    "severity": "error",
                    "rule_id": "CDX-REF-003"
                })
    
    # CDX-VERSIONS-001: Validate versions array
    # Spec: "One of: Option 1 (version required), Option 2 (range required)"
    if "versions" in affect and isinstance(affect["versions"], list):
        for ver_idx, version in enumerate(affect["versions"]):
            if isinstance(version, dict):
                has_version = "version" in version
                has_range = "range" in version
                
                if not has_version and not has_range:
                    errors.append({
                        "path": f"{path}/versions/{ver_idx}",
                        "message": "[VEX-CycloneDX] version entry MUST have either 'version' or 'range'",
                        "schema_path": f"{path}/versions/{ver_idx}",
                        "severity": "error",
                        "rule_id": "CDX-VERSIONS-001"
                    })
                
                # CDX-VERSIONS-002: Validate status values
                if "status" in version:
                    status = version["status"]
                    valid_statuses = {"affected", "unaffected", "unknown"}
                    if status not in valid_statuses:
                        errors.append({
                            "path": f"{path}/versions/{ver_idx}/status",
                            "message": f"[VEX-CycloneDX] Invalid version status '{status}'. Must be one of: {', '.join(sorted(valid_statuses))}",
                            "schema_path": f"{path}/versions/{ver_idx}/status",
                            "severity": "error",
                            "rule_id": "CDX-VERSIONS-002"
                        })


def _validate_timestamp(value: Any, context: str) -> Dict[str, Any]:
    """Validate timestamp format (ISO 8601 date-time)"""
    
    if not isinstance(value, str):
        return {
            "valid": False,
            "reason": f"{context} must be a string in ISO 8601 date-time format",
            "severity": "error"
        }
    
    dt = _parse_datetime(value)
    if not dt:
        return {
            "valid": False,
            "reason": f"{context} must be in ISO 8601 date-time format",
            "severity": "error"
        }
    
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
        print("Valid CycloneDX document")
        print("  - JSON Schema: OK")
        print("  - CycloneDX Spec Rules: OK")
    else:
        error_items = [e for e in errors if e["severity"] == "error"]
        warning_items = [e for e in errors if e["severity"] == "warning"]
        
        print(f"Invalid CycloneDX document")
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