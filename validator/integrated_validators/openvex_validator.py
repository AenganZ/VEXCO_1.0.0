#!/usr/bin/env python3
"""
OpenVEX Validator v2.1
Based on OpenVEX Specification v0.2.0
https://github.com/openvex/spec

Only validates rules explicitly stated in the official specification.
"""

import json
import re
from jsonschema import Draft7Validator
from typing import Dict, Any, List, Tuple
from datetime import datetime


def validate_openvex(data: Dict[str, Any], schema: Dict[str, Any]) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    OpenVEX validation based on official specification v0.2.0
    
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
    
    # ============ STEP 2: OpenVEX Specification Rules ============
    # Reference: https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md
    
    # Document-level validations
    _validate_document_fields(data, errors)
    
    # Statement-level validations
    if "statements" in data and isinstance(data["statements"], list):
        for idx, statement in enumerate(data["statements"]):
            _validate_statement(statement, idx, errors)
    
    # Determine overall validity
    has_errors = any(e["severity"] == "error" for e in errors)
    return not has_errors, errors


def _validate_document_fields(data: Dict[str, Any], errors: List[Dict[str, Any]]):
    """
    Validate document-level OpenVEX requirements
    
    Spec Reference - Document Struct Fields:
    - @context: REQUIRED - URL linking to OpenVEX context definition
    - @id: REQUIRED - IRI identifying the VEX document
    - author: REQUIRED - Identifier for the author
    - timestamp: REQUIRED - Time at which the document was issued
    - version: REQUIRED - Document version (must increment on changes)
    - statements: REQUIRED - List of statements
    """
    
    # OVX-CTX-001: @context format validation
    # Spec: "The URL is structured as https://openvex.dev/ns/v[version]"
    if "@context" in data:
        context = data["@context"]
        if not isinstance(context, str) or not context.startswith("https://openvex.dev/ns/"):
            errors.append({
                "path": "/@context",
                "message": "[VEX-OpenVEX] @context MUST start with 'https://openvex.dev/ns/' (e.g., 'https://openvex.dev/ns/v0.2.0')",
                "schema_path": "/@context",
                "severity": "error",
                "rule_id": "OVX-CTX-001"
            })
    
    # OVX-ID-001: @id must be an IRI
    # Spec: "The IRI identifying the VEX document"
    if "@id" in data:
        doc_id = data["@id"]
        if isinstance(doc_id, str) and len(doc_id.strip()) == 0:
            errors.append({
                "path": "/@id",
                "message": "[VEX-OpenVEX] @id MUST NOT be empty",
                "schema_path": "/@id",
                "severity": "error",
                "rule_id": "OVX-ID-001"
            })
    
    # OVX-TS-001: Timestamp format validation
    # Spec: "Timestamp defines the time at which the document was issued"
    if "timestamp" in data:
        ts_result = _validate_timestamp(data["timestamp"], "document timestamp")
        if not ts_result["valid"]:
            errors.append({
                "path": "/timestamp",
                "message": f"[VEX-OpenVEX] {ts_result['reason']}",
                "schema_path": "/timestamp",
                "severity": ts_result["severity"],
                "rule_id": "OVX-TS-001"
            })
    
    # OVX-TS-002: last_updated format validation (optional field)
    # Spec: "Date of last modification to the document"
    if "last_updated" in data:
        lu_result = _validate_timestamp(data["last_updated"], "last_updated")
        if not lu_result["valid"]:
            errors.append({
                "path": "/last_updated",
                "message": f"[VEX-OpenVEX] {lu_result['reason']}",
                "schema_path": "/last_updated",
                "severity": lu_result["severity"],
                "rule_id": "OVX-TS-002"
            })
    
    # OVX-VER-001: Version must be positive integer
    # Spec: "Version is the document version. It must be incremented when any content changes"
    if "version" in data:
        version = data["version"]
        if isinstance(version, int) and version < 1:
            errors.append({
                "path": "/version",
                "message": "[VEX-OpenVEX] version MUST be greater than or equal to 1",
                "schema_path": "/version",
                "severity": "error",
                "rule_id": "OVX-VER-001"
            })


def _validate_statement(statement: Dict[str, Any], idx: int, errors: List[Dict[str, Any]]):
    """
    Validate individual OpenVEX statement
    
    Spec Reference - Statement Fields:
    - vulnerability: REQUIRED
    - status: REQUIRED - One of: not_affected, affected, fixed, under_investigation
    - justification: REQUIRED for not_affected (OR impact_statement)
    - impact_statement: REQUIRED for not_affected (OR justification)
    - action_statement: For affected status, "MUST include a statement"
    """
    path_prefix = f"/statements/{idx}"
    
    status = statement.get("status")
    
    # OVX-STATE-001: not_affected requires justification OR impact_statement
    # Spec: "For statements conveying a not_affected status, a VEX statement MUST include 
    #        either a status justification or an impact_statement"
    if status == "not_affected":
        has_justification = "justification" in statement
        has_impact = "impact_statement" in statement
        
        if not has_justification and not has_impact:
            errors.append({
                "path": path_prefix,
                "message": "[VEX-OpenVEX] status 'not_affected' MUST include either 'justification' or 'impact_statement'",
                "schema_path": f"{path_prefix}/status",
                "severity": "error",
                "rule_id": "OVX-STATE-001"
            })
        
        # OVX-JUST-001: Validate justification values if present
        # Spec: "Justifications are fixed labels defined by VEX"
        if has_justification:
            justification = statement["justification"]
            valid_justifications = {
                "component_not_present",
                "vulnerable_code_not_present",
                "vulnerable_code_not_in_execute_path",
                "vulnerable_code_cannot_be_controlled_by_adversary",
                "inline_mitigations_already_exist"
            }
            
            if justification not in valid_justifications:
                errors.append({
                    "path": f"{path_prefix}/justification",
                    "message": f"[VEX-OpenVEX] Invalid justification value '{justification}'. Must be one of: {', '.join(sorted(valid_justifications))}",
                    "schema_path": f"{path_prefix}/justification",
                    "severity": "error",
                    "rule_id": "OVX-JUST-001"
                })
    
    # OVX-STATE-002: affected requires action_statement
    # Spec: "For a statement with 'affected' status, a VEX statement MUST include a statement 
    #        that SHOULD describe actions to remediate or mitigate"
    elif status == "affected":
        if "action_statement" not in statement:
            errors.append({
                "path": path_prefix,
                "message": "[VEX-OpenVEX] status 'affected' MUST include 'action_statement'",
                "schema_path": f"{path_prefix}/status",
                "severity": "error",
                "rule_id": "OVX-STATE-002"
            })
    
    # OVX-STATUS-001: Validate status values
    # Spec: "status MUST be one of the labels defined by VEX"
    if status:
        valid_statuses = {"not_affected", "affected", "fixed", "under_investigation"}
        if status not in valid_statuses:
            errors.append({
                "path": f"{path_prefix}/status",
                "message": f"[VEX-OpenVEX] Invalid status value '{status}'. Must be one of: {', '.join(sorted(valid_statuses))}",
                "schema_path": f"{path_prefix}/status",
                "severity": "error",
                "rule_id": "OVX-STATUS-001"
            })
    
    # OVX-VULN-001: Vulnerability must have name
    # Spec: Vulnerability struct requires at least a name to identify it
    if "vulnerability" in statement:
        vuln = statement["vulnerability"]
        if isinstance(vuln, dict):
            if "name" not in vuln:
                errors.append({
                    "path": f"{path_prefix}/vulnerability",
                    "message": "[VEX-OpenVEX] vulnerability MUST have 'name' field",
                    "schema_path": f"{path_prefix}/vulnerability/name",
                    "severity": "error",
                    "rule_id": "OVX-VULN-001"
                })
            elif "name" in vuln:
                name = vuln["name"]
                if isinstance(name, str) and len(name.strip()) == 0:
                    errors.append({
                        "path": f"{path_prefix}/vulnerability/name",
                        "message": "[VEX-OpenVEX] vulnerability name MUST NOT be empty",
                        "schema_path": f"{path_prefix}/vulnerability/name",
                        "severity": "error",
                        "rule_id": "OVX-VULN-002"
                    })
    
    # OVX-PROD-001: Products must have @id
    # Spec: Product struct requires @id for identification
    if "products" in statement and isinstance(statement["products"], list):
        for prod_idx, product in enumerate(statement["products"]):
            if isinstance(product, dict):
                if "@id" not in product:
                    errors.append({
                        "path": f"{path_prefix}/products/{prod_idx}",
                        "message": "[VEX-OpenVEX] Product MUST have '@id' field",
                        "schema_path": f"{path_prefix}/products/{prod_idx}/@id",
                        "severity": "error",
                        "rule_id": "OVX-PROD-001"
                    })
                elif "@id" in product:
                    prod_id = product["@id"]
                    if isinstance(prod_id, str) and len(prod_id.strip()) == 0:
                        errors.append({
                            "path": f"{path_prefix}/products/{prod_idx}/@id",
                            "message": "[VEX-OpenVEX] Product @id MUST NOT be empty",
                            "schema_path": f"{path_prefix}/products/{prod_idx}/@id",
                            "severity": "error",
                            "rule_id": "OVX-PROD-002"
                        })
    
    # OVX-TS-003: Statement timestamp format (optional field)
    if "timestamp" in statement:
        ts_result = _validate_timestamp(statement["timestamp"], "statement timestamp")
        if not ts_result["valid"]:
            errors.append({
                "path": f"{path_prefix}/timestamp",
                "message": f"[VEX-OpenVEX] {ts_result['reason']}",
                "schema_path": f"{path_prefix}/timestamp",
                "severity": ts_result["severity"],
                "rule_id": "OVX-TS-003"
            })


def _validate_timestamp(value: Any, context: str) -> Dict[str, Any]:
    """Validate timestamp format (ISO 8601)"""
    
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
            "reason": f"{context} must be in ISO 8601 date-time format (e.g., '2024-01-15T10:00:00Z')",
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
        print("Usage: python openvex_validator.py <schema.json> <document.json>")
        sys.exit(1)
    
    schema = load_schema(sys.argv[1])
    document = load_document(sys.argv[2])
    
    is_valid, errors = validate_openvex(document, schema)
    
    if is_valid:
        print("Valid OpenVEX document")
        print("  - JSON Schema: OK")
        print("  - OpenVEX Spec Rules: OK")
    else:
        error_items = [e for e in errors if e["severity"] == "error"]
        warning_items = [e for e in errors if e["severity"] == "warning"]
        
        print(f"Invalid OpenVEX document")
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