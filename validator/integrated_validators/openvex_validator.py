#!/usr/bin/env python3
"""
OpenVEX Enhanced Validator v2.0
Complete implementation of all OpenVEX VEX business rules
"""

import json
import re
from jsonschema import Draft7Validator
from typing import Dict, Any, List, Tuple, Set
from datetime import datetime
from urllib.parse import urlparse


def validate_openvex(data: Dict[str, Any], schema: Dict[str, Any]) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Complete OpenVEX validation with all VEX business rules
    
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
    
    # ============ STEP 2: VEX Business Rules Validation ============
    # Note: We proceed even if schema has errors to show all problems
    
    # Document-level validations
    _validate_document_fields(data, errors)
    
    # Statement-level validations
    if "statements" in data and isinstance(data["statements"], list):
        # Collect for duplicate/conflict detection
        product_vuln_map = {}
        
        for idx, statement in enumerate(data["statements"]):
            _validate_statement(statement, idx, errors)
            _collect_product_vuln(statement, idx, product_vuln_map)
        
        # Cross-statement validations
        _check_duplicates_and_conflicts(product_vuln_map, errors)
    
    # Determine overall validity
    has_errors = any(e["severity"] == "error" for e in errors)
    return not has_errors, errors


def _validate_document_fields(data: Dict[str, Any], errors: List[Dict[str, Any]]):
    """Validate document-level OpenVEX requirements"""
    
    # OVX-CTX-001: @context format validation
    if "@context" in data:
        context = data["@context"]
        if not isinstance(context, str) or not context.startswith("https://openvex.dev/ns/"):
            errors.append({
                "path": "/@context",
                "message": "[VEX-OpenVEX] @context must start with 'https://openvex.dev/ns/' (e.g., 'https://openvex.dev/ns/v0.2.0')",
                "schema_path": "/@context",
                "severity": "error",
                "rule_id": "OVX-CTX-001"
            })
    
    # OVX-TS-001: Timestamp logic validation
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
    
    # OVX-TS-002: last_updated logic
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
        
        # Check timestamp < last_updated
        if "timestamp" in data:
            try:
                ts = _parse_datetime(data["timestamp"])
                lu = _parse_datetime(data["last_updated"])
                if ts and lu and lu < ts:
                    errors.append({
                        "path": "/last_updated",
                        "message": "[VEX-OpenVEX] last_updated cannot be earlier than timestamp",
                        "schema_path": "/last_updated",
                        "severity": "warning",
                        "rule_id": "OVX-TS-003"
                    })
            except:
                pass


def _validate_statement(statement: Dict[str, Any], idx: int, errors: List[Dict[str, Any]]):
    """Validate individual OpenVEX statement with all VEX rules"""
    path_prefix = f"/statements/{idx}"
    
    status = statement.get("status")
    
    # OVX-STATE-001: Status-specific field requirements
    if status == "not_affected":
        has_justification = "justification" in statement
        has_impact = "impact_statement" in statement
        
        if not has_justification and not has_impact:
            errors.append({
                "path": path_prefix,
                "message": "[VEX-OpenVEX] status 'not_affected' MUST include either 'justification' (machine-readable) or 'impact_statement' (human-readable)",
                "schema_path": f"{path_prefix}/status",
                "severity": "error",
                "rule_id": "OVX-STATE-001"
            })
    
    elif status == "affected":
        if "action_statement" not in statement:
            errors.append({
                "path": path_prefix,
                "message": "[VEX-OpenVEX] status 'affected' MUST include 'action_statement' describing remediation actions",
                "schema_path": f"{path_prefix}/status",
                "severity": "error",
                "rule_id": "OVX-STATE-002"
            })
    
    elif status == "under_investigation":
        # SHOULD have detail about investigation
        has_detail = any(k in statement for k in ["impact_statement", "action_statement"])
        if not has_detail:
            errors.append({
                "path": path_prefix,
                "message": "[VEX-OpenVEX] status 'under_investigation' SHOULD include impact_statement or action_statement describing investigation status",
                "schema_path": f"{path_prefix}/status",
                "severity": "warning",
                "rule_id": "OVX-STATE-003"
            })
    
    # OVX-VULNID-001: Vulnerability identifier validation
    if "vulnerability" in statement:
        vuln = statement["vulnerability"]
        if isinstance(vuln, dict):
            if "name" in vuln:
                name = vuln["name"]
                if isinstance(name, str):
                    if len(name.strip()) == 0:
                        errors.append({
                            "path": f"{path_prefix}/vulnerability/name",
                            "message": "[VEX-OpenVEX] vulnerability name should not be empty",
                            "schema_path": f"{path_prefix}/vulnerability/name",
                            "severity": "error",
                            "rule_id": "OVX-VULNID-001"
                        })
                    elif not _is_valid_vuln_id(name):
                        errors.append({
                            "path": f"{path_prefix}/vulnerability/name",
                            "message": f"[VEX-OpenVEX] vulnerability name '{name}' should follow standard format (CVE-YYYY-NNNNN, GHSA-xxxx-xxxx-xxxx, etc.)",
                            "schema_path": f"{path_prefix}/vulnerability/name",
                            "severity": "warning",
                            "rule_id": "OVX-VULNID-002"
                        })
    
    # OVX-IDENT-001: Product identifier validation
    if "products" in statement and isinstance(statement["products"], list):
        for prod_idx, product in enumerate(statement["products"]):
            _validate_product(product, f"{path_prefix}/products/{prod_idx}", errors)
    
    # OVX-TS-004: Statement timestamps
    for ts_field in ["timestamp", "last_updated", "action_statement_timestamp"]:
        if ts_field in statement:
            ts_result = _validate_timestamp(statement[ts_field], f"statement {ts_field}")
            if not ts_result["valid"]:
                errors.append({
                    "path": f"{path_prefix}/{ts_field}",
                    "message": f"[VEX-OpenVEX] {ts_result['reason']}",
                    "schema_path": f"{path_prefix}/{ts_field}",
                    "severity": ts_result["severity"],
                    "rule_id": "OVX-TS-004"
                })
    
    # OVX-REFER-001: External references validation
    if "vex_metadata" in statement and isinstance(statement["vex_metadata"], dict):
        if "references" in statement["vex_metadata"]:
            refs = statement["vex_metadata"]["references"]
            if isinstance(refs, list):
                for ref_idx, ref in enumerate(refs):
                    if isinstance(ref, dict) and "url" in ref:
                        url = ref["url"]
                        if not _is_valid_url(url):
                            errors.append({
                                "path": f"{path_prefix}/vex_metadata/references/{ref_idx}/url",
                                "message": f"[VEX-OpenVEX] Invalid URL format: {url}",
                                "schema_path": f"{path_prefix}/vex_metadata/references/{ref_idx}/url",
                                "severity": "warning",
                                "rule_id": "OVX-REFER-001"
                            })


def _validate_product(product: Dict[str, Any], path: str, errors: List[Dict[str, Any]]):
    """OVX-IDENT-001: Product identifier validation"""
    
    has_id = "@id" in product
    has_identifiers = "identifiers" in product
    
    if not has_id and not has_identifiers:
        errors.append({
            "path": path,
            "message": "[VEX-OpenVEX] Product MUST have either '@id' (IRI) or 'identifiers' (purl/cpe) to identify the component",
            "schema_path": path,
            "severity": "error",
            "rule_id": "OVX-IDENT-001"
        })
    
    # Validate identifiers structure
    if has_identifiers:
        identifiers = product["identifiers"]
        if isinstance(identifiers, dict):
            valid_id_types = {"purl", "cpe22", "cpe23"}
            if not any(k in identifiers for k in valid_id_types):
                errors.append({
                    "path": f"{path}/identifiers",
                    "message": "[VEX-OpenVEX] identifiers MUST contain at least one of: purl, cpe22, cpe23",
                    "schema_path": f"{path}/identifiers",
                    "severity": "error",
                    "rule_id": "OVX-IDENT-002"
                })
    
    # OVX-HASH-001: Hash algorithm validation
    if "hashes" in product:
        hashes = product["hashes"]
        if isinstance(hashes, dict):
            valid_hash_types = {
                "md5", "sha1", "sha-256", "sha-384", "sha-512",
                "sha3-224", "sha3-256", "sha3-384", "sha3-512",
                "blake2s-256", "blake2b-256", "blake2b-512"
            }
            for hash_type, hash_value in hashes.items():
                if hash_type not in valid_hash_types:
                    errors.append({
                        "path": f"{path}/hashes/{hash_type}",
                        "message": f"[VEX-OpenVEX] Unknown hash algorithm '{hash_type}'. Known types: {', '.join(sorted(valid_hash_types))}",
                        "schema_path": f"{path}/hashes",
                        "severity": "warning",
                        "rule_id": "OVX-HASH-001"
                    })
                
                # Validate hash length
                if isinstance(hash_value, str):
                    expected_lengths = {
                        "md5": 32, "sha1": 40, "sha-256": 64, "sha-384": 96, "sha-512": 128,
                        "sha3-224": 56, "sha3-256": 64, "sha3-384": 96, "sha3-512": 128,
                        "blake2s-256": 64, "blake2b-256": 64, "blake2b-512": 128
                    }
                    expected = expected_lengths.get(hash_type)
                    if expected and len(hash_value) != expected:
                        errors.append({
                            "path": f"{path}/hashes/{hash_type}",
                            "message": f"[VEX-OpenVEX] Hash value length mismatch. Expected {expected} hex chars for {hash_type}, got {len(hash_value)}",
                            "schema_path": f"{path}/hashes/{hash_type}",
                            "severity": "warning",
                            "rule_id": "OVX-HASH-002"
                        })


def _collect_product_vuln(statement: Dict[str, Any], idx: int, product_vuln_map: Dict):
    """Collect product-vulnerability pairs for duplicate detection"""
    
    vuln_id = None
    if "vulnerability" in statement and isinstance(statement["vulnerability"], dict):
        vuln_id = statement["vulnerability"].get("name") or statement["vulnerability"].get("id")
    
    if not vuln_id:
        return
    
    status = statement.get("status")
    
    if "products" in statement and isinstance(statement["products"], list):
        for product in statement["products"]:
            prod_id = _normalize_product_id(product)
            if prod_id:
                key = (prod_id, vuln_id)
                if key not in product_vuln_map:
                    product_vuln_map[key] = []
                product_vuln_map[key].append({
                    "statement_idx": idx,
                    "status": status,
                    "product": product
                })


def _check_duplicates_and_conflicts(product_vuln_map: Dict, errors: List[Dict[str, Any]]):
    """OVX-DUP-001: Check for duplicate/conflicting statements"""
    
    for (prod_id, vuln_id), entries in product_vuln_map.items():
        if len(entries) > 1:
            # Check for conflicts
            statuses = set(e["status"] for e in entries if e["status"])
            
            # Conflicting statuses
            conflicting_pairs = [
                {"not_affected", "affected"},
                {"not_affected", "fixed"},
                {"affected", "fixed"}
            ]
            
            for pair in conflicting_pairs:
                if pair.issubset(statuses):
                    indices = [e["statement_idx"] for e in entries]
                    errors.append({
                        "path": f"/statements (indices: {indices})",
                        "message": f"[VEX-OpenVEX] Conflicting statuses for product '{prod_id}' and vulnerability '{vuln_id}': {', '.join(sorted(statuses))}. Statements at indices {indices} declare incompatible states.",
                        "schema_path": "/statements",
                        "severity": "error",
                        "rule_id": "OVX-DUP-001"
                    })
                    break


def _normalize_product_id(product: Dict[str, Any]) -> str:
    """Normalize product identifier for comparison"""
    if "@id" in product:
        return product["@id"].strip().lower()
    
    if "identifiers" in product and isinstance(product["identifiers"], dict):
        idents = product["identifiers"]
        # Prefer purl
        if "purl" in idents:
            return idents["purl"].strip().lower()
        if "cpe23" in idents:
            return idents["cpe23"].strip().lower()
        if "cpe22" in idents:
            return idents["cpe22"].strip().lower()
    
    return None


def _validate_timestamp(value: Any, context: str) -> Dict[str, Any]:
    """Validate timestamp format and logic"""
    
    if not isinstance(value, str):
        return {
            "valid": False,
            "reason": f"{context} must be a string in ISO 8601 format",
            "severity": "error"
        }
    
    # Try to parse
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


def _is_valid_vuln_id(vuln_id: str) -> bool:
    """Check if vulnerability ID follows standard patterns"""
    patterns = [
        r'^CVE-\d{4}-\d{4,}$',  # CVE
        r'^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$',  # GitHub Security Advisory
        r'^PYSEC-\d{4}-\d+$',  # Python Security
        r'^RUSTSEC-\d{4}-\d+$',  # Rust Security
        r'^OSV-\d{4}-\d+$',  # OSV
        r'^GO-\d{4}-\d+$',  # Go
    ]
    
    return any(re.match(pattern, vuln_id, re.IGNORECASE) for pattern in patterns)


def _is_valid_url(url: str) -> bool:
    """Validate URL format"""
    try:
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc])
    except:
        return False


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
        print("✓ Valid OpenVEX document")
        print("  - JSON Schema: ✓")
        print("  - VEX Rules: ✓")
    else:
        # Separate by severity
        error_items = [e for e in errors if e["severity"] == "error"]
        warning_items = [e for e in errors if e["severity"] == "warning"]
        
        print(f"✗ Invalid OpenVEX document")
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