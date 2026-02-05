#!/usr/bin/env python3
"""
CSAF Enhanced Validator v2.0
Complete implementation of all CSAF VEX Profile business rules
"""

import json
from jsonschema import Draft7Validator
from typing import Dict, Any, List, Tuple, Set
from datetime import datetime


def validate_csaf(data: Dict[str, Any], schema: Dict[str, Any]) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Complete CSAF validation with all VEX Profile business rules
    
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
    
    # ============ STEP 2: CSAF VEX Profile Business Rules ============
    
    # Check if this is a VEX document
    is_vex = False
    if "document" in data and "category" in data["document"]:
        is_vex = data["document"]["category"] == "csaf_vex"
    
    if is_vex:
        _validate_vex_profile(data, errors)
    
    # Determine overall validity
    has_errors = any(e["severity"] == "error" for e in errors)
    return not has_errors, errors


def _validate_vex_profile(data: Dict[str, Any], errors: List[Dict[str, Any]]):
    """Validate all CSAF VEX Profile requirements"""
    
    # CSAF-VEX-CATEGORY-001: VEX documents should use csaf_vex category
    document = data.get("document", {})
    category = document.get("category", "")
    if category and category != "csaf_vex":
        errors.append({
            "path": "/document/category",
            "message": f"[VEX-CSAF] VEX Profile documents SHOULD use category 'csaf_vex', found '{category}'",
            "schema_path": "/document/category",
            "severity": "warning",
            "rule_id": "CSAF-VEX-CATEGORY-001"
        })
    
    # CSAF-PROD-001: product_tree is required for VEX
    if "product_tree" not in data:
        errors.append({
            "path": "/",
            "message": "[VEX-CSAF] CSAF VEX Profile requires 'product_tree' - it must list all products referenced in vulnerabilities",
            "schema_path": "/product_tree",
            "severity": "error",
            "rule_id": "CSAF-PROD-001"
        })
        return  # Cannot proceed without product_tree
    
    # CSAF-VULN-REQ-001: vulnerabilities array is required
    if "vulnerabilities" not in data:
        errors.append({
            "path": "/",
            "message": "[VEX-CSAF] CSAF VEX Profile requires 'vulnerabilities' array",
            "schema_path": "/vulnerabilities",
            "severity": "error",
            "rule_id": "CSAF-VULN-REQ-001"
        })
        return
    
    # Collect product IDs, group mappings, and validate product_tree structure
    product_ids = _collect_product_ids(data.get("product_tree", {}))
    group_mappings = _collect_group_mappings(data.get("product_tree", {}))
    
    # CSAF-PROD-002: Validate product_tree has actual products
    if len(product_ids) == 0:
        errors.append({
            "path": "/product_tree",
            "message": "[VEX-CSAF] product_tree must contain at least one product definition (in full_product_names, branches, or relationships)",
            "schema_path": "/product_tree",
            "severity": "error",
            "rule_id": "CSAF-PROD-002"
        })
    
    # CSAF-PROD-DUP-001: Validate product IDs are unique (6.1.2)
    _validate_product_id_uniqueness(data.get("product_tree", {}), errors)
    
    # CSAF-GROUP-001: Validate all group_ids are defined
    _validate_group_references(data.get("product_tree", {}), group_mappings, errors)
    
    # CSAF-GROUP-DUP-001: Validate product group IDs are unique (6.1.5)
    _validate_group_id_uniqueness(data.get("product_tree", {}), errors)
    
    # Validate each vulnerability
    vulnerabilities = data.get("vulnerabilities", [])
    if isinstance(vulnerabilities, list):
        for idx, vuln in enumerate(vulnerabilities):
            _validate_vulnerability(vuln, idx, product_ids, group_mappings, errors)
    
    # Document-level validations
    _validate_document_tracking(data.get("document", {}), errors)
    _validate_document_metadata(data.get("document", {}), errors)
    _validate_vulnerabilities_metadata(vulnerabilities, errors)
    _validate_vex_notes(vulnerabilities, errors)  # NEW!


def _collect_product_ids(product_tree: Dict[str, Any]) -> Set[str]:
    """Collect all product IDs from CSAF product tree"""
    product_ids = set()
    
    # From full_product_names
    if "full_product_names" in product_tree:
        for product in product_tree["full_product_names"]:
            if "product_id" in product:
                product_ids.add(product["product_id"])
    
    # From branches (recursive)
    if "branches" in product_tree:
        product_ids.update(_collect_from_branches(product_tree["branches"]))
    
    # From relationships
    if "relationships" in product_tree:
        for rel in product_tree["relationships"]:
            if "product_reference" in rel:
                product_ids.add(rel["product_reference"])
            if "relates_to_product_reference" in rel:
                product_ids.add(rel["relates_to_product_reference"])
            if "full_product_name" in rel and "product_id" in rel["full_product_name"]:
                product_ids.add(rel["full_product_name"]["product_id"])
    
    return product_ids


def _validate_product_id_uniqueness(product_tree: Dict[str, Any], errors: List[Dict[str, Any]]):
    """CSAF-PROD-DUP-001: Validate product IDs are unique (6.1.2)"""
    seen_ids = {}
    
    # Check full_product_names
    if "full_product_names" in product_tree:
        for idx, product in enumerate(product_tree["full_product_names"]):
            if "product_id" in product:
                pid = product["product_id"]
                if pid in seen_ids:
                    errors.append({
                        "path": f"/product_tree/full_product_names/{idx}/product_id",
                        "message": f"[VEX-CSAF] Product ID '{pid}' is defined multiple times (first at {seen_ids[pid]})",
                        "schema_path": f"/product_tree/full_product_names/{idx}/product_id",
                        "severity": "error",
                        "rule_id": "CSAF-PROD-DUP-001"
                    })
                else:
                    seen_ids[pid] = f"/product_tree/full_product_names/{idx}"
    
    # Check branches (recursive)
    if "branches" in product_tree:
        _check_branches_product_id_duplicates(product_tree["branches"], "/product_tree/branches", seen_ids, errors)
    
    # Check relationships
    if "relationships" in product_tree:
        for idx, rel in enumerate(product_tree["relationships"]):
            if "full_product_name" in rel and "product_id" in rel["full_product_name"]:
                pid = rel["full_product_name"]["product_id"]
                if pid in seen_ids:
                    errors.append({
                        "path": f"/product_tree/relationships/{idx}/full_product_name/product_id",
                        "message": f"[VEX-CSAF] Product ID '{pid}' is defined multiple times (first at {seen_ids[pid]})",
                        "schema_path": f"/product_tree/relationships/{idx}/full_product_name/product_id",
                        "severity": "error",
                        "rule_id": "CSAF-PROD-DUP-001"
                    })
                else:
                    seen_ids[pid] = f"/product_tree/relationships/{idx}/full_product_name"


def _check_branches_product_id_duplicates(branches: List[Dict], path: str, seen_ids: Dict[str, str], errors: List[Dict[str, Any]]):
    """Recursively check product ID duplicates in branches"""
    for idx, branch in enumerate(branches):
        branch_path = f"{path}/{idx}"
        
        if "product" in branch and "product_id" in branch["product"]:
            pid = branch["product"]["product_id"]
            if pid in seen_ids:
                errors.append({
                    "path": f"{branch_path}/product/product_id",
                    "message": f"[VEX-CSAF] Product ID '{pid}' is defined multiple times (first at {seen_ids[pid]})",
                    "schema_path": f"{branch_path}/product/product_id",
                    "severity": "error",
                    "rule_id": "CSAF-PROD-DUP-001"
                })
            else:
                seen_ids[pid] = f"{branch_path}/product"
        
        if "branches" in branch:
            _check_branches_product_id_duplicates(branch["branches"], f"{branch_path}/branches", seen_ids, errors)


def _collect_from_branches(branches: List[Dict]) -> Set[str]:
    """Recursively collect product IDs from branches"""
    product_ids = set()
    for branch in branches:
        if "product" in branch and "product_id" in branch["product"]:
            product_ids.add(branch["product"]["product_id"])
        if "branches" in branch:
            product_ids.update(_collect_from_branches(branch["branches"]))
    return product_ids


def _collect_group_mappings(product_tree: Dict[str, Any]) -> Dict[str, Set[str]]:
    """Collect product group ID to product IDs mappings"""
    mappings = {}
    
    if "product_groups" in product_tree:
        for group in product_tree["product_groups"]:
            if "group_id" in group and "product_ids" in group:
                mappings[group["group_id"]] = set(group["product_ids"])
    
    return mappings


def _validate_group_references(product_tree: Dict[str, Any], 
                               group_mappings: Dict[str, Set[str]], 
                               errors: List[Dict[str, Any]]):
    """CSAF-GROUP-001: Validate product groups reference integrity"""
    
    # Validate that group product_ids exist
    all_product_ids = _collect_product_ids(product_tree)
    
    if "product_groups" in product_tree:
        for idx, group in enumerate(product_tree["product_groups"]):
            if "group_id" in group and "product_ids" in group:
                for pid_idx, pid in enumerate(group["product_ids"]):
                    if pid not in all_product_ids:
                        errors.append({
                            "path": f"/product_tree/product_groups/{idx}/product_ids/{pid_idx}",
                            "message": f"[VEX-CSAF] Product ID '{pid}' in group '{group['group_id']}' is not defined in product_tree",
                            "schema_path": f"/product_tree/product_groups/{idx}/product_ids",
                            "severity": "error",
                            "rule_id": "CSAF-GROUP-001"
                        })


def _validate_group_id_uniqueness(product_tree: Dict[str, Any], errors: List[Dict[str, Any]]):
    """CSAF-GROUP-DUP-001: Validate product group IDs are unique (6.1.5)"""
    seen_group_ids = {}
    
    if "product_groups" in product_tree:
        for idx, group in enumerate(product_tree["product_groups"]):
            if "group_id" in group:
                gid = group["group_id"]
                if gid in seen_group_ids:
                    errors.append({
                        "path": f"/product_tree/product_groups/{idx}/group_id",
                        "message": f"[VEX-CSAF] Product Group ID '{gid}' is defined multiple times (first at {seen_group_ids[gid]})",
                        "schema_path": f"/product_tree/product_groups/{idx}/group_id",
                        "severity": "error",
                        "rule_id": "CSAF-GROUP-DUP-001"
                    })
                else:
                    seen_group_ids[gid] = f"/product_tree/product_groups/{idx}"


def _validate_vulnerability(vuln: Dict[str, Any], idx: int, 
                           product_ids: Set[str], 
                           group_mappings: Dict[str, Set[str]], 
                           errors: List[Dict[str, Any]]):
    """Validate CSAF vulnerability with VEX Profile rules"""
    path_prefix = f"/vulnerabilities/{idx}"
    
    # CSAF-VULNID-001: CVE or IDs required
    has_cve = "cve" in vuln and vuln["cve"]
    has_ids = "ids" in vuln and isinstance(vuln["ids"], list) and len(vuln["ids"]) > 0
    
    if not has_cve and not has_ids:
        errors.append({
            "path": path_prefix,
            "message": "[VEX-CSAF] vulnerability MUST have either 'cve' or 'ids' field to identify the vulnerability",
            "schema_path": f"{path_prefix}",
            "severity": "error",
            "rule_id": "CSAF-VULNID-001"
        })
    
    # CSAF-PSTAT-001: product_status required
    if "product_status" not in vuln:
        errors.append({
            "path": path_prefix,
            "message": "[VEX-CSAF] vulnerability MUST have 'product_status' field",
            "schema_path": f"{path_prefix}/product_status",
            "severity": "error",
            "rule_id": "CSAF-PSTAT-001"
        })
        return
    
    product_status = vuln["product_status"]
    
    # CSAF-PSTAT-002: Must have at least one VEX status
    vex_statuses = {"fixed", "known_affected", "known_not_affected", "under_investigation"}
    has_vex_status = any(status in product_status for status in vex_statuses)
    
    if not has_vex_status:
        errors.append({
            "path": f"{path_prefix}/product_status",
            "message": f"[VEX-CSAF] product_status MUST contain at least one VEX status: {', '.join(sorted(vex_statuses))}",
            "schema_path": f"{path_prefix}/product_status",
            "severity": "error",
            "rule_id": "CSAF-PSTAT-002"
        })
        return
    
    # Validate product references exist
    _validate_product_references(product_status, path_prefix, product_ids, group_mappings, errors)
    
    # CSAF-KNA-001: known_not_affected requirements
    if "known_not_affected" in product_status:
        not_affected_products = product_status["known_not_affected"]
        if isinstance(not_affected_products, list):
            _validate_not_affected_products(
                vuln, not_affected_products, path_prefix, 
                product_ids, group_mappings, errors
            )
    
    # CSAF-KA-001: known_affected requirements
    if "known_affected" in product_status:
        affected_products = product_status["known_affected"]
        if isinstance(affected_products, list):
            _validate_affected_products(
                vuln, affected_products, path_prefix, 
                product_ids, group_mappings, errors
            )
    
    # CSAF-REMED-STRUCT-001: Validate remediation structure
    if "remediations" in vuln and isinstance(vuln["remediations"], list):
        for rem_idx, remediation in enumerate(vuln["remediations"]):
            _validate_remediation(remediation, f"{path_prefix}/remediations/{rem_idx}", 
                                product_ids, group_mappings, errors)


def _validate_product_references(product_status: Dict[str, Any],
                                path_prefix: str,
                                product_ids: Set[str],
                                group_mappings: Dict[str, Set[str]],
                                errors: List[Dict[str, Any]]):
    """CSAF-PROD-003: Validate all product references exist"""
    
    for status_type in ["fixed", "known_affected", "known_not_affected", 
                       "under_investigation", "first_affected", "last_affected",
                       "first_fixed", "recommended"]:
        if status_type in product_status:
            products = product_status[status_type]
            if isinstance(products, list):
                for prod_idx, prod_id in enumerate(products):
                    if prod_id not in product_ids:
                        # Check if it's a group_id
                        if prod_id not in group_mappings:
                            errors.append({
                                "path": f"{path_prefix}/product_status/{status_type}/{prod_idx}",
                                "message": f"[VEX-CSAF] Product ID '{prod_id}' is not defined in product_tree",
                                "schema_path": f"{path_prefix}/product_status/{status_type}",
                                "severity": "error",
                                "rule_id": "CSAF-PROD-003"
                            })


def _validate_not_affected_products(vuln: Dict[str, Any], 
                                    not_affected_ids: List[str],
                                    path_prefix: str,
                                    product_ids: Set[str],
                                    group_mappings: Dict[str, Set[str]],
                                    errors: List[Dict[str, Any]]):
    """CSAF-KNA-001: known_not_affected products MUST have impact statement"""
    
    # Collect products with impact statements from flags
    products_with_flags = set()
    if "flags" in vuln and isinstance(vuln["flags"], list):
        for flag in vuln["flags"]:
            if "product_ids" in flag and isinstance(flag["product_ids"], list):
                products_with_flags.update(flag["product_ids"])
            
            if "group_ids" in flag and isinstance(flag["group_ids"], list):
                for gid in flag["group_ids"]:
                    if gid in group_mappings:
                        products_with_flags.update(group_mappings[gid])
    
    # Collect products with impact from threats
    products_with_threats = set()
    if "threats" in vuln and isinstance(vuln["threats"], list):
        for threat in vuln["threats"]:
            if threat.get("category") == "impact":
                if "product_ids" in threat and isinstance(threat["product_ids"], list):
                    products_with_threats.update(threat["product_ids"])
                
                if "group_ids" in threat and isinstance(threat["group_ids"], list):
                    for gid in threat["group_ids"]:
                        if gid in group_mappings:
                            products_with_threats.update(group_mappings[gid])
    
    products_with_impact = products_with_flags | products_with_threats
    
    # Check each not_affected product
    for product_id in not_affected_ids:
        if product_id not in products_with_impact:
            errors.append({
                "path": f"{path_prefix}/product_status/known_not_affected",
                "message": f"[VEX-CSAF] Product '{product_id}' is listed as known_not_affected but has no impact statement. MUST provide either a flag (machine-readable justification) or a threat with category='impact' (human-readable explanation).",
                "schema_path": f"{path_prefix}/product_status/known_not_affected",
                "severity": "error",
                "rule_id": "CSAF-KNA-001"
            })


def _validate_affected_products(vuln: Dict[str, Any],
                               affected_ids: List[str],
                               path_prefix: str,
                               product_ids: Set[str],
                               group_mappings: Dict[str, Set[str]],
                               errors: List[Dict[str, Any]]):
    """CSAF-KA-001: known_affected products MUST have action statement"""
    
    # Collect products with remediations
    products_with_remediation = set()
    if "remediations" in vuln and isinstance(vuln["remediations"], list):
        for remediation in vuln["remediations"]:
            if "product_ids" in remediation and isinstance(remediation["product_ids"], list):
                products_with_remediation.update(remediation["product_ids"])
            
            if "group_ids" in remediation and isinstance(remediation["group_ids"], list):
                for gid in remediation["group_ids"]:
                    if gid in group_mappings:
                        products_with_remediation.update(group_mappings[gid])
    
    # Check each affected product
    for product_id in affected_ids:
        if product_id not in products_with_remediation:
            errors.append({
                "path": f"{path_prefix}/product_status/known_affected",
                "message": f"[VEX-CSAF] Product '{product_id}' is listed as known_affected but has no action statement. MUST provide a remediation entry describing actions to remediate or mitigate the vulnerability.",
                "schema_path": f"{path_prefix}/product_status/known_affected",
                "severity": "error",
                "rule_id": "CSAF-KA-001"
            })


def _validate_remediation(remediation: Dict[str, Any],
                         path: str,
                         product_ids: Set[str],
                         group_mappings: Dict[str, Set[str]],
                         errors: List[Dict[str, Any]]):
    """CSAF-REMED-STRUCT-001: Validate remediation structure"""
    
    # MUST have category
    if "category" not in remediation:
        errors.append({
            "path": path,
            "message": "[VEX-CSAF] remediation MUST have 'category' field",
            "schema_path": f"{path}/category",
            "severity": "error",
            "rule_id": "CSAF-REMED-STRUCT-001"
        })
    
    # MUST have details or url
    has_details = "details" in remediation
    has_url = "url" in remediation
    
    if not has_details and not has_url:
        errors.append({
            "path": path,
            "message": "[VEX-CSAF] remediation MUST have either 'details' or 'url' field describing the remediation action",
            "schema_path": path,
            "severity": "error",
            "rule_id": "CSAF-REMED-STRUCT-002"
        })
    
    # MUST have product_ids or group_ids
    has_product_ids = "product_ids" in remediation and isinstance(remediation["product_ids"], list) and len(remediation["product_ids"]) > 0
    has_group_ids = "group_ids" in remediation and isinstance(remediation["group_ids"], list) and len(remediation["group_ids"]) > 0
    
    if not has_product_ids and not has_group_ids:
        errors.append({
            "path": path,
            "message": "[VEX-CSAF] remediation MUST have either 'product_ids' or 'group_ids' to identify which products it applies to",
            "schema_path": path,
            "severity": "error",
            "rule_id": "CSAF-REMED-STRUCT-003"
        })
    
    # Validate group_ids exist
    if "group_ids" in remediation and isinstance(remediation["group_ids"], list):
        for gid_idx, gid in enumerate(remediation["group_ids"]):
            if gid not in group_mappings:
                errors.append({
                    "path": f"{path}/group_ids/{gid_idx}",
                    "message": f"[VEX-CSAF] Group ID '{gid}' in remediation is not defined in product_tree.product_groups",
                    "schema_path": f"{path}/group_ids",
                    "severity": "error",
                    "rule_id": "CSAF-GROUP-002"
                })


def _validate_document_tracking(document: Dict[str, Any], errors: List[Dict[str, Any]]):
    """CSAF-TIMELINE-003: Validate document tracking timestamp logic"""
    
    if "tracking" not in document:
        return
    
    tracking = document["tracking"]
    
    # Note: Timestamp format validation (ISO 8601) is handled by JSON Schema
    # We only validate business logic here
    
    # CSAF-TIMELINE-003: Check initial_release_date <= current_release_date
    if "initial_release_date" in tracking and "current_release_date" in tracking:
        try:
            ird = _parse_datetime(tracking["initial_release_date"])
            crd = _parse_datetime(tracking["current_release_date"])
            if ird and crd and crd < ird:
                errors.append({
                    "path": "/document/tracking/current_release_date",
                    "message": "[VEX-CSAF] current_release_date cannot be earlier than initial_release_date",
                    "schema_path": "/document/tracking/current_release_date",
                    "severity": "error",
                    "rule_id": "CSAF-TIMELINE-003"
                })
        except:
            pass
    
    # CSAF-REV-SORTED-001: Validate revision history is sorted (6.1.14)
    if "revision_history" in tracking:
        revision_history = tracking["revision_history"]
        if isinstance(revision_history, list) and len(revision_history) > 1:
            _validate_revision_history_sorted(revision_history, errors)
    
    # CSAF-STATUS-DRAFT-001: Validate document status matches version (6.1.17)
    if "version" in tracking and "status" in tracking:
        _validate_document_status_draft(tracking["version"], tracking["status"], errors)


def _validate_revision_history_sorted(revision_history: List[Dict[str, Any]], errors: List[Dict[str, Any]]):
    """CSAF-REV-SORTED-001: Validate revision history is sorted by date (6.1.14)"""
    
    # Sort by date and version number
    sorted_revisions = []
    for idx, rev in enumerate(revision_history):
        if isinstance(rev, dict) and "date" in rev and "number" in rev:
            date = _parse_datetime(rev["date"])
            if date:
                sorted_revisions.append((idx, date, str(rev["number"])))
    
    if len(sorted_revisions) < 2:
        return
    
    # Check if sorted ascending by date, then by version
    for i in range(len(sorted_revisions) - 1):
        idx1, date1, ver1 = sorted_revisions[i]
        idx2, date2, ver2 = sorted_revisions[i + 1]
        
        # Compare versions numerically
        if not _is_version_ascending(ver1, ver2, date1, date2):
            errors.append({
                "path": f"/document/tracking/revision_history/{idx2}",
                "message": f"[VEX-CSAF] Revision history MUST be sorted ascending by date and version. Item {idx2} (version {ver2}, date {revision_history[idx2]['date']}) should come before or after item {idx1} (version {ver1}, date {revision_history[idx1]['date']})",
                "schema_path": f"/document/tracking/revision_history/{idx2}",
                "severity": "error",
                "rule_id": "CSAF-REV-SORTED-001"
            })
            break


def _is_version_ascending(ver1: str, ver2: str, date1, date2) -> bool:
    """Check if version numbers are in ascending order considering dates"""
    
    # If dates are different, versions must follow date order
    if date1 < date2:
        # ver2 should be >= ver1
        return _compare_versions(ver1, ver2) <= 0
    elif date1 > date2:
        # This should not happen - dates should be ascending
        return False
    else:
        # Same date: ver2 should be > ver1
        return _compare_versions(ver1, ver2) < 0


def _compare_versions(v1: str, v2: str) -> int:
    """Compare version numbers. Returns -1 if v1<v2, 0 if equal, 1 if v1>v2"""
    
    # Try integer versioning first
    try:
        iv1 = int(v1)
        iv2 = int(v2)
        if iv1 < iv2:
            return -1
        elif iv1 > iv2:
            return 1
        else:
            return 0
    except ValueError:
        pass
    
    # Try semantic versioning (x.y.z)
    try:
        parts1 = v1.split('.')
        parts2 = v2.split('.')
        
        for i in range(max(len(parts1), len(parts2))):
            p1 = int(parts1[i]) if i < len(parts1) else 0
            p2 = int(parts2[i]) if i < len(parts2) else 0
            
            if p1 < p2:
                return -1
            elif p1 > p2:
                return 1
        
        return 0
    except (ValueError, IndexError):
        # Fallback to string comparison
        if v1 < v2:
            return -1
        elif v1 > v2:
            return 1
        else:
            return 0


def _validate_document_status_draft(version: str, status: str, errors: List[Dict[str, Any]]):
    """CSAF-STATUS-DRAFT-001: Validate document status matches version (6.1.17)"""
    
    # Version 0 or 0.y.z must have status "draft"
    is_zero_version = False
    
    # Check for integer version 0
    try:
        if int(version) == 0:
            is_zero_version = True
    except ValueError:
        # Check for semantic version 0.y.z
        if version.startswith("0."):
            is_zero_version = True
        # Check for pre-release (contains hyphen)
        elif "-" in version:
            is_zero_version = True
    
    if is_zero_version and status != "draft":
        errors.append({
            "path": "/document/tracking/status",
            "message": f"[VEX-CSAF] Document status MUST be 'draft' when version is {version} (0 or 0.y.z or contains pre-release)",
            "schema_path": "/document/tracking/status",
            "severity": "error",
            "rule_id": "CSAF-STATUS-DRAFT-001"
        })


def _validate_document_metadata(document: Dict[str, Any], errors: List[Dict[str, Any]]):
    """Validate CSAF document metadata requirements"""
    
    # CSAF-DEPRECATED-PROFILE-001: Check for deprecated profile
    category = document.get("category", "")
    if category.startswith("csaf_deprecated_"):
        errors.append({
            "path": "/document/category",
            "message": f"[VEX-CSAF] Deprecated profile '{category}' (still valid but not recommended for new documents). Consider using current profile instead (e.g., 'csaf_security_advisory', 'csaf_vex')",
            "schema_path": "/document/category",
            "severity": "warning",
            "rule_id": "CSAF-DEPRECATED-PROFILE-001"
        })
    
    # CSAF-TRANSLATOR-001: translator requires source_lang
    if document.get("publisher", {}).get("category") == "translator":
        if "source_lang" not in document:
            errors.append({
                "path": "/document/source_lang",
                "message": "[VEX-CSAF] source_lang MUST be present when publisher category is 'translator'",
                "schema_path": "/document/source_lang",
                "severity": "error",
                "rule_id": "CSAF-TRANSLATOR-001"
            })
    
    # CSAF-NOTE-REQ-001: At least one note with specific categories
    notes = document.get("notes", [])
    if isinstance(notes, list):
        has_required_note = any(
            note.get("category") in ["description", "details", "general", "summary"]
            for note in notes
            if isinstance(note, dict)
        )
        if not has_required_note:
            errors.append({
                "path": "/document/notes",
                "message": "[VEX-CSAF] Document SHOULD have at least one note with category: description, details, general, or summary",
                "schema_path": "/document/notes",
                "severity": "warning",
                "rule_id": "CSAF-NOTE-REQ-001"
            })
    
    # CSAF-REF-REQ-001: At least one external reference
    references = document.get("references", [])
    if isinstance(references, list):
        has_external = any(
            ref.get("category") == "external"
            for ref in references
            if isinstance(ref, dict)
        )
        if not has_external:
            errors.append({
                "path": "/document/references",
                "message": "[VEX-CSAF] Document SHOULD have at least one external reference",
                "schema_path": "/document/references",
                "severity": "warning",
                "rule_id": "CSAF-REF-REQ-001"
            })
    
    # CSAF-REV-DUP-001: Revision history version uniqueness
    tracking = document.get("tracking", {})
    if "revision_history" in tracking:
        revision_history = tracking["revision_history"]
        if isinstance(revision_history, list):
            versions = []
            for idx, rev in enumerate(revision_history):
                if isinstance(rev, dict) and "number" in rev:
                    version = str(rev["number"])
                    if version in versions:
                        errors.append({
                            "path": f"/document/tracking/revision_history/{idx}/number",
                            "message": f"[VEX-CSAF] Revision history version '{version}' appears multiple times (MUST be unique)",
                            "schema_path": f"/document/tracking/revision_history/{idx}/number",
                            "severity": "error",
                            "rule_id": "CSAF-REV-DUP-001"
                        })
                    else:
                        versions.append(version)
    
    # CSAF-HASH-DUP-001: Hash algorithm uniqueness in each hash list
    def check_hash_duplicates(hashes, path_prefix):
        if isinstance(hashes, list):
            algorithms = []
            for idx, hash_item in enumerate(hashes):
                if isinstance(hash_item, dict) and "algorithm" in hash_item:
                    algo = hash_item["algorithm"]
                    if algo in algorithms:
                        errors.append({
                            "path": f"{path_prefix}/{idx}/algorithm",
                            "message": f"[VEX-CSAF] Hash algorithm '{algo}' appears multiple times in same hash list (MUST be unique)",
                            "schema_path": f"{path_prefix}/{idx}/algorithm",
                            "severity": "error",
                            "rule_id": "CSAF-HASH-DUP-001"
                        })
                    else:
                        algorithms.append(algo)
    
    # Check document aggregates
    if "aggregates" in document:
        aggregates = document["aggregates"]
        if isinstance(aggregates, list):
            for idx, agg in enumerate(aggregates):
                if isinstance(agg, dict) and "hashes" in agg:
                    check_hash_duplicates(agg["hashes"], f"/document/aggregates/{idx}/hashes")


def _validate_vulnerabilities_metadata(vulnerabilities: List[Dict[str, Any]], errors: List[Dict[str, Any]]):
    """Validate vulnerabilities-level metadata requirements"""
    
    if not isinstance(vulnerabilities, list):
        return
    
    # CSAF-CVE-DUP-001: CVE uniqueness across vulnerabilities
    cve_ids = []
    for idx, vuln in enumerate(vulnerabilities):
        if isinstance(vuln, dict) and "cve" in vuln:
            cve = vuln["cve"]
            if cve in cve_ids:
                errors.append({
                    "path": f"/vulnerabilities/{idx}/cve",
                    "message": f"[VEX-CSAF] CVE '{cve}' appears in multiple vulnerability items (MUST be unique)",
                    "schema_path": f"/vulnerabilities/{idx}/cve",
                    "severity": "error",
                    "rule_id": "CSAF-CVE-DUP-001"
                })
            else:
                cve_ids.append(cve)


def _validate_vex_notes(vulnerabilities: List[Dict[str, Any]], errors: List[Dict[str, Any]]):
    """Validate VEX Profile requirement for vulnerability notes"""
    
    if not isinstance(vulnerabilities, list):
        return
    
    # CSAF-VEX-NOTES-001: VEX Profile recommends notes for each vulnerability
    for idx, vuln in enumerate(vulnerabilities):
        if isinstance(vuln, dict):
            notes = vuln.get("notes", [])
            if not notes or (isinstance(notes, list) and len(notes) == 0):
                errors.append({
                    "path": f"/vulnerabilities/{idx}/notes",
                    "message": "[VEX-CSAF] VEX Profile SHOULD include notes for each vulnerability to provide details",
                    "schema_path": f"/vulnerabilities/{idx}/notes",
                    "severity": "warning",
                    "rule_id": "CSAF-VEX-NOTES-001"
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
    
    # Future date check removed - not part of official CSAF 2.1 spec
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
        print("Usage: python csaf_validator.py <schema.json> <document.json>")
        sys.exit(1)
    
    schema = load_schema(sys.argv[1])
    document = load_document(sys.argv[2])
    
    is_valid, errors = validate_csaf(document, schema)
    
    if is_valid:
        print("✓ Valid CSAF document")
        print("  - JSON Schema: ✓")
        if document.get("document", {}).get("category") == "csaf_vex":
            print("  - CSAF VEX Profile Rules: ✓")
    else:
        error_items = [e for e in errors if e["severity"] == "error"]
        warning_items = [e for e in errors if e["severity"] == "warning"]
        
        print(f"✗ Invalid CSAF document")
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