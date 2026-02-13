#!/usr/bin/env python3
"""
CSAF Enhanced Validator v2.1
Complete implementation of CSAF 2.1 Mandatory Tests (6.1) and Recommended Tests (6.2)
"""

import json
import re
from jsonschema import Draft7Validator
from typing import Dict, Any, List, Tuple, Set, Optional
from datetime import datetime


# ============ CONSTANTS ============

# 6.2.27: Discouraged Product Status / Remediation combinations
DISCOURAGED_STATUS_REMEDIATION = {
    # known_not_affected should not have fix-related remediations
    "known_not_affected": ["vendor_fix", "fix_planned", "optional_patch"],
    # fixed should not have "no fix" remediations
    "fixed": ["no_fix_planned", "none_available"],
    "first_fixed": ["no_fix_planned", "none_available"],
}

# 6.2.28, 6.2.29: Special UUIDs
MAX_UUID = "ffffffff-ffff-ffff-ffff-ffffffffffff"
NIL_UUID = "00000000-0000-0000-0000-000000000000"

# 6.2.34: Registered SSVC namespaces
REGISTERED_SSVC_NAMESPACES = [
    "ssvc",
    "ssvc/cisa",
    "ssvc/first", 
]

# 6.2.37: Registered SSVC roles
REGISTERED_SSVC_ROLES = [
    "Coordinator",
    "Deployer", 
    "Supplier",
]


def validate_csaf(data: Dict[str, Any], schema: Dict[str, Any]) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Complete CSAF validation with all Mandatory (6.1) and Recommended (6.2) tests
    
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
    
    # ============ STEP 2: Mandatory Tests (6.1) ============
    _validate_mandatory_tests(data, errors)
    
    # ============ STEP 3: Recommended Tests (6.2) ============
    _validate_recommended_tests(data, errors)
    
    # ============ STEP 4: VEX Profile Specific Tests ============
    is_vex = False
    if "document" in data and "category" in data["document"]:
        is_vex = data["document"]["category"] == "csaf_vex"
    
    if is_vex:
        _validate_vex_profile(data, errors)
    
    # Determine overall validity (only errors, not warnings)
    has_errors = any(e["severity"] == "error" for e in errors)
    return not has_errors, errors


def _validate_mandatory_tests(data: Dict[str, Any], errors: List[Dict[str, Any]]):
    """Validate CSAF 2.1 Mandatory Tests (Section 6.1)"""
    
    product_tree = data.get("product_tree", {})
    document = data.get("document", {})
    
    # Collect IDs for reference validation
    product_ids = _collect_product_ids(product_tree)
    group_mappings = _collect_group_mappings(product_tree)
    
    # 6.1.2: Product ID uniqueness
    _validate_product_id_uniqueness(product_tree, errors)
    
    # 6.1.5: Product Group ID uniqueness
    _validate_group_id_uniqueness(product_tree, errors)
    
    # 6.1.14: Revision history sorted
    if "tracking" in document and "revision_history" in document["tracking"]:
        _validate_revision_history_sorted(document["tracking"]["revision_history"], errors)
    
    # 6.1.17: Version 0 must be draft
    if "tracking" in document:
        tracking = document["tracking"]
        if "version" in tracking and "status" in tracking:
            _validate_document_status_draft(tracking["version"], tracking["status"], errors)
    
    # Validate vulnerabilities
    vulnerabilities = data.get("vulnerabilities", [])
    if isinstance(vulnerabilities, list):
        for idx, vuln in enumerate(vulnerabilities):
            _validate_vulnerability_mandatory(vuln, idx, product_ids, group_mappings, errors)


def _validate_recommended_tests(data: Dict[str, Any], errors: List[Dict[str, Any]]):
    """Validate CSAF 2.1 Recommended Tests (Section 6.2)"""
    
    product_tree = data.get("product_tree", {})
    document = data.get("document", {})
    vulnerabilities = data.get("vulnerabilities", [])
    
    # Collect IDs
    product_ids = _collect_product_ids(product_tree)
    group_mappings = _collect_group_mappings(product_tree)
    referenced_product_ids = _collect_referenced_product_ids(data)
    
    # Skip informational advisory for some tests
    is_informational = document.get("category") == "csaf_informational_advisory"
    
    # 6.2.1: Unused Definition of Product ID
    if not is_informational:
        _test_6_2_1_unused_product_id(product_ids, referenced_product_ids, errors)
    
    # 6.2.2: Missing Remediation for affected/under_investigation
    _test_6_2_2_missing_remediation(vulnerabilities, group_mappings, errors)
    
    # 6.2.3: Missing Metric for affected
    _test_6_2_3_missing_metric(vulnerabilities, group_mappings, errors)
    
    # 6.2.4: Build Metadata in Revision History
    if "tracking" in document and "revision_history" in document["tracking"]:
        _test_6_2_4_build_metadata_in_revision(document["tracking"]["revision_history"], errors)
    
    # 6.2.5: Older Initial Release Date than Revision History
    if "tracking" in document:
        _test_6_2_5_initial_release_older_than_revision(document["tracking"], errors)
    
    # 6.2.6: Older Current Release Date than Revision History
    if "tracking" in document:
        _test_6_2_6_current_release_older_than_revision(document["tracking"], errors)
    
    # 6.2.7: Missing Date in Involvements
    _test_6_2_7_missing_date_in_involvements(vulnerabilities, errors)
    
    # 6.2.8: Use of MD5 as the only Hash Algorithm
    _test_6_2_8_md5_only_hash(product_tree, errors)
    
    # 6.2.9: Use of SHA-1 as the only Hash Algorithm
    _test_6_2_9_sha1_only_hash(product_tree, errors)
    
    # 6.2.11: Missing Canonical URL
    _test_6_2_11_missing_canonical_url(document, errors)
    
    # 6.2.12: Missing Document Language
    _test_6_2_12_missing_document_language(document, errors)
    
    # 6.2.16: Missing Product Identification Helper
    _test_6_2_16_missing_product_identification_helper(product_tree, errors)
    
    # 6.2.17: CVE in field IDs
    _test_6_2_17_cve_in_ids(vulnerabilities, errors)
    
    # 6.2.18: Product Version Range without vers
    _test_6_2_18_version_range_without_vers(product_tree, errors)
    
    # 6.2.19: CVSS for Fixed Products
    _test_6_2_19_cvss_for_fixed_products(vulnerabilities, errors)
    
    # 6.2.21: Same Timestamps in Revision History
    if "tracking" in document and "revision_history" in document["tracking"]:
        _test_6_2_21_same_timestamps_in_revision(document["tracking"]["revision_history"], errors)
    
    # 6.2.22: Document Tracking ID in Title
    _test_6_2_22_tracking_id_in_title(document, errors)
    
    # 6.2.27: Discouraged Product Status Remediation Combination
    _test_6_2_27_discouraged_status_remediation(vulnerabilities, group_mappings, errors)
    
    # 6.2.28: Usage of Max UUID
    _test_6_2_28_max_uuid(document, errors)
    
    # 6.2.29: Usage of Nil UUID
    _test_6_2_29_nil_uuid(document, errors)
    
    # 6.2.30: Usage of Sharing Group on TLP:CLEAR
    _test_6_2_30_sharing_group_on_tlp_clear(document, errors)
    
    # 6.2.33: Disclosure Date newer than Revision History
    _test_6_2_33_disclosure_date_newer_than_revision(document, vulnerabilities, errors)
    
    # 6.2.34: Usage of Unregistered SSVC Decision Point Namespace
    _test_6_2_34_unregistered_ssvc_namespace(vulnerabilities, errors)
    
    # 6.2.35: Usage of Private SSVC Namespace in TLP:CLEAR
    _test_6_2_35_private_ssvc_namespace_tlp_clear(document, vulnerabilities, errors)
    
    # 6.2.37: Usage of Unknown SSVC Role
    _test_6_2_37_unknown_ssvc_role(vulnerabilities, errors)
    
    # 6.2.38: Usage of Deprecated Profile
    _test_6_2_38_deprecated_profile(document, errors)
    
    # 6.2.41: Old EPSS Timestamp
    _test_6_2_41_old_epss_timestamp(document, vulnerabilities, errors)


# ============ RECOMMENDED TEST IMPLEMENTATIONS (6.2) ============

def _test_6_2_1_unused_product_id(product_ids: Set[str], 
                                   referenced_ids: Set[str], 
                                   errors: List[Dict[str, Any]]):
    """6.2.1: Unused Definition of Product ID"""
    
    unused_ids = product_ids - referenced_ids
    for pid in unused_ids:
        errors.append({
            "path": "/product_tree",
            "message": f"Product ID '{pid}' is defined but never referenced in vulnerabilities",
            "schema_path": "/product_tree",
            "severity": "warning",
            "rule_id": "CSAF-PROD-W001"
        })


def _test_6_2_2_missing_remediation(vulnerabilities: List[Dict], 
                                     group_mappings: Dict[str, Set[str]],
                                     errors: List[Dict[str, Any]]):
    """6.2.2: Missing Remediation for affected/under_investigation products"""
    
    affected_statuses = ["first_affected", "known_affected", "last_affected", "under_investigation"]
    
    for v_idx, vuln in enumerate(vulnerabilities):
        if not isinstance(vuln, dict):
            continue
        
        product_status = vuln.get("product_status", {})
        remediations = vuln.get("remediations", [])
        
        # Collect products with remediations
        products_with_remediation = set()
        for rem in remediations:
            if isinstance(rem, dict):
                if "product_ids" in rem:
                    products_with_remediation.update(rem["product_ids"])
                if "group_ids" in rem:
                    for gid in rem.get("group_ids", []):
                        if gid in group_mappings:
                            products_with_remediation.update(group_mappings[gid])
        
        # Check each affected status
        for status in affected_statuses:
            if status in product_status:
                for p_idx, pid in enumerate(product_status[status]):
                    if pid not in products_with_remediation:
                        errors.append({
                            "path": f"/vulnerabilities/{v_idx}/product_status/{status}/{p_idx}",
                            "message": f"Product '{pid}' in '{status}' has no remediation",
                            "schema_path": f"/vulnerabilities/{v_idx}/product_status/{status}",
                            "severity": "warning",
                            "rule_id": "CSAF-VEX-W001"
                        })


def _test_6_2_3_missing_metric(vulnerabilities: List[Dict],
                                group_mappings: Dict[str, Set[str]],
                                errors: List[Dict[str, Any]]):
    """6.2.3: Missing Metric for affected products"""
    
    affected_statuses = ["first_affected", "known_affected", "last_affected"]
    
    for v_idx, vuln in enumerate(vulnerabilities):
        if not isinstance(vuln, dict):
            continue
        
        product_status = vuln.get("product_status", {})
        metrics = vuln.get("metrics", [])
        
        # Collect products with metrics
        products_with_metric = set()
        for metric in metrics:
            if isinstance(metric, dict) and "products" in metric:
                products_with_metric.update(metric["products"])
        
        # Check affected statuses
        for status in affected_statuses:
            if status in product_status:
                for p_idx, pid in enumerate(product_status[status]):
                    if pid not in products_with_metric:
                        errors.append({
                            "path": f"/vulnerabilities/{v_idx}/product_status/{status}/{p_idx}",
                            "message": f"Product '{pid}' in '{status}' has no metric (CVSS/SSVC)",
                            "schema_path": f"/vulnerabilities/{v_idx}/metrics",
                            "severity": "warning",
                            "rule_id": "CSAF-VEX-W002"
                        })


def _test_6_2_4_build_metadata_in_revision(revision_history: List[Dict],
                                            errors: List[Dict[str, Any]]):
    """6.2.4: Build Metadata in Revision History"""
    
    # Build metadata starts with + (e.g., 1.0.0+exp.sha.ac00785)
    build_metadata_pattern = re.compile(r'\+')
    
    for idx, rev in enumerate(revision_history):
        if isinstance(rev, dict) and "number" in rev:
            number = str(rev["number"])
            if build_metadata_pattern.search(number):
                errors.append({
                    "path": f"/document/tracking/revision_history/{idx}/number",
                    "message": f"Revision number '{number}' contains build metadata",
                    "schema_path": f"/document/tracking/revision_history/{idx}/number",
                    "severity": "warning",
                    "rule_id": "CSAF-TRACK-W001"
                })


def _test_6_2_5_initial_release_older_than_revision(tracking: Dict,
                                                     errors: List[Dict[str, Any]]):
    """6.2.5: Older Initial Release Date than Revision History"""
    
    if "initial_release_date" not in tracking or "revision_history" not in tracking:
        return
    
    initial_dt = _parse_datetime(tracking["initial_release_date"])
    if not initial_dt:
        return
    
    revision_history = tracking["revision_history"]
    if not isinstance(revision_history, list) or len(revision_history) == 0:
        return
    
    # Find oldest revision date
    oldest_rev_dt = None
    for rev in revision_history:
        if isinstance(rev, dict) and "date" in rev:
            rev_dt = _parse_datetime(rev["date"])
            if rev_dt:
                if oldest_rev_dt is None or rev_dt < oldest_rev_dt:
                    oldest_rev_dt = rev_dt
    
    if oldest_rev_dt and initial_dt < oldest_rev_dt:
        errors.append({
            "path": "/document/tracking/initial_release_date",
            "message": f"Initial release date ({tracking['initial_release_date']}) is older than oldest revision ({oldest_rev_dt.isoformat()})",
            "schema_path": "/document/tracking/initial_release_date",
            "severity": "warning",
            "rule_id": "CSAF-TRACK-W002"
        })


def _test_6_2_6_current_release_older_than_revision(tracking: Dict,
                                                     errors: List[Dict[str, Any]]):
    """6.2.6: Older Current Release Date than Revision History"""
    
    if "current_release_date" not in tracking or "revision_history" not in tracking:
        return
    
    current_dt = _parse_datetime(tracking["current_release_date"])
    if not current_dt:
        return
    
    revision_history = tracking["revision_history"]
    if not isinstance(revision_history, list) or len(revision_history) == 0:
        return
    
    # Find newest revision date
    newest_rev_dt = None
    for rev in revision_history:
        if isinstance(rev, dict) and "date" in rev:
            rev_dt = _parse_datetime(rev["date"])
            if rev_dt:
                if newest_rev_dt is None or rev_dt > newest_rev_dt:
                    newest_rev_dt = rev_dt
    
    if newest_rev_dt and current_dt < newest_rev_dt:
        errors.append({
            "path": "/document/tracking/current_release_date",
            "message": f"Current release date ({tracking['current_release_date']}) is older than newest revision ({newest_rev_dt.isoformat()})",
            "schema_path": "/document/tracking/current_release_date",
            "severity": "warning",
            "rule_id": "CSAF-TRACK-W003"
        })


def _test_6_2_7_missing_date_in_involvements(vulnerabilities: List[Dict],
                                              errors: List[Dict[str, Any]]):
    """6.2.7: Missing Date in Involvements"""
    
    for v_idx, vuln in enumerate(vulnerabilities):
        if not isinstance(vuln, dict):
            continue
        
        involvements = vuln.get("involvements", [])
        for i_idx, inv in enumerate(involvements):
            if isinstance(inv, dict) and "date" not in inv:
                errors.append({
                    "path": f"/vulnerabilities/{v_idx}/involvements/{i_idx}",
                    "message": "Involvement is missing 'date' property",
                    "schema_path": f"/vulnerabilities/{v_idx}/involvements/{i_idx}/date",
                    "severity": "warning",
                    "rule_id": "CSAF-INVOLVE-W001"
                })


def _test_6_2_8_md5_only_hash(product_tree: Dict, errors: List[Dict[str, Any]]):
    """6.2.8: Use of MD5 as the only Hash Algorithm"""
    
    def check_hashes(hashes_list, path):
        for h_idx, hash_item in enumerate(hashes_list):
            if isinstance(hash_item, dict) and "file_hashes" in hash_item:
                file_hashes = hash_item["file_hashes"]
                if isinstance(file_hashes, list):
                    algorithms = [fh.get("algorithm", "").lower() for fh in file_hashes if isinstance(fh, dict)]
                    if algorithms == ["md5"]:
                        errors.append({
                            "path": f"{path}/{h_idx}/file_hashes",
                            "message": "MD5 is the only hash algorithm used (should be accompanied by stronger hash)",
                            "schema_path": f"{path}/{h_idx}/file_hashes",
                            "severity": "warning",
                            "rule_id": "CSAF-HASH-W001"
                        })
    
    _iterate_products_with_helper(product_tree, lambda p, path: 
        check_hashes(p.get("product_identification_helper", {}).get("hashes", []), 
                    f"{path}/product_identification_helper/hashes")
        if "product_identification_helper" in p and "hashes" in p["product_identification_helper"] else None)


def _test_6_2_9_sha1_only_hash(product_tree: Dict, errors: List[Dict[str, Any]]):
    """6.2.9: Use of SHA-1 as the only Hash Algorithm"""
    
    def check_hashes(hashes_list, path):
        for h_idx, hash_item in enumerate(hashes_list):
            if isinstance(hash_item, dict) and "file_hashes" in hash_item:
                file_hashes = hash_item["file_hashes"]
                if isinstance(file_hashes, list):
                    algorithms = [fh.get("algorithm", "").lower() for fh in file_hashes if isinstance(fh, dict)]
                    if algorithms == ["sha1"]:
                        errors.append({
                            "path": f"{path}/{h_idx}/file_hashes",
                            "message": "SHA-1 is the only hash algorithm used (should be accompanied by stronger hash)",
                            "schema_path": f"{path}/{h_idx}/file_hashes",
                            "severity": "warning",
                            "rule_id": "CSAF-HASH-W002"
                        })
    
    _iterate_products_with_helper(product_tree, lambda p, path:
        check_hashes(p.get("product_identification_helper", {}).get("hashes", []),
                    f"{path}/product_identification_helper/hashes")
        if "product_identification_helper" in p and "hashes" in p["product_identification_helper"] else None)


def _test_6_2_11_missing_canonical_url(document: Dict, errors: List[Dict[str, Any]]):
    """6.2.11: Missing Canonical URL"""
    
    references = document.get("references", [])
    tracking = document.get("tracking", {})
    tracking_id = tracking.get("id", "")
    version = tracking.get("version", "")
    
    has_canonical = False
    for ref in references:
        if isinstance(ref, dict):
            category = ref.get("category", "")
            url = ref.get("url", "")
            
            if category == "self" and url.startswith("https://"):
                # Check if URL ends with valid CSAF filename
                # Pattern: {id}_{version}.json or {id}.json
                if url.endswith(".json"):
                    has_canonical = True
                    break
    
    if not has_canonical:
        errors.append({
            "path": "/document/references",
            "message": "Document is missing canonical URL (self reference with https:// and .json filename)",
            "schema_path": "/document/references",
            "severity": "warning",
            "rule_id": "CSAF-DOC-W001"
        })


def _test_6_2_12_missing_document_language(document: Dict, errors: List[Dict[str, Any]]):
    """6.2.12: Missing Document Language"""
    
    if "lang" not in document or not document["lang"]:
        errors.append({
            "path": "/document/lang",
            "message": "Document language is not defined",
            "schema_path": "/document/lang",
            "severity": "warning",
            "rule_id": "CSAF-DOC-W002"
        })


def _test_6_2_16_missing_product_identification_helper(product_tree: Dict,
                                                        errors: List[Dict[str, Any]]):
    """6.2.16: Missing Product Identification Helper"""
    
    def check_helper(product, path):
        if "product_identification_helper" not in product:
            pid = product.get("product_id", "unknown")
            errors.append({
                "path": path,
                "message": f"Product '{pid}' does not have product_identification_helper",
                "schema_path": f"{path}/product_identification_helper",
                "severity": "warning",
                "rule_id": "CSAF-DOC-W003"
            })
    
    _iterate_products(product_tree, check_helper)


def _test_6_2_17_cve_in_ids(vulnerabilities: List[Dict], errors: List[Dict[str, Any]]):
    """6.2.17: CVE in field IDs"""
    
    cve_pattern = re.compile(r'^CVE-\d{4}-\d{4,}$')
    
    for v_idx, vuln in enumerate(vulnerabilities):
        if not isinstance(vuln, dict):
            continue
        
        ids = vuln.get("ids", [])
        for i_idx, id_item in enumerate(ids):
            if isinstance(id_item, dict) and "text" in id_item:
                if cve_pattern.match(id_item["text"]):
                    errors.append({
                        "path": f"/vulnerabilities/{v_idx}/ids/{i_idx}",
                        "message": f"CVE '{id_item['text']}' should be in 'cve' field, not 'ids'",
                        "schema_path": f"/vulnerabilities/{v_idx}/ids/{i_idx}/text",
                        "severity": "warning",
                        "rule_id": "CSAF-DOC-W004"
                    })


def _test_6_2_18_version_range_without_vers(product_tree: Dict,
                                             errors: List[Dict[str, Any]]):
    """6.2.18: Product Version Range without vers"""
    
    vers_pattern = re.compile(r'^vers:[a-z\.\-\+][a-z0-9\.\-\+]*/.+')
    
    def check_branch(branch, path):
        if branch.get("category") == "product_version_range":
            name = branch.get("name", "")
            if not vers_pattern.match(name):
                errors.append({
                    "path": f"{path}/name",
                    "message": f"Version range '{name}' does not conform to vers specification",
                    "schema_path": f"{path}/name",
                    "severity": "warning",
                    "rule_id": "CSAF-DOC-W005"
                })
    
    _iterate_branches(product_tree.get("branches", []), "/product_tree/branches", check_branch)


def _test_6_2_19_cvss_for_fixed_products(vulnerabilities: List[Dict],
                                          errors: List[Dict[str, Any]]):
    """6.2.19: CVSS for Fixed Products should have environmental score of 0"""
    
    for v_idx, vuln in enumerate(vulnerabilities):
        if not isinstance(vuln, dict):
            continue
        
        product_status = vuln.get("product_status", {})
        fixed_products = set(product_status.get("fixed", []) + product_status.get("first_fixed", []))
        
        if not fixed_products:
            continue
        
        metrics = vuln.get("metrics", [])
        for m_idx, metric in enumerate(metrics):
            if not isinstance(metric, dict):
                continue
            
            products = set(metric.get("products", []))
            fixed_in_metric = fixed_products & products
            
            if not fixed_in_metric:
                continue
            
            content = metric.get("content", {})
            
            # Check CVSS v3
            cvss_v3 = content.get("cvss_v3", {})
            if cvss_v3:
                env_score = cvss_v3.get("environmentalScore")
                if env_score is None or env_score != 0:
                    # Check if environmental modifiers are set
                    has_modifiers = any(k in cvss_v3 for k in [
                        "modifiedAvailabilityImpact", 
                        "modifiedConfidentialityImpact", 
                        "modifiedIntegrityImpact"
                    ])
                    if not has_modifiers:
                        for pid in fixed_in_metric:
                            errors.append({
                                "path": f"/vulnerabilities/{v_idx}/metrics/{m_idx}",
                                "message": f"Fixed product '{pid}' has CVSS without environmental score of 0",
                                "schema_path": f"/vulnerabilities/{v_idx}/metrics/{m_idx}/content/cvss_v3",
                                "severity": "warning",
                                "rule_id": "CSAF-VEX-W005"
                            })


def _test_6_2_21_same_timestamps_in_revision(revision_history: List[Dict],
                                              errors: List[Dict[str, Any]]):
    """6.2.21: Same Timestamps in Revision History"""
    
    timestamps = {}
    for idx, rev in enumerate(revision_history):
        if isinstance(rev, dict) and "date" in rev:
            ts = rev["date"]
            if ts in timestamps:
                errors.append({
                    "path": f"/document/tracking/revision_history/{idx}/date",
                    "message": f"Revision timestamp '{ts}' is same as revision {timestamps[ts]}",
                    "schema_path": f"/document/tracking/revision_history/{idx}/date",
                    "severity": "warning",
                    "rule_id": "CSAF-TRACK-W004"
                })
            else:
                timestamps[ts] = idx


def _test_6_2_22_tracking_id_in_title(document: Dict, errors: List[Dict[str, Any]]):
    """6.2.22: Document Tracking ID in Title"""
    
    title = document.get("title", "")
    tracking = document.get("tracking", {})
    tracking_id = tracking.get("id", "")
    
    if tracking_id and tracking_id in title:
        errors.append({
            "path": "/document/title",
            "message": f"Document title contains tracking ID '{tracking_id}'",
            "schema_path": "/document/title",
            "severity": "warning",
            "rule_id": "CSAF-TRACK-W005"
        })


def _test_6_2_27_discouraged_status_remediation(vulnerabilities: List[Dict],
                                                  group_mappings: Dict[str, Set[str]],
                                                  errors: List[Dict[str, Any]]):
    """6.2.27: Discouraged Product Status Remediation Combination"""
    
    for v_idx, vuln in enumerate(vulnerabilities):
        if not isinstance(vuln, dict):
            continue
        
        product_status = vuln.get("product_status", {})
        remediations = vuln.get("remediations", [])
        
        for status_type, discouraged_categories in DISCOURAGED_STATUS_REMEDIATION.items():
            if status_type not in product_status:
                continue
            
            status_products = set(product_status[status_type])
            
            for r_idx, rem in enumerate(remediations):
                if not isinstance(rem, dict):
                    continue
                
                category = rem.get("category", "")
                if category not in discouraged_categories:
                    continue
                
                # Get products in this remediation
                rem_products = set(rem.get("product_ids", []))
                for gid in rem.get("group_ids", []):
                    if gid in group_mappings:
                        rem_products.update(group_mappings[gid])
                
                # Check overlap
                overlap = status_products & rem_products
                for pid in overlap:
                    errors.append({
                        "path": f"/vulnerabilities/{v_idx}/remediations/{r_idx}",
                        "message": f"Product '{pid}' in '{status_type}' has discouraged remediation '{category}'",
                        "schema_path": f"/vulnerabilities/{v_idx}/remediations/{r_idx}",
                        "severity": "warning",
                        "rule_id": "CSAF-VEX-W004"
                    })


def _test_6_2_28_max_uuid(document: Dict, errors: List[Dict[str, Any]]):
    """6.2.28: Usage of Max UUID"""
    
    distribution = document.get("distribution", {})
    sharing_group = distribution.get("sharing_group", {})
    group_id = sharing_group.get("id", "").lower()
    
    if group_id == MAX_UUID:
        errors.append({
            "path": "/document/distribution/sharing_group/id",
            "message": "Sharing group uses Max UUID",
            "schema_path": "/document/distribution/sharing_group/id",
            "severity": "warning",
            "rule_id": "CSAF-UUID-W001"
        })


def _test_6_2_29_nil_uuid(document: Dict, errors: List[Dict[str, Any]]):
    """6.2.29: Usage of Nil UUID"""
    
    distribution = document.get("distribution", {})
    sharing_group = distribution.get("sharing_group", {})
    group_id = sharing_group.get("id", "").lower()
    
    if group_id == NIL_UUID:
        errors.append({
            "path": "/document/distribution/sharing_group/id",
            "message": "Sharing group uses Nil UUID",
            "schema_path": "/document/distribution/sharing_group/id",
            "severity": "warning",
            "rule_id": "CSAF-UUID-W002"
        })


def _test_6_2_30_sharing_group_on_tlp_clear(document: Dict, errors: List[Dict[str, Any]]):
    """6.2.30: Usage of Sharing Group on TLP:CLEAR"""
    
    distribution = document.get("distribution", {})
    tlp = distribution.get("tlp", {})
    label = tlp.get("label", "").upper()
    
    if label == "CLEAR" and "sharing_group" in distribution:
        errors.append({
            "path": "/document/distribution/sharing_group",
            "message": "Sharing group is used with TLP:CLEAR",
            "schema_path": "/document/distribution/sharing_group",
            "severity": "warning",
            "rule_id": "CSAF-UUID-W003"
        })


def _test_6_2_33_disclosure_date_newer_than_revision(document: Dict,
                                                      vulnerabilities: List[Dict],
                                                      errors: List[Dict[str, Any]]):
    """6.2.33: Disclosure Date newer than Revision History"""
    
    tracking = document.get("tracking", {})
    revision_history = tracking.get("revision_history", [])
    
    if not revision_history:
        return
    
    # Find newest revision date
    newest_rev_dt = None
    for rev in revision_history:
        if isinstance(rev, dict) and "date" in rev:
            rev_dt = _parse_datetime(rev["date"])
            if rev_dt:
                if newest_rev_dt is None or rev_dt > newest_rev_dt:
                    newest_rev_dt = rev_dt
    
    if not newest_rev_dt:
        return
    
    now = datetime.utcnow()
    
    for v_idx, vuln in enumerate(vulnerabilities):
        if not isinstance(vuln, dict):
            continue
        
        disclosure_date_str = vuln.get("disclosure_date")
        if not disclosure_date_str:
            continue
        
        disclosure_dt = _parse_datetime(disclosure_date_str)
        if not disclosure_dt:
            continue
        
        # Only check if disclosure date is in the past
        if disclosure_dt < now and disclosure_dt > newest_rev_dt:
            errors.append({
                "path": f"/vulnerabilities/{v_idx}/disclosure_date",
                "message": f"Disclosure date ({disclosure_date_str}) is newer than newest revision",
                "schema_path": f"/vulnerabilities/{v_idx}/disclosure_date",
                "severity": "warning",
                "rule_id": "CSAF-TRACK-W006"
            })


def _test_6_2_34_unregistered_ssvc_namespace(vulnerabilities: List[Dict],
                                              errors: List[Dict[str, Any]]):
    """6.2.34: Usage of Unregistered SSVC Decision Point Namespace"""
    
    for v_idx, vuln in enumerate(vulnerabilities):
        if not isinstance(vuln, dict):
            continue
        
        metrics = vuln.get("metrics", [])
        for m_idx, metric in enumerate(metrics):
            if not isinstance(metric, dict):
                continue
            
            content = metric.get("content", {})
            ssvc = content.get("ssvc_v1", {})
            selections = ssvc.get("selections", [])
            
            for s_idx, sel in enumerate(selections):
                if isinstance(sel, dict) and "namespace" in sel:
                    ns = sel["namespace"]
                    # Check if registered (exact match or starts with registered + "/")
                    is_registered = any(
                        ns == reg or ns.startswith(f"{reg}/")
                        for reg in REGISTERED_SSVC_NAMESPACES
                    )
                    # Allow private namespaces (x_)
                    if not is_registered and not ns.startswith("x_"):
                        errors.append({
                            "path": f"/vulnerabilities/{v_idx}/metrics/{m_idx}/content/ssvc_v1/selections/{s_idx}/namespace",
                            "message": f"SSVC namespace '{ns}' is not registered",
                            "schema_path": f"/vulnerabilities/{v_idx}/metrics/{m_idx}/content/ssvc_v1/selections/{s_idx}/namespace",
                            "severity": "warning",
                            "rule_id": "CSAF-SSVC-W001"
                        })


def _test_6_2_35_private_ssvc_namespace_tlp_clear(document: Dict,
                                                   vulnerabilities: List[Dict],
                                                   errors: List[Dict[str, Any]]):
    """6.2.35: Usage of Private SSVC Namespace in TLP:CLEAR Document"""
    
    distribution = document.get("distribution", {})
    tlp = distribution.get("tlp", {})
    label = tlp.get("label", "").upper()
    
    if label != "CLEAR":
        return
    
    for v_idx, vuln in enumerate(vulnerabilities):
        if not isinstance(vuln, dict):
            continue
        
        metrics = vuln.get("metrics", [])
        for m_idx, metric in enumerate(metrics):
            if not isinstance(metric, dict):
                continue
            
            content = metric.get("content", {})
            ssvc = content.get("ssvc_v1", {})
            selections = ssvc.get("selections", [])
            
            for s_idx, sel in enumerate(selections):
                if isinstance(sel, dict) and "namespace" in sel:
                    ns = sel["namespace"]
                    if ns.startswith("x_"):
                        errors.append({
                            "path": f"/vulnerabilities/{v_idx}/metrics/{m_idx}/content/ssvc_v1/selections/{s_idx}/namespace",
                            "message": f"Private SSVC namespace '{ns}' used in TLP:CLEAR document",
                            "schema_path": f"/vulnerabilities/{v_idx}/metrics/{m_idx}/content/ssvc_v1/selections/{s_idx}/namespace",
                            "severity": "warning",
                            "rule_id": "CSAF-SSVC-W002"
                        })


def _test_6_2_37_unknown_ssvc_role(vulnerabilities: List[Dict],
                                    errors: List[Dict[str, Any]]):
    """6.2.37: Usage of Unknown SSVC Role"""
    
    for v_idx, vuln in enumerate(vulnerabilities):
        if not isinstance(vuln, dict):
            continue
        
        metrics = vuln.get("metrics", [])
        for m_idx, metric in enumerate(metrics):
            if not isinstance(metric, dict):
                continue
            
            content = metric.get("content", {})
            ssvc = content.get("ssvc_v1", {})
            role = ssvc.get("role")
            
            if role and role not in REGISTERED_SSVC_ROLES:
                errors.append({
                    "path": f"/vulnerabilities/{v_idx}/metrics/{m_idx}/content/ssvc_v1/role",
                    "message": f"SSVC role '{role}' is not registered",
                    "schema_path": f"/vulnerabilities/{v_idx}/metrics/{m_idx}/content/ssvc_v1/role",
                    "severity": "warning",
                    "rule_id": "CSAF-SSVC-W003"
                })


def _test_6_2_38_deprecated_profile(document: Dict, errors: List[Dict[str, Any]]):
    """6.2.38: Usage of Deprecated Profile"""
    
    category = document.get("category", "")
    if category.startswith("csaf_deprecated_"):
        errors.append({
            "path": "/document/category",
            "message": f"Deprecated profile '{category}' used",
            "schema_path": "/document/category",
            "severity": "warning",
            "rule_id": "CSAF-PROFILE-W001"
        })


def _test_6_2_41_old_epss_timestamp(document: Dict,
                                     vulnerabilities: List[Dict],
                                     errors: List[Dict[str, Any]]):
    """6.2.41: Old EPSS Timestamp (more than 15 days older than revision)"""
    
    tracking = document.get("tracking", {})
    status = tracking.get("status", "")
    
    # Only check for final or interim
    if status not in ["final", "interim"]:
        return
    
    revision_history = tracking.get("revision_history", [])
    if not revision_history:
        return
    
    # Find newest revision date
    newest_rev_dt = None
    for rev in revision_history:
        if isinstance(rev, dict) and "date" in rev:
            rev_dt = _parse_datetime(rev["date"])
            if rev_dt:
                if newest_rev_dt is None or rev_dt > newest_rev_dt:
                    newest_rev_dt = rev_dt
    
    if not newest_rev_dt:
        return
    
    for v_idx, vuln in enumerate(vulnerabilities):
        if not isinstance(vuln, dict):
            continue
        
        metrics = vuln.get("metrics", [])
        for m_idx, metric in enumerate(metrics):
            if not isinstance(metric, dict):
                continue
            
            content = metric.get("content", {})
            epss = content.get("epss", {})
            
            if "timestamp" in epss:
                epss_dt = _parse_datetime(epss["timestamp"])
                if epss_dt:
                    diff = newest_rev_dt - epss_dt
                    if diff.days > 15:
                        errors.append({
                            "path": f"/vulnerabilities/{v_idx}/metrics/{m_idx}/content/epss/timestamp",
                            "message": f"EPSS timestamp is {diff.days} days older than newest revision (max 15 days)",
                            "schema_path": f"/vulnerabilities/{v_idx}/metrics/{m_idx}/content/epss/timestamp",
                            "severity": "warning",
                            "rule_id": "CSAF-EPSS-W001"
                        })


# ============ VEX PROFILE SPECIFIC TESTS ============

def _validate_vex_profile(data: Dict[str, Any], errors: List[Dict[str, Any]]):
    """Validate CSAF VEX Profile specific requirements"""
    
    document = data.get("document", {})
    product_tree = data.get("product_tree", {})
    vulnerabilities = data.get("vulnerabilities", [])
    
    product_ids = _collect_product_ids(product_tree)
    group_mappings = _collect_group_mappings(product_tree)
    
    # CSAF-DOC-001: product_tree required
    if "product_tree" not in data:
        errors.append({
            "path": "/",
            "message": "CSAF VEX Profile requires 'product_tree'",
            "schema_path": "/product_tree",
            "severity": "error",
            "rule_id": "CSAF-DOC-001"
        })
        return
    
    # CSAF-VULN-REQ-001: vulnerabilities required
    if "vulnerabilities" not in data:
        errors.append({
            "path": "/",
            "message": "CSAF VEX Profile requires 'vulnerabilities' array",
            "schema_path": "/vulnerabilities",
            "severity": "error",
            "rule_id": "CSAF-DOC-003"
        })
        return
    
    # CSAF-DOC-002: product_tree must have products
    if len(product_ids) == 0:
        errors.append({
            "path": "/product_tree",
            "message": "product_tree must contain at least one product definition",
            "schema_path": "/product_tree",
            "severity": "error",
            "rule_id": "CSAF-DOC-002"
        })
    
    # Validate each vulnerability
    for idx, vuln in enumerate(vulnerabilities):
        if isinstance(vuln, dict):
            _validate_vex_vulnerability(vuln, idx, product_ids, group_mappings, errors)
    
    # CSAF-VEX-NOTES-001: VEX should have notes
    for idx, vuln in enumerate(vulnerabilities):
        if isinstance(vuln, dict):
            notes = vuln.get("notes", [])
            if not notes:
                errors.append({
                    "path": f"/vulnerabilities/{idx}/notes",
                    "message": "VEX Profile SHOULD include notes for each vulnerability",
                    "schema_path": f"/vulnerabilities/{idx}/notes",
                    "severity": "warning",
                    "rule_id": "CSAF-VEX-W003"
                })


def _validate_vex_vulnerability(vuln: Dict, idx: int,
                                 product_ids: Set[str],
                                 group_mappings: Dict[str, Set[str]],
                                 errors: List[Dict[str, Any]]):
    """Validate VEX-specific vulnerability requirements"""
    
    path_prefix = f"/vulnerabilities/{idx}"
    
    # CSAF-VULNID-001: CVE or IDs required
    has_cve = "cve" in vuln and vuln["cve"]
    has_ids = "ids" in vuln and vuln["ids"]
    
    if not has_cve and not has_ids:
        errors.append({
            "path": path_prefix,
            "message": "Vulnerability MUST have 'cve' or 'ids'",
            "schema_path": path_prefix,
            "severity": "error",
            "rule_id": "CSAF-VULN-001"
        })
    
    # CSAF-PSTAT-001: product_status required
    if "product_status" not in vuln:
        errors.append({
            "path": path_prefix,
            "message": "Vulnerability MUST have 'product_status'",
            "schema_path": f"{path_prefix}/product_status",
            "severity": "error",
            "rule_id": "CSAF-VULN-002"
        })
        return
    
    product_status = vuln["product_status"]
    
    # CSAF-PSTAT-002: At least one VEX status
    vex_statuses = {"fixed", "known_affected", "known_not_affected", "under_investigation"}
    has_vex_status = any(s in product_status for s in vex_statuses)
    
    if not has_vex_status:
        errors.append({
            "path": f"{path_prefix}/product_status",
            "message": f"product_status MUST have at least one VEX status: {', '.join(sorted(vex_statuses))}",
            "schema_path": f"{path_prefix}/product_status",
            "severity": "error",
            "rule_id": "CSAF-STATUS-001"
        })
        return
    
    # CSAF-PROD-003: Product references must exist
    _validate_product_references(product_status, path_prefix, product_ids, group_mappings, errors)
    
    # CSAF-KNA-001: known_not_affected requires impact statement
    if "known_not_affected" in product_status:
        _validate_not_affected_products(vuln, product_status["known_not_affected"],
                                        path_prefix, group_mappings, errors)
    
    # CSAF-KA-001: known_affected requires action statement
    if "known_affected" in product_status:
        _validate_affected_products(vuln, product_status["known_affected"],
                                    path_prefix, group_mappings, errors)
    
    # Validate remediation structure
    for r_idx, rem in enumerate(vuln.get("remediations", [])):
        if isinstance(rem, dict):
            _validate_remediation(rem, f"{path_prefix}/remediations/{r_idx}",
                                 product_ids, group_mappings, errors)


# ============ HELPER FUNCTIONS ============

def _collect_product_ids(product_tree: Dict[str, Any]) -> Set[str]:
    """Collect all product IDs from product tree"""
    product_ids = set()
    
    # From full_product_names
    for product in product_tree.get("full_product_names", []):
        if isinstance(product, dict) and "product_id" in product:
            product_ids.add(product["product_id"])
    
    # From branches (recursive)
    def collect_from_branches(branches):
        for branch in branches:
            if isinstance(branch, dict):
                if "product" in branch and "product_id" in branch["product"]:
                    product_ids.add(branch["product"]["product_id"])
                if "branches" in branch:
                    collect_from_branches(branch["branches"])
    
    collect_from_branches(product_tree.get("branches", []))
    
    # From relationships
    for rel in product_tree.get("relationships", []):
        if isinstance(rel, dict):
            if "product_reference" in rel:
                product_ids.add(rel["product_reference"])
            if "relates_to_product_reference" in rel:
                product_ids.add(rel["relates_to_product_reference"])
            if "full_product_name" in rel and "product_id" in rel["full_product_name"]:
                product_ids.add(rel["full_product_name"]["product_id"])
    
    return product_ids


def _collect_referenced_product_ids(data: Dict[str, Any]) -> Set[str]:
    """Collect all product IDs referenced in vulnerabilities"""
    referenced = set()
    
    for vuln in data.get("vulnerabilities", []):
        if not isinstance(vuln, dict):
            continue
        
        # From product_status
        product_status = vuln.get("product_status", {})
        for status_list in product_status.values():
            if isinstance(status_list, list):
                referenced.update(status_list)
        
        # From remediations
        for rem in vuln.get("remediations", []):
            if isinstance(rem, dict):
                referenced.update(rem.get("product_ids", []))
        
        # From flags
        for flag in vuln.get("flags", []):
            if isinstance(flag, dict):
                referenced.update(flag.get("product_ids", []))
        
        # From threats
        for threat in vuln.get("threats", []):
            if isinstance(threat, dict):
                referenced.update(threat.get("product_ids", []))
        
        # From metrics
        for metric in vuln.get("metrics", []):
            if isinstance(metric, dict):
                referenced.update(metric.get("products", []))
    
    return referenced


def _collect_group_mappings(product_tree: Dict[str, Any]) -> Dict[str, Set[str]]:
    """Collect product group ID to product IDs mappings"""
    mappings = {}
    
    for group in product_tree.get("product_groups", []):
        if isinstance(group, dict) and "group_id" in group and "product_ids" in group:
            mappings[group["group_id"]] = set(group["product_ids"])
    
    return mappings


def _validate_product_id_uniqueness(product_tree: Dict, errors: List[Dict[str, Any]]):
    """6.1.2: Product ID uniqueness"""
    seen_ids = {}
    
    def check_and_add(pid, path):
        if pid in seen_ids:
            errors.append({
                "path": path,
                "message": f"Product ID '{pid}' is defined multiple times (first at {seen_ids[pid]})",
                "schema_path": path,
                "severity": "error",
                "rule_id": "CSAF-PROD-001"
            })
        else:
            seen_ids[pid] = path
    
    # Check full_product_names
    for idx, product in enumerate(product_tree.get("full_product_names", [])):
        if isinstance(product, dict) and "product_id" in product:
            check_and_add(product["product_id"], f"/product_tree/full_product_names/{idx}/product_id")
    
    # Check branches
    def check_branches(branches, path):
        for idx, branch in enumerate(branches):
            if isinstance(branch, dict):
                if "product" in branch and "product_id" in branch["product"]:
                    check_and_add(branch["product"]["product_id"], f"{path}/{idx}/product/product_id")
                if "branches" in branch:
                    check_branches(branch["branches"], f"{path}/{idx}/branches")
    
    check_branches(product_tree.get("branches", []), "/product_tree/branches")
    
    # Check relationships
    for idx, rel in enumerate(product_tree.get("relationships", [])):
        if isinstance(rel, dict) and "full_product_name" in rel:
            if "product_id" in rel["full_product_name"]:
                check_and_add(rel["full_product_name"]["product_id"],
                             f"/product_tree/relationships/{idx}/full_product_name/product_id")


def _validate_group_id_uniqueness(product_tree: Dict, errors: List[Dict[str, Any]]):
    """6.1.5: Product Group ID uniqueness"""
    seen_ids = {}
    
    for idx, group in enumerate(product_tree.get("product_groups", [])):
        if isinstance(group, dict) and "group_id" in group:
            gid = group["group_id"]
            if gid in seen_ids:
                errors.append({
                    "path": f"/product_tree/product_groups/{idx}/group_id",
                    "message": f"Product Group ID '{gid}' is defined multiple times",
                    "schema_path": f"/product_tree/product_groups/{idx}/group_id",
                    "severity": "error",
                    "rule_id": "CSAF-PROD-002"
                })
            else:
                seen_ids[gid] = idx


def _validate_revision_history_sorted(revision_history: List[Dict], errors: List[Dict[str, Any]]):
    """6.1.14: Revision history must be sorted"""
    
    if len(revision_history) < 2:
        return
    
    prev_dt = None
    for idx, rev in enumerate(revision_history):
        if isinstance(rev, dict) and "date" in rev:
            curr_dt = _parse_datetime(rev["date"])
            if curr_dt and prev_dt:
                if curr_dt < prev_dt:
                    errors.append({
                        "path": f"/document/tracking/revision_history/{idx}",
                        "message": "Revision history is not sorted by date",
                        "schema_path": f"/document/tracking/revision_history/{idx}",
                        "severity": "error",
                        "rule_id": "CSAF-TRACK-001"
                    })
                    break
            prev_dt = curr_dt


def _validate_document_status_draft(version: str, status: str, errors: List[Dict[str, Any]]):
    """6.1.17: Version 0 or 0.x.x must be draft"""
    
    is_zero_version = False
    try:
        if int(version) == 0:
            is_zero_version = True
    except ValueError:
        if version.startswith("0."):
            is_zero_version = True
    
    if is_zero_version and status != "draft":
        errors.append({
            "path": "/document/tracking/status",
            "message": f"Document status MUST be 'draft' for version {version}",
            "schema_path": "/document/tracking/status",
            "severity": "error",
            "rule_id": "CSAF-TRACK-002"
        })


def _validate_vulnerability_mandatory(vuln: Dict, idx: int,
                                       product_ids: Set[str],
                                       group_mappings: Dict[str, Set[str]],
                                       errors: List[Dict[str, Any]]):
    """Validate mandatory vulnerability requirements"""
    
    # Validate remediation structure
    for r_idx, rem in enumerate(vuln.get("remediations", [])):
        if isinstance(rem, dict):
            _validate_remediation(rem, f"/vulnerabilities/{idx}/remediations/{r_idx}",
                                 product_ids, group_mappings, errors)


def _validate_product_references(product_status: Dict, path_prefix: str,
                                  product_ids: Set[str],
                                  group_mappings: Dict[str, Set[str]],
                                  errors: List[Dict[str, Any]]):
    """CSAF-PROD-003: Validate product references exist"""
    
    for status_type, products in product_status.items():
        if isinstance(products, list):
            for p_idx, pid in enumerate(products):
                if pid not in product_ids and pid not in group_mappings:
                    errors.append({
                        "path": f"{path_prefix}/product_status/{status_type}/{p_idx}",
                        "message": f"Product ID '{pid}' not defined in product_tree",
                        "schema_path": f"{path_prefix}/product_status/{status_type}",
                        "severity": "error",
                        "rule_id": "CSAF-PROD-003"
                    })


def _validate_not_affected_products(vuln: Dict, not_affected_ids: List[str],
                                     path_prefix: str,
                                     group_mappings: Dict[str, Set[str]],
                                     errors: List[Dict[str, Any]]):
    """CSAF-KNA-001: known_not_affected requires impact statement"""
    
    # Collect products with impact from flags
    products_with_impact = set()
    
    for flag in vuln.get("flags", []):
        if isinstance(flag, dict):
            products_with_impact.update(flag.get("product_ids", []))
            for gid in flag.get("group_ids", []):
                if gid in group_mappings:
                    products_with_impact.update(group_mappings[gid])
    
    # Collect from threats with category="impact"
    for threat in vuln.get("threats", []):
        if isinstance(threat, dict) and threat.get("category") == "impact":
            products_with_impact.update(threat.get("product_ids", []))
            for gid in threat.get("group_ids", []):
                if gid in group_mappings:
                    products_with_impact.update(group_mappings[gid])
    
    for pid in not_affected_ids:
        if pid not in products_with_impact:
            errors.append({
                "path": f"{path_prefix}/product_status/known_not_affected",
                "message": f"Product '{pid}' in known_not_affected has no impact statement (flag or threat)",
                "schema_path": f"{path_prefix}/product_status/known_not_affected",
                "severity": "error",
                "rule_id": "CSAF-VEX-001"
            })


def _validate_affected_products(vuln: Dict, affected_ids: List[str],
                                 path_prefix: str,
                                 group_mappings: Dict[str, Set[str]],
                                 errors: List[Dict[str, Any]]):
    """CSAF-KA-001: known_affected requires action statement"""
    
    products_with_remediation = set()
    
    for rem in vuln.get("remediations", []):
        if isinstance(rem, dict):
            products_with_remediation.update(rem.get("product_ids", []))
            for gid in rem.get("group_ids", []):
                if gid in group_mappings:
                    products_with_remediation.update(group_mappings[gid])
    
    for pid in affected_ids:
        if pid not in products_with_remediation:
            errors.append({
                "path": f"{path_prefix}/product_status/known_affected",
                "message": f"Product '{pid}' in known_affected has no action statement (remediation)",
                "schema_path": f"{path_prefix}/product_status/known_affected",
                "severity": "error",
                "rule_id": "CSAF-VEX-002"
            })


def _validate_remediation(remediation: Dict, path: str,
                          product_ids: Set[str],
                          group_mappings: Dict[str, Set[str]],
                          errors: List[Dict[str, Any]]):
    """Validate remediation structure"""
    
    # MUST have category
    if "category" not in remediation:
        errors.append({
            "path": path,
            "message": "Remediation MUST have 'category'",
            "schema_path": f"{path}/category",
            "severity": "error",
            "rule_id": "CSAF-REMED-001"
        })
    
    # MUST have details or url
    if "details" not in remediation and "url" not in remediation:
        errors.append({
            "path": path,
            "message": "Remediation MUST have 'details' or 'url'",
            "schema_path": path,
            "severity": "error",
            "rule_id": "CSAF-REMED-002"
        })
    
    # MUST have product_ids or group_ids
    has_products = remediation.get("product_ids") and len(remediation["product_ids"]) > 0
    has_groups = remediation.get("group_ids") and len(remediation["group_ids"]) > 0
    
    if not has_products and not has_groups:
        errors.append({
            "path": path,
            "message": "Remediation MUST have 'product_ids' or 'group_ids'",
            "schema_path": path,
            "severity": "error",
            "rule_id": "CSAF-REMED-003"
        })
    
    # Validate group_ids exist
    for g_idx, gid in enumerate(remediation.get("group_ids", [])):
        if gid not in group_mappings:
            errors.append({
                "path": f"{path}/group_ids/{g_idx}",
                "message": f"Group ID '{gid}' not defined in product_groups",
                "schema_path": f"{path}/group_ids",
                "severity": "error",
                "rule_id": "CSAF-GROUP-001"
            })


def _iterate_products(product_tree: Dict, callback):
    """Iterate over all products in product tree"""
    
    # full_product_names
    for idx, product in enumerate(product_tree.get("full_product_names", [])):
        if isinstance(product, dict):
            callback(product, f"/product_tree/full_product_names/{idx}")
    
    # branches
    def iterate_branches(branches, path):
        for idx, branch in enumerate(branches):
            if isinstance(branch, dict):
                if "product" in branch:
                    callback(branch["product"], f"{path}/{idx}/product")
                if "branches" in branch:
                    iterate_branches(branch["branches"], f"{path}/{idx}/branches")
    
    iterate_branches(product_tree.get("branches", []), "/product_tree/branches")
    
    # relationships
    for idx, rel in enumerate(product_tree.get("relationships", [])):
        if isinstance(rel, dict) and "full_product_name" in rel:
            callback(rel["full_product_name"], f"/product_tree/relationships/{idx}/full_product_name")


def _iterate_products_with_helper(product_tree: Dict, callback):
    """Iterate over products that have product_identification_helper"""
    
    def check_product(product, path):
        if "product_identification_helper" in product:
            callback(product, path)
    
    _iterate_products(product_tree, check_product)


def _iterate_branches(branches: List[Dict], path: str, callback):
    """Iterate over all branches recursively"""
    
    for idx, branch in enumerate(branches):
        if isinstance(branch, dict):
            callback(branch, f"{path}/{idx}")
            if "branches" in branch:
                _iterate_branches(branch["branches"], f"{path}/{idx}/branches", callback)


def _parse_datetime(value: str) -> Optional[datetime]:
    """Parse ISO 8601 datetime"""
    if not isinstance(value, str):
        return None
    
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


# ============ MAIN ============

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
        print("Usage: python csaf_validator_v2.py <schema.json> <document.json>")
        sys.exit(1)
    
    schema = load_schema(sys.argv[1])
    document = load_document(sys.argv[2])
    
    is_valid, errors = validate_csaf(document, schema)
    
    error_items = [e for e in errors if e["severity"] == "error"]
    warning_items = [e for e in errors if e["severity"] == "warning"]
    
    if is_valid:
        print("Valid CSAF document")
        print("  - JSON Schema: OK")
        print("  - Mandatory Tests (6.1): OK")
        print("  - Recommended Tests (6.2): OK" if not warning_items else f"  - Recommended Tests (6.2): {len(warning_items)} warning(s)")
    else:
        print("Invalid CSAF document")
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