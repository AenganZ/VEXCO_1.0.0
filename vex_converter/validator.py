"""
Validator and Loss Analyzer
"""
import json
from typing import Dict, List, Any, Set, Optional

from jsonschema import ValidationError
from .models import CIM, TrackingTable, DocumentFormat
from .constants import MAPPING_TABLE
from .utils import extract_all_fields, normalize_field_path

class Validator:
    @staticmethod
    def validate_input(data: Dict, format_name: str):
        if format_name == "OpenVEX":
            if "@context" not in data:
                raise ValidationError("Missing @context in OpenVEX document")
            if "statements" not in data:
                raise ValidationError("Missing statements in OpenVEX document")

        elif format_name == "CycloneDX":
            if "bomFormat" not in data or data["bomFormat"] != "CycloneDX":
                raise ValidationError("Invalid CycloneDX document")
            if "vulnerabilities" not in data:
                raise ValidationError("Missing vulnerabilities in CycloneDX document")

        elif format_name == "CSAF":
            if "document" not in data:
                raise ValidationError("Missing document in CSAF")
            if "product_tree" not in data:
                raise ValidationError("Missing product_tree in CSAF")
            if "vulnerabilities" not in data:
                raise ValidationError("Missing vulnerabilities in CSAF")

# ===== LOSS ANALYZER =====

class LossAnalyzer:
    # Define standard fields for each format
    STANDARD_FIELDS = {
        "OpenVEX": {
            "document": ["@context", "@id", "author", "timestamp", "version", "statements"],
            "statement": ["vulnerability", "timestamp", "products", "status", "justification", 
                         "impact_statement", "action_statement", "status_notes"]
        },
        "CycloneDX": {
            "document": ["bomFormat", "specVersion", "serialNumber", "version", "metadata", "components", "vulnerabilities"],
            "vulnerability": ["id", "affects", "analysis", "description", "ratings", "cwes", "references"]
        },
        "CSAF": {
            "document": ["document", "product_tree", "vulnerabilities"],
            "vulnerability": ["cve", "product_status", "flags", "notes", "references"]
        }
    }

    def analyze(self, source_data: Dict, source_format: str, cim: CIM, result: Dict, target_format: str, use_free_text: bool) -> Dict:
        analysis = {
            "source": source_format,
            "target": target_format,
            "summary": {
                "source_subjects": 0,
                "source_vulnerabilities": 0,
                "source_statements": 0,
                "cim_subjects": len(cim.subjects),
                "cim_vulnerabilities": len(cim.vulnerabilities),
                "cim_statements": len(cim.statements),
                "output_subjects": 0,
                "output_vulnerabilities": 0,
                "output_statements": 0
            },
            "details": [],
            "has_data_loss": False
        }

        # Count source data
        source_counts = self._count_source_data(source_data, source_format)
        analysis["summary"]["source_subjects"] = source_counts["subjects"]
        analysis["summary"]["source_vulnerabilities"] = source_counts["vulnerabilities"]
        analysis["summary"]["source_statements"] = source_counts["statements"]

        # Count output data
        output_counts = self._count_source_data(result, target_format)
        analysis["summary"]["output_subjects"] = output_counts["subjects"]
        analysis["summary"]["output_vulnerabilities"] = output_counts["vulnerabilities"]
        analysis["summary"]["output_statements"] = output_counts["statements"]

        # Compare source -> CIM conversion
        if source_counts["vulnerabilities"] != len(cim.vulnerabilities):
            loss = source_counts["vulnerabilities"] - len(cim.vulnerabilities)
            if loss > 0:
                analysis["has_data_loss"] = True
                analysis["details"].append({
                    "severity": "CRITICAL",
                    "category": "vulnerability_loss_in_parsing",
                    "count": loss,
                    "message": f"Lost {loss} vulnerabilities during {source_format} -> CIM conversion"
                })

        if source_counts["subjects"] != len(cim.subjects):
            loss = source_counts["subjects"] - len(cim.subjects)
            if loss > 0:
                analysis["has_data_loss"] = True
                analysis["details"].append({
                    "severity": "CRITICAL",
                    "category": "subject_loss_in_parsing",
                    "count": loss,
                    "message": f"Lost {loss} subjects during {source_format} -> CIM conversion"
                })

        # Compare CIM -> output conversion
        if len(cim.vulnerabilities) != output_counts["vulnerabilities"]:
            loss = len(cim.vulnerabilities) - output_counts["vulnerabilities"]
            if loss > 0:
                analysis["has_data_loss"] = True
                analysis["details"].append({
                    "severity": "CRITICAL",
                    "category": "vulnerability_loss_in_output",
                    "count": loss,
                    "message": f"Lost {loss} vulnerabilities during CIM -> {target_format} conversion"
                })

        if len(cim.subjects) != output_counts["subjects"]:
            loss = len(cim.subjects) - output_counts["subjects"]
            if loss > 0:
                # CycloneDX uses dedupe_components which intentionally merges duplicate PURLs/CPEs
                # OpenVEX is statement-driven: only products mentioned in statements appear in output
                if target_format == "CycloneDX":
                    analysis["details"].append({
                        "severity": "INFO",
                        "category": "component_deduplication",
                        "count": loss,
                        "message": f"Merged {loss} duplicate components (same PURL/CPE)"
                    })
                elif target_format == "OpenVEX":
                    analysis["details"].append({
                        "severity": "INFO",
                        "category": "statement_driven_filtering",
                        "count": loss,
                        "message": f"Excluded {loss} products not referenced in any statement (OpenVEX is statement-driven)"
                    })
                else:
                    analysis["has_data_loss"] = True
                    analysis["details"].append({
                        "severity": "CRITICAL",
                        "category": "subject_loss_in_output",
                        "count": loss,
                        "message": f"Lost {loss} subjects during CIM -> {target_format} conversion"
                    })

        # Check for phantom components
        explicit_subjects = {s.ref for s in cim.subjects if any(
            i.type in ("purl", "cpe") for i in s.identifiers
        )}
        phantom_subjects = {s.ref for s in cim.subjects if s.ref not in explicit_subjects}

        if phantom_subjects:
            analysis["details"].append({
                "severity": "LOW",
                "category": "phantom_components",
                "count": len(phantom_subjects),
                "message": "Component details inferred from affects refs (no explicit components in source)"
            })

        # Check for CycloneDX special states
        special_states = [st for st in cim.statements if st.status.original_state in ["false_positive", "resolved_with_pedigree"]]
        if special_states:
            analysis["details"].append({
                "severity": "INFO",
                "category": "cyclonedx_special_states",
                "count": len(special_states),
                "message": f"CycloneDX special states preserved: {', '.join(set(st.status.original_state for st in special_states))}"
            })

        # Check for unmappable justifications
        custom_justs = [st for st in cim.statements if st.status.custom_justification]
        if custom_justs:
            analysis["details"].append({
                "severity": "MEDIUM",
                "category": "custom_justifications",
                "count": len(custom_justs),
                "message": "Custom justifications that don't map to standard enums"
            })

        # Detect non-standard field loss
        non_standard_fields = self._detect_non_standard_fields(source_data, source_format)
        if non_standard_fields:
            for field_info in non_standard_fields:
                field_name = field_info['field'].replace('statements.', '')
                analysis["details"].append({
                    "severity": "MEDIUM",
                    "category": "non_standard_field_loss",
                    "count": 1,
                    "message": f"{field_name}: Lost (non-standard field)"
                })
                analysis["has_data_loss"] = True

        # Detect standard field loss (e.g., action_statement)
        standard_field_losses = self._detect_standard_field_loss(cim, target_format)
        if standard_field_losses:
            for loss_info in standard_field_losses:
                analysis["details"].append({
                    "severity": "MEDIUM",
                    "category": "standard_field_loss",
                    "count": loss_info["count"],
                    "message": f"{loss_info['field']}: Lost (no corresponding field in {target_format})"
                })
                analysis["has_data_loss"] = True

        # Detect field-level loss (detailed information loss)
        field_level_losses = self._detect_field_level_loss(source_data, source_format, result, target_format, cim)
        if field_level_losses:
            analysis["lost_fields"] = field_level_losses
            analysis["has_data_loss"] = True

        return analysis

    def _detect_non_standard_fields(self, data: Dict, format_name: str) -> List[Dict]:
        """Detect non-standard fields that will be lost"""
        non_standard = []
        seen_fields = set()

        if format_name == "OpenVEX":
            # Check document-level non-standard fields
            doc_standard = self.STANDARD_FIELDS["OpenVEX"]["document"]
            for key in data.keys():
                if key not in doc_standard and key not in seen_fields:
                    non_standard.append({
                        "field": key,
                        "reason": "Non-standard OpenVEX document field"
                    })
                    seen_fields.add(key)

            # Check statement-level non-standard fields
            stmt_standard = self.STANDARD_FIELDS["OpenVEX"]["statement"]
            for stmt in data.get("statements", []):
                for key in stmt.keys():
                    field_name = f"statements.{key}"
                    if key not in stmt_standard and field_name not in seen_fields:
                        non_standard.append({
                            "field": field_name,
                            "reason": "Non-standard OpenVEX statement field"
                        })
                        seen_fields.add(field_name)

        elif format_name == "CycloneDX":
            # Check for non-standard CycloneDX fields
            for vuln in data.get("vulnerabilities", []):
                analysis = vuln.get("analysis", {})
                for key in analysis.keys():
                    field_name = f"vulnerabilities.analysis.{key}"
                    if key not in ["state", "justification", "detail", "response", "ratings", "firstIssued", "lastUpdated"] and field_name not in seen_fields:
                        non_standard.append({
                            "field": field_name,
                            "reason": "Non-standard CycloneDX analysis field"
                        })
                        seen_fields.add(field_name)

        return non_standard

    def _detect_standard_field_loss(self, cim: CIM, target_format: str) -> List[Dict]:
        """Detect standard fields that will be lost in target format"""
        losses = []

        # Check action_statement loss
        action_statements = [st for st in cim.statements if st.action_statement]
        if action_statements and target_format in ["CycloneDX", "CSAF"]:
            losses.append({
                "field": "action_statement",
                "count": len(action_statements),
                "reason": f"No corresponding field in {target_format} format"
            })

        return losses

    # Field mappings between formats (source → target)
    FIELD_MAPPINGS = {
        ("CSAF", "CycloneDX"): {
            # Document-level mappings
            "document.publisher.name": "metadata.tools.vendor",
            "document.tracking.initial_release_date": "metadata.timestamp",
            "document.tracking.id": "serialNumber",  # Regenerated but conceptually mapped

            # Product mappings
            "product_tree": "components",  # Different structure but mapped
            "product_tree.branches": "components",
            "product_tree.relationships": "components",  # Relationships expressed differently

            # Vulnerability mappings
            "vulnerabilities.cve": "vulnerabilities.id",
            "vulnerabilities.cwe.id": "vulnerabilities.cwes",
            "vulnerabilities.cwe.name": "vulnerabilities.cwes",  # ID only, name lost
            "vulnerabilities.notes": "vulnerabilities.description",  # Only description note
            "vulnerabilities.scores.cvss_v3": "vulnerabilities.ratings",
            "vulnerabilities.scores.cvss_v3.baseScore": "vulnerabilities.ratings.score",
            "vulnerabilities.scores.cvss_v3.baseSeverity": "vulnerabilities.ratings.severity",
            "vulnerabilities.scores.cvss_v3.vectorString": "vulnerabilities.ratings.vector",
            "vulnerabilities.scores.cvss_v3.attackComplexity": "vulnerabilities.ratings.vector",  # In vector
            "vulnerabilities.scores.cvss_v3.attackVector": "vulnerabilities.ratings.vector",
            "vulnerabilities.scores.cvss_v3.availabilityImpact": "vulnerabilities.ratings.vector",
            "vulnerabilities.scores.cvss_v3.confidentialityImpact": "vulnerabilities.ratings.vector",
            "vulnerabilities.scores.cvss_v3.integrityImpact": "vulnerabilities.ratings.vector",
            "vulnerabilities.scores.cvss_v3.privilegesRequired": "vulnerabilities.ratings.vector",
            "vulnerabilities.scores.cvss_v3.scope": "vulnerabilities.ratings.vector",
            "vulnerabilities.scores.cvss_v3.userInteraction": "vulnerabilities.ratings.vector",
            "vulnerabilities.scores.products": "vulnerabilities.ratings",  # Implicit in structure
            "vulnerabilities.references": "vulnerabilities.references",
            "vulnerabilities.references.url": "vulnerabilities.references.source.url",
            "vulnerabilities.references.summary": "vulnerabilities.references.source.name",
            "vulnerabilities.references.category": "vulnerabilities.references",  # Preserved in structure
            "vulnerabilities.product_status.known_affected": "vulnerabilities.affects",
        },
        ("CSAF", "OpenVEX"): {
            # Document-level mappings
            "document.publisher.name": "author",
            "document.tracking.initial_release_date": "timestamp",

            # Product mappings - OpenVEX is statement-driven
            "product_tree": "statements.products",

            # Vulnerability mappings
            "vulnerabilities.cve": "statements.vulnerability.name",
            "vulnerabilities.notes": "statements",  # Description goes to impact_statement
            "vulnerabilities.product_status": "statements.status",
        },
        ("OpenVEX", "CycloneDX"): {
            "@context": "bomFormat",  # Format identifier
            "@id": "serialNumber",  # Document ID
            "author": "metadata.tools.vendor",
            "timestamp": "metadata.timestamp",
            "statements": "vulnerabilities",
            "statements.vulnerability": "vulnerabilities",
            "statements.vulnerability.name": "vulnerabilities.id",
            "statements.status": "vulnerabilities.analysis.state",
            "statements.justification": "vulnerabilities.analysis.justification",
            "statements.impact_statement": "vulnerabilities.analysis.detail",
            "statements.action_statement": "vulnerabilities.analysis.response",
            "statements.products": "vulnerabilities.affects",
        },
        ("OpenVEX", "CSAF"): {
            "@context": "document.category",  # Format identifier
            "@id": "document.tracking.id",
            "author": "document.publisher.name",
            "timestamp": "document.tracking.initial_release_date",
            "statements": "vulnerabilities",
            "statements.vulnerability": "vulnerabilities",
            "statements.vulnerability.name": "vulnerabilities.cve",
            "statements.status": "vulnerabilities.product_status",
            "statements.justification": "vulnerabilities.flags",
            "statements.impact_statement": "vulnerabilities.notes",
            "statements.action_statement": "vulnerabilities.remediations",
            "statements.products": "vulnerabilities.product_status",
        },
        ("CycloneDX", "OpenVEX"): {
            "metadata.tools": "author",  # Tool vendor becomes author
            "metadata.tools.vendor": "author",
            "metadata.tools.name": "author",
            "components": "statements.products",
            "vulnerabilities.id": "statements.vulnerability.name",
            "vulnerabilities.source": "statements",  # Source info goes to CIM references
            "vulnerabilities.source.url": "statements",  # Part of references
            "vulnerabilities.source.name": "statements",  # Part of references
            "vulnerabilities.description": "statements",  # Goes to impact_statement
            "vulnerabilities.affects": "statements.products",
            "vulnerabilities.analysis.state": "statements.status",
            "vulnerabilities.analysis.justification": "statements.justification",
            "vulnerabilities.analysis.detail": "statements.impact_statement",
            "vulnerabilities.analysis.response": "statements",  # Lost - no response field
            "vulnerabilities.ratings": "statements.status_notes",  # Summarized in status_notes
            "vulnerabilities.ratings.method": "statements.status_notes",
            "vulnerabilities.ratings.score": "statements.status_notes",
            "vulnerabilities.ratings.severity": "statements.status_notes",
            "vulnerabilities.ratings.vector": "statements.status_notes",
        },
        ("CycloneDX", "CSAF"): {
            # Document-level mappings (reverse of CSAF → CycloneDX)
            "metadata.tools": "document.publisher",
            "metadata.tools.vendor": "document.publisher.name",
            "metadata.tools.name": "document.publisher",  # Partially mapped
            "metadata.timestamp": "document.tracking.initial_release_date",
            "serialNumber": "document.tracking.id",
            "bomFormat": "document.category",
            "specVersion": "document.csaf_version",

            # Product mappings
            "components": "product_tree.full_product_names",

            # Vulnerability mappings (reverse)
            "vulnerabilities": "vulnerabilities",
            "vulnerabilities.id": "vulnerabilities.cve",
            "vulnerabilities.cwes": "vulnerabilities.cwe.id",
            "vulnerabilities.description": "vulnerabilities.notes",
            "vulnerabilities.affects": "vulnerabilities.product_status",
            "vulnerabilities.analysis": "vulnerabilities.product_status",
            "vulnerabilities.analysis.state": "vulnerabilities.product_status",
            "vulnerabilities.analysis.justification": "vulnerabilities.flags",
            "vulnerabilities.analysis.detail": "vulnerabilities.notes",
            "vulnerabilities.analysis.response": "vulnerabilities.remediations",
            "vulnerabilities.ratings": "vulnerabilities.scores.cvss_v3",
            "vulnerabilities.ratings.score": "vulnerabilities.scores.cvss_v3.baseScore",
            "vulnerabilities.ratings.severity": "vulnerabilities.scores.cvss_v3.baseSeverity",
            "vulnerabilities.ratings.vector": "vulnerabilities.scores.cvss_v3.vectorString",
            "vulnerabilities.ratings.method": "vulnerabilities.scores",
            "vulnerabilities.references": "vulnerabilities.references",
            "vulnerabilities.references.source.url": "vulnerabilities.references.url",
            "vulnerabilities.references.source.name": "vulnerabilities.references.summary",
        },
    }

    def _get_mapped_field(self, source_field: str, source_format: str, target_format: str) -> Optional[str]:
        """Get the target field that source_field maps to, if any"""
        key = (source_format, target_format)
        if key not in self.FIELD_MAPPINGS:
            return None

        mappings = self.FIELD_MAPPINGS[key]

        # Check exact match
        if source_field in mappings:
            return mappings[source_field]

        # Check prefix match (e.g., vulnerabilities.scores.cvss_v3.* → vulnerabilities.ratings)
        for source_pattern, target_field in mappings.items():
            if source_field.startswith(source_pattern + "."):
                return target_field

        return None

    def _detect_field_level_loss(self, source_data: Dict, source_format: str, result: Dict, target_format: str, cim: CIM) -> List[str]:
        """Detect which specific fields are lost during conversion by comparing all fields"""

        # Extract all fields from source and target
        source_fields = extract_all_fields(source_data)
        target_fields = extract_all_fields(result)

        # Find fields that exist in source but not in target
        lost_fields = source_fields - target_fields

        # Skip fields that are expected to change (tool-generated fields)
        skip_patterns = [
            '@context',  # OpenVEX context URL
            '@id',  # May be regenerated
            'serialNumber',  # CycloneDX generates new
            'version',  # Document version may change
            'bomFormat',  # Target format identifier
            'specVersion',  # Target spec version
            'metadata.timestamp',  # Timestamp updated
            'timestamp',  # Timestamp updated
            'author',  # May map from publisher
            'tracking.current_release_date',  # Updated by tool
            'tracking.generator',  # Tool-specific, not preserved
            'tracking.revision_history',  # May be regenerated
        ]

        # Filter significant losses
        significant_losses = []
        for field in sorted(lost_fields):
            # Skip expected changes
            if any(pattern in field for pattern in skip_patterns):
                continue

            # Check if this field is mapped to target format
            mapped_field = self._get_mapped_field(field, source_format, target_format)
            if mapped_field:
                # Field is mapped, not lost
                continue

            # Skip redundant parent paths (we only want leaf fields)
            # e.g., if we have "document.notes.text", don't also report "document.notes"
            is_parent = any(other.startswith(field + '.') for other in lost_fields)
            if not is_parent:
                significant_losses.append(field)

        return significant_losses

    def _count_source_data(self, data: Dict, format_name: str) -> Dict:
        counts = {"subjects": 0, "vulnerabilities": 0, "statements": 0}

        if format_name == "OpenVEX":
            # Count unique products across all statements
            unique_products = set()
            for stmt in data.get("statements", []):
                for prod in stmt.get("products", []):
                    prod_id = prod.get("@id", "").strip()
                    if prod_id:
                        unique_products.add(prod_id)
                    # Also check subcomponents
                    for sub in prod.get("subcomponents", []):
                        sub_id = sub.get("@id", "").strip()
                        if sub_id:
                            unique_products.add(sub_id)
            counts["subjects"] = len(unique_products)
            counts["vulnerabilities"] = len(set(s.get("vulnerability", {}).get("name") for s in data.get("statements", [])))
            counts["statements"] = len(data.get("statements", []))

        elif format_name == "CycloneDX":
            counts["subjects"] = len(data.get("components", []))

            # Count unique vulnerability IDs (not entries, as same CVE can affect multiple products)
            unique_vuln_ids = set()
            for v in data.get("vulnerabilities", []):
                vuln_id = v.get("id", "")
                if vuln_id:
                    unique_vuln_ids.add(vuln_id)
            counts["vulnerabilities"] = len(unique_vuln_ids)

            # Count statements by expanding affects
            stmt_count = 0
            for v in data.get("vulnerabilities", []):
                stmt_count += len(v.get("affects", []))
            counts["statements"] = stmt_count

        elif format_name == "CSAF":
            pt = data.get("product_tree", {})

            # Count from full_product_names
            fpn_count = len(pt.get("full_product_names", []))

            # Count from branches (recursive)
            def count_branches(branches):
                count = 0
                for branch in branches:
                    if branch.get("product", {}).get("product_id"):
                        count += 1
                    count += count_branches(branch.get("branches", []))
                return count

            branches_count = count_branches(pt.get("branches", []))

            # Count from relationships
            relationships_count = len(pt.get("relationships", []))

            # Total unique subjects
            counts["subjects"] = fpn_count + branches_count + relationships_count
            counts["vulnerabilities"] = len(data.get("vulnerabilities", []))

            # Count statements from product_status
            stmt_count = 0
            for v in data.get("vulnerabilities", []):
                ps = v.get("product_status", {})
                for status_list in ps.values():
                    stmt_count += len(status_list)
            counts["statements"] = stmt_count

        return counts

# ===== MAIN CONVERTER =====