"""
CIM → Format Converters
"""
import uuid
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Set, Any
from .models import (
    CIM, Subject, Vulnerability, VEXStatement, VulnerabilityStatus,
    Justification, DocumentFormat, ConversionMetadata, ConversionOptions,
    TrackingTable, Identifier, CvssRating, Reference, Publisher, Metadata
)
from .utils import (
    dt_to_iso_z, ensure_urn_uuid, normalize_purl, classify_component_type,
    create_product_identification_helper, encode_structured_text,
    set_extension_field, get_extension_field, generate_bomlink,
    dedupe_components, now_utc, safe_str, dedupe_ratings, unique_list,
    filter_placeholder_ratings, simplify_product_id, normalize_identifier,
    dedupe_references
)
from .constants import (
    MAPPING_TABLE, justification_enum_to_openvex_str,
    justification_enum_to_cyclonedx_str, justification_enum_to_csaf_flag,
    map_openvex_justification_str_to_enum
)

class CIMToOpenVEX:
    def __init__(self, options: ConversionOptions, tracking_table: TrackingTable = None):
        self.options = options
        self.tracking_table = tracking_table or TrackingTable()

    def convert(self, cim: CIM) -> Dict:
        # Try to restore original @id from extension_data
        doc_id = get_extension_field(cim.metadata, "openvex", "@id")
        
        if not doc_id:
            # Fallback to original_id
            doc_id = cim.metadata.original_id
            
        if not doc_id or not doc_id.startswith("http"):
            doc_id = f"https://openvex.dev/docs/public/vex-{cim.metadata.id}"

        # Consolidate statements to avoid conflicts
        # OpenVEX doesn't allow multiple statements for same product+vulnerability
        statements = self._consolidate_statements(cim.statements)

        out = {
            "@context": get_extension_field(cim.metadata, "openvex", "@context", "https://openvex.dev/ns/v0.2.0"),
            "@id": doc_id,
            "author": cim.metadata.publisher.name,
            "timestamp": dt_to_iso_z(cim.metadata.created_at),
            "version": get_extension_field(cim.metadata, "openvex", "version", 1),
            "statements": [self._stmt(s, cim) for s in statements]
        }
        
        # Restore OpenVEX document fields from extension_data
        # role
        role = get_extension_field(cim.metadata, "openvex", "role")
        if role:
            out["role"] = role
        
        # last_updated
        last_updated = get_extension_field(cim.metadata, "openvex", "last_updated")
        if last_updated:
            out["last_updated"] = last_updated
        
        # tooling
        tooling = get_extension_field(cim.metadata, "openvex", "tooling")
        if tooling:
            out["tooling"] = tooling
        
        # Reversible mode: store metadata in first statement's status_notes
        if self.options.reversible:
            lost_data = self._collect_lost_data(cim)
            
            # Collect extension_data
            extension_data = {}
            if cim.metadata.extension_data:
                extension_data["metadata"] = cim.metadata.extension_data
            for idx, subj in enumerate(cim.subjects):
                if subj.extension_data:
                    extension_data[f"subject_{idx}"] = subj.extension_data
            for vuln in cim.vulnerabilities:
                vuln_ext = {}
                if vuln.extension_data:
                    vuln_ext.update(vuln.extension_data)
                
                # Store references (lost in OpenVEX)
                if vuln.references:
                    refs_data = []
                    for r in vuln.references:
                        ref_dict = {"url": r.url}
                        if r.summary:
                            ref_dict["summary"] = r.summary
                        if r.category:
                            ref_dict["category"] = r.category
                        if r.id:
                            ref_dict["id"] = r.id
                        refs_data.append(ref_dict)
                    vuln_ext["references"] = refs_data
                
                # Store ratings (lost in OpenVEX)
                if vuln.ratings:
                    ratings_data = []
                    for r in vuln.ratings:
                        rating_dict = {}
                        if r.method:
                            rating_dict["method"] = r.method
                        if r.score is not None:
                            rating_dict["score"] = r.score
                        if r.severity:
                            rating_dict["severity"] = r.severity
                        if r.vector:
                            rating_dict["vector"] = r.vector
                        ratings_data.append(rating_dict)
                    vuln_ext["ratings"] = ratings_data
                
                # Store cwes (lost in OpenVEX for some cases)
                if vuln.cwes:
                    vuln_ext["cwes"] = vuln.cwes
                
                if vuln_ext:
                    extension_data[f"vulnerability_{vuln.id}"] = vuln_ext
            for idx, stmt in enumerate(cim.statements):
                if stmt.extension_data:
                    extension_data[f"statement_{idx}"] = stmt.extension_data
            
            # Collect subject_mappings
            subject_mappings = {}
            for subj in cim.subjects:
                if subj.original_id:
                    subject_mappings[subj.ref] = subj.original_id
                else:
                    subject_mappings[subj.ref] = subj.ref
            
            if lost_data or extension_data or subject_mappings:
                conv_meta = ConversionMetadata(
                    version="1.0",
                    source_format="CIM",
                    target_format="OpenVEX",
                    timestamp=dt_to_iso_z(now_utc()),
                    lost_data=lost_data,
                    extension_data=extension_data,
                    subject_mappings=subject_mappings
                )
                encoded = conv_meta.encode()
                
                # Store in first statement's status_notes
                if out["statements"]:
                    if "status_notes" not in out["statements"][0]:
                        out["statements"][0]["status_notes"] = encoded
                    else:
                        # Prepend to existing notes
                        out["statements"][0]["status_notes"] = encoded + " | " + out["statements"][0]["status_notes"]
                
                items_count = len(lost_data) + len(extension_data) + len(subject_mappings)
                print(f"\n[Reversible Mode] Stored {items_count} item(s) in status_notes:")
                if lost_data:
                    print(f"  - {len(lost_data)} lost fields (not recoverable)")
                else:
                    print(f"  - 0 lost fields (all data preserved!)")
                if extension_data:
                    print(f"  - {len(extension_data)} extension data entries (recoverable)")
                if subject_mappings:
                    print(f"  - {len(subject_mappings)} subject ID mappings (recoverable)")

        return out
    
    def _collect_lost_data(self, cim: CIM) -> Dict[str, Any]:
        """Collect data that will be lost in OpenVEX conversion"""
        lost = {}
        
        # Collect CSAF-specific fields that don't map to OpenVEX
        # (Most CIM fields map to OpenVEX, so lost_data is minimal)
        
        return lost
    
    def _consolidate_statements(self, statements: List[VEXStatement]) -> List[VEXStatement]:
        """
        Consolidate statements to avoid conflicts in OpenVEX.
        OpenVEX allows only ONE statement per (product @id, vulnerability) pair.
        
        Strategy:
        1. Group by (vulnerability_id, effective_product_id)
        2. For conflicts, keep statement with highest priority status
        3. Priority: AFFECTED > FIXED > NOT_AFFECTED > UNDER_INVESTIGATION
        
        Note: After version-specific @id generation, conflicts should be rare.
        """
        # Build effective product @id for each subject_ref
        def get_effective_product_id(subject_ref: str, subjects: List[Subject]) -> str:
            """Get the @id that will be used in OpenVEX for this subject"""
            subj = next((s for s in subjects if s.ref == subject_ref), None)
            if not subj:
                return subject_ref
            
            # Same logic as _stmt method
            if ':v' in subject_ref:
                base_ref = subject_ref.split(':v')[0]
                version_suffix = subject_ref.split(':v', 1)[1]
                
                if version_suffix.startswith('vers:'):
                    # Range: use base without version
                    if '@' in base_ref:
                        return base_ref.split('@')[0]
                    return base_ref
                else:
                    # Specific version
                    if '@' in base_ref:
                        base_without_version = base_ref.split('@')[0]
                        return f"{base_without_version}@{version_suffix}"
                    return f"{base_ref}@{version_suffix}"
            elif subj.original_id:
                return subj.original_id
            else:
                return normalize_identifier(subject_ref)
        
        # Priority order
        priority_order = {
            VulnerabilityStatus.AFFECTED: 0,
            VulnerabilityStatus.FIXED: 1,
            VulnerabilityStatus.NOT_AFFECTED: 2,
            VulnerabilityStatus.UNDER_INVESTIGATION: 3
        }
        
        # Build subjects list for product_id calculation
        subjects = []
        for stmt in statements:
            for sref in stmt.subject_refs:
                # We'll need access to subjects - use first statement's context
                # This is a limitation but works for consolidation
                pass
        
        # Index: (vuln_id, product_@id) → (priority, statement)
        conflict_map = {}
        
        for stmt in statements:
            vuln_id = stmt.vulnerability_id
            priority = priority_order.get(stmt.status.value, 999)
            
            # Track which product @ids this statement will generate
            stmt_product_ids = set()
            for subject_ref in stmt.subject_refs:
                # Calculate effective product @id (same logic as _stmt)
                if ':v' in subject_ref:
                    base_ref = subject_ref.split(':v')[0]
                    version_suffix = subject_ref.split(':v', 1)[1]
                    
                    # Get base without version
                    if '@' in base_ref:
                        base_without_version = base_ref.split('@')[0]
                    else:
                        base_without_version = base_ref
                    
                    if version_suffix.startswith('vers:'):
                        # Range: @id includes range notation
                        # vers:semver/<1.0.1 → pkg:maven/product@range:<1.0.1
                        if '/' in version_suffix:
                            version_constraint = version_suffix.split('/', 1)[1]
                        else:
                            version_constraint = version_suffix
                        product_id = f"{base_without_version}@range:{version_constraint}"
                    else:
                        # Specific version: @id includes version
                        product_id = f"{base_without_version}@{version_suffix}"
                else:
                    product_id = subject_ref
                
                stmt_product_ids.add(product_id)
            
            # Check for conflicts with each product_id
            for product_id in stmt_product_ids:
                key = (vuln_id, product_id)
                
                if key not in conflict_map:
                    conflict_map[key] = (priority, stmt)
                else:
                    existing_priority = conflict_map[key][0]
                    if priority < existing_priority:
                        # Higher priority - replace
                        conflict_map[key] = (priority, stmt)
        
        # Collect unique statements (may be duplicates if statement covers multiple products)
        unique_stmts = set()
        for _, stmt in conflict_map.values():
            unique_stmts.add(id(stmt))  # Use object id to track uniqueness
        
        # Return statements that survived consolidation
        result = [stmt for stmt in statements if id(stmt) in unique_stmts]
        
        return result

    def _stmt(self, stmt: VEXStatement, cim: CIM) -> Dict:
        products = []
        seen_ids = set()  # 중복 제거
        for sref in stmt.subject_refs:
            subj = next((s for s in cim.subjects if s.ref == sref), None)
            if subj:
                # Determine product @id
                # OpenVEX requires unique @id per product+version combination
                
                product_id = None
                
                # Check if this is a version-specific subject (ref contains :v)
                if ':v' in sref:
                    # This is a version-specific subject from CycloneDX versions array
                    # Example: pkg:maven/product@1.0.0:vvers:semver/<1.0.1
                    
                    # Extract base ref and version
                    base_ref = sref.split(':v')[0]
                    version_suffix = sref.split(':v', 1)[1]
                    
                    # Get base package without version
                    if '@' in base_ref:
                        base_without_version = base_ref.split('@')[0]
                    else:
                        base_without_version = base_ref
                    
                    # For ranges, create descriptive @id with range notation
                    if version_suffix.startswith('vers:'):
                        # Range format: vers:semver/<1.0.1
                        # Create @id like: pkg:maven/com.acme/product@range:<1.0.1
                        # Extract version constraint from vers: format
                        # vers:semver/<1.0.1 → <1.0.1
                        # vers:semver/>=2.0.0|<2.3.0 → >=2.0.0|<2.3.0
                        
                        range_spec = version_suffix  # vers:semver/<1.0.1
                        
                        # Extract just the version part after vers:scheme/
                        if '/' in range_spec:
                            version_constraint = range_spec.split('/', 1)[1]  # <1.0.1
                        else:
                            version_constraint = range_spec
                        
                        # Create @id with range notation
                        product_id = f"{base_without_version}@range:{version_constraint}"
                    else:
                        # Specific version: v1.0.1
                        # Create @id with that version: pkg:maven/com.acme/product@1.0.1
                        product_id = f"{base_without_version}@{version_suffix}"
                else:
                    # Not version-specific
                    if subj.original_id:
                        # Use original_id if available
                        product_id = subj.original_id
                    else:
                        # Use normalized ref
                        product_id = normalize_identifier(subj.ref)

                # 중복 체크
                if product_id in seen_ids:
                    continue
                seen_ids.add(product_id)

                product_entry = {"@id": product_id}
                
                # Note: OpenVEX spec does not support identifiers field
                # Product identification is done solely through @id (PURL, CPE, or custom ID)
                # Versions should be encoded in the @id (e.g., pkg:npm/lodash@4.17.21)
                
                # Add hashes if available
                if subj.hashes:
                    hashes = {}
                    for hash_info in subj.hashes:
                        alg = hash_info.get("algorithm")
                        val = hash_info.get("value")
                        if alg and val:
                            hashes[alg] = val
                    if hashes:
                        product_entry["hashes"] = hashes

                products.append(product_entry)

        # Build vulnerability object with description
        vuln_obj = {"name": stmt.vulnerability_id}

        # Add description from vulnerability data
        vuln_data = next((v for v in cim.vulnerabilities if v.id == stmt.vulnerability_id), None)
        if vuln_data and vuln_data.description:
            vuln_obj["description"] = vuln_data.description

        result = {
            "vulnerability": vuln_obj,
            "timestamp": dt_to_iso_z(stmt.timestamp),
            "products": products,
            "status": stmt.status.value.value
        }
        
        # Track status conversion
        self.tracking_table.add(
            source_field="CIM.statement.status.value",
            source_value=str(stmt.status.value),
            target_field="statements.status",
            target_value=stmt.status.value.value,
            rule=f"{stmt.status.value} → OpenVEX status",
            status="TRANSFORMED" if stmt.status.value.value != str(stmt.status.value).split('.')[-1].lower() else "OK"
        )

        # Add justification for not_affected status
        if stmt.status.value == VulnerabilityStatus.NOT_AFFECTED:
            # PRIORITY 1: Use original OpenVEX justification from custom_justification if valid
            # PRIORITY 2: Use justification enum
            justification_to_use = None
            
            if stmt.status.custom_justification:
                # Check if custom_justification is a valid OpenVEX justification (without cyclonedx: prefix)
                custom_just = stmt.status.custom_justification
                if not custom_just.startswith("cyclonedx:"):
                    # It's an OpenVEX justification - use it directly (preserves original)
                    valid_openvex_just = [
                        "component_not_present",
                        "vulnerable_code_not_present",
                        "vulnerable_code_not_in_execute_path",
                        "vulnerable_code_cannot_be_controlled_by_adversary",
                        "inline_mitigations_already_exist"
                    ]
                    if custom_just in valid_openvex_just:
                        justification_to_use = custom_just
            
            # Fallback to enum conversion
            if not justification_to_use and stmt.status.justification:
                justification_to_use = justification_enum_to_openvex_str(stmt.status.justification)
            
            if justification_to_use:
                result["justification"] = justification_to_use
                # Track justification
                self.tracking_table.add(
                    source_field="CIM.statement.status.justification",
                    source_value=str(stmt.status.custom_justification or stmt.status.justification),
                    target_field="statements.justification",
                    target_value=result["justification"],
                    rule="Justification (original preserved if available)",
                    status="TRANSFORMED"
                )
            
            # CRITICAL: OpenVEX requires EITHER justification OR impact_statement for not_affected
            # If neither exists, add a default impact_statement
            if not justification_to_use and not stmt.status.impact_statement:
                result["impact_statement"] = "This product is not affected by this vulnerability."

        # Add impact_statement (only for not_affected status)
        # For other statuses, impact_statement is not part of OpenVEX spec
        if stmt.status.value == VulnerabilityStatus.NOT_AFFECTED and stmt.status.impact_statement:
            result["impact_statement"] = stmt.status.impact_statement

        # Add action_statement (ONLY for affected status)
        action_parts = []

        # ONLY for AFFECTED status
        if stmt.status.value == VulnerabilityStatus.AFFECTED:
            # Existing action_statement
            if stmt.action_statement:
                action_parts.append(stmt.action_statement)

            # Add remediations as action_statement
            if vuln_data and vuln_data.remediations:
                for rem in vuln_data.remediations:
                    category = rem.get("category", "")
                    details = rem.get("details", "")

                    # Check if this remediation applies to any of the products in this statement
                    rem_product_ids = set(rem.get("product_ids", []))
                    stmt_product_ids = set(stmt.subject_refs)

                    # Match if:
                    # 1. rem_product_ids is empty (applies to all products)
                    # 2. Direct match: rem_product_id in stmt_product_ids
                    # 3. Partial match: rem_product_id is contained in any stmt_product_id
                    matches = False
                    if not rem_product_ids:
                        matches = True
                    else:
                        # Check for direct match
                        if rem_product_ids.intersection(stmt_product_ids):
                            matches = True
                        else:
                            # Check for partial match (rem_product_id contained in stmt_product_id)
                            for rem_pid in rem_product_ids:
                                for stmt_pid in stmt_product_ids:
                                    if rem_pid in stmt_pid:
                                        matches = True
                                        break
                                if matches:
                                    break

                    if matches:
                        # Build action statement: "category: details" format
                        # Only include vendor_fix, mitigation, workaround
                        if category in ["vendor_fix", "mitigation", "workaround"]:
                            if category and details:
                                action_parts.append(f"{category}: {details}")
                            elif details:
                                action_parts.append(details)

            # Add action_statement if any parts collected (join with newline)
            # OpenVEX requires action_statement for affected status
            if action_parts:
                result["action_statement"] = "\n".join(action_parts)
            else:
                # Default action_statement for affected status
                result["action_statement"] = "No remediation information available"

        # Add impact_statement/action_statement for UNDER_INVESTIGATION status
        if stmt.status.value == VulnerabilityStatus.UNDER_INVESTIGATION:
            # Add impact_statement if available
            if stmt.status.impact_statement:
                result["impact_statement"] = stmt.status.impact_statement
            elif not result.get("action_statement"):
                # If no impact_statement, provide default
                result["impact_statement"] = "Investigation in progress to determine impact"
            
            # Add action_statement if available
            if stmt.action_statement and not result.get("action_statement"):
                result["action_statement"] = stmt.action_statement
            elif not result.get("action_statement") and not result.get("impact_statement"):
                # Provide at least one of impact_statement or action_statement
                result["impact_statement"] = "Investigation in progress to determine impact"

        # Use human-readable status_notes instead of JSON dump
        # OR in default mode, still preserve impact_statement for affected/fixed/under_investigation
        notes_parts = []
        
        if self.options.use_free_text_encoding:
            vuln = next((v for v in cim.vulnerabilities if v.id == stmt.vulnerability_id), None)
            if vuln:
                # Add original CycloneDX state note
                if stmt.status.original_state:
                    if stmt.status.original_state == "false_positive":
                        notes_parts.append("Note: This was identified as a false positive in the original assessment.")
                    elif stmt.status.original_state == "resolved_with_pedigree":
                        notes_parts.append("Note: Resolution includes pedigree information (commit history, diffs).")

                # For AFFECTED status, preserve impact_statement as status_notes
                if stmt.status.value == VulnerabilityStatus.AFFECTED and stmt.status.impact_statement:
                    notes_parts.append(stmt.status.impact_statement)
                
                # For FIXED status, preserve impact_statement as status_notes
                if stmt.status.value == VulnerabilityStatus.FIXED and stmt.status.impact_statement:
                    notes_parts.append(stmt.status.impact_statement)
                
                # For UNDER_INVESTIGATION status, preserve impact_statement as status_notes
                if stmt.status.value == VulnerabilityStatus.UNDER_INVESTIGATION and stmt.status.impact_statement:
                    notes_parts.append(stmt.status.impact_statement)

                # Add CVSS summary
                if vuln.ratings:
                    ratings_filtered = filter_placeholder_ratings([{
                        "method": r.method, "score": r.score, "severity": r.severity, "vector": r.vector
                    } for r in vuln.ratings])
                    if ratings_filtered:
                        rating = ratings_filtered[0]
                        notes_parts.append(f"CVSS: {rating.get('severity', 'unknown').upper()} ({rating.get('score', 'N/A')})")

                # Add CWE summary
                if vuln.cwes:
                    cwes_str = ", ".join([f"CWE-{c}" for c in vuln.cwes[:3]])
                    if len(vuln.cwes) > 3:
                        cwes_str += f" (+{len(vuln.cwes)-3} more)"
                    notes_parts.append(f"CWEs: {cwes_str}")

                # Add reference count and primary source
                if vuln.references:
                    # Check for primary source (category == "source")
                    primary_source = next((r for r in vuln.references if r.category == "source"), None)
                    if primary_source and primary_source.url:
                        source_name = primary_source.summary or "Source"
                        notes_parts.append(f"{source_name}: {primary_source.url}")
                    elif len(vuln.references) == 1:
                        # Single reference - show it
                        ref = vuln.references[0]
                        ref_name = ref.summary or "Reference"
                        notes_parts.append(f"{ref_name}: {ref.url}")
                    else:
                        # Multiple references - show count
                        notes_parts.append(f"References: {len(vuln.references)} available")
        else:
            # Default mode: still preserve impact_statement for affected/fixed/under_investigation
            if stmt.status.value == VulnerabilityStatus.AFFECTED and stmt.status.impact_statement:
                notes_parts.append(stmt.status.impact_statement)
            elif stmt.status.value == VulnerabilityStatus.FIXED and stmt.status.impact_statement:
                notes_parts.append(stmt.status.impact_statement)
            elif stmt.status.value == VulnerabilityStatus.UNDER_INVESTIGATION and stmt.status.impact_statement:
                notes_parts.append(stmt.status.impact_statement)
        
        if notes_parts:
            result["status_notes"] = " | ".join(notes_parts)
        
        # Restore OpenVEX extension_data fields
        # Vulnerability fields
        if vuln_data:
            vuln_id_ext = get_extension_field(vuln_data, "openvex", "vulnerability.@id")
            if vuln_id_ext:
                result["vulnerability"]["@id"] = vuln_id_ext
            
            aliases = get_extension_field(vuln_data, "openvex", "vulnerability.aliases")
            if aliases:
                result["vulnerability"]["aliases"] = aliases
        
        # Statement fields
        # status_notes (raw, not the generated one)
        # PRIORITY: Restore original status_notes first
        status_notes_ext = get_extension_field(stmt, "openvex", "status_notes")
        if status_notes_ext:
            # Original status_notes takes priority
            if "status_notes" in result:
                # Combine original with generated
                result["status_notes"] = status_notes_ext + " | " + result["status_notes"]
            else:
                result["status_notes"] = status_notes_ext
        
        # supplier
        supplier = get_extension_field(stmt, "openvex", "supplier")
        if supplier:
            result["supplier"] = supplier
        
        # Product identifiers restoration
        for prod in result.get("products", []):
            prod_id = prod.get("@id")
            if prod_id:
                # Note: OpenVEX spec v0.2.0 does not support identifiers field
                # Product identification is done solely through @id
                pass

        return result

class CIMToCycloneDX:
    def __init__(self, options: ConversionOptions, tracking_table: TrackingTable = None):
        self.options = options
        self.tracking_table = tracking_table or TrackingTable()

    def convert(self, cim: CIM) -> Dict:
        # Restore original components if available (perfect restoration)
        original_components = get_extension_field(cim.metadata, "cyclonedx", "components")
        
        if original_components and self.options.restore:
            # Perfect restoration: use original components structure
            components = original_components
            
            # Build ref_mapping from original components
            ref_mapping = {}
            for comp in components:
                bom_ref = comp.get("bom-ref", "")
                if bom_ref:
                    ref_mapping[bom_ref] = bom_ref
            
            print(f"[Restore Mode] Restored {len(components)} original component(s)")
        else:
            # Normal mode: generate components from subjects
            components = [self._comp(s) for s in cim.subjects]
            components, ref_mapping = dedupe_components(components)
        
        # Collect all base refs used in affects (only in normal mode)
        # These will be used as affects[].ref, so we need corresponding components
        if not (original_components and self.options.restore):
            base_refs_in_affects = set()
            for stmt in cim.statements:
                for ref in stmt.subject_refs:
                    # Extract base ref (same logic as in _vulns)
                    subj = next((s for s in cim.subjects if s.ref == ref), None)
                    if subj and subj.original_id:
                        # Use original_id to determine base
                        base_ref = subj.original_id
                        if ':v' in base_ref:
                            parts = base_ref.split(':v')
                            if len(parts) >= 2:
                                base_ref = parts[0]
                    else:
                        base_ref = ref
                        if ':v' in base_ref:
                            base_ref = ref.split(':v')[0]
                    
                    base_refs_in_affects.add(base_ref)
            
            # Add base ref components if not already present
            existing_bom_refs = {c["bom-ref"] for c in components}
            for base_ref in base_refs_in_affects:
                if base_ref not in existing_bom_refs:
                    # Find a subject with this base ref
                    for s in cim.subjects:
                        s_base_ref = s.ref.split(':v')[0] if ':v' in s.ref else s.ref
                        if s_base_ref == base_ref or (s.original_id and s.original_id.split(':v')[0] == base_ref):
                            # Create base component (without version)
                            base_name = s.name.split(' ')[0] if s.name else base_ref
                            # Remove version suffix from name
                            for version_marker in [' vers:', ' v', ' 1.', ' 2.', ' 3.', ' 4.', ' 5.']:
                                if version_marker in base_name:
                                    base_name = base_name.split(version_marker)[0]
                                    break
                            
                            comp_type = s.type if s.type else "library"
                            base_comp = {
                                "type": comp_type,
                                "name": base_name,
                                "bom-ref": base_ref
                            }
                            
                            # Add version if available
                            version_to_set = s.version
                            
                            # Try to extract version from purl if not in s.version
                            purl = next((i.value for i in s.identifiers if i.type == "purl"), None)
                            if purl and "@" in purl and not version_to_set:
                                parts = purl.split("@")
                                version_part = parts[1]
                                
                                # Handle range: format
                                if version_part.startswith("range:"):
                                    # range:<1.0.1 → vers:semver/<1.0.1
                                    version_to_set = "vers:semver/" + version_part[6:]
                                elif version_part.startswith("vers:"):
                                    # vers:semver/<1.0.1 → keep as is
                                    version_to_set = version_part
                                else:
                                    # 1.0.1 → keep as is
                                    version_to_set = version_part
                            
                            if version_to_set:
                                base_comp["version"] = version_to_set
                            
                            # Add identifiers if available (without version)
                            if purl:
                                # Remove version from PURL
                                if "@" in purl:
                                    purl_base = purl.split("@")[0]
                                    base_comp["purl"] = purl_base
                            
                            cpe = next((i.value for i in s.identifiers if i.type == "cpe"), None)
                            if cpe:
                                base_comp["cpe"] = cpe
                            
                            # Add hashes if available
                            if s.hashes:
                                # Convert CIM format to CycloneDX format
                                # CIM: [{"algorithm": "sha-256", "value": "..."}]
                                # CDX: [{"alg": "SHA-256", "content": "..."}]
                                cdx_hashes = []
                                for h in s.hashes:
                                    alg = h.get("algorithm", "")
                                    val = h.get("value", "")
                                    if alg and val:
                                        # Convert algorithm name
                                        # sha-256 → SHA-256
                                        alg_upper = alg.upper().replace("-", "-")
                                        if alg_upper.startswith("SHA"):
                                            alg_upper = alg_upper.replace("SHA", "SHA-")
                                        cdx_hashes.append({"alg": alg_upper, "content": val})
                                if cdx_hashes:
                                    base_comp["hashes"] = cdx_hashes
                            
                            components.append(base_comp)
                            existing_bom_refs.add(base_ref)
                            break
        
        vulns = self._vulns(cim, ref_mapping)

        metadata = {
            "timestamp": dt_to_iso_z(cim.metadata.created_at),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "VEXCO",
                        "version": "1.0",
                        "supplier": {
                            "name": cim.metadata.publisher.name
                        }
                    }
                ]
            }
        }
        
        # Add publisher.namespace to supplier.url (if available, from CSAF)
        if cim.metadata.publisher.namespace:
            if "url" not in metadata["tools"]["components"][0]["supplier"]:
                metadata["tools"]["components"][0]["supplier"]["url"] = []
            metadata["tools"]["components"][0]["supplier"]["url"].append(cim.metadata.publisher.namespace)
        
        # Add document.references to externalReferences (if available, from CSAF)
        external_refs = []
        csaf_references = get_extension_field(cim.metadata, "csaf", "document.references")
        if csaf_references:
            for ref in csaf_references:
                ext_ref = {}
                
                # category → type (CSAF category to CycloneDX type mapping)
                if ref.get("category"):
                    category = ref["category"]
                    # Map CSAF categories to CycloneDX types
                    category_to_type = {
                        "external": "website",
                        "self": "vcs",
                        "related": "other"
                    }
                    ext_ref["type"] = category_to_type.get(category, "other")
                else:
                    ext_ref["type"] = "other"
                
                # url → url
                if ref.get("url"):
                    ext_ref["url"] = ref["url"]
                
                # summary → comment
                if ref.get("summary"):
                    ext_ref["comment"] = ref["summary"]
                
                if ext_ref.get("url"):
                    external_refs.append(ext_ref)
        
        # Restore original metadata.supplier if available
        if self.options.restore:
            original_supplier = get_extension_field(cim.metadata, "cyclonedx", "metadata.supplier")
            if original_supplier:
                metadata["supplier"] = original_supplier
        
        # Restore metadata.component (important for VDR)
        metadata_component = get_extension_field(cim.metadata, "cyclonedx", "metadata.component")
        if metadata_component:
            metadata["component"] = metadata_component

        result = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "serialNumber": ensure_urn_uuid(cim.metadata.original_id),
            "version": 1,
            "metadata": metadata,
            "components": components,
            "vulnerabilities": vulns
        }
        
        # Add externalReferences at top level (not in metadata)
        if external_refs:
            result["externalReferences"] = external_refs

        # Reversible mode: store metadata for restoration
        if self.options.reversible:
            lost_data = self._collect_lost_data(cim)
            
            # Collect extension_data from all CIM entities
            extension_data = {}
            
            # Metadata extension_data
            if cim.metadata.extension_data:
                extension_data["metadata"] = cim.metadata.extension_data
            
            # Subject extension_data
            for idx, subj in enumerate(cim.subjects):
                if subj.extension_data:
                    extension_data[f"subject_{idx}"] = subj.extension_data
            
            # Vulnerability extension_data (use ID as key, not index)
            for vuln in cim.vulnerabilities:
                if vuln.extension_data:
                    extension_data[f"vulnerability_{vuln.id}"] = vuln.extension_data
            
            # Statement extension_data
            for idx, stmt in enumerate(cim.statements):
                if stmt.extension_data:
                    extension_data[f"statement_{idx}"] = stmt.extension_data
            
            # Collect subject_mappings (ref → original_id)
            subject_mappings = {}
            for subj in cim.subjects:
                # Always store if original_id exists
                if subj.original_id:
                    subject_mappings[subj.ref] = subj.original_id
                else:
                    # Even if original_id doesn't exist, store ref → ref mapping
                    # This helps with restoration
                    subject_mappings[subj.ref] = subj.ref
            
            if lost_data or extension_data or subject_mappings:
                conv_meta = ConversionMetadata(
                    version="1.0",
                    source_format="CIM",
                    target_format="CycloneDX",
                    timestamp=dt_to_iso_z(now_utc()),
                    lost_data=lost_data,
                    extension_data=extension_data,
                    subject_mappings=subject_mappings
                )
                encoded = conv_meta.encode()
                
                # Store in result.metadata.properties (not local metadata variable)
                if "properties" not in result["metadata"]:
                    result["metadata"]["properties"] = []
                result["metadata"]["properties"].append({
                    "name": "VEXCO.metadata",
                    "value": encoded
                })
                
                items_count = len(lost_data) + len(extension_data) + len(subject_mappings)
                print(f"\n[Reversible Mode] Stored {items_count} item(s) in properties:")
                if lost_data:
                    print(f"  - {len(lost_data)} lost fields (not recoverable)")
                else:
                    print(f"  - 0 lost fields (all data preserved!)")
                if extension_data:
                    print(f"  - {len(extension_data)} extension data entries (recoverable)")
                if subject_mappings:
                    print(f"  - {len(subject_mappings)} subject ID mappings (recoverable)")

        return result
    
    def _collect_lost_data(self, cim: CIM) -> Dict[str, Any]:
        """Collect data that will be lost in CycloneDX conversion"""
        lost = {}
        
        # Collect individual statement statuses (for resolved state preservation)
        # When multiple statements with different statuses map to same CDX vulnerability,
        # we need to preserve which subject had which status
        for stmt in cim.statements:
            # Store status for each subject_ref
            for ref in stmt.subject_refs:
                key = f"stmt_status_{ref}_{stmt.vulnerability_id}"
                lost[key] = stmt.status.value.name  # e.g., "AFFECTED", "FIXED"
        
        # Collect justifications for not_affected status
        for stmt in cim.statements:
            if stmt.status.value == VulnerabilityStatus.NOT_AFFECTED:
                if stmt.status.justification:
                    key = f"stmt_{stmt.id}_justification"
                    lost[key] = justification_enum_to_openvex_str(stmt.status.justification)
                if stmt.status.custom_justification:
                    key = f"stmt_{stmt.id}_custom_justification"
                    lost[key] = stmt.status.custom_justification
        
        # Collect action_statements
        for stmt in cim.statements:
            if stmt.action_statement:
                key = f"stmt_{stmt.id}_action_statement"
                lost[key] = stmt.action_statement
        
        return lost

    def _comp(self, s: Subject) -> Dict:
        purl = next((i.value for i in s.identifiers if i.type == "purl"), None)
        
        # Handle purl with @range: format
        # pkg:maven/com.acme/product@range:<1.0.1 → purl: pkg:maven/com.acme/product
        version_from_purl = None
        if purl and "@" in purl:
            parts = purl.split("@")
            purl_base = parts[0]
            version_part = parts[1]
            
            # Extract version from @range: or @vers:
            if version_part.startswith("range:"):
                # range:<1.0.1 → vers:semver/<1.0.1
                version_from_purl = "vers:semver/" + version_part[6:]
                purl = purl_base  # Use base without version
            elif version_part.startswith("vers:"):
                # vers:semver/<1.0.1 → keep as is
                version_from_purl = version_part
                purl = purl_base  # Use base without version
            # else: regular version like 1.0.1, keep purl as is
        
        normalized_purl = normalize_purl(purl) if purl else None

        # Extract base name (without version)
        if s.name:
            name = s.name
            # Remove version suffix from name if present
            # Examples: "product-ABC 2.4" → "product-ABC"
            #           "product-ABC vers:generic/..." → "product-ABC"
            if s.version:
                # Remove " {version}" or " vers:..." from name
                if s.version.startswith("vers:"):
                    # Remove version range from name
                    name = name.replace(f" {s.version}", "").strip()
                else:
                    # Remove regular version from name
                    name = name.replace(f" {s.version}", "").strip()
        elif normalized_purl:
            try:
                # Extract name from PURL (without version)
                name = normalized_purl.split("/")[-1].split("@")[0].split("?")[0]
            except:
                name = s.ref.split(":")[0] if ":" in s.ref else s.ref
        else:
            # Use base ref without version
            name = s.ref.split(":")[0] if ":" in s.ref else s.ref

        # Classify component type based on identifier and name
        comp_type = classify_component_type(
            normalized_purl or s.ref,
            name
        ) if not s.type else s.type

        # Use simple ref as bom-ref (not bomlink URN)
        # This matches the affects[].ref format in _vulns()
        c = {"type": comp_type, "name": name, "bom-ref": s.ref}
        
        # Determine version: prioritize s.version > version_from_purl
        version_to_use = s.version or version_from_purl
        
        # Add version or versionRange
        if version_to_use:
            if version_to_use.startswith("vers:"):
                # Version range - use version field (not versionRange for compatibility)
                c["version"] = version_to_use
            elif version_to_use not in ["unknown", ""]:
                # Regular version - use version field
                c["version"] = version_to_use
        
        if normalized_purl: c["purl"] = normalized_purl
        cpe = next((i.value for i in s.identifiers if i.type == "cpe"), None)
        if cpe: c["cpe"] = cpe
        
        # Add hashes if available
        if s.hashes:
            # Convert CIM format to CycloneDX format
            # CIM: [{"algorithm": "sha-256", "value": "..."}]
            # CDX: [{"alg": "SHA-256", "content": "..."}]
            cdx_hashes = []
            for h in s.hashes:
                alg = h.get("algorithm", "")
                val = h.get("value", "")
                if alg and val:
                    # Convert algorithm name
                    # sha-256 → SHA-256
                    alg_upper = alg.upper().replace("-", "-")
                    if alg_upper.startswith("SHA"):
                        # Ensure SHA-256 format (not SHA256)
                        if not "-" in alg_upper:
                            alg_upper = alg_upper.replace("SHA", "SHA-")
                    cdx_hashes.append({"alg": alg_upper, "content": val})
            if cdx_hashes:
                c["hashes"] = cdx_hashes
        
        return c

    def _vulns(self, cim: CIM, ref_mapping: Dict[str, str]) -> List[Dict]:
        by_vuln = {}
        for st in cim.statements:
            by_vuln.setdefault(st.vulnerability_id, []).append(st)
        vuln_idx = {v.id: v for v in cim.vulnerabilities}
        out = []

        # Get serial number for bomlink generation
        serial_number = cim.metadata.original_id or f"urn:uuid:{cim.metadata.id}"

        for vid, stmts in sorted(by_vuln.items()):
            # Group statements by subject to collect version information
            by_subject = {}
            for st in stmts:
                for ref in st.subject_refs:
                    if ref not in by_subject:
                        by_subject[ref] = []
                    by_subject[ref].append(st)

            # Build affects array with perfect restoration support
            vv = vuln_idx.get(vid)
            original_affects = get_extension_field(vv, "cyclonedx", "affects") if vv else None
            
            if original_affects and self.options.restore:
                # Perfect restoration: use original affects structure
                affects = original_affects
                
                # Track: Original affects restored
                self.tracking_table.add(
                    source_field="CIM.vulnerability.extension_data.cyclonedx.affects",
                    source_value=f"{len(original_affects)} affects entries",
                    target_field="vulnerabilities.affects",
                    target_value=f"{len(original_affects)} affects (exact restoration)",
                    rule="Restore original CycloneDX affects structure",
                    status="OK"
                )
            else:
                # Normal mode: reconstruct affects from statements
                # Group statements by base ref (using original_id as base)
                by_base_ref = {}
                for st in stmts:
                    for ref in st.subject_refs:
                        # Get subject to find original_id
                        subj = next((s for s in cim.subjects if s.ref == ref), None)
                        
                        # Extract base ref (without version info)
                        base_ref = ref
                        
                        # Priority 1: Use original_id if available
                        if subj and subj.original_id:
                            base_ref = subj.original_id
                            # Remove version suffix
                            if ':v' in base_ref:
                                base_ref = base_ref.split(':v')[0]
                        
                        # Priority 2: Extract from ref
                        # Handle different formats:
                        # - pkg:maven/test/lib@range:<2.0.0 → pkg:maven/test/lib
                        # - pkg:maven/test/lib@2.0.0 → pkg:maven/test/lib
                        # - pkg:maven/test/lib@1.0.0:vvers:semver/<2.0.0 → pkg:maven/test/lib@1.0.0
                        
                        if ':v' in base_ref:
                            # Has :v suffix - split it
                            base_ref = base_ref.split(':v')[0]
                        
                        # Remove version from PURL (after @)
                        if base_ref.startswith('pkg:') and '@' in base_ref:
                            # pkg:maven/test/lib@range:<2.0.0 → pkg:maven/test/lib
                            # pkg:maven/test/lib@2.0.0 → pkg:maven/test/lib
                            parts = base_ref.split('@')
                            if len(parts) >= 2:
                                # Check if version part starts with "range:" or is a version
                                version_part = parts[1]
                                if version_part.startswith('range:') or any(c.isdigit() for c in version_part):
                                    # This is a version, remove it
                                    base_ref = parts[0]
                        
                        if base_ref not in by_base_ref:
                            by_base_ref[base_ref] = []
                        by_base_ref[base_ref].append((ref, st))
                
                affects = []
                for base_ref, ref_stmt_pairs in by_base_ref.items():
                    # Get the first subject to determine original_id
                    first_ref = ref_stmt_pairs[0][0]
                    subject = next((s for s in cim.subjects if s.ref == first_ref), None)
                    
                    # Use original_id if available (preserves urn:cdx:... format)
                    if subject and subject.original_id:
                        final_ref = subject.original_id
                    else:
                        final_ref = ref_mapping.get(base_ref, base_ref)
                    
                    # Create affect object
                    affect_obj = {"ref": final_ref}
                    
                    # Collect all versions from all refs under this base_ref
                    all_versions = []
                    
                    for ref, st in ref_stmt_pairs:
                        subj = next((s for s in cim.subjects if s.ref == ref), None)
                        if not subj:
                            continue
                        
                        version_val = subj.version
                        if not version_val:
                            continue
                        
                        # Create version entry
                        version_entry = {}
                        
                        # Check if version is a range (starts with vers:)
                        if version_val.startswith("vers:"):
                            version_entry["range"] = version_val
                        else:
                            version_entry["version"] = version_val
                        
                        # Map status
                        if st.status.value == VulnerabilityStatus.AFFECTED:
                            version_entry["status"] = "affected"
                        elif st.status.value == VulnerabilityStatus.NOT_AFFECTED:
                            version_entry["status"] = "unaffected"
                        elif st.status.value == VulnerabilityStatus.FIXED:
                            version_entry["status"] = "unaffected"
                        else:
                            version_entry["status"] = "unknown"
                        
                        all_versions.append(version_entry)
                    
                    if all_versions:
                        # Deduplicate versions
                        seen_versions = set()
                        unique_versions = []
                        for v in all_versions:
                            key = (v.get("version"), v.get("range"), v.get("status"))
                            if key not in seen_versions:
                                seen_versions.add(key)
                                unique_versions.append(v)
                        
                        if unique_versions:
                            affect_obj["versions"] = unique_versions
                    
                    affects.append(affect_obj)

            # Determine state with priority: affected > fixed > not_affected > under_investigation
            original_state = next((st.status.original_state for st in stmts if st.status.original_state), None)

            # ALWAYS use original_state if available (perfect restoration)
            if original_state:
                state = original_state  # Restore exact original CycloneDX state
                # Track: Original CycloneDX state restored
                self.tracking_table.add(
                    source_field="CIM.statement.status.original_state",
                    source_value=original_state,
                    target_field="vulnerabilities.analysis.state",
                    target_value=state,
                    rule="Restore original CycloneDX state (exact)",
                    status="OK"
                )
            else:
                statuses = set(st.status.value for st in stmts)
                # If both AFFECTED and FIXED exist, it means patch is available → resolved
                if VulnerabilityStatus.AFFECTED in statuses and VulnerabilityStatus.FIXED in statuses:
                    state = "resolved"
                elif VulnerabilityStatus.AFFECTED in statuses:
                    state = "exploitable"
                elif VulnerabilityStatus.FIXED in statuses:
                    state = "resolved"
                elif VulnerabilityStatus.NOT_AFFECTED in statuses:
                    state = "not_affected"
                else:
                    state = "in_triage"
                
                # Track: Status mapping
                source_status = list(statuses)[0] if statuses else "UNDER_INVESTIGATION"
                self.tracking_table.add(
                    source_field="CIM.statement.status.value",
                    source_value=str(source_status),
                    target_field="vulnerabilities.analysis.state",
                    target_value=state,
                    rule=f"Priority: affected>fixed>not_affected",
                    status="TRANSFORMED"
                )

            # Create v_obj with ordered fields: id, source, ratings, analysis, affects
            v_obj = {"id": vid}

            # Add NVD source for CVE (SECOND)
            if vid.startswith("CVE-"):
                v_obj["source"] = {
                    "name": "NVD",
                    "url": f"https://nvd.nist.gov/vuln/detail/{vid}"
                }

            # Add ratings THIRD (will be populated later if exists)
            # Placeholder to maintain order
            vv = vuln_idx.get(vid)
            if vv and vv.ratings:
                ratings_data = [self._rating(r) for r in vv.ratings]
                ratings_data = filter_placeholder_ratings(ratings_data)
                ratings_data = dedupe_ratings(ratings_data)
                if ratings_data:
                    v_obj["ratings"] = ratings_data

            # Add analysis FOURTH
            v_obj["analysis"] = {"state": state}
            
            # Restore original CycloneDX response from extension_data (if available)
            original_response = None
            for st in stmts:
                if st.extension_data and "cyclonedx_response" in st.extension_data:
                    original_response = st.extension_data["cyclonedx_response"]
                    break
            
            if original_response:
                # Use original response array (preserves multiple values like ["will_not_fix", "update"])
                v_obj["analysis"]["response"] = original_response
            elif state == "exploitable":
                # For exploitable state without original response,
                # try to infer response from action_statement
                action_stmt = None
                impact_stmt = None
                for st in stmts:
                    if st.status.value == VulnerabilityStatus.AFFECTED:
                        if st.action_statement:
                            action_stmt = st.action_statement
                        if st.status.impact_statement:
                            impact_stmt = st.status.impact_statement
                        if action_stmt or impact_stmt:
                            break
                
                # Parse action_statement to determine response
                if action_stmt:
                    response_list = []
                    action_lower = action_stmt.lower()
                    
                    # Check for common patterns
                    if "update" in action_lower or "upgrade" in action_lower or "patch" in action_lower:
                        response_list.append("update")
                    if "workaround" in action_lower:
                        response_list.append("workaround_available")
                    if "rollback" in action_lower or "revert" in action_lower:
                        response_list.append("rollback")
                    
                    if response_list:
                        v_obj["analysis"]["response"] = response_list
            
            # Restore original detail if available (perfect restoration)
            # This applies to ALL states, not just exploitable
            original_detail = get_extension_field(vv, "cyclonedx", "analysis.detail")
            if original_detail and self.options.restore:
                v_obj["analysis"]["detail"] = original_detail
            elif state == "exploitable":
                # For exploitable state, try to set detail from impact/action statements
                action_stmt = None
                impact_stmt = None
                for st in stmts:
                    if st.status.value == VulnerabilityStatus.AFFECTED:
                        if st.action_statement:
                            action_stmt = st.action_statement
                        if st.status.impact_statement:
                            impact_stmt = st.status.impact_statement
                        if action_stmt or impact_stmt:
                            break
                
                # Priority: impact_statement > action_statement
                if impact_stmt:
                    v_obj["analysis"]["detail"] = impact_stmt
                elif action_stmt and action_stmt != "No remediation information available":
                    v_obj["analysis"]["detail"] = action_stmt
            
            # Restore analysis timestamps (firstIssued, lastUpdated)
            original_first_issued = get_extension_field(vv, "cyclonedx", "analysis.firstIssued")
            if original_first_issued and self.options.restore:
                v_obj["analysis"]["firstIssued"] = original_first_issued
            
            original_last_updated = get_extension_field(vv, "cyclonedx", "analysis.lastUpdated")
            if original_last_updated and self.options.restore:
                v_obj["analysis"]["lastUpdated"] = original_last_updated
            
            # VDR (Vulnerability Disclosure Report) 필드 복원
            # detail - 상세 설명
            detail = get_extension_field(vv, "cyclonedx", "detail")
            if detail:
                v_obj["detail"] = detail
            
            # recommendation - 해결 방안
            recommendation = get_extension_field(vv, "cyclonedx", "recommendation")
            if recommendation:
                v_obj["recommendation"] = recommendation
            
            # workaround - 임시 조치
            workaround = get_extension_field(vv, "cyclonedx", "workaround")
            if workaround:
                v_obj["workaround"] = workaround
            
            # proofOfConcept - POC
            proof_of_concept = get_extension_field(vv, "cyclonedx", "proofOfConcept")
            if proof_of_concept:
                v_obj["proofOfConcept"] = proof_of_concept
            
            # credits - 발견자 정보
            credits = get_extension_field(vv, "cyclonedx", "credits")
            if credits:
                v_obj["credits"] = credits

            # Add affects FIFTH
            v_obj["affects"] = affects

            # Add justification ONLY if state is not_affected
            # (justification is only valid for not_affected state in CycloneDX)
            just_enum, custom_just, original_just_str = None, None, None
            for st in stmts:
                # Check custom_justification first
                if st.status.custom_justification:
                    custom_just = st.status.custom_justification
                    # If it's CycloneDX format (starts with "cyclonedx:"), keep it
                    # If it's OpenVEX format, try to map it to enum
                    if not custom_just.startswith("cyclonedx:"):
                        # Try to map OpenVEX justification to enum
                        just_enum = map_openvex_justification_str_to_enum(custom_just)
                        if just_enum:
                            original_just_str = custom_just
                            custom_just = None  # Clear custom_just so we use just_enum
                    break
                elif st.status.justification:
                    just_enum = st.status.justification
                    original_just_str = justification_enum_to_openvex_str(st.status.justification)
                    break

            # Only add justification if state is "not_affected"
            if state == "not_affected":
                # Use custom_just if it's a CycloneDX justification
                if custom_just and custom_just.startswith("cyclonedx:"):
                    cdx_just = custom_just[10:]  # Remove "cyclonedx:" prefix
                    v_obj["analysis"]["justification"] = cdx_just
                elif just_enum:
                    cdx_just = justification_enum_to_cyclonedx_str(just_enum)
                    if cdx_just:
                        v_obj["analysis"]["justification"] = cdx_just

                        # Add detail with original justification if needed
                        if self.options.use_free_text_encoding:
                            if original_just_str in ["vulnerable_code_cannot_be_controlled_by_adversary",
                                                    "component_not_present", "vulnerable_code_not_present"]:
                                embedded_data = {"original_justification": original_just_str}
                                encoded = encode_structured_text(embedded_data)
                                detail_parts = [encoded]
                                for st in stmts:
                                    if st.status.impact_statement:
                                        detail_parts.append(st.status.impact_statement)
                                        break
                                v_obj["analysis"]["detail"] = " ".join(detail_parts)
                    else:
                        # Unmappable justification
                        if self.options.use_free_text_encoding and original_just_str:
                            embedded_data = {"original_justification": original_just_str}
                            detail_parts = [encode_structured_text(embedded_data)]
                            for st in stmts:
                                if st.status.impact_statement:
                                    detail_parts.append(st.status.impact_statement)
                                    break
                            v_obj["analysis"]["detail"] = " ".join(detail_parts)

            elif custom_just and self.options.use_free_text_encoding:
                embedded_data = {"custom_justification": custom_just}
                detail_parts = [encode_structured_text(embedded_data)]
                for st in stmts:
                    if st.status.impact_statement:
                        detail_parts.append(st.status.impact_statement)
                        break
                v_obj["analysis"]["detail"] = " ".join(detail_parts)

            # Add impact statement as detail if not already added
            detail = next((st.status.impact_statement for st in stmts if st.status.impact_statement), None)
            if detail and "detail" not in v_obj["analysis"]:
                v_obj["analysis"]["detail"] = detail

            # Add false_positive note
            if original_state == "false_positive" and "detail" not in v_obj["analysis"]:
                v_obj["analysis"]["detail"] = "False Positive: This vulnerability does not apply to this component."

            # Add resolved_with_pedigree note
            if original_state == "resolved_with_pedigree" and "detail" not in v_obj["analysis"]:
                v_obj["analysis"]["detail"] = "Resolved with pedigree evidence (commit history, diffs available)."

            # Add vulnerability details
            if vv:
                # ratings already added above in correct order

                # Map CSAF notes to analysis.detail
                # Restore original notes category from extension_data
                if cim.metadata.source_format == DocumentFormat.CSAF and vv.notes:
                    detail_notes = []
                    
                    # Check if original notes exist in extension_data
                    original_notes = get_extension_field(vv, "csaf", "notes")
                    
                    for note in vv.notes:
                        category = note.get("category", "")
                        text = note.get("text", "")
                        
                        # Find original category from extension_data
                        original_category = category
                        if original_notes:
                            for orig_note in original_notes:
                                if orig_note.get("text") == text:
                                    original_category = orig_note.get("category", category)
                                    break
                        
                        # Include "details" category notes (원본 category 기준)
                        if original_category == "details" and text:
                            detail_notes.append(text)
                        # Include "summary" that was originally "details" (원본 복원)
                        elif original_category == "details" and category == "summary" and text:
                            detail_notes.append(text)
                        # Also include other non-standard categories
                        elif original_category not in ["description", "summary", "general", "legal_disclaimer"] and text:
                            detail_notes.append(text)
                    
                    if detail_notes:
                        # Combine with existing justification if present
                        if "detail" in v_obj["analysis"]:
                            # Append notes to existing detail
                            existing_detail = v_obj["analysis"]["detail"]
                            combined_detail = existing_detail + " | " + " | ".join(detail_notes)
                            v_obj["analysis"]["detail"] = combined_detail
                        else:
                            # Create new detail from notes
                            v_obj["analysis"]["detail"] = " | ".join(detail_notes)

                # Keep description separate
                if vv.description:
                    v_obj["description"] = vv.description

                if vv.cwes:
                    v_obj["cwes"] = unique_list(vv.cwes)
                if vv.references:
                    refs_data = []
                    for r in vv.references:
                        # Use Reference.id if available (from CycloneDX)
                        ref_id = r.id
                        
                        # If no id, extract from URL
                        if not ref_id and r.url:
                            ref_id = r.url
                            if "CVE-" in r.url:
                                # Extract CVE-ID from URL
                                import re
                                cve_match = re.search(r'CVE-\d{4}-\d+', r.url)
                                if cve_match:
                                    ref_id = cve_match.group(0)
                            elif "bugzilla.redhat.com" in r.url and "id=" in r.url:
                                # Extract RHBZ# format: https://bugzilla.redhat.com/show_bug.cgi?id=2345824 → RHBZ#2345824
                                import re
                                bz_match = re.search(r'id=(\d+)', r.url)
                                if bz_match:
                                    ref_id = f"RHBZ#{bz_match.group(1)}"
                            elif "bugzilla" in r.url and "id=" in r.url:
                                # Generic bugzilla: id=12345 → BZ#12345
                                import re
                                bz_match = re.search(r'id=(\d+)', r.url)
                                if bz_match:
                                    ref_id = f"BZ#{bz_match.group(1)}"

                        # If summary is same as URL or missing, extract domain name
                        name = r.summary or "Ref"
                        if name == r.url or name == "Ref":
                            # Extract domain from URL
                            try:
                                from urllib.parse import urlparse
                                parsed = urlparse(r.url) if r.url else None
                                if parsed:
                                    domain = parsed.netloc
                                    if domain:
                                        # Convert domain to readable name
                                        if 'nvd.nist.gov' in domain:
                                            name = "NVD"
                                        elif 'cve.org' in domain:
                                            name = "CVE.org"
                                        elif 'github.com' in domain:
                                            name = "GitHub Advisories"
                                        elif 'access.redhat.com' in domain:
                                            name = "Red Hat"
                                        elif 'bugzilla.redhat.com' in domain:
                                            name = "RHBZ"
                                        elif 'bugzilla' in domain:
                                            name = "Bugzilla"
                                        else:
                                            # Use domain as name
                                            name = domain
                            except:
                                pass

                        # Build reference object
                        ref_obj = {}
                        if ref_id:
                            ref_obj["id"] = ref_id
                        if r.url:
                            if "source" not in ref_obj:
                                ref_obj["source"] = {}
                            ref_obj["source"]["url"] = r.url
                        if name and name != "Ref":
                            if "source" not in ref_obj:
                                ref_obj["source"] = {}
                            ref_obj["source"]["name"] = name
                        
                        if ref_obj:
                            refs_data.append(ref_obj)

                    refs_data = dedupe_references(refs_data)
                    if refs_data:
                        v_obj["references"] = refs_data
                
                # Restore recommendation from extension_data
                recommendation = get_extension_field(vv, "cyclonedx", "recommendation")
                if recommendation:
                    v_obj["recommendation"] = recommendation

                # Process remediations from CSAF
                if vv.remediations:
                    # Collect all remediations for this vulnerability
                    # Get ALL product IDs for this vulnerability (not just affected)
                    # remediations can apply to any status (affected, not_affected, fixed, etc)
                    all_pids = set()
                    for st in stmts:
                        for ref in st.subject_refs:
                            mapped_ref = ref_mapping.get(ref, ref)
                            all_pids.add(mapped_ref)

                    response_list = []
                    workaround_list = []
                    recommendation_list = []

                    for rem in vv.remediations:
                        category = rem.get("category", "")
                        details = rem.get("details", "")
                        rem_product_ids = set(rem.get("product_ids", []))

                        # Check if this remediation applies to affected products
                        # product_ids가 없으면 모든 affected 제품에 적용된다고 가정
                        if rem_product_ids:
                            # product_ids가 명시된 경우에만 교집합 체크
                            if not rem_product_ids.intersection(all_pids):
                                # Skip remediations that don't apply to any affected products
                                continue
                        # product_ids가 없으면 모든 affected 제품에 적용

                        # Map CSAF category to CycloneDX response
                        if category == "vendor_fix":
                            response_list.append("update")
                            # Add to recommendation in "category: details" format
                            if details:
                                recommendation_list.append(f"vendor_fix: {details}")
                            # Track
                            self.tracking_table.add(
                                source_field="vulnerabilities.remediations.category",
                                source_value="vendor_fix",
                                target_field="vulnerabilities.analysis.response",
                                target_value="update",
                                rule="CSAF vendor_fix → CycloneDX update",
                                status="TRANSFORMED"
                            )

                        elif category == "workaround":
                            response_list.append("workaround_available")
                            # Add to recommendation in "category: details" format
                            if details:
                                recommendation_list.append(f"workaround: {details}")
                                workaround_list.append(details)
                            # Track
                            self.tracking_table.add(
                                source_field="vulnerabilities.remediations.category",
                                source_value="workaround",
                                target_field="vulnerabilities.analysis.response",
                                target_value="workaround_available",
                                rule="CSAF workaround → CycloneDX workaround_available",
                                status="TRANSFORMED"
                            )

                        elif category == "mitigation":
                            # Keyword check: rollback keyword
                            if details and any(kw in details.lower() for kw in ["rollback", "revert", "previous version", "downgrade", "older release"]):
                                response_list.append("rollback")
                            else:
                                response_list.append("workaround_available")
                            # Add to recommendation in "category: details" format
                            if details:
                                recommendation_list.append(f"mitigation: {details}")

                        elif category == "no_fix_planned":
                            response_list.append("will_not_fix")
                            # Do NOT add to recommendation (only vendor_fix/mitigation/workaround)
                            # Track
                            self.tracking_table.add(
                                source_field="vulnerabilities.remediations.category",
                                source_value="no_fix_planned",
                                target_field="vulnerabilities.analysis.response",
                                target_value="will_not_fix",
                                rule="CSAF no_fix_planned → CycloneDX will_not_fix",
                                status="TRANSFORMED"
                            )

                        elif category == "none_available":
                            # CSAF none_available: 
                            # - If exploitable state: add can_not_fix (SHOULD have response)
                            # - Otherwise: omit response
                            if state == "exploitable":
                                response_list.append("can_not_fix")
                                # Track
                                self.tracking_table.add(
                                    source_field="vulnerabilities.remediations.category",
                                    source_value="none_available",
                                    target_field="vulnerabilities.analysis.response",
                                    target_value="can_not_fix",
                                    rule="CSAF none_available (exploitable) → CycloneDX can_not_fix",
                                    status="TRANSFORMED"
                                )
                            else:
                                # Track
                                self.tracking_table.add(
                                    source_field="vulnerabilities.remediations.category",
                                    source_value="none_available",
                                    target_field="vulnerabilities.analysis.response",
                                    target_value="(omitted)",
                                    rule="CSAF none_available (non-exploitable) → CycloneDX response omitted",
                                    status="TRANSFORMED"
                                )

                        elif category == "fix_planned":
                            response_list.append("update")
                            # Do NOT add to recommendation (only vendor_fix/mitigation/workaround)

                        elif category == "optional_patch":
                            response_list.append("update")
                            # Do NOT add to recommendation (only vendor_fix/mitigation/workaround)

                        else:
                            # Unknown category, add to recommendation
                            if details:
                                recommendation_list.append(details)

                    # remediations.details를 analysis.detail로 복사
                    detail_parts = []
                    if recommendation_list:
                        detail_parts.extend(recommendation_list)
                    if workaround_list:
                        detail_parts.extend(workaround_list)

                    # remediations.details가 있으면 우선 (threats.details 덮어쓰기)
                    # BUT: restore 모드일 때는 원본 detail을 유지
                    if detail_parts:
                        original_detail = get_extension_field(vv, "cyclonedx", "analysis.detail")
                        if not (original_detail and self.options.restore):
                            v_obj["analysis"]["detail"] = " | ".join(detail_parts)

                    # Add to v_obj
                    if response_list:
                        # Deduplicate but preserve order
                        seen = set()
                        unique_responses = []
                        for r in response_list:
                            if r not in seen:
                                seen.add(r)
                                unique_responses.append(r)

                        if "response" not in v_obj["analysis"]:
                            v_obj["analysis"]["response"] = unique_responses
                        else:
                            # Merge with existing responses
                            existing = v_obj["analysis"]["response"]
                            if not isinstance(existing, list):
                                existing = [existing]
                            for r in unique_responses:
                                if r not in existing:
                                    existing.append(r)
                            v_obj["analysis"]["response"] = existing

                    if workaround_list:
                        v_obj["workaround"] = " | ".join(workaround_list)

                    # Recommendation: Join with newline (multiple remediations separated by newline)
                    if recommendation_list:
                        v_obj["recommendation"] = "\n".join(recommendation_list)

            out.append(v_obj)
        return out

    @staticmethod
    def _rating(r: CvssRating) -> Dict:
        o = {}

        # Add source FIRST with CVSS calculator URL
        if r.vector and r.method:
            # Determine CVSS version from method
            version = None
            if "CVSSv3.1" in r.method or "3.1" in r.method:
                version = "3.1"
            elif "CVSSv3.0" in r.method or "3.0" in r.method:
                version = "3.0"
            elif "CVSSv2" in r.method or "2" in r.method:
                version = "2"

            if version and version in ["3.0", "3.1"]:
                # Build CVSS calculator URL
                vector_clean = r.vector
                if vector_clean.startswith("CVSS:"):
                    vector_clean = vector_clean.split("/", 1)[1] if "/" in vector_clean else vector_clean

                calc_url = f"https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector={vector_clean}&version={version}"
                o["source"] = {
                    "name": "NVD",
                    "url": calc_url
                }

        # Order: score, severity, method, vector (as requested)
        if r.score is not None:
            o["score"] = r.score
        if r.severity:
            # Normalize severity to lowercase (CycloneDX requirement)
            o["severity"] = r.severity.lower()
        if r.method:
            # Normalize method to CycloneDX format
            # CVSSv3.1 → CVSSv31, CVSSv3.0 → CVSSv3, CVSSv2 → CVSSv2
            method = r.method
            if "CVSSv3.1" in method or method == "CVSSv3.1":
                o["method"] = "CVSSv31"
            elif "CVSSv3.0" in method or method == "CVSSv3.0" or method == "CVSSv3":
                o["method"] = "CVSSv3"
            elif "CVSSv2" in method or method == "CVSSv2":
                o["method"] = "CVSSv2"
            elif method in ["CVSSv4", "OWASP", "SSVC", "other"]:
                o["method"] = method
            else:
                # Default: use as-is
                o["method"] = method

        # Remove CVSS version prefix from vector (e.g., "CVSS:3.1/" → "")
        if r.vector:
            vector = r.vector
            if vector.startswith("CVSS:"):
                # Remove "CVSS:3.1/" or "CVSS:3.0/" prefix
                parts = vector.split("/", 1)
                vector = parts[1] if len(parts) > 1 else vector
            o["vector"] = vector

        return o

class CIMToCSAF:
    def __init__(self, options: ConversionOptions, tracking_table: TrackingTable = None):
        self.options = options
        self.tracking_table = tracking_table or TrackingTable()

    def convert(self, cim: CIM) -> Dict:
        pub = cim.metadata.publisher

        # Extract namespace from original_id if it's a URL
        namespace = pub.namespace

        # Ensure namespace has https:// prefix
        if namespace and not namespace.startswith(("http://", "https://")):
            namespace = f"https://{namespace}"

        if not namespace and cim.metadata.original_id:
            original_id = cim.metadata.original_id
            if original_id.startswith("http://") or original_id.startswith("https://"):
                # Extract domain from URL: https://openvex.dev/docs/... → https://openvex.dev
                from urllib.parse import urlparse
                parsed = urlparse(original_id)
                namespace = f"{parsed.scheme}://{parsed.netloc}"

        # Fallback to clean author-based namespace (without .example.com)
        if not namespace:
            if pub.name == "Unknown":
                # Use generic namespace for unknown publishers
                namespace = "https://csaf.io/unknown"
            else:
                namespace = f"https://{pub.name.lower().replace(' ', '-')}.com"

        full_product_names = []
        product_id_map = {}  # original_ref → simple_id

        # Get serial number for bomlink generation
        serial_number = cim.metadata.original_id or f"urn:uuid:{cim.metadata.id}"

        # Collect product information for branches structure
        products_by_vendor = {}  # vendor → {product_name → [versions]}

        for s in cim.subjects:
            # Simplify product_id
            purl = next((i.value for i in s.identifiers if i.type == "purl"), None)
            cpe = next((i.value for i in s.identifiers if i.type == "cpe"), None)

            # Extract vendor first (needed for unique product_id)
            # vendor 일관화: purl 기반 표준화
            vendor = "Unknown Vendor"
            base_product_name = s.name or ""
            version = s.version  # Start with Subject.version (most accurate)
            product_name = base_product_name

            # Try to extract vendor from PURL first
            if purl:
                try:
                    # Normalize PURL: remove query strings (e.g., repository_url)
                    # pkg:oci/trivy?repository_url=... → pkg:oci/trivy
                    normalized_purl = purl.split("?")[0].split("#")[0]
                    
                    # pkg:type/namespace/name@version OR pkg:type/name@version
                    parts = normalized_purl.split("/")
                    
                    if len(parts) >= 3:
                        # pkg:type/namespace/name - namespace is vendor
                        vendor = parts[1]
                        # Extract product name
                        name_part = parts[-1].split("@")[0]
                        if name_part:
                            product_name = name_part
                    elif len(parts) == 2:
                        # pkg:type/name - use type as vendor
                        pkg_type = normalized_purl.split(":")[1].split("/")[0]
                        vendor = pkg_type.capitalize()
                        # Extract product name
                        name_part = parts[-1].split("@")[0]
                        if name_part:
                            product_name = name_part

                    # Extract version from purl ONLY if s.version is not set
                    if not version and "@" in normalized_purl:
                        version_part = normalized_purl.split("@")[1]
                        if version_part:
                            version = version_part
                except:
                    pass

            # Try to extract vendor from CPE
            if not vendor or vendor == "Unknown Vendor":
                if cpe:
                    try:
                        # cpe:2.3:a:vendor:product:version:...
                        cpe_parts = cpe.split(":")
                        if len(cpe_parts) >= 4:
                            vendor = cpe_parts[3]
                            if len(cpe_parts) >= 5:
                                product_name = cpe_parts[4]
                            if len(cpe_parts) >= 6:
                                version = cpe_parts[5]
                    except:
                        pass

            # FINAL: Always clean product_name (remove any remaining version patterns)
            import re
            if product_name:
                # Remove "vers:..." patterns: "product-ABC vers:generic/>=1.0|<=2.3" → "product-ABC"
                product_name = re.sub(r'\s+vers:[^\s]+', '', product_name)
                # Remove trailing versions: " 1.0", " v2.4", " 2.4.1"
                product_name = re.sub(r'\s+v?\d+[\.\d]*.*$', '', product_name)
                # Remove trailing versions: "-1.0", "-v2.4", "-2.4.1"  
                product_name = re.sub(r'-v?\d+[\.\d]*.*$', '', product_name)
                # Remove trailing versions: "_1.0", "_v2.4", "_2.4.1"
                product_name = re.sub(r'_v?\d+[\.\d]*.*$', '', product_name)
                # Remove if product_name is just a version number or range
                if re.match(r'^v?\d+[\.\d]*$', product_name) or product_name.startswith('vers:'):
                    product_name = "product"  # Fallback name
                # Remove empty name
                if not product_name or product_name.strip() == "":
                    product_name = "product"

            # vendor/product 중복 방지 및 일관화
            if vendor and product_name:
                # 같으면 vendor를 Unknown Vendor로
                if vendor.lower() == product_name.lower():
                    vendor = "Unknown Vendor"
                # vendor 표준화 (oci, Oci, OCI → oci)
                vendor = vendor.strip()
                if vendor.lower() == "oci":
                    vendor = "oci"

            # Now create unique product_id with vendor prefix and version
            # This ensures different vendors with same product name get different IDs
            base_simple_id = simplify_product_id(purl or cpe or s.ref, product_name)

            # Make product_id unique by including vendor
            # PRIORITY 1: If subject has original_id from CSAF, use it directly
            if s.original_id and not s.original_id.startswith("urn:cdx"):
                # Use original CSAF product_id directly (no modifications)
                simple_id = s.original_id
                product_id_map[s.ref] = simple_id
            else:
                # PRIORITY 2: Generate new product_id
                vendor_prefix = vendor.lower().replace(" ", "-").replace(".", "-")[:20]
                if vendor_prefix and vendor_prefix != "unknown-vendor":
                    simple_id = f"{vendor_prefix}-{base_simple_id}"
                else:
                    simple_id = base_simple_id
                
                # IMPORTANT: Ensure product_id includes version to prevent duplicates
                # Check if version is already in simple_id (from purl/cpe)
                version_suffix = f":v{version}" if version and version != "unknown" else ":unknown"
                
                # Only add version if not already present
                if version and version != "unknown":
                    # Check if version is already in simple_id
                    if version not in simple_id and not simple_id.endswith(version):
                        simple_id = f"{simple_id}:v{version}"
                else:
                    # No version or unknown: add ":unknown" if not already present
                    if not simple_id.endswith(":unknown"):
                        simple_id = f"{simple_id}:unknown"

                product_id_map[s.ref] = simple_id

            # Store in hierarchy
            if vendor not in products_by_vendor:
                products_by_vendor[vendor] = {}

            if product_name not in products_by_vendor[vendor]:
                products_by_vendor[vendor][product_name] = []

            # Create comprehensive product identification helper
            pih = create_product_identification_helper(s, serial_number)

            # Check for duplicate product_id before adding
            existing_ids = [v["product_id"] for v in products_by_vendor[vendor][product_name]]
            if simple_id not in existing_ids:
                products_by_vendor[vendor][product_name].append({
                    "product_id": simple_id,
                    "name": product_name,  # Product name only, no version
                    "version": version,
                    "pih": pih,
                    "subject": s
                })

        # Generate tracking ID
        # First, try to restore from extension_data
        tracking_id = get_extension_field(cim.metadata, "csaf", "tracking.id")
        
        if not tracking_id:
            # Fallback to original_id if it's not a URL
            if cim.metadata.original_id and not cim.metadata.original_id.startswith(("http://", "https://")):
                tracking_id = cim.metadata.original_id.strip()
            else:
                # Generate new tracking ID: CSAF-YYYYMMDD-NNNN
                from datetime import datetime
                date_str = datetime.now().strftime("%Y%m%d")
                tracking_id = f"CSAF-{date_str}-{cim.metadata.id[:8]}"

        # Try to restore original branches from extension_data first
        original_branches = get_extension_field(cim.metadata, "csaf", "product_tree.branches")
        
        if original_branches:
            # Use original branches structure, but convert purl → purls for CSAF 2.0 compliance
            def convert_purl_to_purls(branch):
                """Recursively convert 'purl' (single) to 'purls' (array) in branches"""
                if "product" in branch:
                    pih = branch["product"].get("product_identification_helper", {})
                    if pih and "purl" in pih and "purls" not in pih:
                        # Convert single purl to purls array
                        pih["purls"] = [pih["purl"]]
                        del pih["purl"]
                
                # Recursively process sub-branches
                if "branches" in branch:
                    for sub_branch in branch["branches"]:
                        convert_purl_to_purls(sub_branch)
                
                return branch
            
            # Convert all branches
            branches = [convert_purl_to_purls(b.copy()) for b in original_branches]
        else:
            # Build branches structure: vendor -> product_name -> product_version
            branches = []
            for vendor, products in sorted(products_by_vendor.items()):
                product_branches = []

                for product_name, versions in sorted(products.items()):
                    version_branches = []

                    for v_info in versions:
                        version = v_info["version"]
                    
                        # Skip subjects without version (version is None or empty)
                        # These are base product references, not specific versions
                        if not version or version in ["unknown", ""]:
                            continue

                        # Determine category based on version
                        if version and ":" not in version and not version.startswith("vers:"):
                            # Single version
                            category = "product_version"
                            name = version
                        elif version and version.startswith("vers:"):
                            # Version range
                            category = "product_version_range"
                            name = version
                        else:
                            # Complex version
                            category = "product_version"
                            name = version

                        # Build full product name: "Vendor Product Version"
                        # Example: "Example Company Controller A 1.0"
                        full_name_parts = []
                        if vendor and vendor != "Unknown Vendor":
                            full_name_parts.append(vendor)
                        full_name_parts.append(product_name)
                        if version:
                            full_name_parts.append(version)

                        full_product_name = " ".join(full_name_parts)
                    
                        # Ensure product name is different from product_id
                        product_display_name = full_product_name
                        if product_display_name == v_info["product_id"]:
                            # If they're the same, add more context
                            if version and version != "unknown":
                                product_display_name = f"{product_name} {version}"
                            else:
                                product_display_name = f"{product_name} (unversioned)"

                        # product_id와 name이 중복되지 않도록 수정
                        # name은 "Vendor Product Version" 형식
                        # product_id는 간단한 식별자
                        version_branch = {
                            "category": category,
                            "name": name,
                            "product": {
                                "product_id": v_info["product_id"],
                                "name": product_display_name
                            }
                        }

                        if v_info["pih"]:
                            version_branch["product"]["product_identification_helper"] = v_info["pih"]

                        version_branches.append(version_branch)

                    # Only add product_branch if it has version_branches
                    # CSAF requires branches to be non-empty if present
                    if version_branches:
                        product_branch = {
                            "category": "product_name",
                            "name": product_name,
                            "branches": version_branches
                        }
                        product_branches.append(product_branch)

                # Only add vendor_branch if it has product_branches
                # CSAF requires branches to be non-empty if present
                if product_branches:
                    vendor_branch = {
                        "category": "vendor",
                        "name": vendor,
                        "branches": product_branches
                    }
                    branches.append(vendor_branch)

        # Check which products are in branches
        products_in_branches = set()
        for vendor_branch in branches:
            for product_branch in vendor_branch.get("branches", []):
                for version_branch in product_branch.get("branches", []):
                    if "product" in version_branch:
                        products_in_branches.add(version_branch["product"]["product_id"])
        
        # CHANGED: Always use branches structure only (not full_product_names)
        # This ensures consistency between regular and restore modes
        # All products should be in branches already
        full_product_names = []
        
        # Build product_tree
        pt = {}
        
        # Helper function to recursively remove empty branches
        def remove_empty_branches(branch):
            """
            Recursively remove empty branches arrays from branch structure.
            CSAF requires branches to be non-empty if present.
            """
            if "branches" in branch:
                # Filter out empty or None branches
                non_empty = [
                    remove_empty_branches(b) 
                    for b in branch["branches"] 
                    if b is not None
                ]
                
                if non_empty:
                    # Keep non-empty branches
                    branch["branches"] = non_empty
                else:
                    # Remove empty branches field entirely
                    del branch["branches"]
            
            return branch
        
        # Add branches if not empty
        if branches:
            # Clean up empty branches recursively
            cleaned_branches = []
            for vb in branches:
                if vb.get("branches"):  # Has product branches
                    cleaned_vb = remove_empty_branches(vb.copy())
                    # Only add if still has branches after cleaning
                    if "branches" in cleaned_vb or "product" in cleaned_vb:
                        cleaned_branches.append(cleaned_vb)
            
            if cleaned_branches:
                pt["branches"] = cleaned_branches
        
        # Add full_product_names if any products were not in branches
        if full_product_names:
            pt["full_product_names"] = full_product_names
        
        # CRITICAL: Ensure product_tree has at least one product definition
        # CSAF requires product_tree to contain at least one product
        if not pt:
            # No branches and no full_product_names - this is an error
            # Add all subjects to full_product_names as fallback
            full_product_names = []
            for s in cim.subjects:
                product_id = product_id_map.get(s.ref, s.ref)
                product_name = s.name or product_id
                pih = create_product_identification_helper(s, serial_number)
                
                fpn = {
                    "product_id": product_id,
                    "name": product_name
                }
                
                if pih:
                    fpn["product_identification_helper"] = pih
                
                full_product_names.append(fpn)
            
            if full_product_names:
                pt["full_product_names"] = full_product_names
        
        # Restore product_tree.relationships from extension_data
        relationships = get_extension_field(cim.metadata, "csaf", "product_tree.relationships")
        if relationships:
            # Convert purl → purls in relationships
            for rel in relationships:
                fpn = rel.get("full_product_name", {})
                pih = fpn.get("product_identification_helper", {})
                if pih and "purl" in pih and "purls" not in pih:
                    pih["purls"] = [pih["purl"]]
                    del pih["purl"]
            pt["relationships"] = relationships
        
        vulns = self._vulns(cim, product_id_map)

        # Create product_groups for frequently used product sets (optional for consistency)
        if self.options.use_csaf_product_groups:
            product_groups = self._create_product_groups(vulns, product_id_map)
            if product_groups:
                pt["product_groups"] = product_groups

        # Set title based on source format and vulnerabilities
        # Title should be canonical name or sufficiently unique
        vuln_count = len(set(st.vulnerability_id for st in cim.statements))
        product_count = len(cim.subjects)

        if cim.metadata.source_format == DocumentFormat.CYCLONEDX:
            title = f"CSAF VEX Document for {vuln_count} CVEs across {product_count} Products (CycloneDX-derived)"
        elif cim.metadata.source_format == DocumentFormat.OPENVEX:
            title = f"CSAF VEX Document for {vuln_count} CVEs across {product_count} Products (OpenVEX-derived)"
        else:
            title = f"CSAF VEX Document for {vuln_count} CVEs across {product_count} Products"

        result = {
            "$schema": "https://docs.oasis-open.org/csaf/csaf/v2.1/schema/csaf.json",
            "document": self._build_document(cim, pub, namespace, tracking_id, title),
            "product_tree": pt,
            "vulnerabilities": vulns
        }
        
        # Reversible mode: store metadata in document.notes
        if self.options.reversible:
            lost_data = self._collect_lost_data(cim)
            
            # Collect extension_data
            extension_data = {}
            if cim.metadata.extension_data:
                extension_data["metadata"] = cim.metadata.extension_data
            for idx, subj in enumerate(cim.subjects):
                if subj.extension_data:
                    extension_data[f"subject_{idx}"] = subj.extension_data
            for vuln in cim.vulnerabilities:
                if vuln.extension_data:
                    extension_data[f"vulnerability_{vuln.id}"] = vuln.extension_data
            for idx, stmt in enumerate(cim.statements):
                if stmt.extension_data:
                    extension_data[f"statement_{idx}"] = stmt.extension_data
            
            # Collect subject_mappings
            subject_mappings = {}
            for subj in cim.subjects:
                if subj.original_id:
                    subject_mappings[subj.ref] = subj.original_id
                else:
                    subject_mappings[subj.ref] = subj.ref
            
            if lost_data or extension_data or subject_mappings:
                conv_meta = ConversionMetadata(
                    version="1.0",
                    source_format="CIM",
                    target_format="CSAF",
                    timestamp=dt_to_iso_z(now_utc()),
                    lost_data=lost_data,
                    extension_data=extension_data,
                    subject_mappings=subject_mappings
                )
                encoded = conv_meta.encode()
                
                # Store in document.notes
                if "notes" not in result["document"]:
                    result["document"]["notes"] = []
                
                result["document"]["notes"].insert(0, {
                    "category": "general",
                    "title": "VEXCO Conversion Metadata",
                    "text": encoded
                })
                
                items_count = len(lost_data) + len(extension_data) + len(subject_mappings)
                print(f"\n[Reversible Mode] Stored {items_count} item(s) in document.notes:")
                if lost_data:
                    print(f"  - {len(lost_data)} lost fields (not recoverable)")
                else:
                    print(f"  - 0 lost fields (all data preserved!)")
                if extension_data:
                    print(f"  - {len(extension_data)} extension data entries (recoverable)")
                if subject_mappings:
                    print(f"  - {len(subject_mappings)} subject ID mappings (recoverable)")
        
        return result
    
    def _collect_lost_data(self, cim: CIM) -> Dict[str, Any]:
        """Collect data that will be lost in CSAF conversion"""
        lost = {}
        
        # Collect OpenVEX/CycloneDX-specific fields that don't map to CSAF
        # (Most CIM fields map to CSAF, so lost_data is minimal)
        
        return lost

    def _build_document(self, cim: CIM, pub: Publisher, namespace: str, tracking_id: str, title: str) -> Dict:
        """Build CSAF document section with extension_data restoration"""
        
        doc = {
            "category": get_extension_field(cim.metadata, "csaf", "document.category", "csaf_vex"),
            "csaf_version": "2.1",
            "distribution": get_extension_field(cim.metadata, "csaf", "document.distribution", {
                "tlp": {
                    "label": "CLEAR",
                    "url": "https://www.first.org/tlp/"
                }
            }),
            "publisher": {
                "category": pub.role or "multiplier",
                "name": pub.name or "The Computer and Communication Security Laboratory",
                "namespace": namespace
            },
            "title": get_extension_field(cim.metadata, "csaf", "document.title", title),
            "tracking": {
                "id": tracking_id,
                "status": get_extension_field(cim.metadata, "csaf", "document.tracking.status", "final"),
                "version": get_extension_field(cim.metadata, "csaf", "document.tracking.version", "1"),
                "revision_history": get_extension_field(cim.metadata, "csaf", "document.tracking.revision_history", [{
                    "date": dt_to_iso_z(now_utc()),
                    "number": "1",
                    "summary": f"Converted from {cim.metadata.source_format.value}"
                }]),
                "initial_release_date": dt_to_iso_z(cim.metadata.created_at),
                "current_release_date": None,  # Will be set below
                "generator": get_extension_field(cim.metadata, "csaf", "document.tracking.generator", {
                    "engine": {
                        "name": "VEXCO Engine",
                        "version": "1.0.0"
                    },
                    "date": dt_to_iso_z(now_utc())
                })
            }
        }
        
        # Ensure current_release_date is not earlier than initial_release_date
        initial_dt = cim.metadata.created_at
        current_dt = now_utc()
        
        # If current time is earlier than initial time (can happen due to timezone issues),
        # use initial time as current time
        if current_dt < initial_dt:
            current_dt = initial_dt
        
        # Check for stored current_release_date in extension_data
        stored_current_date = get_extension_field(cim.metadata, "csaf", "document.tracking.current_release_date")
        if stored_current_date:
            # Parse stored date
            try:
                stored_dt = datetime.fromisoformat(stored_current_date.replace('Z', '+00:00'))
                # Use stored date only if it's not earlier than initial date
                if stored_dt >= initial_dt:
                    current_dt = stored_dt
            except:
                pass  # Use calculated current_dt
        
        doc["tracking"]["current_release_date"] = dt_to_iso_z(current_dt)
        
        # Restore optional CSAF fields from extension_data
        
        # aggregate_severity
        aggregate_severity = get_extension_field(cim.metadata, "csaf", "document.aggregate_severity")
        if aggregate_severity:
            doc["aggregate_severity"] = aggregate_severity
        
        # lang
        lang = get_extension_field(cim.metadata, "csaf", "document.lang")
        if lang:
            doc["lang"] = lang
        
        # source_lang
        source_lang = get_extension_field(cim.metadata, "csaf", "document.source_lang")
        if source_lang:
            doc["source_lang"] = source_lang
        
        # publisher additional fields
        contact_details = get_extension_field(cim.metadata, "csaf", "document.publisher.contact_details")
        if contact_details:
            doc["publisher"]["contact_details"] = contact_details
        
        issuing_authority = get_extension_field(cim.metadata, "csaf", "document.publisher.issuing_authority")
        if issuing_authority:
            doc["publisher"]["issuing_authority"] = issuing_authority
        
        # tracking additional fields
        aliases = get_extension_field(cim.metadata, "csaf", "document.tracking.aliases")
        if aliases:
            doc["tracking"]["aliases"] = aliases
        
        # references
        references = get_extension_field(cim.metadata, "csaf", "document.references")
        if not references:
            references = []
        
        # Always add NVD as a default external reference (CSAF-REF-REQ-001)
        # Check if NVD already exists
        has_nvd = any(
            ref.get("url") == "https://nvd.nist.gov/" 
            for ref in references
        )
        if not has_nvd:
            references.insert(0, {
                "category": "external",
                "summary": "National Vulnerability Database",
                "url": "https://nvd.nist.gov/"
            })
        
        if references:
            doc["references"] = references
        
        # notes
        notes = get_extension_field(cim.metadata, "csaf", "document.notes")
        if notes:
            doc["notes"] = notes
        
        # acknowledgments
        acknowledgments = get_extension_field(cim.metadata, "csaf", "document.acknowledgments")
        if acknowledgments:
            doc["acknowledgments"] = acknowledgments
        
        return doc

    def _vulns(self, cim: CIM, product_id_map: Dict[str, str]) -> List[Dict]:
        by_vuln = {}
        for st in cim.statements:
            by_vuln.setdefault(st.vulnerability_id, []).append(st)
        vuln_idx = {v.id: v for v in cim.vulnerabilities}
        out = []

        for vid, stmts in sorted(by_vuln.items()):
            # Store original statements for perfect restoration
            vv = vuln_idx.get(vid)
            if vv and self.options.reversible:
                # Serialize statements to dict format for storage
                stmt_data = []
                for st in stmts:
                    stmt_dict = {
                        "subject_refs": st.subject_refs,
                        "status": {
                            "value": st.status.value.name,
                            "justification": st.status.justification.value if st.status.justification else None,
                            "custom_justification": st.status.custom_justification,
                            "impact_statement": st.status.impact_statement,
                            "original_state": st.status.original_state
                        },
                        "action_statement": st.action_statement,
                        "timestamp": st.timestamp.isoformat() if st.timestamp else None
                    }
                    stmt_data.append(stmt_dict)
                
                set_extension_field(vv, "csaf", "original_statements", stmt_data)
            
            # Apply product status priority to prevent duplicates
            if self.options.apply_csaf_product_priority:
                ps = self._apply_product_priority(stmts, product_id_map)
            else:
                ps = self._collect_product_statuses(stmts, product_id_map)

            # Only add flags for products that are actually in known_not_affected
            not_affected_products = set(ps.get("known_not_affected", []))

            # CSAF VEX: Add flags with justification labels for NOT_AFFECTED products
            flags = []
            flags_by_label = {}  # label → [product_ids]
            
            # Track which products have flags
            products_with_flags = set()

            for st in stmts:
                if st.status.value == VulnerabilityStatus.NOT_AFFECTED and st.status.justification:
                    # Map justification to CSAF flag label
                    label = justification_enum_to_csaf_flag(st.status.justification)
                    if label:
                        if label not in flags_by_label:
                            flags_by_label[label] = []
                        mapped_pids = [product_id_map.get(pid, pid) for pid in st.subject_refs]
                        flags_by_label[label].extend(mapped_pids)
                        products_with_flags.update(mapped_pids)
                        
                        # Track justification conversion
                        self.tracking_table.add(
                            source_field="CIM.statement.status.justification",
                            source_value=str(st.status.justification),
                            target_field="flags.label",
                            target_value=label,
                            rule=f"Justification → CSAF flag label",
                            status="TRANSFORMED"
                        )
            
            # IMPORTANT: For known_not_affected products without flags,
            # add default flag to satisfy CSAF validator
            # (CSAF requires either flag or threat for known_not_affected products)
            not_affected_without_flags = not_affected_products - products_with_flags
            if not_affected_without_flags:
                # Add default "component_not_present" flag
                default_label = "component_not_present"
                if default_label not in flags_by_label:
                    flags_by_label[default_label] = []
                flags_by_label[default_label].extend(list(not_affected_without_flags))

            # Build flags array
            for label, pids in flags_by_label.items():
                flags.append({
                    "label": label,
                    "product_ids": unique_list(pids)
                })

            v_obj = {"cve": vid}
            
            # CWE information should be in notes, not as a separate field in CSAF
            # CSAF schema does not have a cwe field at vulnerabilities level

            # Remove empty arrays from product_status
            ps_cleaned = {k: v for k, v in ps.items() if v}
            if ps_cleaned:
                v_obj["product_status"] = ps_cleaned

            # Add flags if present
            if flags:
                v_obj["flags"] = flags

            vv = vuln_idx.get(vid)
            if vv:
                notes = []
                
                # Restore original notes with their categories
                if vv.notes:
                    for note in vv.notes:
                        note_obj = {}
                        if note.get("category"):
                            note_obj["category"] = note["category"]
                        if note.get("text"):
                            note_obj["text"] = note["text"]
                        if note.get("title"):
                            note_obj["title"] = note["title"]
                        if note_obj:
                            notes.append(note_obj)
                
                # Add description as a note if not already in notes
                if vv.description:
                    # Check if description is already in notes
                    desc_exists = any(n.get("text") == vv.description for n in notes)
                    if not desc_exists:
                        notes.insert(0, {"category": "description", "text": vv.description, "title": "Vulnerability description"})
                else:
                    # If no description, add impact_statement/action_statement to notes
                    # (they will be excluded from threats.details below)
                    for st in stmts:
                        # NOT_AFFECTED: impact_statement → notes
                        if st.status.value == VulnerabilityStatus.NOT_AFFECTED and st.status.impact_statement:
                            if st.status.impact_statement not in [n.get("text") for n in notes]:
                                notes.append({
                                    "category": "summary",
                                    "text": st.status.impact_statement,
                                    "title": "Vulnerability Summary"
                                })
                        
                        # AFFECTED: action_statement → notes
                        elif st.status.value == VulnerabilityStatus.AFFECTED and st.action_statement:
                            if st.action_statement not in [n.get("text") for n in notes]:
                                notes.append({
                                    "category": "general",
                                    "text": st.action_statement,
                                    "title": "Recommended Action"
                                })
                        
                        # UNDER_INVESTIGATION: detail → notes
                        elif st.status.value == VulnerabilityStatus.UNDER_INVESTIGATION:
                            detail_text = get_extension_field(st, "cyclonedx", "analysis.detail")
                            if detail_text and detail_text not in [n.get("text") for n in notes]:
                                notes.append({
                                    "category": "general",
                                    "text": detail_text,
                                    "title": "Analysis Details"
                                })
                
                # Add recommendation as general note if available
                recommendation = get_extension_field(vv, "cyclonedx", "recommendation")
                if not recommendation:
                    # Fallback to vuln-level recommendation
                    vuln = vuln_idx.get(vid)
                    if vuln:
                        recommendation = get_extension_field(vuln, "cyclonedx", "recommendation")
                
                if recommendation:
                    # Check if already exists to avoid duplicates
                    rec_exists = any(
                        n.get("text") == recommendation and 
                        n.get("title") == "General Security Recommendations"
                        for n in notes
                    )
                    if not rec_exists:
                        notes.append({
                            "category": "general",
                            "text": recommendation,
                            "title": "General Security Recommendations"
                        })

                # Collect impact_statements that will go into threats
                threat_impact_statements = set()
                for st in stmts:
                    if st.status.value == VulnerabilityStatus.NOT_AFFECTED and st.status.impact_statement:
                        threat_impact_statements.add(st.status.impact_statement)

                # Add impact_statement from AFFECTED products to notes (only if NOT in threats)
                impact_statements = []
                for st in stmts:
                    if st.status.value != VulnerabilityStatus.NOT_AFFECTED:  # Only AFFECTED products
                        if st.status.impact_statement and st.status.impact_statement not in impact_statements:
                            impact_statements.append(st.status.impact_statement)

                for impact in impact_statements:
                    notes.append({"category": "summary", "text": impact, "title": "Impact Statement"})

                # Add notes for CycloneDX special states
                has_false_positive = any(st.status.original_state == "false_positive" for st in stmts)
                has_pedigree = any(st.status.original_state == "resolved_with_pedigree" for st in stmts)

                if has_false_positive:
                    notes.append({
                        "category": "summary",
                        "text": "Note: Some affected products were identified as false positives in the original assessment."
                    })

                if has_pedigree:
                    notes.append({
                        "category": "summary",
                        "text": "Note: Resolution includes pedigree information with commit history and code diffs."
                    })
                
                if notes:
                    # Auto-bind product_ids to notes based on content matching
                    # CSAF spec: If a note is specific to a product or product group,
                    # it MUST be bound via product_ids
                    
                    # Build product name mapping: name/version → product_id
                    product_name_map = {}
                    for st in stmts:
                        for ref in st.subject_refs:
                            # Get mapped product_id
                            pid = product_id_map.get(ref, ref)
                            
                            # Get subject
                            subj = next((s for s in cim.subjects if s.ref == ref), None)
                            if subj:
                                # Add name variations
                                if subj.name:
                                    product_name_map[subj.name.lower()] = pid
                                if subj.version:
                                    product_name_map[subj.version.lower()] = pid
                                    if subj.name:
                                        # name + version
                                        product_name_map[f"{subj.name} {subj.version}".lower()] = pid
                                
                                # Add identifier values
                                for ident in subj.identifiers:
                                    if ident.value:
                                        # Extract product name from purl or cpe
                                        if ident.type == "purl" and "/" in ident.value:
                                            parts = ident.value.split("/")
                                            if parts:
                                                prod_name = parts[-1].split("@")[0]
                                                product_name_map[prod_name.lower()] = pid
                    
                    # Match notes to products
                    for note in notes:
                        if "product_ids" in note:
                            # Already has product_ids, skip
                            continue
                        
                        # Check title and text for product mentions
                        search_text = ""
                        if note.get("title"):
                            search_text += note["title"].lower() + " "
                        if note.get("text"):
                            search_text += note["text"].lower()
                        
                        if not search_text:
                            continue
                        
                        # Find matching products
                        matched_pids = set()
                        for prod_name, pid in product_name_map.items():
                            if prod_name in search_text:
                                matched_pids.add(pid)
                        
                        # Add product_ids if matches found
                        if matched_pids:
                            note["product_ids"] = sorted(list(matched_pids))
                    
                    v_obj["notes"] = notes
                
                # CSAF VEX Profile: Add notes from remediations if no notes exist
                # This satisfies CSAF-VEX-NOTES-001 validator requirement
                if not notes and vv and vv.remediations:
                    notes_from_remed = []
                    for rem in vv.remediations:
                        if rem.get("details"):
                            notes_from_remed.append({
                                "category": "general",
                                "text": rem["details"],
                                "title": f"Remediation: {rem.get('category', 'unknown').replace('_', ' ').title()}"
                            })
                    if notes_from_remed:
                        v_obj["notes"] = notes_from_remed
                
                # Add CWEs (CSAF format: array of objects with mandatory id, name, version)
                # CWE version: CSAF requires version field for each CWE
                # We use the latest CWE version (4.13 as of 2024)
                # Source: https://cwe.mitre.org/data/index.html
                # The version represents the CWE List version, not the weakness version
                if vv.cwes:
                    # Common CWE names mapping (for most frequent CWEs)
                    cwe_names = {
                        "22": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
                        "79": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
                        "89": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                        "94": "Improper Control of Generation of Code ('Code Injection')",
                        "119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
                        "125": "Out-of-bounds Read",
                        "190": "Integer Overflow or Wraparound",
                        "200": "Exposure of Sensitive Information to an Unauthorized Actor",
                        "287": "Improper Authentication",
                        "352": "Cross-Site Request Forgery (CSRF)",
                        "416": "Use After Free",
                        "476": "NULL Pointer Dereference",
                        "502": "Deserialization of Untrusted Data",
                        "787": "Out-of-bounds Write",
                        "798": "Use of Hard-coded Credentials",
                        "862": "Missing Authorization",
                        "918": "Server-Side Request Forgery (SSRF)",
                    }
                    
                    cwes_list = []
                    for cwe in vv.cwes:
                        # Extract CWE number
                        if isinstance(cwe, int):
                            cwe_num = str(cwe)
                            cwe_id = f"CWE-{cwe}"
                        else:
                            cwe_id = cwe if cwe.startswith("CWE-") else f"CWE-{cwe}"
                            cwe_num = cwe_id.replace("CWE-", "")
                        
                        # Get name from mapping or use generic name
                        cwe_name = cwe_names.get(cwe_num, f"Weakness {cwe_id}")
                        
                        # CSAF requires id, name, and version (all mandatory)
                        cwe_obj = {
                            "id": cwe_id,
                            "name": cwe_name,
                            "version": "4.13"  # Latest CWE version as of 2024
                        }
                        cwes_list.append(cwe_obj)
                    
                    if cwes_list:
                        v_obj["cwes"] = cwes_list

                # Add CVSS metrics (CSAF format: metrics not scores)
                if vv.ratings:
                    metrics_list = []
                    for rating in vv.ratings:
                        metric_obj = {}
                        
                        # Determine CVSS version
                        if rating.method and "3.1" in rating.method:
                            cvss_key = "cvss_v3"
                            version = "3.1"
                        elif rating.method and "3.0" in rating.method:
                            cvss_key = "cvss_v3"
                            version = "3.0"
                        elif rating.method and "2" in rating.method:
                            cvss_key = "cvss_v2"
                            version = "2.0"
                        else:
                            cvss_key = "cvss_v3"
                            version = "3.1"
                        
                        # Build CVSS object
                        cvss_obj = {}
                        if version:
                            cvss_obj["version"] = version
                        if rating.vector:
                            cvss_obj["vectorString"] = rating.vector
                        if rating.score is not None:
                            cvss_obj["baseScore"] = rating.score
                        if rating.severity:
                            cvss_obj["baseSeverity"] = rating.severity.upper()
                        
                        if cvss_obj:
                            # CSAF requires "content" wrapper
                            metric_obj["content"] = {cvss_key: cvss_obj}
                            
                            # Add products (all products affected by this vulnerability)
                            product_ids = []
                            for st in stmts:
                                for ref in st.subject_refs:
                                    pid = product_id_map.get(ref, ref)
                                    if pid not in product_ids:
                                        product_ids.append(pid)
                            
                            if product_ids:
                                metric_obj["products"] = product_ids
                            
                            metrics_list.append(metric_obj)
                    
                    if metrics_list:
                        v_obj["metrics"] = metrics_list

                # Add threats with impact details - GROUP BY DETAILS
                # Include justification information for NOT_AFFECTED products
                # Include detail information for UNDER_INVESTIGATION products
                # NOTE: If no description, impact_statement goes to notes instead of threats
                threats_by_details = {}
                for st in stmts:
                    # Add threats for NOT_AFFECTED and UNDER_INVESTIGATION products
                    if st.status.value in [VulnerabilityStatus.NOT_AFFECTED, VulnerabilityStatus.UNDER_INVESTIGATION]:
                        # Build details with justification info
                        details_parts = []

                        # Add justification if present (for NOT_AFFECTED)
                        if st.status.value == VulnerabilityStatus.NOT_AFFECTED and st.status.justification:
                            just_label = st.status.justification.value.replace("_", " ").title()
                            details_parts.append(f"Justification: {just_label}")

                        # Add custom justification (original CycloneDX/OpenVEX justification)
                        if st.status.custom_justification:
                            custom_just = st.status.custom_justification
                            # If it's a CycloneDX justification, format it nicely
                            if custom_just.startswith("cyclonedx:"):
                                cdx_just = custom_just[10:]  # Remove "cyclonedx:" prefix (10 chars)
                                cdx_just_formatted = cdx_just.replace("_", " ").title()
                                details_parts.append(f"Original Justification: {cdx_just_formatted}")
                            else:
                                details_parts.append(f"Custom Justification: {custom_just}")

                        # Add impact statement ONLY if description exists
                        # (if no description, impact_statement goes to notes)
                        if vv.description and st.status.impact_statement:
                            details_parts.append(st.status.impact_statement)
                        
                        # For UNDER_INVESTIGATION, add detail ONLY if description exists
                        if st.status.value == VulnerabilityStatus.UNDER_INVESTIGATION and vv.description:
                            # Get detail from extension_data if available
                            detail_text = get_extension_field(st, "cyclonedx", "analysis.detail")
                            if detail_text and detail_text not in details_parts:
                                details_parts.append(detail_text)

                        # If no details at all, skip this statement
                        if not details_parts:
                            continue

                        details = ". ".join(details_parts)

                        if details not in threats_by_details:
                            threats_by_details[details] = []

                        mapped_pids = [product_id_map.get(pid, pid) for pid in st.subject_refs]
                        threats_by_details[details].extend(mapped_pids)

                threats = []
                for details, pids in threats_by_details.items():
                    threats.append({
                        "category": "impact",
                        "details": details,
                        "product_ids": unique_list(pids)
                    })

                if threats:
                    v_obj["threats"] = threats

                # Add remediations (REQUIRED for affected products in csaf_vex)
                remediations = []

                # Collect action statements from AFFECTED products
                # Priority order for categories: vendor_fix > mitigation > workaround > fix_planned > no_fix_planned > optional_patch > none_available
                category_priority = {
                    "vendor_fix": 1,
                    "mitigation": 2,
                    "workaround": 3,
                    "fix_planned": 4,
                    "no_fix_planned": 5,
                    "optional_patch": 6,
                    "none_available": 7
                }
                
                action_statements_by_category = {}
                for st in stmts:
                    if st.status.value == VulnerabilityStatus.AFFECTED:
                        mapped_pids = [product_id_map.get(pid, pid) for pid in st.subject_refs]
                        
                        # Use action_statement as details (primary)
                        # Fallback to impact_statement if no action_statement
                        if st.action_statement:
                            details = st.action_statement
                        elif st.status.impact_statement:
                            details = st.status.impact_statement
                        else:
                            details = "No remediation information available"

                        # Try to extract category from action_statement with priority
                        categories_found = []
                        if st.action_statement:
                            action_lower = st.action_statement.lower()
                            
                            # Check for explicit category format
                            if "," in st.action_statement and st.action_statement.split(",")[0] in [
                                "vendor_fix", "workaround", "mitigation", "no_fix_planned", 
                                "none_available", "fix_planned", "optional_patch"
                            ]:
                                parts = st.action_statement.split(",", 1)
                                categories_found.append(parts[0].strip())
                            else:
                                # Check for keywords and collect all applicable categories
                                if "update" in action_lower or "patch" in action_lower or "upgrade" in action_lower:
                                    categories_found.append("vendor_fix")
                                if "will not fix" in action_lower or "wont fix" in action_lower:
                                    categories_found.append("no_fix_planned")
                                if "workaround" in action_lower:
                                    categories_found.append("workaround")
                                if "mitigation" in action_lower or "mitigate" in action_lower:
                                    categories_found.append("mitigation")
                        
                        # Use highest priority category
                        if categories_found:
                            category = min(categories_found, key=lambda c: category_priority.get(c, 99))
                        else:
                            category = "vendor_fix"  # Default

                        key = (category, details)
                        if key not in action_statements_by_category:
                            action_statements_by_category[key] = []
                        action_statements_by_category[key].extend(mapped_pids)

                # Build remediations
                # First, use original remediations from vuln_idx
                if vv and vv.remediations:
                    for rem in vv.remediations:
                        rem_obj = {}
                        if rem.get("category"):
                            rem_obj["category"] = rem["category"]
                        if rem.get("details"):
                            rem_obj["details"] = rem["details"]
                        if rem.get("product_ids"):
                            # Map internal refs to CSAF product IDs
                            mapped_pids = [product_id_map.get(pid, pid) for pid in rem["product_ids"]]
                            rem_obj["product_ids"] = unique_list(mapped_pids)
                        
                        if rem_obj and rem_obj.get("category"):
                            remediations.append(rem_obj)
                
                # If no remediations from vuln, build from action_statements
                if not remediations:
                    for (category, details), pids in action_statements_by_category.items():
                        remediations.append({
                            "category": category,
                            "details": details,
                            "product_ids": unique_list(pids)
                        })
                        
                        # Track remediation conversion
                        self.tracking_table.add(
                            source_field="CIM.statement.action_statement",
                            source_value=f"{category}, {details[:30]}..." if len(details) > 30 else f"{category}, {details}",
                            target_field="remediations",
                            target_value=f"category: {category}",
                            rule="action_statement → CSAF remediation",
                            status="TRANSFORMED"
                        )

                # If we have affected products but no remediations, add default
                affected_pids = ps_cleaned.get("known_affected", [])
                if affected_pids and not remediations:
                    remediations.append({
                        "category": "vendor_fix",
                        "details": "No remediation information available",
                        "product_ids": affected_pids
                    })

                if remediations:
                    v_obj["remediations"] = remediations
                
                # Add references (preserve categories)
                if vv and vv.references:
                    references = []
                    for ref in vv.references:
                        ref_obj = {"url": ref.url}
                        if ref.summary:
                            ref_obj["summary"] = ref.summary
                        if ref.category:
                            ref_obj["category"] = ref.category
                        else:
                            ref_obj["category"] = "external"  # Default
                        references.append(ref_obj)
                    
                    if references:
                        v_obj["references"] = references

                # Add metrics (CVSS) - CORRECT CSAF STRUCTURE
                if vv.ratings:
                    metrics = []
                    seen_metrics = set()  # Track unique metrics
                    
                    for rating in vv.ratings:
                        if rating.vector and rating.score is not None:
                            # Determine CVSS version
                            version = "3.1"
                            if rating.method:
                                if "3.0" in rating.method:
                                    version = "3.0"
                                elif "2" in rating.method:
                                    version = "2.0"

                            # Build vector string
                            # CSAF requires:
                            #   - CVSS v3: vectorString WITH prefix (CVSS:3.1/...)
                            #   - CVSS v2: vectorString WITHOUT prefix (AV:N/AC:L/...)
                            vector = rating.vector
                            if version.startswith("3"):
                                # CVSS v3: add prefix if missing
                                if not vector.startswith("CVSS:"):
                                    vector = f"CVSS:{version}/{vector}"
                            elif version.startswith("2"):
                                # CVSS v2: remove prefix if present
                                if vector.startswith("CVSS:"):
                                    vector = vector.replace("CVSS:2.0/", "")

                            cvss_obj = {
                                "version": version,
                                "vectorString": vector,
                                "baseScore": rating.score
                            }

                            if rating.severity:
                                # CSAF requires baseSeverity in uppercase
                                cvss_obj["baseSeverity"] = rating.severity.upper()

                            # Get all products for this vulnerability
                            all_pids = []
                            for key, pids in ps_cleaned.items():
                                all_pids.extend(pids)

                            # Build metric with content and products
                            metric = {
                                "content": {},
                                "products": unique_list(all_pids)
                            }

                            # Add cvss_v3 or cvss_v2 based on version
                            if version.startswith("3"):
                                metric["content"]["cvss_v3"] = cvss_obj
                            elif version.startswith("2"):
                                metric["content"]["cvss_v2"] = cvss_obj
                            
                            # Create unique key for deduplication
                            # Use vector and products as key
                            metric_key = (vector, tuple(sorted(metric["products"])))
                            
                            if metric_key not in seen_metrics:
                                seen_metrics.add(metric_key)
                                metrics.append(metric)

                    if metrics:
                        v_obj["metrics"] = metrics

                if vv.references:
                    refs_data = []
                    for r in vv.references:
                        # Map category to CSAF allowed values: 'external' or 'self'
                        category = r.category
                        if category not in ['external', 'self']:
                            category = 'external'  # Default to external
                        
                        refs_data.append({
                            "category": category,
                            "summary": r.summary or "Ref",
                            "url": r.url
                        })
                    
                    refs_data = dedupe_references(refs_data)
                    if refs_data:
                        v_obj["references"] = refs_data

            out.append(v_obj)
        return out

    def _apply_product_priority(self, stmts: List[VEXStatement], product_id_map: Dict[str, str]) -> Dict[str, List[str]]:
        """
        Apply priority rules to prevent same product in multiple statuses.
        Priority: fixed > not_affected > affected > under_investigation
        """
        ps = {"known_not_affected": [], "known_affected": [], "fixed": [], "under_investigation": []}

        # Group by product
        by_product = {}
        for st in stmts:
            for pid in st.subject_refs:
                simple_pid = product_id_map.get(pid, pid)
                if simple_pid not in by_product:
                    by_product[simple_pid] = []
                by_product[simple_pid].append(st.status.value)

        # Apply priority for each product
        priority = {
            VulnerabilityStatus.FIXED: 4,
            VulnerabilityStatus.NOT_AFFECTED: 3,
            VulnerabilityStatus.AFFECTED: 2,
            VulnerabilityStatus.UNDER_INVESTIGATION: 1
        }

        for pid, statuses in by_product.items():
            # Get highest priority status
            highest = max(statuses, key=lambda s: priority.get(s, 0))

            if highest == VulnerabilityStatus.NOT_AFFECTED:
                ps["known_not_affected"].append(pid)
                # Track conversion
                self.tracking_table.add(
                    source_field="CIM.statement.status.value",
                    source_value=str(highest),
                    target_field="product_status.known_not_affected",
                    target_value=pid,
                    rule="NOT_AFFECTED → known_not_affected",
                    status="TRANSFORMED"
                )
            elif highest == VulnerabilityStatus.AFFECTED:
                ps["known_affected"].append(pid)
                # Track conversion
                self.tracking_table.add(
                    source_field="CIM.statement.status.value",
                    source_value=str(highest),
                    target_field="product_status.known_affected",
                    target_value=pid,
                    rule="AFFECTED → known_affected",
                    status="TRANSFORMED"
                )
            elif highest == VulnerabilityStatus.FIXED:
                ps["fixed"].append(pid)
                # Track conversion
                self.tracking_table.add(
                    source_field="CIM.statement.status.value",
                    source_value=str(highest),
                    target_field="product_status.fixed",
                    target_value=pid,
                    rule="FIXED → fixed",
                    status="TRANSFORMED"
                )
            else:
                ps["under_investigation"].append(pid)
                # Track conversion
                self.tracking_table.add(
                    source_field="CIM.statement.status.value",
                    source_value=str(highest),
                    target_field="product_status.under_investigation",
                    target_value=pid,
                    rule="UNDER_INVESTIGATION → under_investigation",
                    status="TRANSFORMED"
                )

        for k in ps:
            ps[k] = unique_list(ps[k])

        return ps

    def _collect_product_statuses(self, stmts: List[VEXStatement], product_id_map: Dict[str, str]) -> Dict[str, List[str]]:
        """Collect product statuses without priority (may have duplicates)"""
        ps = {"known_not_affected": [], "known_affected": [], "fixed": [], "under_investigation": []}

        for st in stmts:
            for pid in st.subject_refs:
                simple_pid = product_id_map.get(pid, pid)
                if st.status.value == VulnerabilityStatus.NOT_AFFECTED:
                    ps["known_not_affected"].append(simple_pid)
                elif st.status.value == VulnerabilityStatus.AFFECTED:
                    ps["known_affected"].append(simple_pid)
                elif st.status.value == VulnerabilityStatus.FIXED:
                    ps["fixed"].append(simple_pid)
                else:
                    ps["under_investigation"].append(simple_pid)

        for k in ps:
            ps[k] = unique_list(ps[k])

        return ps

    def _create_product_groups(self, vulns: List[Dict], product_id_map: Dict[str, str]) -> List[Dict]:
        """
        Create product_groups for frequently repeated product sets.
        AGGRESSIVE: Group any set with 2+ products that appears 2+ times.
        This drastically reduces document size.
        """
        # Collect all product ID sets from vulnerabilities
        product_sets = []

        for v in vulns:
            # Collect from product_status (ANY status)
            if "product_status" in v:
                for status, pids in v["product_status"].items():
                    if isinstance(pids, list) and len(pids) >= 2:  # 2+ products
                        product_sets.append(frozenset(pids))

            # Collect from remediations
            if "remediations" in v:
                for rem in v["remediations"]:
                    pids = rem.get("product_ids", [])
                    if len(pids) >= 2:
                        product_sets.append(frozenset(pids))

            # Collect from threats
            if "threats" in v:
                for threat in v["threats"]:
                    pids = threat.get("product_ids", [])
                    if len(pids) >= 2:
                        product_sets.append(frozenset(pids))

            # Collect from metrics
            if "metrics" in v:
                for metric in v["metrics"]:
                    pids = metric.get("products", [])
                    if len(pids) >= 2:
                        product_sets.append(frozenset(pids))

        # Count frequency of each set
        from collections import Counter
        set_counts = Counter(product_sets)

        # Create candidate groups
        # Group if: repeated 2+ times OR has 5+ products (even if used once)
        candidate_groups = []

        for pids_set, count in sorted(set_counts.items(), key=lambda x: (-len(x[0]), -x[1])):
            # AGGRESSIVE: 2+ repetitions OR 5+ products
            if count >= 2 or len(pids_set) >= 5:
                candidate_groups.append(pids_set)

        # Remove subsets: if group A is a subset of group B, remove A
        # This prevents duplicate product IDs across groups
        filtered_groups = []
        for i, group_a in enumerate(candidate_groups):
            is_subset = False
            for j, group_b in enumerate(candidate_groups):
                if i != j and group_a < group_b:  # A is proper subset of B
                    is_subset = True
                    break
            if not is_subset:
                filtered_groups.append(group_a)

        # Create final product_groups with group_ids
        product_groups = []
        group_map = {}  # frozenset → group_id

        for idx, pids_set in enumerate(filtered_groups, 1):
            group_id = f"CSAFGID-{idx:04d}"
            group_map[pids_set] = group_id

            product_groups.append({
                "group_id": group_id,
                "product_ids": sorted(list(pids_set))
            })

        # Replace product_ids with group_ids in vulnerabilities
        if product_groups:
            for v in vulns:
                # Replace in product_status
                if "product_status" in v:
                    for status in list(v["product_status"].keys()):
                        pids = v["product_status"][status]
                        if isinstance(pids, list) and len(pids) > 0:
                            pids_set = frozenset(pids)
                            if pids_set in group_map:
                                # CSAF allows product_group_ids in product_status
                                v["product_status"][status] = [group_map[pids_set]]

                # Replace in remediations
                if "remediations" in v:
                    for rem in v["remediations"]:
                        pids = rem.get("product_ids", [])
                        if pids:
                            pids_set = frozenset(pids)
                            if pids_set in group_map:
                                rem["product_group_ids"] = [group_map[pids_set]]
                                del rem["product_ids"]

                # Replace in threats
                if "threats" in v:
                    for threat in v["threats"]:
                        pids = threat.get("product_ids", [])
                        if pids:
                            pids_set = frozenset(pids)
                            if pids_set in group_map:
                                threat["product_group_ids"] = [group_map[pids_set]]
                                del threat["product_ids"]

                # Replace in metrics
                if "metrics" in v:
                    for metric in v["metrics"]:
                        pids = metric.get("products", [])
                        if pids:
                            pids_set = frozenset(pids)
                            if pids_set in group_map:
                                metric["product_group_ids"] = [group_map[pids_set]]
                                del metric["products"]

        return product_groups


# ===== VALIDATION =====