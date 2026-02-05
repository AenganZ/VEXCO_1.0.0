"""
Format → CIM Converters
"""
import uuid
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from .models import (
    CIM, Metadata, Publisher, Subject, Vulnerability, VEXStatement,
    StatusInfo, Identifier, CvssRating, Reference, DocumentFormat,
    VulnerabilityStatus, Justification, ConversionOptions, ConversionMetadata
)
from .utils import (
    dt_to_iso_z, now_utc, safe_str, decode_structured_text,
    set_extension_field, get_extension_field, dedupe_ratings,
    filter_placeholder_ratings, dedupe_references, unique_list
)
from .constants import (
    MAPPING_TABLE, map_openvex_justification_str_to_enum,
    map_cyclonedx_justification_to_enum, csaf_flag_to_justification_enum
)

class OpenVEXToCIM:
    def __init__(self, options: ConversionOptions = None):
        self.options = options or ConversionOptions()
        
    def convert(self, data: Dict) -> CIM:
        # Restore mode: extract metadata from first statement's status_notes
        restore_metadata = None
        if self.options.restore:
            statements_data = data.get("statements", [])
            if statements_data:
                first_stmt = statements_data[0]
                status_notes = first_stmt.get("status_notes", "")
                if status_notes and status_notes.startswith("[VEXCONV:v1]"):
                    # Extract metadata part (before first | if exists)
                    meta_part = status_notes.split(" | ")[0]
                    restore_metadata = ConversionMetadata.decode(meta_part)
                    if restore_metadata:
                        print(f"[Restore Mode] Found conversion metadata from {restore_metadata.source_format}")
                        print(f"  Timestamp: {restore_metadata.timestamp}")
                        if restore_metadata.lost_data:
                            print(f"  Lost data fields: {len(restore_metadata.lost_data)}")
        
        doc_id = data.get("@id", f"openvex-{uuid.uuid4()}")
        author = data.get("author", "Unknown")
        timestamp_str = data.get("timestamp", dt_to_iso_z(now_utc()))
        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))

        metadata = Metadata(
            id=str(uuid.uuid4()),
            publisher=Publisher(name=author),
            created_at=timestamp,
            source_format=DocumentFormat.OPENVEX,
            original_id=doc_id
        )
        
        # Store OpenVEX @id in extension_data for restoration
        if doc_id:
            set_extension_field(metadata, "openvex", "@id", doc_id)
        
        # Store OpenVEX-specific document fields in extension_data
        # @context
        if data.get("@context"):
            set_extension_field(metadata, "openvex", "@context", data["@context"])
        
        # version
        if data.get("version"):
            set_extension_field(metadata, "openvex", "version", data["version"])
        
        # role
        if data.get("role"):
            set_extension_field(metadata, "openvex", "role", data["role"])
        
        # last_updated
        if data.get("last_updated"):
            set_extension_field(metadata, "openvex", "last_updated", data["last_updated"])
        
        # tooling
        if data.get("tooling"):
            set_extension_field(metadata, "openvex", "tooling", data["tooling"])

        subjects_idx = {}
        statements = []
        vulns_idx = {}

        for stmt_idx, stmt_data in enumerate(data.get("statements", [])):
            vuln = stmt_data.get("vulnerability", {})
            vuln_id = vuln.get("name", f"VULN-{stmt_idx}")

            if vuln_id not in vulns_idx:
                vuln_obj = Vulnerability(id=vuln_id)
                
                # Store OpenVEX vulnerability fields in extension_data
                # vulnerability.@id
                if vuln.get("@id"):
                    set_extension_field(vuln_obj, "openvex", "vulnerability.@id", vuln["@id"])
                
                # vulnerability.description
                if vuln.get("description"):
                    vuln_obj.description = vuln["description"]
                
                # vulnerability.aliases
                if vuln.get("aliases"):
                    set_extension_field(vuln_obj, "openvex", "vulnerability.aliases", vuln["aliases"])
                
                vulns_idx[vuln_id] = vuln_obj

            status_str = stmt_data.get("status", "under_investigation")
            status_enum = {
                "affected": VulnerabilityStatus.AFFECTED,
                "not_affected": VulnerabilityStatus.NOT_AFFECTED,
                "fixed": VulnerabilityStatus.FIXED,
                "under_investigation": VulnerabilityStatus.UNDER_INVESTIGATION
            }.get(status_str, VulnerabilityStatus.UNDER_INVESTIGATION)

            justification_str = stmt_data.get("justification", "").strip()
            just_enum = map_openvex_justification_str_to_enum(justification_str) if justification_str else None
            # Always preserve original justification (even if mapped to enum)
            custom_just = justification_str if justification_str else None

            status_notes = stmt_data.get("status_notes", "").strip()
            
            impact = stmt_data.get("impact_statement", "").strip() or None
            
            # If no impact_statement but status_notes exists, extract from status_notes
            # status_notes format: "[VEXCONV:v1]{...} | text | more text"
            # Extract non-metadata text as impact_statement
            if not impact and status_notes:
                # Remove metadata part
                notes_text = status_notes
                if notes_text.startswith("[VEXCONV:v1]"):
                    parts = notes_text.split(" | ", 1)
                    if len(parts) > 1:
                        notes_text = parts[1]  # Everything after first " | "
                
                # Now extract the actual impact statement (before CVSS/CWE/References)
                # Split by " | " and take parts that are not CVSS/CWE/References
                impact_parts = []
                for part in notes_text.split(" | "):
                    # Skip metadata-like parts
                    if part.startswith("CVSS:") or part.startswith("CWEs:") or part.startswith("References:"):
                        break
                    if part.startswith("Note:"):
                        continue
                    impact_parts.append(part)
                
                if impact_parts:
                    impact = " | ".join(impact_parts)

            embedded_data = decode_structured_text(status_notes) if status_notes else {}
            
            # Parse status_notes for original_state hints
            if status_notes and not embedded_data.get("original_state"):
                if "false positive" in status_notes.lower():
                    embedded_data["original_state"] = "false_positive"
                elif "resolved_with_pedigree" in status_notes.lower() or "pedigree" in status_notes.lower():
                    embedded_data["original_state"] = "resolved_with_pedigree"

            if embedded_data.get("cvss_ratings"):
                for rating_data in embedded_data["cvss_ratings"]:
                    vulns_idx[vuln_id].ratings.append(CvssRating(**rating_data))

            if embedded_data.get("cwes"):
                vulns_idx[vuln_id].cwes.extend(embedded_data["cwes"])

            if embedded_data.get("references"):
                for ref_data in embedded_data["references"]:
                    vulns_idx[vuln_id].references.append(Reference(**ref_data))

            subject_refs = []
            for prod in stmt_data.get("products", []):
                prod_id = prod.get("@id", "").strip()
                if not prod_id: continue
                
                # Normalize PURL: remove repository_url to deduplicate
                # pkg:oci/trivy?repository_url=... → pkg:oci/trivy
                normalized_id = prod_id
                if prod_id.startswith("pkg:"):
                    normalized_id = prod_id.split("?")[0].split("#")[0]

                # Always register the main product as a subject
                if normalized_id not in subjects_idx:
                    id_type = "purl" if normalized_id.startswith("pkg:") else ("cpe" if normalized_id.startswith("cpe:") else "product_id")
                    
                    # Extract version from @id
                    # Examples:
                    # - pkg:maven/com.acme/product-zeta@1.0.1 → version: 1.0.1
                    # - pkg:maven/com.acme/product-zeta@vers:semver/<1.0.1 → version: vers:semver/<1.0.1
                    # - pkg:maven/com.acme/product-zeta@range:>=2.0.0|<2.3.0 → version: vers:semver/>=2.0.0|<2.3.0
                    version = None
                    name = None
                    if "@" in normalized_id:
                        parts = normalized_id.split("@")
                        base_part = parts[0]
                        version_part = parts[1]
                        
                        # Extract name from base_part
                        if "/" in base_part:
                            name = base_part.split("/")[-1]
                        
                        # Handle different version formats
                        if version_part.startswith("range:"):
                            # range:>=2.0.0|<2.3.0 → vers:semver/>=2.0.0|<2.3.0
                            version = "vers:semver/" + version_part[6:]
                        elif version_part.startswith("vers:"):
                            # vers:semver/<1.0.1 → keep as is
                            version = version_part
                        else:
                            # 1.0.1 → keep as is
                            version = version_part
                    
                    # Extract hashes if present
                    hashes = prod.get("hashes")
                    hashes_list = None
                    if hashes:
                        # Convert OpenVEX hashes format to CIM format
                        hashes_list = []
                        for alg, value in hashes.items():
                            hashes_list.append({
                                "algorithm": alg,
                                "value": value
                            })
                    
                    subj = Subject(
                        ref=normalized_id, 
                        identifiers=[Identifier(type=id_type, value=normalized_id)],
                        original_id=prod_id,  # Store original @id for reversible conversion
                        hashes=hashes_list,  # Store hashes
                        version=version,  # Store extracted version
                        name=name  # Store extracted name
                    )
                    
                    # Note: OpenVEX spec v0.2.0 does not support identifiers field
                    # If present in input, it will be ignored
                    
                    subjects_idx[normalized_id] = subj

                subcomps = prod.get("subcomponents", [])
                if subcomps:
                    # If subcomponents exist, add them to subject_refs (they are the actual affected components)
                    for sub in subcomps:
                        sub_id = sub.get("@id", "").strip()
                        if sub_id:
                            # Also normalize subcomponent PURL
                            normalized_sub = sub_id
                            if sub_id.startswith("pkg:"):
                                normalized_sub = sub_id.split("?")[0].split("#")[0]
                            
                            if normalized_sub not in subjects_idx:
                                subj_sub = Subject(
                                    ref=normalized_sub, 
                                    identifiers=[Identifier(
                                        type="purl" if normalized_sub.startswith("pkg:") else "product_id", 
                                        value=normalized_sub
                                    )],
                                    original_id=sub_id  # Store original @id
                                )
                                
                                # Note: OpenVEX spec does not support identifiers
                                
                                subjects_idx[normalized_sub] = subj_sub
                            subject_refs.append(normalized_sub)
                else:
                    # No subcomponents: the main product itself is affected
                    subject_refs.append(normalized_id)

            stmt_ts = stmt_data.get("timestamp")
            stmt_dt = datetime.fromisoformat(stmt_ts.replace('Z', '+00:00')) if stmt_ts else timestamp

            action = stmt_data.get("action_statement", "").strip() or None

            # Restore original CycloneDX state if present
            original_state = embedded_data.get("original_state")

            stmt = VEXStatement(
                id=f"stmt-{stmt_idx}",
                subject_refs=unique_list(subject_refs),
                vulnerability_id=vuln_id,
                status=StatusInfo(
                    value=status_enum,
                    justification=just_enum,
                    custom_justification=custom_just,
                    impact_statement=impact,
                    original_state=original_state
                ),
                timestamp=stmt_dt,
                action_statement=action
            )
            
            # Store OpenVEX statement fields in extension_data
            # status_notes (raw value, not embedded_data)
            if status_notes:
                set_extension_field(stmt, "openvex", "status_notes", status_notes)
            
            # supplier
            if stmt_data.get("supplier"):
                set_extension_field(stmt, "openvex", "supplier", stmt_data["supplier"])
            
            statements.append(stmt)
        
        # Restore mode: apply extension_data and subject_mappings
        if self.options.restore and restore_metadata:
            extension_data = restore_metadata.extension_data
            subject_mappings = restore_metadata.subject_mappings
            restored_count = 0
            
            # Restore extension_data
            if extension_data:
                # Metadata extension_data
                if "metadata" in extension_data:
                    metadata.extension_data = extension_data["metadata"]
                    restored_count += 1
                
                # Subject extension_data
                for idx, subj in enumerate(subjects_idx.values()):
                    key = f"subject_{idx}"
                    if key in extension_data:
                        subj.extension_data = extension_data[key]
                        restored_count += 1
                
                # Vulnerability extension_data (use ID as key, not index)
                for vuln in vulns_idx.values():
                    key = f"vulnerability_{vuln.id}"
                    if key in extension_data:
                        vuln_ext = extension_data[key]
                        vuln.extension_data = vuln_ext
                        restored_count += 1
                        
                        # Restore references from extension_data
                        if "references" in vuln_ext:
                            for ref_dict in vuln_ext["references"]:
                                vuln.references.append(Reference(
                                    url=ref_dict.get("url", ""),
                                    summary=ref_dict.get("summary"),
                                    category=ref_dict.get("category"),
                                    id=ref_dict.get("id")
                                ))
                        
                        # Restore ratings from extension_data
                        if "ratings" in vuln_ext:
                            for rating_dict in vuln_ext["ratings"]:
                                vuln.ratings.append(CvssRating(
                                    method=rating_dict.get("method"),
                                    score=rating_dict.get("score"),
                                    severity=rating_dict.get("severity"),
                                    vector=rating_dict.get("vector")
                                ))
                        
                        # Restore cwes from extension_data
                        if "cwes" in vuln_ext:
                            vuln.cwes = vuln_ext["cwes"]
                
                # Statement extension_data
                for idx, stmt in enumerate(statements):
                    key = f"statement_{idx}"
                    if key in extension_data:
                        stmt.extension_data = extension_data[key]
                        restored_count += 1
            
            # Restore original_id from subject_mappings
            if subject_mappings:
                for subj in subjects_idx.values():
                    if subj.ref in subject_mappings:
                        subj.original_id = subject_mappings[subj.ref]
                        restored_count += 1
            
            if restored_count > 0:
                print(f"[Restore Mode] Restored {restored_count} field(s) from metadata")

        return CIM(
            metadata=metadata,
            subjects=list(subjects_idx.values()),
            vulnerabilities=list(vulns_idx.values()),
            statements=statements
        )

class CycloneDXToCIM:
    def __init__(self, options: ConversionOptions = None):
        self.options = options or ConversionOptions()
        
    def convert(self, data: Dict) -> CIM:
        # Restore mode: extract metadata if present
        restore_metadata = None
        if self.options.restore:
            metadata_section = data.get("metadata", {})
            properties = metadata_section.get("properties", [])
            for prop in properties:
                if prop.get("name") == "VEXCO.metadata":
                    restore_metadata = ConversionMetadata.decode(prop.get("value", ""))
                    if restore_metadata:
                        print(f"\n[Restore Mode] Found conversion metadata from {restore_metadata.source_format}")
                        print(f"  Timestamp: {restore_metadata.timestamp}")
                        print(f"  Lost data fields: {len(restore_metadata.lost_data)}")
                    break
        
        metadata_data = data.get("metadata", {})
        timestamp_str = metadata_data.get("timestamp", dt_to_iso_z(now_utc()))
        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))

        # Extract publisher info from tools or manufacturer
        # Support both old (list) and new (object with components) tools format
        tools_field = metadata_data.get("tools", [])
        vendor = "Unknown"
        
        if isinstance(tools_field, dict):
            # New format: {"components": [...]}
            tool_components = tools_field.get("components", [])
            if tool_components:
                first_tool = tool_components[0]
                # Try supplier.name first, then name
                supplier = first_tool.get("supplier", {})
                if isinstance(supplier, dict) and supplier.get("name"):
                    vendor = supplier["name"]
                elif first_tool.get("name"):
                    vendor = first_tool["name"]
        elif isinstance(tools_field, list) and tools_field:
            # Old format: [{"vendor": "...", "name": "..."}]
            first_tool = tools_field[0]
            vendor = first_tool.get("vendor", first_tool.get("name", "Unknown"))
        
        # Try to get manufacturer info from components (최우선)
        manufacturer_name = None
        manufacturer_url = None
        components = data.get("components", [])
        if components:
            # Get manufacturer from first component with manufacturer info
            for comp in components:
                manufacturer = comp.get("manufacturer", {})
                if manufacturer:
                    if manufacturer.get("name"):
                        manufacturer_name = manufacturer["name"]
                    if manufacturer.get("url"):
                        manufacturer_url = manufacturer["url"]
                    if manufacturer_name or manufacturer_url:
                        break  # Found manufacturer info
        
        # Use manufacturer if available, otherwise use vendor from tools
        publisher_name = manufacturer_name if manufacturer_name else vendor
        publisher_namespace = manufacturer_url if manufacturer_url else None

        metadata = Metadata(
            id=str(uuid.uuid4()),
            publisher=Publisher(
                name=publisher_name,
                namespace=publisher_namespace
            ),
            created_at=timestamp,
            source_format=DocumentFormat.CYCLONEDX,
            original_id=data.get("serialNumber")
        )
        
        # Store original components for perfect restoration
        if self.options.reversible:
            original_components = data.get("components", [])
            if original_components:
                set_extension_field(metadata, "cyclonedx", "components", original_components)
            
            # Store metadata.supplier for perfect restoration
            metadata_supplier = metadata_data.get("supplier")
            if metadata_supplier:
                set_extension_field(metadata, "cyclonedx", "metadata.supplier", metadata_supplier)
        
        # Store metadata.component (VDR에서 중요)
        metadata_component = metadata_data.get("component")
        if metadata_component:
            set_extension_field(metadata, "cyclonedx", "metadata.component", metadata_component)

        subjects_idx = {}
        for comp in data.get("components", []):
            ref = comp.get("bom-ref", "").strip()
            if not ref: continue

            identifiers = []
            if comp.get("purl"): identifiers.append(Identifier(type="purl", value=comp["purl"]))
            if comp.get("cpe"): identifiers.append(Identifier(type="cpe", value=comp["cpe"]))
            
            # Convert CycloneDX hashes to CIM format
            hashes = None
            cdx_hashes = comp.get("hashes", [])
            if cdx_hashes:
                # CDX: [{"alg": "SHA-256", "content": "..."}]
                # CIM: [{"algorithm": "sha-256", "value": "..."}]
                hashes = []
                for h in cdx_hashes:
                    alg = h.get("alg", "")
                    content = h.get("content", "")
                    if alg and content:
                        # Convert algorithm name: SHA-256 → sha-256
                        alg_lower = alg.lower()
                        hashes.append({"algorithm": alg_lower, "value": content})

            subjects_idx[ref] = Subject(
                ref=ref,
                identifiers=identifiers,
                name=comp.get("name"),
                version=comp.get("version"),
                type=comp.get("type", "library"),
                original_id=ref,  # Preserve original URN format (e.g., urn:cdx:...)
                hashes=hashes  # Add hashes
            )

        # Create phantom subjects for affects refs without components
        all_affect_refs = set()
        for v in data.get("vulnerabilities", []):
            for a in v.get("affects", []):
                ref = a.get("ref")
                if ref: all_affect_refs.add(ref)

        for ref in all_affect_refs:
            if ref not in subjects_idx:
                name = self._extract_name_from_ref(ref)
                id_type = "purl" if ref.startswith("pkg:") else ("cpe" if ref.startswith("cpe:") else "product_id")
                
                # In restore mode, try to find original ID
                determined_original_id = None
                if restore_metadata and restore_metadata.subject_mappings:
                    # Try exact match
                    if ref in restore_metadata.subject_mappings:
                        determined_original_id = restore_metadata.subject_mappings[ref]
                    # Try to find by stripping urn:cdx prefix
                    elif "#" in ref:
                        # urn:cdx:xxx#pkg:apk/alpine/busybox:vunknown → pkg:apk/alpine/busybox
                        clean_ref = ref.split("#")[1] if "#" in ref else ref
                        # Remove :vunknown suffix
                        if ":vunknown" in clean_ref:
                            clean_ref = clean_ref.replace(":vunknown", "")
                        # Try to find in mappings
                        if clean_ref in restore_metadata.subject_mappings:
                            determined_original_id = restore_metadata.subject_mappings[clean_ref]
                
                subjects_idx[ref] = Subject(
                    ref=ref,
                    identifiers=[Identifier(type=id_type, value=ref)],
                    name=name,
                    type="library",
                    original_id=determined_original_id
                )

        statements = []
        vulns_idx = {}

        for vidx, v in enumerate(data.get("vulnerabilities", [])):
            vuln_id = v.get("id", f"VULN-{vidx}")

            if vuln_id not in vulns_idx:
                vuln = Vulnerability(id=vuln_id, description=v.get("description"))

                for r in v.get("ratings", []):
                    vuln.ratings.append(CvssRating(
                        method=r.get("method"),
                        score=r.get("score"),
                        severity=r.get("severity"),
                        vector=r.get("vector")
                    ))

                vuln.cwes = v.get("cwes", [])

                # Add source as a reference (primary source for vulnerability info)
                source = v.get("source", {})
                if source and source.get("url"):
                    vuln.references.append(Reference(
                        url=source.get("url", ""),
                        summary=source.get("name", "Primary Source"),
                        category="source"
                    ))

                # Add additional references
                for ref in v.get("references", []):
                    source_obj = ref.get("source", {})
                    ref_id = ref.get("id")
                    ref_url = source_obj.get("url", "")
                    
                    # Only use id as URL if it's actually a valid URL format
                    if not ref_url and ref_id:
                        # Check if id looks like a URL (starts with http:// or https://)
                        if ref_id.startswith(("http://", "https://")):
                            ref_url = ref_id
                        # Otherwise, skip using id as URL
                    
                    # Must have a valid URL to create a reference
                    if ref_url:
                        vuln.references.append(Reference(
                            url=ref_url,
                            summary=source_obj.get("name"),
                            category="external",
                            id=ref_id if ref_id and not ref_id.startswith(("http://", "https://")) else None
                        ))
                
                # Store recommendation in extension_data for CSAF notes
                recommendation = v.get("recommendation")
                if recommendation:
                    set_extension_field(vuln, "cyclonedx", "recommendation", recommendation)
                
                # VDR (Vulnerability Disclosure Report) 필드 처리
                # detail - 상세 설명
                detail = v.get("detail")
                if detail:
                    set_extension_field(vuln, "cyclonedx", "detail", detail)
                
                # workaround - 임시 조치
                workaround = v.get("workaround")
                if workaround:
                    set_extension_field(vuln, "cyclonedx", "workaround", workaround)
                
                # proofOfConcept - POC
                proof_of_concept = v.get("proofOfConcept")
                if proof_of_concept:
                    set_extension_field(vuln, "cyclonedx", "proofOfConcept", proof_of_concept)
                
                # credits - 발견자 정보
                credits = v.get("credits")
                if credits:
                    set_extension_field(vuln, "cyclonedx", "credits", credits)
                
                # Store original affects for perfect restoration
                if self.options.reversible:
                    original_affects = v.get("affects", [])
                    if original_affects:
                        set_extension_field(vuln, "cyclonedx", "affects", original_affects)
                    
                    # Store original analysis.detail for perfect restoration
                    original_detail = v.get("analysis", {}).get("detail")
                    if original_detail:
                        set_extension_field(vuln, "cyclonedx", "analysis.detail", original_detail)
                    
                    # Store analysis timestamps for perfect restoration
                    original_first_issued = v.get("analysis", {}).get("firstIssued")
                    if original_first_issued:
                        set_extension_field(vuln, "cyclonedx", "analysis.firstIssued", original_first_issued)
                    
                    original_last_updated = v.get("analysis", {}).get("lastUpdated")
                    if original_last_updated:
                        set_extension_field(vuln, "cyclonedx", "analysis.lastUpdated", original_last_updated)

                vulns_idx[vuln_id] = vuln

            analysis = v.get("analysis", {})
            state_str = analysis.get("state", "in_triage")
            just_raw = safe_str(analysis.get("justification")).strip() or None

            detail_text = safe_str(analysis.get("detail", "")).strip()
            embedded_data = decode_structured_text(detail_text) if detail_text else {}

            original_just = embedded_data.get("original_justification")
            custom_just = embedded_data.get("custom_justification")

            just_enum = None
            if original_just:
                just_enum = map_openvex_justification_str_to_enum(original_just)
                if not just_enum:
                    custom_just = original_just
            elif just_raw:
                just_enum = map_cyclonedx_justification_to_enum(just_raw)
                # Store original CycloneDX justification for preservation
                if just_enum and just_raw:
                    # If mapped successfully, store original as custom for CSAF output
                    custom_just = f"cyclonedx:{just_raw}"
                elif not just_enum:
                    custom_just = just_raw

            # Store original state for ALL CycloneDX states (for perfect restoration)
            # This includes exploitable, in_triage, resolved, etc.
            original_cdx_state = state_str if state_str else None

            status_str = MAPPING_TABLE["cyclonedx_state_to_openvex_status"].get(state_str, "under_investigation")
            status_enum = {
                "affected": VulnerabilityStatus.AFFECTED,
                "not_affected": VulnerabilityStatus.NOT_AFFECTED,
                "fixed": VulnerabilityStatus.FIXED,
                "under_investigation": VulnerabilityStatus.UNDER_INVESTIGATION
            }.get(status_str, VulnerabilityStatus.UNDER_INVESTIGATION)

            # Extract impact_statement BEFORE processing affects
            # For resolved state, use detail as impact_statement (not just embedded data)
            if state_str == "resolved" and detail_text:
                impact_stmt = detail_text
            elif "impact_statement" in embedded_data:
                impact_stmt = embedded_data.get("impact_statement")
            elif detail_text and status_str == "not_affected":
                # For not_affected, also use detail as impact_statement
                impact_stmt = detail_text
            elif state_str == "in_triage" and detail_text:
                # For in_triage, also use detail as impact_statement
                impact_stmt = detail_text
            elif state_str == "exploitable" and detail_text:
                # For exploitable, also use detail as impact_statement
                impact_stmt = detail_text
            else:
                impact_stmt = None

            # Extract action_statement (recommendation 우선, response는 텍스트 변환)
            action_parts = []
            if status_enum == VulnerabilityStatus.AFFECTED:
                # 1. recommendation 최우선
                recommendation = v.get("recommendation")
                if recommendation:
                    action_parts.append(recommendation)

                # 2. response를 텍스트로 변환
                response = analysis.get("response")
                if response:
                    response_texts = []
                    if isinstance(response, list):
                        for r in response:
                            response_texts.append(self._response_to_text(r))
                    else:
                        response_texts.append(self._response_to_text(response))

                    # and로 연결
                    if response_texts:
                        action_parts.append(" and ".join(response_texts))

                # 3. 아무것도 없으면 기본 메시지
                if not action_parts:
                    action_parts.append("No remediation information available")

                # Get workaround
                workaround = v.get("workaround")
                if workaround:
                    action_parts.append(f"Workaround: {workaround}")

            action_statement = " | ".join(action_parts) if action_parts else None

            # Store original response for preservation
            original_response = analysis.get("response")
            stmt_extension_data = {}
            if original_response:
                stmt_extension_data["cyclonedx_response"] = original_response
            
            affect_refs = []
            
            # Analyze version ranges to detect fixed status
            # If: range: vers:semver/<X.Y.Z + version: X.Y.Z unaffected + response: update
            # Then: version X.Y.Z is FIXED (not just unaffected)
            version_fixes = {}  # version_val → is_fixed
            
            for a in v.get("affects", []):
                versions = a.get("versions", [])
                if len(versions) >= 2:
                    # Check for range + fixed version pattern
                    for i in range(len(versions) - 1):
                        curr_ver = versions[i]
                        next_ver = versions[i + 1]
                        
                        # Check if current is affected range and next is unaffected version
                        curr_range = curr_ver.get("range", "")
                        curr_status = curr_ver.get("status", "")
                        next_version = next_ver.get("version", "")
                        next_status = next_ver.get("status", "")
                        
                        # Pattern: range: vers:semver/<1.0.1 + affected
                        #        + version: 1.0.1 + unaffected
                        #        + response: update
                        # → version 1.0.1 is FIXED
                        if (curr_range.startswith("vers:") and "affected" in curr_status and
                            next_version and ("unaffected" in next_status or "not_affected" in next_status)):
                            # Extract boundary version from range
                            # vers:semver/<1.0.1 → 1.0.1
                            import re
                            match = re.search(r'<([0-9.]+)', curr_range)
                            if match:
                                boundary_version = match.group(1)
                                # Check if next_version matches boundary
                                if next_version == boundary_version:
                                    # Check if response includes "update"
                                    response = analysis.get("response", [])
                                    if isinstance(response, list) and "update" in response:
                                        version_fixes[next_version] = True
                                    elif response == "update":
                                        version_fixes[next_version] = True
            
            # Group versions by status for statement merging
            # Key: (status, action_statement, justification)
            # Value: list of version_refs
            version_groups = {}
            
            for a in v.get("affects", []):
                ref = a.get("ref", "").strip()
                if not ref:
                    continue

                versions = a.get("versions", [])
                if versions:
                    # Group versions by their status
                    for version_info in versions:
                        version_val = version_info.get("version") or version_info.get("range")
                        version_status = version_info.get("status")

                        if not version_val:
                            continue

                        # Create version-specific ref: product:version
                        version_ref = f"{ref}:v{version_val}"

                        # Create version-specific subject if not exists
                        if version_ref not in subjects_idx:
                            base_subject = subjects_idx.get(ref)
                            
                            # Determine original_id for this version
                            # In restore mode, try to find original ID from subject_mappings
                            determined_original_id = None
                            if restore_metadata and restore_metadata.subject_mappings:
                                # Try exact match first
                                if version_ref in restore_metadata.subject_mappings:
                                    determined_original_id = restore_metadata.subject_mappings[version_ref]
                                # Try without version suffix
                                elif ref in restore_metadata.subject_mappings:
                                    determined_original_id = restore_metadata.subject_mappings[ref]
                            
                            if base_subject:
                                subjects_idx[version_ref] = Subject(
                                    ref=version_ref,
                                    identifiers=base_subject.identifiers.copy(),
                                    name=f"{base_subject.name} {version_val}" if base_subject.name else version_val,
                                    version=version_val,
                                    type=base_subject.type,
                                    original_id=determined_original_id or base_subject.original_id,
                                    hashes=base_subject.hashes  # Copy hashes from base subject
                                )
                            else:
                                subjects_idx[version_ref] = Subject(
                                    ref=version_ref,
                                    identifiers=[Identifier(type="product_id", value=version_ref)],
                                    name=version_val,
                                    version=version_val,
                                    type="library",
                                    original_id=determined_original_id
                                )

                        # Map version status to VulnerabilityStatus
                        # Check if this version is identified as fixed
                        if version_val in version_fixes and version_fixes[version_val]:
                            # This version is FIXED (boundary version with patch available)
                            version_status_enum = VulnerabilityStatus.FIXED
                        elif version_status == "affected":
                            version_status_enum = VulnerabilityStatus.AFFECTED
                        elif version_status in ["unaffected", "not_affected"]:
                            # Special case: if analysis.state is "resolved" and response includes "update"
                            # then unaffected versions are FIXED (not just NOT_AFFECTED)
                            if state_str == "resolved":
                                response = analysis.get("response", [])
                                if (isinstance(response, list) and "update" in response) or response == "update":
                                    version_status_enum = VulnerabilityStatus.FIXED
                                else:
                                    version_status_enum = VulnerabilityStatus.NOT_AFFECTED
                            else:
                                version_status_enum = VulnerabilityStatus.NOT_AFFECTED
                        elif version_status == "unknown":
                            version_status_enum = VulnerabilityStatus.UNDER_INVESTIGATION
                        elif version_status is None:
                            version_status_enum = status_enum
                        else:
                            version_status_enum = status_enum

                        # Group by (status, action_statement, justification, detail_text)
                        # Include detail_text to separate different products with different details
                        group_key = (
                            version_status_enum,
                            action_statement,
                            just_enum,
                            custom_just,
                            impact_stmt if isinstance(impact_stmt, str) else None,
                            original_cdx_state,
                            detail_text if detail_text and not embedded_data else None  # Add detail_text for product separation
                        )
                        
                        if group_key not in version_groups:
                            version_groups[group_key] = []
                        version_groups[group_key].append(version_ref)
                else:
                    # No version info, use ref directly
                    # In restore mode, check if we have original status for this ref
                    if restore_metadata and restore_metadata.lost_data:
                        status_key = f"stmt_status_{ref}_{vuln_id}"
                        original_status_name = restore_metadata.lost_data.get(status_key)
                        if original_status_name:
                            # Restore original status
                            try:
                                restored_status = VulnerabilityStatus[original_status_name]
                                # Create separate statement for this ref with its original status
                                statements.append(VEXStatement(
                                    id=f"stmt-{vidx}-{ref}",
                                    subject_refs=[ref],
                                    vulnerability_id=vuln_id,
                                    status=StatusInfo(
                                        value=restored_status,
                                        justification=just_enum,
                                        custom_justification=custom_just,
                                        impact_statement=impact_stmt,
                                        original_state=original_cdx_state
                                    ),
                                    timestamp=timestamp,
                                    action_statement=action_statement,
                                    extension_data=stmt_extension_data.copy()
                                ))
                                continue  # Skip adding to affect_refs
                            except KeyError:
                                pass  # Fall through to default handling
                    
                    # Default: add to affect_refs for batch processing
                    affect_refs.append(ref)

            # Create merged statements from grouped versions
            for idx, (group_key, version_refs) in enumerate(version_groups.items()):
                status_enum_val, action_stmt, just_enum_val, custom_just_val, impact_stmt_val, original_state_val, detail_text_val = group_key
                
                statements.append(VEXStatement(
                    id=f"stmt-{vidx}-group{idx}",
                    subject_refs=unique_list(version_refs),
                    vulnerability_id=vuln_id,
                    status=StatusInfo(
                        value=status_enum_val,
                        justification=just_enum_val,
                        custom_justification=custom_just_val,
                        impact_statement=impact_stmt_val,
                        original_state=original_state_val
                    ),
                    timestamp=timestamp,
                    action_statement=action_stmt,
                    extension_data=stmt_extension_data.copy()
                ))

            # Create statement for affects without version info
            if affect_refs:
                statements.append(VEXStatement(
                    id=f"stmt-{vidx}",
                    subject_refs=unique_list(affect_refs),
                    vulnerability_id=vuln_id,
                    status=StatusInfo(
                        value=status_enum,
                        justification=just_enum,
                        custom_justification=custom_just,
                        impact_statement=impact_stmt if isinstance(impact_stmt, str) else None,
                        original_state=original_cdx_state
                    ),
                    timestamp=timestamp,
                    action_statement=action_statement,
                    extension_data=stmt_extension_data.copy()
                ))

        # Restore mode: apply lost data from metadata
        if self.options.restore and restore_metadata:
            lost_data = restore_metadata.lost_data
            extension_data = restore_metadata.extension_data
            subject_mappings = restore_metadata.subject_mappings
            restored_count = 0
            
            for stmt in statements:
                # Restore justifications
                just_key = f"stmt_{stmt.id}_justification"
                if just_key in lost_data:
                    stmt.status.justification = map_openvex_justification_str_to_enum(lost_data[just_key])
                    restored_count += 1
                
                custom_just_key = f"stmt_{stmt.id}_custom_justification"
                if custom_just_key in lost_data:
                    stmt.status.custom_justification = lost_data[custom_just_key]
                    restored_count += 1
                
                # Restore action_statements
                action_key = f"stmt_{stmt.id}_action_statement"
                if action_key in lost_data:
                    stmt.action_statement = lost_data[action_key]
                    restored_count += 1
            
            # Restore extension_data
            if extension_data:
                # Metadata extension_data
                if "metadata" in extension_data:
                    metadata.extension_data = extension_data["metadata"]
                    restored_count += 1
                
                # Subject extension_data
                for idx, subj in enumerate(subjects_idx.values()):
                    key = f"subject_{idx}"
                    if key in extension_data:
                        subj.extension_data = extension_data[key]
                        restored_count += 1
                
                # Vulnerability extension_data
                for idx, vuln in enumerate(vulns_idx.values()):
                    key = f"vulnerability_{idx}"
                    if key in extension_data:
                        vuln.extension_data = extension_data[key]
                        restored_count += 1
                        
                        # Restore notes from extension_data
                        notes = get_extension_field(vuln, "csaf", "notes")
                        if notes:
                            vuln.notes = notes
                            restored_count += 1
                
                # Statement extension_data
                for idx, stmt in enumerate(statements):
                    key = f"statement_{idx}"
                    if key in extension_data:
                        stmt.extension_data = extension_data[key]
                        restored_count += 1
            
            # Restore original_id from subject_mappings
            if subject_mappings:
                for subj in subjects_idx.values():
                    if subj.ref in subject_mappings:
                        subj.original_id = subject_mappings[subj.ref]
                        restored_count += 1
            
            if restored_count > 0:
                print(f"[Restore Mode] Restored {restored_count} field(s) from metadata")

        return CIM(
            metadata=metadata,
            subjects=list(subjects_idx.values()),
            vulnerabilities=list(vulns_idx.values()),
            statements=statements
        )

    def _response_to_text(self, response):
        """CycloneDX response 열거형을 텍스트로 변환"""
        mapping = {
            "update": "Update to a different revision or release",
            "workaround_available": "There is a workaround available",
            "rollback": "Revert to a previous revision or release",
            "will_not_fix": "Will not fix",
            "can_not_fix": "Can not fix"
        }
        return mapping.get(response, response)

    @staticmethod
    def _extract_name_from_ref(ref: str) -> str:
        """Extract meaningful name from component reference"""
        ref = ref.strip()

        # PURL format: pkg:type/namespace/name@version
        if ref.startswith("pkg:"):
            try:
                parts = ref.split("/")
                if len(parts) >= 2:
                    name_part = parts[-1].split("@")[0].split("?")[0]
                    return name_part
            except: pass

        # URN with fragment: urn:cdx:...#product-ABC
        if "#" in ref:
            return ref.split("#")[-1]

        # CPE format: cpe:2.3:a:vendor:product:...
        if ref.startswith("cpe:"):
            try:
                parts = ref.split(":")
                if len(parts) >= 5:
                    return parts[4]  # product name
            except: pass

        # Path-like: .../product-ABC
        if "/" in ref:
            return ref.split("/")[-1]

        # Colon-separated: prefix:product-ABC
        if ":" in ref:
            return ref.split(":")[-1]

        # Fallback: use ref itself (truncate if too long)
        return ref[:100] if len(ref) <= 100 else ref[:100]

class CSAFToCIM:
    def __init__(self, options: ConversionOptions = None):
        self.options = options or ConversionOptions()
        
    def convert(self, data: Dict) -> CIM:
        # Restore mode: extract metadata from document.notes
        restore_metadata = None
        if self.options.restore:
            doc = data.get("document", {})
            notes = doc.get("notes", [])
            for note in notes:
                if note.get("title") == "VEXCO Conversion Metadata":
                    text = note.get("text", "")
                    if text.startswith("[VEXCONV:v1]"):
                        restore_metadata = ConversionMetadata.decode(text)
                        if restore_metadata:
                            print(f"[Restore Mode] Found conversion metadata from {restore_metadata.source_format}")
                            print(f"  Timestamp: {restore_metadata.timestamp}")
                            if restore_metadata.lost_data:
                                print(f"  Lost data fields: {len(restore_metadata.lost_data)}")
                        break
        
        doc = data.get("document", {})
        tracking = doc.get("tracking", {})
        publisher_data = doc.get("publisher", {})

        timestamp_str = tracking.get("initial_release_date", dt_to_iso_z(now_utc()))
        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))

        metadata = Metadata(
            id=str(uuid.uuid4()),
            publisher=Publisher(
                name=publisher_data.get("name", "Unknown"),
                namespace=publisher_data.get("namespace"),
                role=publisher_data.get("category")
            ),
            created_at=timestamp,
            source_format=DocumentFormat.CSAF,
            original_id=tracking.get("id")
        )
        
        # Store CSAF tracking.id in extension_data for restoration
        if tracking.get("id"):
            set_extension_field(metadata, "csaf", "tracking.id", tracking["id"])
        
        # Store CSAF-specific document fields in extension_data
        # aggregate_severity
        if doc.get("aggregate_severity"):
            set_extension_field(metadata, "csaf", "document.aggregate_severity", doc["aggregate_severity"])
        
        # distribution
        if doc.get("distribution"):
            distribution = doc["distribution"]
            
            # Convert CSAF 2.0 TLP labels to CSAF 2.1 format
            if "tlp" in distribution and "label" in distribution["tlp"]:
                tlp_label = distribution["tlp"]["label"]
                
                # CSAF 2.0 → 2.1 mapping
                tlp_2_0_to_2_1 = {
                    "WHITE": "CLEAR",
                    "AMBER": "AMBER",
                    "GREEN": "GREEN",
                    "RED": "RED"
                }
                
                if tlp_label in tlp_2_0_to_2_1:
                    # Create a copy to avoid modifying original
                    distribution = distribution.copy()
                    distribution["tlp"] = distribution["tlp"].copy()
                    distribution["tlp"]["label"] = tlp_2_0_to_2_1[tlp_label]
            
            set_extension_field(metadata, "csaf", "document.distribution", distribution)
        
        # lang
        if doc.get("lang"):
            set_extension_field(metadata, "csaf", "document.lang", doc["lang"])
        
        # source_lang
        if doc.get("source_lang"):
            set_extension_field(metadata, "csaf", "document.source_lang", doc["source_lang"])
        
        # category
        if doc.get("category"):
            set_extension_field(metadata, "csaf", "document.category", doc["category"])
        
        # title
        if doc.get("title"):
            set_extension_field(metadata, "csaf", "document.title", doc["title"])
        
        # publisher additional fields
        if publisher_data.get("contact_details"):
            set_extension_field(metadata, "csaf", "document.publisher.contact_details", publisher_data["contact_details"])
        
        if publisher_data.get("issuing_authority"):
            set_extension_field(metadata, "csaf", "document.publisher.issuing_authority", publisher_data["issuing_authority"])
        
        # tracking additional fields
        if tracking.get("status"):
            set_extension_field(metadata, "csaf", "document.tracking.status", tracking["status"])
        
        if tracking.get("version"):
            set_extension_field(metadata, "csaf", "document.tracking.version", tracking["version"])
        
        if tracking.get("revision_history"):
            set_extension_field(metadata, "csaf", "document.tracking.revision_history", tracking["revision_history"])
        
        if tracking.get("current_release_date"):
            set_extension_field(metadata, "csaf", "document.tracking.current_release_date", tracking["current_release_date"])
        
        if tracking.get("generator"):
            set_extension_field(metadata, "csaf", "document.tracking.generator", tracking["generator"])
        
        if tracking.get("aliases"):
            set_extension_field(metadata, "csaf", "document.tracking.aliases", tracking["aliases"])
        
        # document references
        if doc.get("references"):
            set_extension_field(metadata, "csaf", "document.references", doc["references"])
        
        # document notes (top-level)
        if doc.get("notes"):
            set_extension_field(metadata, "csaf", "document.notes", doc["notes"])
        
        # document acknowledgments
        if doc.get("acknowledgments"):
            set_extension_field(metadata, "csaf", "document.acknowledgments", doc["acknowledgments"])

        pt = data.get("product_tree", {})
        
        # Store product_tree.relationships in extension_data
        if pt.get("relationships"):
            set_extension_field(metadata, "csaf", "product_tree.relationships", pt["relationships"])
        
        # Store original branches structure for complete restoration
        if pt.get("branches"):
            set_extension_field(metadata, "csaf", "product_tree.branches", pt["branches"])
        
        subjects_idx = {}

        # Process full_product_names (simple format)
        for p in pt.get("full_product_names", []):
            pid = p.get("product_id", "").strip()
            if not pid: continue

            pih = p.get("product_identification_helper", {})
            identifiers = []

            # Standard identifiers
            if pih.get("purls"):
                for purl in pih["purls"]:
                    identifiers.append(Identifier(type="purl", value=purl))
            elif pih.get("purl"):  # Legacy single purl
                identifiers.append(Identifier(type="purl", value=pih["purl"]))

            if pih.get("cpe"):
                identifiers.append(Identifier(type="cpe", value=pih["cpe"]))

            # Extended fields
            # Convert CSAF 2.1 hashes format to CIM format
            hashes_csaf = pih.get("hashes")
            hashes = None
            if hashes_csaf:
                # CSAF 2.1: [{"file_hashes": [...], "filename": "..."}]
                # CIM: [{"algorithm": "...", "value": "..."}]
                hashes = []
                for hash_entry in hashes_csaf:
                    file_hashes = hash_entry.get("file_hashes", [])
                    for fh in file_hashes:
                        alg = fh.get("algorithm")
                        val = fh.get("value")
                        if alg and val:
                            # Convert sha256 → sha-256 for consistency
                            if alg.startswith("sha") and not alg.startswith("sha-"):
                                alg = alg.replace("sha", "sha-")
                            hashes.append({"algorithm": alg, "value": val})
            
            model_numbers = pih.get("model_numbers")
            sbom_urls = pih.get("sbom_urls")
            serial_numbers = pih.get("serial_numbers")
            skus = pih.get("skus")

            # Extract version from product_id first (priority)
            # Format: base-id:vversion
            # Example: com-acme-maven-product-eta-2.3.0:vvers:semver/>=2.0.0|<2.3.0
            version = None
            if ":v" in pid:
                parts = pid.split(":v", 1)
                if len(parts) == 2:
                    version = parts[1]  # "vers:semver/>=2.0.0|<2.3.0"
            
            # If no version in product_id, try to extract from purl
            if not version:
                for ident in identifiers:
                    if ident.type == "purl" and "@" in ident.value:
                        try:
                            version = ident.value.split("@")[1].split("?")[0].split("#")[0]
                            break
                        except:
                            pass
            
            subjects_idx[pid] = Subject(
                ref=pid,
                identifiers=identifiers,
                name=p.get("name", pid),
                version=version,
                hashes=hashes,
                model_numbers=model_numbers,
                sbom_urls=sbom_urls,
                serial_numbers=serial_numbers,
                skus=skus
            )

        # Process branches (Red Hat style)
        branches_products = self._extract_from_branches(pt.get("branches", []))
        for pid, prod_info in branches_products.items():
            if pid not in subjects_idx:
                identifiers = []
                if prod_info.get("purl"): 
                    identifiers.append(Identifier(type="purl", value=prod_info["purl"]))
                if prod_info.get("cpe"): 
                    identifiers.append(Identifier(type="cpe", value=prod_info["cpe"]))
                
                # Extract version from product_id if not in prod_info
                version = prod_info.get("version")
                if not version and ":v" in pid:
                    parts = pid.split(":v", 1)
                    if len(parts) == 2:
                        version = parts[1]

                subjects_idx[pid] = Subject(
                    ref=pid,
                    identifiers=identifiers,
                    name=prod_info.get("name", pid),
                    version=version,
                    hashes=prod_info.get("hashes")  # 추가
                )

        # Process relationships (creates composite product IDs)
        # Also create mapping from composite_pid to comp_ref for remediations
        composite_to_comp = {}
        for rel in pt.get("relationships", []):
            fpn = rel.get("full_product_name", {})
            composite_pid = fpn.get("product_id", "").strip()
            comp_ref = rel.get("product_reference", "")
            
            # Store mapping
            if composite_pid and comp_ref:
                composite_to_comp[composite_pid] = comp_ref
            
            if composite_pid and composite_pid not in subjects_idx:
                # Inherit identifiers from component products
                parent_ref = rel.get("relates_to_product_reference", "")

                identifiers = []
                name = fpn.get("name", composite_pid)

                # Try to inherit purl/cpe from component
                if comp_ref in subjects_idx:
                    identifiers = subjects_idx[comp_ref].identifiers.copy()

                subjects_idx[composite_pid] = Subject(
                    ref=composite_pid,
                    identifiers=identifiers,
                    name=name
                )

        statements = []
        vulns_idx = {}

        # Phase 1: Create all vulnerabilities first
        for vidx, v in enumerate(data.get("vulnerabilities", [])):
            vuln_id = v.get("cve", f"VULN-{vidx}")

            if vuln_id not in vulns_idx:
                vuln = Vulnerability(id=vuln_id)

                # Extract all notes
                for note in v.get("notes", []):
                    note_entry = {}
                    if note.get("category"):
                        note_entry["category"] = note["category"]
                    if note.get("text"):
                        note_entry["text"] = note["text"]
                    if note.get("title"):
                        note_entry["title"] = note["title"]
                    if note_entry:
                        vuln.notes.append(note_entry)
                
                # Store notes in extension_data for reversible conversion
                if self.options.reversible and vuln.notes:
                    set_extension_field(vuln, "csaf", "notes", vuln.notes)

                # Extract description (first description note)
                for note in v.get("notes", []):
                    if note.get("category") == "description":
                        vuln.description = note.get("text")
                        break

                # Extract CWE (both singular "cwe" and plural "cwes" for CSAF 2.0/2.1 compatibility)
                cwe = v.get("cwe", {})
                if cwe and cwe.get("id"):
                    cwe_id = cwe["id"].replace("CWE-", "")
                    try:
                        vuln.cwes.append(int(cwe_id))
                    except ValueError:
                        pass
                
                # Also support "cwes" array (CSAF 2.1+)
                cwes = v.get("cwes", [])
                for cwe_obj in cwes:
                    if cwe_obj and cwe_obj.get("id"):
                        cwe_id = cwe_obj["id"].replace("CWE-", "")
                        try:
                            cwe_int = int(cwe_id)
                            if cwe_int not in vuln.cwes:
                                vuln.cwes.append(cwe_int)
                        except ValueError:
                            pass

                # Extract CVSS ratings (CSAF 2.0: scores, CSAF 2.1: metrics)
                # Try metrics first (CSAF 2.1 format)
                metrics = v.get("metrics", [])
                for metric_obj in metrics:
                    content = metric_obj.get("content", {})
                    cvss3 = content.get("cvss_v3")
                    cvss2 = content.get("cvss_v2")
                    
                    if cvss3:
                        version = cvss3.get("version", "3.1")
                        method = f"CVSSv{version}"
                        vuln.ratings.append(CvssRating(
                            method=method,
                            score=cvss3.get("baseScore"),
                            severity=cvss3.get("baseSeverity"),
                            vector=cvss3.get("vectorString")
                        ))
                    if cvss2:
                        vuln.ratings.append(CvssRating(
                            method="CVSSv2",
                            score=cvss2.get("baseScore"),
                            severity=cvss2.get("baseSeverity"),
                            vector=cvss2.get("vectorString")
                        ))

                # Also try CSAF 2.0 "scores" format
                scores = v.get("scores", [])
                for score_obj in scores:
                    cvss3 = score_obj.get("cvss_v3")
                    cvss2 = score_obj.get("cvss_v2")
                    
                    if cvss3:
                        version = cvss3.get("version", "3.1")
                        method = f"CVSSv{version}"
                        vuln.ratings.append(CvssRating(
                            method=method,
                            score=cvss3.get("baseScore"),
                            severity=cvss3.get("baseSeverity"),
                            vector=cvss3.get("vectorString")
                        ))
                    if cvss2:
                        vuln.ratings.append(CvssRating(
                            method="CVSSv2",
                            score=cvss2.get("baseScore"),
                            severity=cvss2.get("baseSeverity"),
                            vector=cvss2.get("vectorString")
                        ))

                # Extract references
                for ref_obj in v.get("references", []):
                    ref_url = ref_obj.get("url")
                    if ref_url:
                        vuln.references.append(Reference(
                            url=ref_url,
                            summary=ref_obj.get("summary"),
                            category=ref_obj.get("category", "external")
                        ))

                # Extract remediations
                for rem_obj in v.get("remediations", []):
                    rem_entry = {
                        "category": rem_obj.get("category", ""),
                        "details": rem_obj.get("details", "")
                    }
                    if rem_obj.get("url"):
                        rem_entry["url"] = rem_obj["url"]
                    vuln.remediations.append(rem_entry)

                vulns_idx[vuln_id] = vuln

        # Phase 2: Restore extension_data for vulnerabilities (if restore mode)
        if self.options.restore and restore_metadata:
            extension_data = restore_metadata.extension_data
            if extension_data:
                # Use vulnerability ID as key (not index)
                for v in data.get("vulnerabilities", []):
                    vuln_id = v.get("cve", "")
                    if vuln_id:
                        vuln = vulns_idx.get(vuln_id)
                        if vuln:
                            key = f"vulnerability_{vuln_id}"
                            if key in extension_data:
                                vuln.extension_data = extension_data[key]
                                print(f"[Restore Mode] Restored extension_data for vulnerability {vuln_id}")

        # Phase 3: Create statements (now extension_data is available)
        for vidx, v in enumerate(data.get("vulnerabilities", [])):
            vuln_id = v.get("cve", f"VULN-{vidx}")

            # Restore original statements if available (perfect restoration)
            vuln = vulns_idx.get(vuln_id)
            original_statements = get_extension_field(vuln, "csaf", "original_statements") if vuln else None
            
            if original_statements and self.options.restore:
                # Perfect restoration: recreate statements from stored data
                for stmt_dict in original_statements:
                    # Reconstruct StatusInfo
                    status_data = stmt_dict.get("status", {})
                    status_value_name = status_data.get("value", "UNDER_INVESTIGATION")
                    status_enum = {
                        "AFFECTED": VulnerabilityStatus.AFFECTED,
                        "NOT_AFFECTED": VulnerabilityStatus.NOT_AFFECTED,
                        "FIXED": VulnerabilityStatus.FIXED,
                        "UNDER_INVESTIGATION": VulnerabilityStatus.UNDER_INVESTIGATION
                    }.get(status_value_name, VulnerabilityStatus.UNDER_INVESTIGATION)
                    
                    # Reconstruct justification
                    just_value = status_data.get("justification")
                    just_enum = None
                    if just_value:
                        just_enum = map_openvex_justification_str_to_enum(just_value.lower())
                    
                    status_info = StatusInfo(
                        value=status_enum,
                        justification=just_enum,
                        custom_justification=status_data.get("custom_justification"),
                        impact_statement=status_data.get("impact_statement"),
                        original_state=status_data.get("original_state")
                    )
                    
                    # Reconstruct timestamp
                    timestamp_str = stmt_dict.get("timestamp")
                    timestamp_obj = None
                    if timestamp_str:
                        try:
                            timestamp_obj = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                        except:
                            pass
                    
                    # Create statement
                    statements.append(VEXStatement(
                        id=f"stmt-{vidx}-restored-{len(statements)}",
                        subject_refs=stmt_dict.get("subject_refs", []),
                        vulnerability_id=vuln_id,
                        status=status_info,
                        timestamp=timestamp_obj,
                        action_statement=stmt_dict.get("action_statement")
                    ))
                
                # Skip normal processing
                continue
            
            # Normal processing (no stored statements)
            ps = v.get("product_status", {})
            flags_map = {}
            for fl in v.get("flags", []):
                lbl = safe_str(fl.get("label")).strip()
                for pid in fl.get("product_ids", []):
                    flags_map[safe_str(pid).strip()] = lbl

            # Extract impact statements from threats
            threats_map = {}
            for threat in v.get("threats", []):
                if threat.get("category") == "impact":
                    details = threat.get("details", "")
                    for pid in threat.get("product_ids", []):
                        pid_clean = safe_str(pid).strip()
                        if pid_clean and details:
                            threats_map[pid_clean] = details
            
            # Extract action statements from remediations
            remediations_map = {}
            for rem in v.get("remediations", []):
                category = rem.get("category", "")
                details = rem.get("details", "")
                if details:
                    for pid in rem.get("product_ids", []):
                        pid_clean = safe_str(pid).strip()
                        if pid_clean:
                            # Format: "category: details" or just details
                            if category:
                                action_text = f"{category}: {details}"
                            else:
                                action_text = details
                            
                            # Append to existing action (if any)
                            if pid_clean in remediations_map:
                                remediations_map[pid_clean] += "\n" + action_text
                            else:
                                remediations_map[pid_clean] = action_text

            # Map CSAF product status to VulnerabilityStatus
            status_mapping = [
                ("known_not_affected", VulnerabilityStatus.NOT_AFFECTED),
                ("known_affected", VulnerabilityStatus.AFFECTED),
                ("first_affected", VulnerabilityStatus.AFFECTED),
                ("last_affected", VulnerabilityStatus.AFFECTED),
                ("fixed", VulnerabilityStatus.FIXED),
                ("first_fixed", VulnerabilityStatus.FIXED),
                ("recommended", VulnerabilityStatus.FIXED),
                ("under_investigation", VulnerabilityStatus.UNDER_INVESTIGATION)
            ]

            for key, status_value in status_mapping:
                for pid in ps.get(key, []):
                    pid = safe_str(pid).strip()
                    if not pid: continue

                    if pid not in subjects_idx:
                        subjects_idx[pid] = Subject(ref=pid, name=pid, identifiers=[
                            Identifier(type="product_id", value=pid)
                        ])

                    flag_label = flags_map.get(pid)
                    just_enum = csaf_flag_to_justification_enum(flag_label) if flag_label else None
                    custom_just = flag_label if flag_label and not just_enum else None

                    # Get impact statement from threats
                    impact_stmt = threats_map.get(pid)
                    
                    # Get action statement from remediations
                    action_stmt = remediations_map.get(pid)

                    statements.append(VEXStatement(
                        id=f"stmt-{vidx}-{pid}",
                        subject_refs=[pid],
                        vulnerability_id=vuln_id,
                        status=StatusInfo(
                            value=status_value,
                            justification=just_enum,
                            custom_justification=custom_just,
                            impact_statement=impact_stmt
                        ),
                        action_statement=action_stmt,
                        timestamp=timestamp
                    ))
        
        # Restore mode: apply extension_data and subject_mappings
        if self.options.restore and restore_metadata:
            extension_data = restore_metadata.extension_data
            subject_mappings = restore_metadata.subject_mappings
            restored_count = 0
            
            # Restore extension_data
            if extension_data:
                # Metadata extension_data
                if "metadata" in extension_data:
                    metadata.extension_data = extension_data["metadata"]
                    restored_count += 1
                
                # Subject extension_data
                for idx, subj in enumerate(subjects_idx.values()):
                    key = f"subject_{idx}"
                    if key in extension_data:
                        subj.extension_data = extension_data[key]
                        restored_count += 1
                
                # Vulnerability extension_data
                for idx, vuln in enumerate(vulns_idx.values()):
                    key = f"vulnerability_{idx}"
                    if key in extension_data:
                        vuln.extension_data = extension_data[key]
                        restored_count += 1
                
                # Statement extension_data
                for idx, stmt in enumerate(statements):
                    key = f"statement_{idx}"
                    if key in extension_data:
                        stmt.extension_data = extension_data[key]
                        restored_count += 1
            
            # Restore original_id from subject_mappings
            if subject_mappings:
                for subj in subjects_idx.values():
                    if subj.ref in subject_mappings:
                        subj.original_id = subject_mappings[subj.ref]
                        restored_count += 1
            
            if restored_count > 0:
                print(f"[Restore Mode] Restored {restored_count} field(s) from metadata")

        return CIM(
            metadata=metadata,
            subjects=list(subjects_idx.values()),
            vulnerabilities=list(vulns_idx.values()),
            statements=statements
        )

    def _extract_from_branches(self, branches: List[Dict]) -> Dict[str, Dict]:
        """
        Recursively extract product information from branches
        수정: 버전 정보도 추출하여 반환
        """
        products = {}

        for branch in branches:
            category = branch.get("category", "")
            branch_name = branch.get("name", "")
            
            # Check if this branch has a product
            prod = branch.get("product", {})
            if prod and prod.get("product_id"):
                pid = prod["product_id"]
                pih = prod.get("product_identification_helper", {})
                
                # CSAF 2.0 uses "purls" (array), but also check "purl" for compatibility
                purl_value = None
                if pih.get("purls"):
                    # purls is array, take first one
                    purl_value = pih["purls"][0] if pih["purls"] else None
                elif pih.get("purl"):
                    # Legacy single purl
                    purl_value = pih["purl"]
                
                # Extract version from product_id first (priority)
                # Format: base-id:vversion
                version = None
                if ":v" in pid:
                    parts = pid.split(":v", 1)
                    if len(parts) == 2:
                        version = parts[1]  # Use version from product_id
                
                # If no version in product_id, extract from category/name or purl
                if not version:
                    if category == "product_version":
                        # branch name contains version (e.g., "1.2.3")
                        version = branch_name
                    elif purl_value and "@" in purl_value:
                        # Extract from purl
                        try:
                            version = purl_value.split("@")[1].split("?")[0].split("#")[0]
                        except:
                            pass
                
                # Extract hashes from CSAF 2.1 format
                hashes_csaf = pih.get("hashes")
                hashes = None
                if hashes_csaf:
                    # CSAF 2.1: [{"file_hashes": [...], "filename": "..."}]
                    # CIM: [{"algorithm": "...", "value": "..."}]
                    hashes = []
                    for hash_entry in hashes_csaf:
                        file_hashes = hash_entry.get("file_hashes", [])
                        for fh in file_hashes:
                            alg = fh.get("algorithm")
                            val = fh.get("value")
                            if alg and val:
                                # Convert sha256 → sha-256
                                if alg.startswith("sha") and not alg.startswith("sha-"):
                                    alg = alg.replace("sha", "sha-")
                                hashes.append({"algorithm": alg, "value": val})
                
                products[pid] = {
                    "name": prod.get("name", pid),
                    "purl": purl_value,
                    "cpe": pih.get("cpe"),
                    "version": version,  # 추가
                    "hashes": hashes  # 추가
                }

            # Recursively process sub-branches
            sub_branches = branch.get("branches", [])
            if sub_branches:
                sub_products = self._extract_from_branches(sub_branches)
                products.update(sub_products)

        return products

# ===== CONVERTERS FROM CIM =====