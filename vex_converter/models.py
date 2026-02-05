"""
VEX Converter Data Models
"""
import json
import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any
from enum import Enum

class DocumentFormat(Enum):
    OPENVEX = "OpenVEX"
    CYCLONEDX = "CycloneDX"
    CSAF = "CSAF"

class VulnerabilityStatus(Enum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"

class Justification(Enum):
    COMPONENT_NOT_PRESENT = "component_not_present"
    VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present"
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY = "vulnerable_code_cannot_be_controlled_by_adversary"
    INLINE_MITIGATIONS_ALREADY_EXIST = "inline_mitigations_already_exist"

# ===== Conversion Tracking and Reversibility =====

@dataclass
class MappingRecord:
    """Record of a single field mapping during conversion"""
    source_field: str
    source_value: Any
    target_field: str
    target_value: Any
    rule: str  # Mapping rule description
    status: str  # "OK", "LOSSY", "TRANSFORMED", "MERGED"
    loss_description: Optional[str] = None

class TrackingTable:
    """Tracks field mappings during conversion for display and analysis"""
    
    def __init__(self):
        self.records: List[MappingRecord] = []
    
    def add(self, source_field: str, source_value: Any, 
            target_field: str, target_value: Any,
            rule: str, status: str = "OK", loss_description: Optional[str] = None):
        """Add a mapping record"""
        self.records.append(MappingRecord(
            source_field=source_field,
            source_value=self._format_value(source_value),
            target_field=target_field,
            target_value=self._format_value(target_value),
            rule=rule,
            status=status,
            loss_description=loss_description
        ))
    
    def _format_value(self, value: Any) -> str:
        """Format value for display"""
        if value is None:
            return "null"
        elif isinstance(value, (list, dict)):
            s = json.dumps(value, ensure_ascii=False)
            if len(s) > 60:
                return s[:57] + "..."
            return s
        else:
            s = str(value)
            if len(s) > 60:
                return s[:57] + "..."
            return s
    
    def print_table(self, source_format: str, target_format: str):
        """Print mapping table in terminal (simplified format)"""
        if not self.records:
            print("\nNo field mappings tracked.")
            return
        
        print(f"\nCONVERSION MAPPING: {source_format} → {target_format}")
        
        for rec in self.records:
            # Remove CIM intermediate layer for cleaner display
            display_source_field = rec.source_field
            display_source_field = display_source_field.replace("CIM.statement.", "")
            display_source_field = display_source_field.replace("CIM.vulnerability.", "")
            display_source_field = display_source_field.replace("CIM.metadata.", "")
            display_source_field = display_source_field.replace("CIM.subject.", "")
            display_source_field = display_source_field.replace("CIM.", "")
            
            # Simple format: source → target (status)
            # Only show status if not OK
            if rec.status == "OK":
                print(f"  {display_source_field} → {rec.target_field}")
            else:
                status_color = {
                    "LOSSY": "\033[93m",  # Yellow
                    "TRANSFORMED": "\033[96m",  # Cyan
                    "MERGED": "\033[95m"  # Magenta
                }.get(rec.status, "")
                reset = "\033[0m" if status_color else ""
                print(f"  {display_source_field} → {rec.target_field} {status_color}({rec.status}){reset}")
        
        # Summary
        status_counts = {}
        for rec in self.records:
            status_counts[rec.status] = status_counts.get(rec.status, 0) + 1
        
        print(f"\nSummary: {sum(status_counts.values())} mappings")
        if status_counts.get("TRANSFORMED", 0) > 0:
            print(f"  Transformed: {status_counts['TRANSFORMED']}")
        if status_counts.get("LOSSY", 0) > 0:
            print(f"  Lossy: {status_counts['LOSSY']}")
        if status_counts.get("MERGED", 0) > 0:
            print(f"  Merged: {status_counts['MERGED']}")
        print()

@dataclass
class ConversionMetadata:
    """Metadata for reversible conversions"""
    version: str = "1.0"
    source_format: str = ""
    target_format: str = ""
    timestamp: str = ""
    lost_data: Dict[str, Any] = field(default_factory=dict)
    # Extension data from CIM (all format-specific fields)
    extension_data: Dict[str, Any] = field(default_factory=dict)
    # Subject ID mappings: original_ref → modified_ref
    # Example: {"pkg:apk/alpine/busybox": "pkg:apk/alpine/busybox:vunknown"}
    subject_mappings: Dict[str, str] = field(default_factory=dict)
    
    def encode(self) -> str:
        """Encode metadata as plain JSON string with signature"""
        data = {
            "version": self.version,
            "source_format": self.source_format,
            "target_format": self.target_format,
            "timestamp": self.timestamp,
            "lost_data": self.lost_data,
            "extension_data": self.extension_data,
            "subject_mappings": self.subject_mappings
        }
        json_str = json.dumps(data, ensure_ascii=False, separators=(',', ':'))
        return f"[VEXCONV:v1]{json_str}"
    
    @staticmethod
    def decode(encoded: str) -> Optional['ConversionMetadata']:
        """Decode metadata from plain JSON signature"""
        if not encoded or not encoded.startswith("[VEXCONV:v1]"):
            return None
        
        try:
            # Extract JSON part after signature
            json_str = encoded[len("[VEXCONV:v1]"):]
            # Handle both plain JSON and base64 (backwards compatibility)
            if json_str.startswith("{"):
                # Plain JSON
                data = json.loads(json_str)
            else:
                # Legacy base64 format (backwards compatibility)
                b64 = json_str.rstrip("]")
                json_str = base64.b64decode(b64).decode('utf-8')
                data = json.loads(json_str)
            
            return ConversionMetadata(
                version=data.get("version", "1.0"),
                source_format=data.get("source_format", ""),
                target_format=data.get("target_format", ""),
                timestamp=data.get("timestamp", ""),
                lost_data=data.get("lost_data", {}),
                extension_data=data.get("extension_data", {}),
                subject_mappings=data.get("subject_mappings", {})
            )
        except Exception:
            return None

    INLINE_MITIGATIONS_ALREADY_EXIST = "inline_mitigations_already_exist"

@dataclass
class ConversionOptions:
    use_free_text_encoding: bool = True
    preserve_cyclonedx_special_states: bool = True  # false_positive, resolved_with_pedigree
    consolidate_duplicate_statements: bool = True   # For OpenVEX output
    apply_csaf_product_priority: bool = True        # Prevent duplicate product statuses
    use_csaf_product_groups: bool = False           # Use product_groups in CSAF (for consistency, disabled by default)
    enable_nvd_enrichment: bool = False             # Fetch CWE, CVSS from NVD API
    nvd_api_key: Optional[str] = None               # NVD API key (optional, but increases rate limit)
    reversible: bool = False                        # Enable reversible conversion (store metadata for restoration)
    restore: bool = False                           # Restore from reversible conversion
    show_mapping_table: bool = True                 # Show field mapping table during conversion
    input_vdr: bool = False                         # Treat input CycloneDX as VDR (Vulnerability Disclosure Report)

class ValidationError(Exception):
    pass

@dataclass
class Identifier:
    type: str
    value: str

@dataclass
class Subject:
    ref: str
    identifiers: List[Identifier] = field(default_factory=list)
    name: Optional[str] = None
    version: Optional[str] = None
    type: Optional[str] = None
    # Extended CSAF product_identification_helper fields
    hashes: Optional[List[Dict]] = None  # List of {algorithm, value, filename}
    model_numbers: Optional[List[str]] = None
    sbom_urls: Optional[List[str]] = None
    serial_numbers: Optional[List[str]] = None
    skus: Optional[List[str]] = None
    # Extension data for format-specific fields
    # Keys: "cyclonedx.<field>", "openvex.<field>", "csaf.<field>"
    extension_data: Dict[str, Any] = field(default_factory=dict)
    # Original ID from source format (for reversible conversions)
    # Example: "pkg:apk/alpine/busybox" → preserves original @id from OpenVEX
    original_id: Optional[str] = None

@dataclass
class StatusInfo:
    value: VulnerabilityStatus
    justification: Optional[Justification] = None
    custom_justification: Optional[str] = None
    impact_statement: Optional[str] = None
    original_state: Optional[str] = None  # For CycloneDX false_positive, resolved_with_pedigree

@dataclass
class VEXStatement:
    id: str
    subject_refs: List[str]
    vulnerability_id: str
    status: StatusInfo
    timestamp: datetime
    action_statement: Optional[str] = None
    # Extension data for format-specific fields
    extension_data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class CvssRating:
    method: Optional[str] = None
    score: Optional[float] = None
    severity: Optional[str] = None
    vector: Optional[str] = None

@dataclass
class Reference:
    url: str
    summary: Optional[str] = None
    category: Optional[str] = None
    id: Optional[str] = None  # For CycloneDX reference id

@dataclass
class Vulnerability:
    id: str
    description: Optional[str] = None
    ratings: List[CvssRating] = field(default_factory=list)
    cwes: List[int] = field(default_factory=list)
    references: List[Reference] = field(default_factory=list)
    notes: List[Dict[str, str]] = field(default_factory=list)  # For CSAF notes
    remediations: List[Dict[str, Any]] = field(default_factory=list)  # For CSAF remediations
    # Extension data for format-specific fields
    extension_data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Publisher:
    name: str
    namespace: Optional[str] = None
    role: Optional[str] = None

@dataclass
class Metadata:
    id: str
    publisher: Publisher
    created_at: datetime
    source_format: DocumentFormat
    original_id: Optional[str] = None
    # Extension data for format-specific document-level fields
    # e.g., "csaf.document.aggregate_severity": {"namespace": "...", "text": "..."}
    extension_data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class CIM:
    """Common Intermediate Model with Extension Data Support
    
    Extension Data Format:
    - Namespace: "cyclonedx.", "openvex.", "csaf."
    - Nested fields: "csaf.document.aggregate_severity" → {"namespace": "...", "text": "..."}
    - Preserved in --reversible mode and restored in --restore mode
    """
    metadata: Metadata
    subjects: List[Subject]
    vulnerabilities: List[Vulnerability]
    statements: List[VEXStatement]
    # Global extension data for document-level fields that don't fit in metadata
    extension_data: Dict[str, Any] = field(default_factory=dict)