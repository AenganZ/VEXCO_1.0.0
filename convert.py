#!/usr/bin/env python3
"""
VEX Format Converter CLI
"""
#!/usr/bin/env python3
"""
VEX Format Converter - Complete Version with Edge Case Handling
Supports: OpenVEX â†” CycloneDX â†” CSAF

IMPORTANT NOTES ON STATE NORMALIZATION:
1. CycloneDX "exploitable" state maps to VEX "affected" status
   - CycloneDX: exploitable, in_triage, not_affected, resolved, false_positive, resolved_with_pedigree
   - VEX Standard: affected, not_affected, fixed, under_investigation
   - Mapping: exploitable â†’ affected, resolved â†’ fixed

2. CSAF product_status includes version-specific fields:
   - first_affected, last_affected â†’ map to affected products
   - first_fixed, recommended â†’ map to fixed products

3. Special CycloneDX states preservation:
   - false_positive: Maps to "not_affected" but original state preserved in metadata
   - resolved_with_pedigree: Maps to "fixed" but pedigree info should be in references
"""

import json, re, uuid, hashlib, base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple, Set, Any
from enum import Enum


import sys
import json
import argparse
from pathlib import Path

from jsonschema import ValidationError

from vex_converter import (
    DocumentFormat, ConversionOptions,
    OpenVEXToCIM, CycloneDXToCIM, CSAFToCIM,
    CIMToOpenVEX, CIMToCycloneDX, CIMToCSAF,
    Validator, __version__
)
from vex_converter.models import CIM, TrackingTable
from vex_converter.nvd_client import NVDAPIClient
from vex_converter.validator import LossAnalyzer

class VEXConverter:
    def __init__(self, options: ConversionOptions = None):
        self.options = options or ConversionOptions()
        self.tracking_table = TrackingTable()

    def convert(self, source_data: Dict, source_format: str, target_format: str) -> Tuple[Dict, Dict]:
        Validator.validate_input(source_data, source_format)

        if source_format == "OpenVEX":
            cim = OpenVEXToCIM(self.options).convert(source_data)
        elif source_format == "CycloneDX":
            cim = CycloneDXToCIM(self.options).convert(source_data)
        elif source_format == "CSAF":
            cim = CSAFToCIM(self.options).convert(source_data)
        else:
            raise ValidationError(f"Unsupported source format: {source_format}")

        # Enrich vulnerabilities with NVD API if enabled
        if self.options.enable_nvd_enrichment:
            nvd_client = NVDAPIClient(self.options.nvd_api_key)
            enriched_vulns = []
            for vuln in cim.vulnerabilities:
                enriched = nvd_client.enrich_vulnerability(vuln)
                enriched_vulns.append(enriched)
            cim = CIM(
                metadata=cim.metadata,
                subjects=cim.subjects,
                vulnerabilities=enriched_vulns,
                statements=cim.statements
            )

        if target_format == "OpenVEX":
            result = CIMToOpenVEX(self.options, self.tracking_table).convert(cim)
        elif target_format == "CycloneDX":
            result = CIMToCycloneDX(self.options, self.tracking_table).convert(cim)
        elif target_format == "CSAF":
            result = CIMToCSAF(self.options, self.tracking_table).convert(cim)
        else:
            raise ValidationError(f"Unsupported target format: {target_format}")

        # Show mapping table if enabled
        if self.options.show_mapping_table and self.tracking_table.records:
            self.tracking_table.print_table(source_format, target_format)

        analyzer = LossAnalyzer()
        analysis = analyzer.analyze(source_data, source_format, cim, result, target_format, self.options.use_free_text_encoding)

        return result, analysis

def print_analysis(analysis: Dict):
    print("\n" + "=" * 70)
    print(f"CONVERSION ANALYSIS: {analysis['source']} -> {analysis['target']}")
    print("=" * 70)
    summary = analysis.get("summary", {})

    print(f"\nData Flow:")
    print(f"  Source:  {summary.get('source_subjects', 0)} subjects, {summary.get('source_vulnerabilities', 0)} vulnerabilities, {summary.get('source_statements', 0)} statements")
    print(f"  CIM:     {summary.get('cim_subjects', 0)} subjects, {summary.get('cim_vulnerabilities', 0)} vulnerabilities, {summary.get('cim_statements', 0)} statements")
    print(f"  Output:  {summary.get('output_subjects', 0)} subjects, {summary.get('output_vulnerabilities', 0)} vulnerabilities, {summary.get('output_statements', 0)} statements")

    # Print informational details (deduplication, filtering, etc.)
    details = analysis.get("details", [])
    info_details = [d for d in details if d.get("severity") == "INFO"]
    if info_details:
        print(f"\nFormat Notes:")
        for d in info_details:
            message = d.get("message", "")
            print(f"  - {message}")

    # Print lost fields
    lost_fields = analysis.get("lost_fields", [])
    if lost_fields:
        print(f"\nLost Fields ({len(lost_fields)} fields):")
        for field in lost_fields:
            print(f"  - {field}")

    # Print other warnings (non-INFO severity)
    other_details = [d for d in details if d.get("severity") != "INFO"]
    if other_details:
        print(f"\nWarnings:")
        for d in other_details:
            severity = d.get("severity", "")
            message = d.get("message", "")
            print(f"  [{severity}] {message}")

    if not analysis.get("has_data_loss", False) and not lost_fields and not other_details:
        print("\nNo data loss detected!")
    elif analysis.get("has_data_loss", False):
        print("\n*** WARNING: DATA LOSS DETECTED ***")

# ===== FORMAT DETECTION =====

def detect_format(data: Dict) -> str:
    if "@context" in data and "statements" in data:
        return "OpenVEX"
    elif "bomFormat" in data and data.get("bomFormat") == "CycloneDX":
        return "CycloneDX"
    elif "document" in data and "product_tree" in data and "vulnerabilities" in data:
        return "CSAF"
    else:
        raise ValidationError("Unknown format: could not detect OpenVEX, CycloneDX, or CSAF")

# ===== CLI =====

if __name__ == "__main__":
    import sys
    import argparse
    import os

    parser = argparse.ArgumentParser(description='VEX Format Converter')
    parser.add_argument('input', help='Input JSON file')
    parser.add_argument('--source', '-s', help='Source format (OpenVEX, CycloneDX, CSAF). Auto-detect if not specified')
    parser.add_argument('--target', '-t', required=True, help='Target format (OpenVEX, CycloneDX, CSAF)')
    parser.add_argument('--output', '-o', help='Output file path (default: <input>_to_<target>.json)')
    parser.add_argument('--nvd-api-key', nargs='?', const='', 
                        help='Enable NVD API enrichment. Optionally provide API key (or use NVD_API_KEY env var)')
    parser.add_argument('--reversible', action='store_true',
                        help='Enable reversible conversion (store metadata for restoration)')
    parser.add_argument('--restore', action='store_true',
                        help='Restore from reversible conversion')
    parser.add_argument('--no-table', action='store_true',
                        help='Disable field mapping table display')

    args = parser.parse_args()

    with open(args.input, 'r', encoding='utf-8') as f:
        source_data = json.load(f)

    if args.source:
        source_format = args.source
    else:
        source_format = detect_format(source_data)
        print(f"Auto-detected source format: {source_format}")

    # NVD API enrichment logic
    # If --nvd-api-key is provided (with or without value), enable NVD
    enable_nvd = args.nvd_api_key is not None
    
    if enable_nvd:
        # Use provided key, or fall back to environment variable
        if args.nvd_api_key:  # Non-empty string provided
            nvd_api_key = args.nvd_api_key
        else:  # Empty string (--nvd-api-key without value)
            nvd_api_key = os.environ.get('NVD_API_KEY')
    else:
        nvd_api_key = None

    options = ConversionOptions(
        use_free_text_encoding=True,
        preserve_cyclonedx_special_states=True,
        consolidate_duplicate_statements=True,
        apply_csaf_product_priority=True,
        enable_nvd_enrichment=enable_nvd,
        nvd_api_key=nvd_api_key,
        reversible=args.reversible,
        restore=args.restore,
        show_mapping_table=not args.no_table
    )

    if enable_nvd:
        if nvd_api_key:
            print("NVD API enrichment enabled (with API key)")
        else:
            print("NVD API enrichment enabled (without API key - rate limited to 50/30s)")

    target_format = args.target

    converter = VEXConverter(options)
    result, analysis = converter.convert(source_data, source_format, target_format)

    if args.output:
        output_file = args.output
    else:
        output_file = f"{args.input.rsplit('.', 1)[0]}_to_{target_format}.json"

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"\nConversion complete: {output_file}")
    print_analysis(analysis)

