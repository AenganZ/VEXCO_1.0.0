#!/usr/bin/env python3
"""
VEX 형식 변환기 CLI
지원: OpenVEX <-> CycloneDX <-> CSAF
"""

import sys
import json
import argparse
from typing import Dict, Tuple

from vex_converter import (
    ConversionOptions,
    OpenVEXToCIM, CycloneDXToCIM, CSAFToCIM,
    CIMToOpenVEX, CIMToCycloneDX, CIMToCSAF,
    Validator, LossAnalyzer, __version__
)
from vex_converter.models import TrackingTable


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
            raise ValueError(f"Unsupported source format: {source_format}")

        if target_format == "OpenVEX":
            result = CIMToOpenVEX(self.options, self.tracking_table).convert(cim)
        elif target_format == "CycloneDX":
            result = CIMToCycloneDX(self.options, self.tracking_table).convert(cim)
        elif target_format == "CSAF":
            result = CIMToCSAF(self.options, self.tracking_table).convert(cim)
        else:
            raise ValueError(f"Unsupported target format: {target_format}")

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

    details = analysis.get("details", [])
    info_details = [d for d in details if d.get("severity") == "INFO"]
    if info_details:
        print(f"\nFormat Notes:")
        for d in info_details:
            print(f"  - {d.get('message', '')}")

    lost_fields = analysis.get("lost_fields", [])
    if lost_fields:
        print(f"\nLost Fields ({len(lost_fields)} fields):")
        for field in lost_fields:
            print(f"  - {field}")

    other_details = [d for d in details if d.get("severity") != "INFO"]
    if other_details:
        print(f"\nWarnings:")
        for d in other_details:
            print(f"  [{d.get('severity', '')}] {d.get('message', '')}")

    if not analysis.get("has_data_loss", False) and not lost_fields and not other_details:
        print("\nNo data loss detected!")
    elif analysis.get("has_data_loss", False):
        print("\n*** WARNING: DATA LOSS DETECTED ***")


def detect_format(data: Dict) -> str:
    """문서 구조에서 VEX 형식 자동 감지."""
    if "@context" in data and "statements" in data:
        return "OpenVEX"
    elif "bomFormat" in data and data.get("bomFormat") == "CycloneDX":
        return "CycloneDX"
    elif "document" in data and "product_tree" in data and "vulnerabilities" in data:
        return "CSAF"
    else:
        raise ValueError("Unknown format: could not detect OpenVEX, CycloneDX, or CSAF")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=f'VEX Format Converter v{__version__}',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python convert.py input.json -t CSAF
  python convert.py cyclonedx.json -t OpenVEX -o output.json
  python convert.py vex.json -s OpenVEX -t CycloneDX --reversible
        """
    )
    parser.add_argument('input', help='Input JSON file')
    parser.add_argument('--source', '-s', 
                        choices=['OpenVEX', 'CycloneDX', 'CSAF'],
                        help='Source format (auto-detect if not specified)')
    parser.add_argument('--target', '-t', required=True,
                        choices=['OpenVEX', 'CycloneDX', 'CSAF'],
                        help='Target format')
    parser.add_argument('--output', '-o', 
                        help='Output file path (default: <input>_to_<target>.json)')
    parser.add_argument('--reversible', action='store_true',
                        help='Enable reversible conversion (store metadata for restoration)')
    parser.add_argument('--restore', action='store_true',
                        help='Restore from reversible conversion')
    parser.add_argument('--no-table', action='store_true',
                        help='Disable field mapping table display')
    parser.add_argument('--version', '-v', action='version', 
                        version=f'%(prog)s {__version__}')

    args = parser.parse_args()

    try:
        with open(args.input, 'r', encoding='utf-8') as f:
            source_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: File not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {args.input}: {e}", file=sys.stderr)
        sys.exit(1)

    if args.source:
        source_format = args.source
    else:
        try:
            source_format = detect_format(source_data)
            print(f"Auto-detected source format: {source_format}")
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    options = ConversionOptions(
        use_free_text_encoding=True,
        preserve_cyclonedx_special_states=True,
        consolidate_duplicate_statements=True,
        apply_csaf_product_priority=True,
        reversible=args.reversible,
        restore=args.restore,
        show_mapping_table=not args.no_table
    )

    target_format = args.target
    
    try:
        converter = VEXConverter(options)
        result, analysis = converter.convert(source_data, source_format, target_format)
    except Exception as e:
        print(f"Error during conversion: {e}", file=sys.stderr)
        sys.exit(1)

    if args.output:
        output_file = args.output
    else:
        base_name = args.input.rsplit('.', 1)[0]
        output_file = f"{base_name}_to_{target_format}.json"

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"\nConversion complete: {output_file}")
    print_analysis(analysis)