#!/usr/bin/env python3
"""
VEX Tools - Integrated Web Application
Combines VEX Validator and VEX Converter in a single web interface
"""

from flask import Flask, request, jsonify, render_template, send_file
import json
import os
import sys
import tempfile
from datetime import datetime, timezone

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Add parent directory to path for vex_converter import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import integrated validators
from integrated_validators.openvex_validator import validate_openvex
from integrated_validators.csaf_validator import validate_csaf
from integrated_validators.cyclonedx_validator import validate_cyclonedx

# Import vex_converter modules
try:
    from vex_converter import (
        OpenVEXToCIM, CycloneDXToCIM, CSAFToCIM,
        CIMToOpenVEX, CIMToCycloneDX, CIMToCSAF,
        ConversionOptions, __version__ as converter_version
    )
    from vex_converter.vdr import vex_to_vdr, enhance_vdr_with_nvd
    CONVERTER_AVAILABLE = True
except ImportError as e:
    print(f"Warning: vex_converter not available: {e}")
    CONVERTER_AVAILABLE = False
    converter_version = "N/A"

# NVD API Key from environment
NVD_API_KEY = os.environ.get('NVD_API_KEY', '')

app = Flask(__name__, 
            template_folder='templates',
            static_folder='static')

# Manual CORS support
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    return response

# Schema paths
SCHEMA_DIR = os.path.join(os.path.dirname(__file__), 'schemas')
SCHEMAS = {
    'openvex': os.path.join(SCHEMA_DIR, 'openvex-0.2.0.json'),
    'csaf': os.path.join(SCHEMA_DIR, 'csaf-2.1.json'),
    'cyclonedx': os.path.join(SCHEMA_DIR, 'cyclonedx-1.7.json')
}

# Load schemas once at startup
loaded_schemas = {}
for name, path in SCHEMAS.items():
    try:
        with open(path, 'r', encoding='utf-8') as f:
            loaded_schemas[name] = json.load(f)
        print(f"[OK] Loaded {name} schema")
    except Exception as e:
        print(f"[FAIL] Failed to load {name} schema: {e}")


def detect_schema_type(data: dict) -> str:
    """Detect document type from content"""
    # OpenVEX detection
    if '@context' in data and 'openvex' in str(data.get('@context', '')).lower():
        return 'openvex'
    if 'statements' in data and any(key in data for key in ['@id', '@context', 'author']):
        return 'openvex'
    
    # CSAF detection  
    if 'document' in data and 'tracking' in data.get('document', {}):
        return 'csaf'
    if '$schema' in data and 'csaf' in str(data.get('$schema', '')).lower():
        return 'csaf'
    
    # CycloneDX detection
    if 'bomFormat' in data and data.get('bomFormat') == 'CycloneDX':
        return 'cyclonedx'
    if 'specVersion' in data and 'components' in data:
        return 'cyclonedx'
    
    return 'unknown'


def extract_all_fields(data, prefix='', max_depth=10):
    """
    Recursively extract all field paths from a document.
    Returns a set of field paths like {'document.title', 'vulnerabilities[].cve', ...}
    """
    if max_depth <= 0:
        return set()
    
    fields = set()
    
    if isinstance(data, dict):
        for key, value in data.items():
            current_path = f"{prefix}.{key}" if prefix else key
            fields.add(current_path)
            
            if isinstance(value, dict):
                fields.update(extract_all_fields(value, current_path, max_depth - 1))
            elif isinstance(value, list) and len(value) > 0:
                array_path = f"{current_path}[]"
                fields.add(array_path)
                if isinstance(value[0], dict):
                    fields.update(extract_all_fields(value[0], array_path, max_depth - 1))
    
    return fields


def extract_all_values(data, prefix='', max_depth=10):
    """
    Recursively extract all leaf values with their paths.
    Returns a dict: {path: value, ...}
    """
    if max_depth <= 0:
        return {}
    
    result = {}
    
    if isinstance(data, dict):
        for key, value in data.items():
            current_path = f"{prefix}.{key}" if prefix else key
            
            if isinstance(value, dict):
                result.update(extract_all_values(value, current_path, max_depth - 1))
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    item_path = f"{current_path}[{i}]"
                    if isinstance(item, dict):
                        result.update(extract_all_values(item, item_path, max_depth - 1))
                    else:
                        result[item_path] = item
            else:
                result[current_path] = value
    
    return result


def cim_to_dict(cim) -> dict:
    """Convert CIM object and all nested objects to dictionary"""
    from dataclasses import is_dataclass, asdict
    from enum import Enum
    
    def convert(obj):
        if obj is None:
            return None
        elif isinstance(obj, Enum):
            return obj.value
        elif is_dataclass(obj) and not isinstance(obj, type):
            return {k: convert(v) for k, v in asdict(obj).items()}
        elif isinstance(obj, dict):
            return {k: convert(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [convert(item) for item in obj]
        else:
            return obj
    
    return convert(cim)


def analyze_unmapped_fields_dynamic(document: dict, source_format: str) -> dict:
    """
    Dynamically analyze which fields are NOT mapped to CIM by performing actual conversion.
    Compare original document values with CIM values to find what's lost.
    """
    if not CONVERTER_AVAILABLE:
        return {'error': 'Converter not available'}
    
    try:
        # Step 1: Extract all values from original document
        original_values = extract_all_values(document)
        original_fields = extract_all_fields(document)
        
        # Step 2: Convert to CIM
        if source_format == 'openvex':
            cim = OpenVEXToCIM().convert(document)
        elif source_format == 'cyclonedx':
            cim = CycloneDXToCIM().convert(document)
        elif source_format == 'csaf':
            cim = CSAFToCIM().convert(document)
        else:
            return {'error': f'Unknown format: {source_format}'}
        
        # Step 3: Convert CIM to dict and extract values
        cim_dict = cim_to_dict(cim)
        cim_values = set()
        
        def collect_values(obj, depth=0):
            if depth > 15:
                return
            if isinstance(obj, dict):
                for v in obj.values():
                    collect_values(v, depth + 1)
            elif isinstance(obj, list):
                for item in obj:
                    collect_values(item, depth + 1)
            elif obj is not None:
                # Normalize value for comparison
                if isinstance(obj, str):
                    cim_values.add(obj)
                    cim_values.add(obj.lower())
                else:
                    cim_values.add(str(obj))
        
        collect_values(cim_dict)
        
        # Step 4: Find original values NOT in CIM
        unmapped_fields = []
        mapped_fields = []
        
        for path, value in original_values.items():
            if value is None:
                continue
            
            # Check if this value appears in CIM
            value_str = str(value) if not isinstance(value, str) else value
            value_found = (
                value_str in cim_values or 
                value_str.lower() in cim_values or
                (isinstance(value, bool) and str(value).lower() in cim_values)
            )
            
            if value_found:
                mapped_fields.append(path)
            else:
                # Skip format-specific metadata that's expected to be lost
                skip_patterns = ['$schema', 'bomFormat', 'specVersion', '@context']
                if not any(pattern in path for pattern in skip_patterns):
                    unmapped_fields.append({
                        'path': path,
                        'value': value_str[:100] if len(value_str) > 100 else value_str
                    })
        
        # Step 5: Group unmapped fields by category
        categorized = {
            'document_metadata': [],
            'vulnerability_data': [],
            'product_data': [],
            'other': []
        }
        
        for item in unmapped_fields:
            path = item['path']
            if any(p in path for p in ['document.', 'metadata.']):
                categorized['document_metadata'].append(item)
            elif any(p in path for p in ['vulnerabilities', 'vulnerability', 'statements']):
                categorized['vulnerability_data'].append(item)
            elif any(p in path for p in ['product', 'component', 'affects']):
                categorized['product_data'].append(item)
            else:
                categorized['other'].append(item)
        
        return {
            'success': True,
            'total_fields': len(original_fields),
            'total_values': len(original_values),
            'mapped_count': len(mapped_fields),
            'unmapped_count': len(unmapped_fields),
            'unmapped_fields': unmapped_fields,
            'categorized': categorized
        }
        
    except Exception as e:
        import traceback
        return {
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }


# ============ ROUTES ============

@app.route('/')
def index():
    """Serve the main page"""
    return render_template('index.html', 
                           converter_version=converter_version if CONVERTER_AVAILABLE else "N/A",
                           converter_available=CONVERTER_AVAILABLE)


@app.route('/api/analyze-loss', methods=['POST'])
def analyze_loss():
    """
    Dynamically analyze uploaded file by performing actual CIM conversion
    and comparing original values with CIM values to find unmapped fields.
    """
    try:
        data = request.get_json()
        
        if not data or 'content' not in data:
            return jsonify({
                'success': False,
                'error': 'No content provided'
            }), 400
        
        document = data['content']
        source_format = detect_schema_type(document)
        
        if source_format == 'unknown':
            return jsonify({
                'success': False,
                'error': 'Could not detect document format'
            }), 400
        
        # Perform dynamic analysis by actual conversion
        analysis = analyze_unmapped_fields_dynamic(document, source_format)
        
        return jsonify({
            'success': analysis.get('success', True),
            'sourceFormat': source_format,
            'analysis': analysis
        })
        
    except Exception as e:
        import traceback
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500


@app.route('/api/validate', methods=['POST'])
def validate():
    """Validate VEX document with integrated validation"""
    try:
        data = request.get_json()
        
        if not data or 'content' not in data:
            return jsonify({
                'success': False,
                'error': 'No content provided'
            }), 400
        
        document = data['content']
        schema_type = detect_schema_type(document)
        
        if schema_type == 'unknown':
            return jsonify({
                'success': True,
                'schemaType': 'unknown',
                'isValid': False,
                'errors': [{
                    'path': '/',
                    'message': 'Could not detect document format (OpenVEX, CSAF, or CycloneDX)',
                    'severity': 'error',
                    'rule_id': 'DETECT-001'
                }],
                'errorCount': 1,
                'validationLevels': {
                    'schema': False,
                    'vexRules': False
                }
            })
        
        schema = loaded_schemas.get(schema_type)
        if not schema:
            return jsonify({
                'success': False,
                'error': f'Schema not loaded for {schema_type}'
            }), 500
        
        # Run integrated validation
        if schema_type == 'openvex':
            is_valid, errors = validate_openvex(document, schema)
        elif schema_type == 'csaf':
            is_valid, errors = validate_csaf(document, schema)
        elif schema_type == 'cyclonedx':
            is_valid, errors = validate_cyclonedx(document, schema)
        
        # Analyze error types
        schema_errors = [e for e in errors if e.get('rule_id', '').startswith('SCHEMA') and e.get('severity') == 'error']
        schema_warnings = [e for e in errors if e.get('rule_id', '').startswith('SCHEMA') and e.get('severity') == 'warning']
        vex_errors = [e for e in errors if not e.get('rule_id', '').startswith('SCHEMA') and e.get('severity') == 'error']
        vex_warnings = [e for e in errors if not e.get('rule_id', '').startswith('SCHEMA') and e.get('severity') == 'warning']
        
        return jsonify({
            'success': True,
            'schemaType': schema_type,
            'isValid': is_valid,
            'errors': errors,
            'errorCount': len(errors),
            'validationLevels': {
                'schema': len(schema_errors) == 0,
                'vexRules': len(vex_errors) == 0,
                'schemaErrorCount': len(schema_errors),
                'vexRuleErrorCount': len(vex_errors),
                'schemaWarningCount': len(schema_warnings),
                'vexRuleWarningCount': len(vex_warnings)
            }
        })
        
    except json.JSONDecodeError as e:
        return jsonify({
            'success': False,
            'error': f'Invalid JSON: {str(e)}'
        }), 400
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Validation error: {str(e)}'
        }), 500


@app.route('/api/convert', methods=['POST'])
def convert():
    """Convert VEX document between formats (including VDR)"""
    if not CONVERTER_AVAILABLE:
        return jsonify({
            'success': False,
            'error': 'VEX Converter module not available'
        }), 500
    
    try:
        data = request.get_json()
        
        if not data or 'content' not in data:
            return jsonify({
                'success': False,
                'error': 'No content provided'
            }), 400
        
        document = data['content']
        target_format = data.get('targetFormat', '').lower()
        options_data = data.get('options', {})
        
        # Detect source format
        source_format = detect_schema_type(document)
        
        if source_format == 'unknown':
            return jsonify({
                'success': False,
                'error': 'Could not detect source format'
            }), 400
        
        valid_targets = ['openvex', 'csaf', 'cyclonedx', 'vdr']
        if target_format not in valid_targets:
            return jsonify({
                'success': False,
                'error': f'Invalid target format: {target_format}. Valid: {valid_targets}'
            }), 400
        
        if source_format == target_format:
            return jsonify({
                'success': False,
                'error': 'Source and target formats are the same'
            }), 400
        
        # Create conversion options
        options = ConversionOptions(
            reversible=options_data.get('reversible', False),
            restore=options_data.get('restore', False)
        )
        
        # Analyze unmapped fields before conversion (dynamic analysis)
        loss_analysis = analyze_unmapped_fields_dynamic(document, source_format)
        
        # Step 1: Convert to CIM
        if source_format == 'openvex':
            cim = OpenVEXToCIM().convert(document)
        elif source_format == 'cyclonedx':
            cim = CycloneDXToCIM().convert(document)
        elif source_format == 'csaf':
            cim = CSAFToCIM().convert(document)
        
        # Step 2: Convert from CIM to target format
        if target_format == 'openvex':
            result = CIMToOpenVEX(options).convert(cim)
        elif target_format == 'cyclonedx':
            result = CIMToCycloneDX(options).convert(cim)
        elif target_format == 'csaf':
            result = CIMToCSAF(options).convert(cim)
        elif target_format == 'vdr':
            # VDR conversion with NVD enrichment
            if NVD_API_KEY:
                try:
                    cim = enhance_vdr_with_nvd(cim, api_key=NVD_API_KEY)
                except Exception as e:
                    print(f"NVD enrichment warning: {e}")
            result = vex_to_vdr(cim)
        
        # Collect conversion info
        conversion_info = {
            'sourceFormat': source_format,
            'targetFormat': target_format,
            'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'converterVersion': converter_version,
            'options': {
                'reversible': options.reversible,
                'restore': options.restore
            },
            'lossAnalysis': loss_analysis,
            'nvdEnriched': target_format == 'vdr' and bool(NVD_API_KEY)
        }
        
        return jsonify({
            'success': True,
            'result': result,
            'conversionInfo': conversion_info
        })
        
    except Exception as e:
        import traceback
        return jsonify({
            'success': False,
            'error': f'Conversion error: {str(e)}',
            'traceback': traceback.format_exc()
        }), 500


@app.route('/api/field-mappings', methods=['GET'])
def get_field_mappings():
    """Get information about the dynamic field analysis feature"""
    return jsonify({
        'success': True,
        'message': 'Field mappings are now analyzed dynamically. Use POST /api/analyze-loss with document content.',
        'supportedFormats': ['openvex', 'csaf', 'cyclonedx'],
        'analysisMethod': 'dynamic_conversion'
    })


@app.route('/api/download', methods=['POST'])
def download():
    """Download converted document as file"""
    try:
        data = request.get_json()
        content = data.get('content')
        source_format = data.get('sourceFormat', 'unknown')
        target_format = data.get('targetFormat', 'unknown')
        
        if not content:
            return jsonify({'success': False, 'error': 'No content'}), 400
        
        # Generate filename: {source}_to_{target}_{timestamp}.json
        timestamp_str = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        filename = f"{source_format}_to_{target_format}_{timestamp_str}.json"
        
        # Create temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(content, f, indent=2, ensure_ascii=False)
            temp_path = f.name
        
        return send_file(
            temp_path,
            as_attachment=True,
            download_name=filename,
            mimetype='application/json'
        )
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/info', methods=['GET'])
def info():
    """Get system information"""
    return jsonify({
        'converterVersion': converter_version if CONVERTER_AVAILABLE else None,
        'converterAvailable': CONVERTER_AVAILABLE,
        'loadedSchemas': list(loaded_schemas.keys()),
        'supportedFormats': ['openvex', 'csaf', 'cyclonedx'],
        'supportedTargets': ['openvex', 'csaf', 'cyclonedx', 'vdr'],
        'nvdConfigured': bool(NVD_API_KEY)
    })


if __name__ == '__main__':
    print("\n" + "="*70)
    print("VEX Tools - Integrated Web Application")
    print("="*70)
    print(f"\nConverter Version: {converter_version if CONVERTER_AVAILABLE else 'N/A'}")
    print(f"Converter Available: {CONVERTER_AVAILABLE}")
    print(f"NVD API Key: {'Configured' if NVD_API_KEY else 'Not configured'}")
    print(f"Loaded Schemas: {', '.join(loaded_schemas.keys())}")
    print(f"Supported Targets: openvex, csaf, cyclonedx, vdr")
    print("\nStarting Flask server on http://localhost:5000")
    print("="*70 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)