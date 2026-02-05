#!/usr/bin/env python3
"""
VEX Validator API - INTEGRATED VERSION
Flask backend with JSON Schema + VEX Business Rules validation
"""

from flask import Flask, request, jsonify, send_file
import json
import os

# ============ INTEGRATED VALIDATORS (Schema + VEX Rules) ============
from integrated_validators.openvex_validator import validate_openvex
from integrated_validators.csaf_validator import validate_csaf
from integrated_validators.cyclonedx_validator import validate_cyclonedx

app = Flask(__name__)

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
        print(f"✓ Loaded {name} schema from {path}")
    except Exception as e:
        print(f"✗ Failed to load {name} schema: {e}")


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


@app.route('/')
def index():
    """Serve the validator HTML page"""
    html_path = os.path.join(os.path.dirname(__file__), 'validator.html')
    return send_file(html_path)


@app.route('/api/validate', methods=['POST'])
def validate():
    """
    Validate VEX document with INTEGRATED validation:
    1. JSON Schema validation (structure, types, enums)
    2. VEX Business Rules validation (status requirements, cross-references)
    
    Request body:
    {
        "content": { ... JSON document ... }
    }
    
    Response:
    {
        "success": true/false,
        "schemaType": "openvex|csaf|cyclonedx|unknown",
        "isValid": true/false,
        "errors": [...],
        "errorCount": 0,
        "validationLevels": {
            "schema": true/false,
            "vexRules": true/false
        }
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'content' not in data:
            return jsonify({
                'success': False,
                'error': 'No content provided'
            }), 400
        
        document = data['content']
        
        # Detect schema type
        schema_type = detect_schema_type(document)
        
        if schema_type == 'unknown':
            return jsonify({
                'success': True,
                'schemaType': 'unknown',
                'isValid': False,
                'errors': [{
                    'path': '/',
                    'message': 'Could not detect document format (OpenVEX, CSAF, or CycloneDX)'
                }],
                'errorCount': 1,
                'validationLevels': {
                    'schema': False,
                    'vexRules': False
                }
            })
        
        # Get schema
        schema = loaded_schemas.get(schema_type)
        if not schema:
            return jsonify({
                'success': False,
                'error': f'Schema not loaded for {schema_type}'
            }), 500
        
        # ============ INTEGRATED VALIDATION ============
        # Now validates BOTH:
        # 1. JSON Schema (structure, types, enums)
        # 2. VEX Business Rules (status requirements, cross-references)
        
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

        error_severity_count = len(schema_errors) + len(vex_errors)
        warning_severity_count = len(schema_warnings) + len(vex_warnings)
        
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
            },
            'severityBreakdown': {
                'errors': error_severity_count,
                'warnings': warning_severity_count
            },
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


@app.route('/api/schemas', methods=['GET'])
def get_schemas():
    """Get available schemas and validation info"""
    return jsonify({
        'schemas': list(SCHEMAS.keys()),
        'loaded': list(loaded_schemas.keys()),
        'validationType': 'integrated',
        'validationLevels': [
            'JSON Schema (structure, types, required fields)',
            'VEX Business Rules (status requirements, cross-references)'
        ]
    })


if __name__ == '__main__':
    print("\n" + "="*70)
    print("VEX Validator API - INTEGRATED VERSION")
    print("="*70)
    print("\nValidation Levels:")
    print("  1. JSON Schema Validation (structure, types, enums)")
    print("  2. VEX Business Rules Validation (status-specific requirements)")
    print("\nThis provides COMPLETE VEX specification compliance!")
    print("="*70)
    print(f"\nLoaded schemas: {', '.join(loaded_schemas.keys())}")
    print("\nStarting Flask server on http://localhost:5000")
    print("Open http://localhost:5000 in your browser")
    print("="*70 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
