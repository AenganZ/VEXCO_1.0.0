#!/usr/bin/env python3
"""
VEX Tools - 통합 웹 애플리케이션
VEX Validator와 VEX Converter를 단일 웹 인터페이스로 통합
"""

from flask import Flask, request, jsonify, render_template, send_file, Response
import json
import os
import sys
import tempfile
from datetime import datetime, timezone

# .env 파일에서 환경 변수 로드
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# vex_converter import를 위해 부모 디렉토리를 경로에 추가
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 통합 검증기 import (같은 디렉토리에서)
from integrated_validators.openvex_validator import validate_openvex
from integrated_validators.csaf_validator import validate_csaf
from integrated_validators.cyclonedx_validator import validate_cyclonedx

# vex_converter 모듈 import
try:
    from vex_converter import (
        OpenVEXToCIM, CycloneDXToCIM, CSAFToCIM,
        CIMToOpenVEX, CIMToCycloneDX, CIMToCSAF,
        ConversionOptions, __version__ as converter_version
    )
    from vex_converter.models import TrackingTable
    from vex_converter.vdr import vex_to_vdr, enhance_vdr_with_nvd
    CONVERTER_AVAILABLE = True
except ImportError as e:
    print(f"Warning: vex_converter not available: {e}")
    CONVERTER_AVAILABLE = False
    converter_version = "N/A"
    TrackingTable = None

# 환경 변수에서 NVD API Key 가져오기
NVD_API_KEY = os.environ.get('NVD_API_KEY', '')

app = Flask(__name__, 
            template_folder='templates',
            static_folder='static')

# 중요: 필드 순서 보존을 위해 JSON 키 정렬 비활성화 (호환성을 위해 여러 방법 사용)
app.config['JSON_SORT_KEYS'] = False
app.json.sort_keys = False  # Flask 2.x 이상

def json_response(data, status=200):
    """필드 순서 보존된 JSON 응답 반환 (정렬 안 함)"""
    return Response(
        json.dumps(data, ensure_ascii=False, indent=2, sort_keys=False),
        status=status,
        mimetype='application/json'
    )

# 수동 CORS 지원
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    return response

# 스키마 경로 - 버전별 스키마
SCHEMA_DIR = os.path.join(os.path.dirname(__file__), 'schemas')
SCHEMAS = {
    # OpenVEX (단일 버전)
    'openvex': os.path.join(SCHEMA_DIR, 'openvex-0.2.0.json'),
    # CSAF 버전
    'csaf': os.path.join(SCHEMA_DIR, 'csaf-2.1.json'),
    'csaf-2.1': os.path.join(SCHEMA_DIR, 'csaf-2.1.json'),
    'csaf-2.0': os.path.join(SCHEMA_DIR, 'csaf-2.0.json'),
    # CycloneDX 버전
    'cyclonedx': os.path.join(SCHEMA_DIR, 'cyclonedx-1.7.json'),
    'cyclonedx-1.7': os.path.join(SCHEMA_DIR, 'cyclonedx-1.7.json'),
    'cyclonedx-1.6': os.path.join(SCHEMA_DIR, 'cyclonedx-1.6.json'),
    'cyclonedx-1.5': os.path.join(SCHEMA_DIR, 'cyclonedx-1.5.json'),
}

# 시작 시 스키마 한 번만 로드
loaded_schemas = {}
for name, path in SCHEMAS.items():
    try:
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                loaded_schemas[name] = json.load(f)
            print(f"[OK] Loaded {name} schema")
        else:
            print(f"[SKIP] Schema not found: {name} ({path})")
    except Exception as e:
        print(f"[FAIL] Failed to load {name} schema: {e}")


def detect_schema_type(data: dict) -> str:
    """문서 내용에서 문서 유형 감지"""
    # OpenVEX 감지
    if '@context' in data and 'openvex' in str(data.get('@context', '')).lower():
        return 'openvex'
    if 'statements' in data and any(key in data for key in ['@id', '@context', 'author']):
        return 'openvex'
    
    # CSAF 감지
    if 'document' in data and 'tracking' in data.get('document', {}):
        return 'csaf'
    if '$schema' in data and 'csaf' in str(data.get('$schema', '')).lower():
        return 'csaf'
    
    # CycloneDX 감지
    if 'bomFormat' in data and data.get('bomFormat') == 'CycloneDX':
        return 'cyclonedx'
    if 'specVersion' in data and 'components' in data:
        return 'cyclonedx'
    
    return 'unknown'


def detect_document_version(data: dict, schema_type: str) -> str:
    """CSAF 및 CycloneDX 문서의 특정 버전 감지"""
    if schema_type == 'csaf':
        document = data.get("document", {})
        csaf_version = document.get("csaf_version", "")
        if csaf_version.startswith("2.1"):
            return "2.1"
        elif csaf_version.startswith("2.0"):
            return "2.0"
        # 폴백: $schema 확인
        schema_url = data.get("$schema", "")
        if "2.1" in schema_url:
            return "2.1"
        elif "2.0" in schema_url:
            return "2.0"
        return "2.1"  # 기본값
    
    elif schema_type == 'cyclonedx':
        spec_version = data.get("specVersion", "")
        if spec_version.startswith("1.7"):
            return "1.7"
        elif spec_version.startswith("1.6"):
            return "1.6"
        elif spec_version.startswith("1.5"):
            return "1.5"
        elif spec_version.startswith("1.4"):
            return "1.4"
        return "1.7"  # 기본값
    
    return ""


def get_schema_for_version(schema_type: str, version: str):
    """형식과 버전에 맞는 적절한 스키마 가져오기"""
    if schema_type == 'openvex':
        return loaded_schemas.get('openvex')
    
    versioned_key = f"{schema_type}-{version}"
    if versioned_key in loaded_schemas:
        return loaded_schemas.get(versioned_key)
    
    # 기본값으로 폴백
    return loaded_schemas.get(schema_type)


def extract_all_fields(data, prefix='', max_depth=10):
    """
    문서에서 모든 필드 경로를 재귀적으로 추출.
    {'document.title', 'vulnerabilities[].cve', ...}와 같은 필드 경로 집합 반환
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
    경로와 함께 모든 리프 값을 재귀적으로 추출.
    {path: value, ...} 형태의 딕셔너리 반환
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
    """CIM 객체와 모든 중첩 객체를 딕셔너리로 변환"""
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


def analyze_unmapped_fields_dynamic(document: dict, source_format: str, target_format: str = None) -> dict:
    """
    최종 출력에서 보존되지 않는 필드를 동적으로 분석.
    전체 변환 수행: Source -> CIM -> Target, 그 후 원본과 출력 비교.
    
    extension_data에 저장된 것이 아닌, 변환에서 실제로 손실되는 필드를 보여줌.
    """
    if not CONVERTER_AVAILABLE:
        return {'error': 'Converter not available'}
    
    try:
        # 1단계: 원본 문서에서 모든 값 추출
        original_values = extract_all_values(document)
        original_fields = extract_all_fields(document)
        
        # 2단계: CIM으로 변환
        if source_format == 'openvex':
            cim = OpenVEXToCIM().convert(document)
        elif source_format == 'cyclonedx':
            cim = CycloneDXToCIM().convert(document)
        elif source_format == 'csaf':
            cim = CSAFToCIM().convert(document)
        else:
            return {'error': f'Unknown format: {source_format}'}
        
        # 3단계: target_format이 지정되면 대상으로 변환하고 최종 출력과 비교
        # 그렇지 않으면 CIM과 비교 (대상 선택 전 hover 미리보기용)
        if target_format and target_format != source_format:
            # 실제 데이터 손실을 확인하기 위해 비가역 옵션 생성
            options = ConversionOptions(reversible=False, restore=False)
            
            if target_format == 'openvex':
                output = CIMToOpenVEX(options).convert(cim)
            elif target_format == 'cyclonedx':
                output = CIMToCycloneDX(options).convert(cim)
            elif target_format == 'csaf':
                output = CIMToCSAF(options).convert(cim)
            elif target_format == 'vdr':
                output = vex_to_vdr(cim)
            else:
                output = cim_to_dict(cim)
        else:
            # 대상 미지정 - 미리보기용 CIM 사용
            output = cim_to_dict(cim)
        
        # 4단계: 출력에서 모든 값과 필드명 추출
        output_values = set()
        output_field_names = set()
        
        def collect_values_and_fields(obj, path="", depth=0):
            if depth > 15:
                return
            if isinstance(obj, dict):
                for k, v in obj.items():
                    # 필드명 수집 (상태 값 → 필드명 매핑 감지용)
                    output_field_names.add(k)
                    output_field_names.add(k.lower())
                    collect_values_and_fields(v, f"{path}.{k}" if path else k, depth + 1)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    collect_values_and_fields(item, f"{path}[{i}]", depth + 1)
            elif obj is not None:
                # 비교를 위한 값 정규화
                if isinstance(obj, str):
                    output_values.add(obj)
                    output_values.add(obj.lower())
                    # 유연한 매칭을 위해 일반 접두사/접미사 없이도 추가
                    cleaned = obj.strip()
                    if cleaned:
                        output_values.add(cleaned)
                        output_values.add(cleaned.lower())
                else:
                    output_values.add(str(obj))
        
        collect_values_and_fields(output)
        
        # 5단계: 값이 필드명이 되는 매핑 정의
        # 이것들은 의미적 변환이지 데이터 손실이 아님
        value_to_field_mappings = {
            # OpenVEX/CycloneDX status → CSAF product_status 필드명
            'not_affected': ['known_not_affected', 'not_affected'],
            'affected': ['known_affected', 'affected', 'exploitable'],
            'fixed': ['fixed', 'resolved'],
            'under_investigation': ['under_investigation', 'in_triage'],
            # CycloneDX state 값
            'exploitable': ['known_affected', 'affected', 'exploitable'],
            'in_triage': ['under_investigation', 'in_triage'],
            'resolved': ['fixed', 'resolved'],
            'resolved_with_pedigree': ['fixed', 'resolved'],
            'false_positive': ['known_not_affected', 'not_affected'],
            # CSAF status → OpenVEX/CycloneDX
            'known_not_affected': ['not_affected'],
            'known_affected': ['affected', 'exploitable'],
            'first_affected': ['affected', 'exploitable'],
            'last_affected': ['affected', 'exploitable'],
            'first_fixed': ['fixed', 'resolved'],
            # Justification 값 (OpenVEX ↔ CycloneDX 매핑)
            'component_not_present': ['requires_dependency', 'code_not_present'],
            'vulnerable_code_not_present': ['code_not_present'],
            'vulnerable_code_not_in_execute_path': ['code_not_reachable'],
            'vulnerable_code_cannot_be_controlled_by_adversary': ['requires_environment', 'requires_configuration'],
            'inline_mitigations_already_exist': ['protected_by_mitigating_control', 'protected_at_runtime'],
            'code_not_present': ['vulnerable_code_not_present', 'component_not_present'],
            'code_not_reachable': ['vulnerable_code_not_in_execute_path'],
            'requires_configuration': ['vulnerable_code_cannot_be_controlled_by_adversary'],
            'requires_dependency': ['component_not_present', 'inline_mitigations_already_exist'],
            'requires_environment': ['vulnerable_code_cannot_be_controlled_by_adversary'],
            'protected_by_compiler': ['vulnerable_code_not_present'],
            'protected_at_runtime': ['inline_mitigations_already_exist'],
            'protected_at_perimeter': ['vulnerable_code_cannot_be_controlled_by_adversary'],
            'protected_by_mitigating_control': ['inline_mitigations_already_exist'],
        }
        
        # 6단계: 최종 출력에 없는 원본 값 찾기
        unmapped_fields = []
        mapped_fields = []
        
        # 형식 메타데이터 필드 (변경 예상됨)
        skip_patterns = [
            '$schema', 'bomFormat', 'specVersion', '@context', 'serialNumber',
            'csaf_version', 'version'  # 버전 번호는 형식 간 변경됨
        ]
        
        for path, value in original_values.items():
            if value is None:
                continue
            
            # 형식별 메타데이터 건너뜀
            if any(pattern in path for pattern in skip_patterns):
                continue
            
            # 이 값이 출력에 있는지 확인
            value_str = str(value) if not isinstance(value, str) else value
            value_lower = value_str.lower()
            
            value_found = (
                value_str in output_values or 
                value_lower in output_values or
                (isinstance(value, bool) and str(value).lower() in output_values)
            )
            
            # 값이 필드명으로 변환되었는지 확인 (의미적 매핑)
            if not value_found and value_lower in value_to_field_mappings:
                mapped_field_names = value_to_field_mappings[value_lower]
                for mapped_name in mapped_field_names:
                    if mapped_name in output_field_names or mapped_name.lower() in output_field_names:
                        value_found = True
                        break
            
            # 값 자체가 필드명으로 사용되는지도 확인
            if not value_found:
                if value_lower in output_field_names:
                    value_found = True
            
            if value_found:
                mapped_fields.append(path)
            else:
                unmapped_fields.append({
                    'path': path,
                    'value': value_str[:100] if len(value_str) > 100 else value_str
                })
        
        # 7단계: 매핑되지 않은 필드를 카테고리별로 그룹화
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
            'all_unmapped_fields': unmapped_fields,  # "전체 보기" 버튼용 전체 목록
            'categorized': categorized,
            'analysis_type': 'full_conversion' if target_format else 'cim_only'
        }
        
    except Exception as e:
        import traceback
        return {
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }


# ============ 라우트 ============

@app.route('/')
def index():
    """메인 페이지 제공"""
    return render_template('index.html', 
                           converter_version=converter_version if CONVERTER_AVAILABLE else "N/A",
                           converter_available=CONVERTER_AVAILABLE)


@app.route('/api/analyze-loss', methods=['POST'])
def analyze_loss():
    """
    업로드된 파일을 실제 변환 수행하여 동적으로 분석하고
    원본 값과 출력 값을 비교하여 매핑되지 않은 필드 찾기.
    
    targetFormat이 제공되면 해당 대상에 대해 전체 Source->CIM->Target 변환 수행.
    analyzeAll이 true이면 모든 대상 형식에 대해 분석하고 결합된 결과 반환.
    그렇지 않으면 CIM과만 비교 (미리보기 모드).
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
        target_format = data.get('targetFormat', None)
        analyze_all = data.get('analyzeAll', False)
        
        if source_format == 'unknown':
            return jsonify({
                'success': False,
                'error': 'Could not detect document format'
            }), 400
        
        # analyzeAll이 true이면 모든 대상 형식에 대해 분석
        if analyze_all:
            all_targets = ['openvex', 'cyclonedx', 'csaf', 'vdr']
            results = {}
            
            for target in all_targets:
                if target == source_format:
                    results[target] = {
                        'success': True,
                        'same_format': True,
                        'total_values': 0,
                        'mapped_count': 0,
                        'unmapped_count': 0,
                        'unmapped_fields': []
                    }
                else:
                    results[target] = analyze_unmapped_fields_dynamic(document, source_format, target)
            
            return jsonify({
                'success': True,
                'sourceFormat': source_format,
                'analysisByTarget': results
            })
        
        # 단일 대상 분석
        analysis = analyze_unmapped_fields_dynamic(document, source_format, target_format)
        
        return jsonify({
            'success': analysis.get('success', True),
            'sourceFormat': source_format,
            'targetFormat': target_format,
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
    """통합 검증 및 버전 감지로 VEX 문서 검증"""
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
        
        # CSAF와 CycloneDX용 버전 감지
        doc_version = detect_document_version(document, schema_type)
        
        # 버전별 스키마 가져오기
        schema = get_schema_for_version(schema_type, doc_version)
        if not schema:
            # 기본 스키마로 폴백
            schema = loaded_schemas.get(schema_type)
        
        if not schema:
            return jsonify({
                'success': False,
                'error': f'Schema not loaded for {schema_type}'
            }), 500
        
        # 버전 정보와 함께 통합 검증 실행
        detected_version = doc_version
        if schema_type == 'openvex':
            is_valid, errors = validate_openvex(document, schema)
            detected_version = "0.2.0"
        elif schema_type == 'csaf':
            is_valid, errors, detected_version = validate_csaf(document, schema, doc_version)
        elif schema_type == 'cyclonedx':
            is_valid, errors, detected_version = validate_cyclonedx(document, schema, doc_version)
        
        # 오류 유형 분석
        schema_errors = [e for e in errors if e.get('rule_id', '').startswith('SCHEMA') and e.get('severity') == 'error']
        schema_warnings = [e for e in errors if e.get('rule_id', '').startswith('SCHEMA') and e.get('severity') == 'warning']
        vex_errors = [e for e in errors if not e.get('rule_id', '').startswith('SCHEMA') and e.get('severity') == 'error']
        vex_warnings = [e for e in errors if not e.get('rule_id', '').startswith('SCHEMA') and e.get('severity') == 'warning']
        
        return jsonify({
            'success': True,
            'schemaType': schema_type,
            'schemaVersion': detected_version,
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
    """VEX 문서를 형식 간 변환 (VDR 포함)"""
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
        
        # 원본 형식 감지
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
        
        # 변환 옵션 생성
        options = ConversionOptions(
            reversible=options_data.get('reversible', False),
            restore=options_data.get('restore', False)
        )
        
        # 전체 변환으로 매핑되지 않은 필드 분석 (Source -> CIM -> Target)
        loss_analysis = analyze_unmapped_fields_dynamic(document, source_format, target_format)
        
        # 1단계: CIM으로 변환
        if source_format == 'openvex':
            cim = OpenVEXToCIM().convert(document)
        elif source_format == 'cyclonedx':
            cim = CycloneDXToCIM().convert(document)
        elif source_format == 'csaf':
            cim = CSAFToCIM().convert(document)
        
        # 2단계: CIM에서 대상 형식으로 변환
        if target_format == 'openvex':
            result = CIMToOpenVEX(options).convert(cim)
        elif target_format == 'cyclonedx':
            result = CIMToCycloneDX(options).convert(cim)
        elif target_format == 'csaf':
            result = CIMToCSAF(options).convert(cim)
        elif target_format == 'vdr':
            # NVD 보강과 함께 VDR 변환
            if NVD_API_KEY:
                try:
                    cim = enhance_vdr_with_nvd(cim, api_key=NVD_API_KEY)
                except Exception as e:
                    print(f"NVD 보강 경고: {e}")
            result = vex_to_vdr(cim)
        
        # 변환 정보 수집
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
        
        return json_response({
            'success': True,
            'result': result,
            'conversionInfo': conversion_info
        })
        
    except Exception as e:
        import traceback
        return json_response({
            'success': False,
            'error': f'Conversion error: {str(e)}',
            'traceback': traceback.format_exc()
        }, 500)


@app.route('/api/field-mappings', methods=['GET'])
def get_field_mappings():
    """동적 필드 분석 기능에 대한 정보 가져오기"""
    return jsonify({
        'success': True,
        'mappings': {},
        'message': '필드 매핑은 동적으로 분석됩니다. 문서 내용과 함께 POST /api/analyze-field-mappings를 사용하세요.',
        'supportedFormats': ['openvex', 'csaf', 'cyclonedx'],
        'analysisMethod': 'dynamic_conversion'
    })


@app.route('/api/analyze-field-mappings', methods=['POST'])
def analyze_field_mappings():
    """
    실제 변환 결과 기반으로 필드 매핑 분석
    - 입력 문서의 모든 필드 추출
    - 실제 변환 수행
    - 출력 문서와 비교하여 매핑/손실 판단
    """
    try:
        data = request.get_json()
        
        if not data or 'content' not in data:
            return jsonify({'success': False, 'error': 'No content provided'}), 400
        
        document = data['content']
        target_format = data.get('targetFormat')
        source_format = detect_schema_type(document)
        
        if source_format == 'unknown':
            return jsonify({'success': False, 'error': 'Could not detect document format'}), 400
        
        if not target_format:
            return jsonify({'success': False, 'error': 'targetFormat is required'}), 400
        
        # target_format 소문자 정규화
        target_format = target_format.lower()
        
        # 지원되는 target_format 확인
        valid_targets = ['openvex', 'cyclonedx', 'csaf', 'vdr']
        if target_format not in valid_targets:
            return jsonify({
                'success': False, 
                'error': f'Invalid targetFormat: {target_format}. Valid: {valid_targets}'
            }), 400
        
        # ========================================
        # 1. 입력 문서의 모든 필드와 값 추출
        # ========================================
        def extract_fields_with_values(obj, prefix=""):
            """재귀적으로 모든 필드 경로와 값 추출"""
            results = []
            
            if isinstance(obj, dict):
                for key, value in obj.items():
                    path = f"{prefix}.{key}" if prefix else key
                    if isinstance(value, dict):
                        results.extend(extract_fields_with_values(value, path))
                    elif isinstance(value, list):
                        if len(value) > 0:
                            for i, item in enumerate(value):
                                item_path = f"{path}[{i}]"
                                if isinstance(item, dict):
                                    results.extend(extract_fields_with_values(item, item_path))
                                else:
                                    results.append({
                                        'path': item_path,
                                        'value': item,
                                        'value_str': str(item)[:100] if item is not None else ''
                                    })
                        else:
                            results.append({
                                'path': path,
                                'value': [],
                                'value_str': '[]'
                            })
                    else:
                        results.append({
                            'path': path,
                            'value': value,
                            'value_str': str(value)[:100] if value is not None else ''
                        })
            
            return results
        
        source_fields = extract_fields_with_values(document)
        
        # ========================================
        # 2. 실제 변환 수행
        # ========================================
        converted_doc = None
        conversion_error = None
        
        if not CONVERTER_AVAILABLE:
            return jsonify({
                'success': False,
                'error': 'VEX Converter module not available'
            }), 500
        
        try:
            options = ConversionOptions(reversible=False)
            
            # Source → CIM
            if source_format == 'openvex':
                cim = OpenVEXToCIM(options).convert(document)
            elif source_format == 'cyclonedx':
                cim = CycloneDXToCIM(options).convert(document)
            elif source_format == 'csaf':
                cim = CSAFToCIM(options).convert(document)
            else:
                cim = None
            
            if not cim:
                return jsonify({
                    'success': False,
                    'error': f'Failed to parse source document as {source_format}'
                }), 400
            
            # CIM → Target
            if target_format == 'openvex':
                converted_doc = CIMToOpenVEX(options).convert(cim)
            elif target_format == 'cyclonedx':
                converted_doc = CIMToCycloneDX(options).convert(cim)
            elif target_format == 'csaf':
                converted_doc = CIMToCSAF(options).convert(cim)
            elif target_format == 'vdr':
                converted_doc = vex_to_vdr(cim)
        except Exception as e:
            import traceback
            conversion_error = f"{str(e)}\n{traceback.format_exc()}"
        
        if not converted_doc:
            return jsonify({
                'success': False, 
                'error': conversion_error or 'Conversion failed'
            }), 400
        
        # ========================================
        # 3. 출력 문서의 모든 필드와 값 추출
        # ========================================
        target_fields = extract_fields_with_values(converted_doc)
        
        # 출력 값들을 세트로 저장 (빠른 검색용)
        target_values = set()
        target_value_to_path = {}
        for tf in target_fields:
            if tf['value'] is not None and tf['value'] != '' and tf['value'] != []:
                val_key = str(tf['value']).strip()
                target_values.add(val_key)
                if val_key not in target_value_to_path:
                    target_value_to_path[val_key] = tf['path']
        
        # ========================================
        # 4. 소스 필드별 매핑 상태 결정 (실제 값 기반)
        # ========================================
        field_mappings = []
        
        for sf in source_fields:
            source_path = sf['path']
            source_value = sf['value']
            source_value_str = sf['value_str']
            
            # 값이 출력 문서에 존재하는지 확인
            matched_target = None
            if source_value is not None and source_value != '' and source_value != []:
                val_key = str(source_value).strip()
                if val_key in target_values:
                    matched_target = target_value_to_path.get(val_key, 'found in output')
            
            if matched_target:
                status = 'MAPPED'
                target_path = matched_target
            else:
                status = 'LOST'
                target_path = None
            
            field_mappings.append({
                'source': source_path,
                'value': source_value_str if len(source_value_str) <= 60 else source_value_str[:57] + '...',
                'target': target_path,
                'status': status
            })
        
        # ========================================
        # 5. 상태/정당화 값 매핑 (참조용)
        # ========================================
        status_mappings = {
            'openvex_to_cyclonedx': {
                'affected': 'exploitable',
                'not_affected': 'not_affected',
                'fixed': 'resolved',
                'under_investigation': 'in_triage'
            },
            'openvex_to_csaf': {
                'affected': 'known_affected',
                'not_affected': 'known_not_affected',
                'fixed': 'fixed',
                'under_investigation': 'under_investigation'
            },
            'cyclonedx_to_openvex': {
                'exploitable': 'affected',
                'not_affected': 'not_affected',
                'resolved': 'fixed',
                'in_triage': 'under_investigation'
            },
            'cyclonedx_to_csaf': {
                'exploitable': 'known_affected',
                'not_affected': 'known_not_affected',
                'resolved': 'fixed',
                'in_triage': 'under_investigation'
            },
            'csaf_to_openvex': {
                'known_affected': 'affected',
                'known_not_affected': 'not_affected',
                'fixed': 'fixed',
                'under_investigation': 'under_investigation'
            },
            'csaf_to_cyclonedx': {
                'known_affected': 'exploitable',
                'known_not_affected': 'not_affected',
                'fixed': 'resolved',
                'under_investigation': 'in_triage'
            }
        }
        
        justification_mappings = {
            'openvex_to_cyclonedx': {
                'component_not_present': 'requires_dependency',
                'vulnerable_code_not_present': 'code_not_present',
                'vulnerable_code_not_in_execute_path': 'code_not_reachable',
                'vulnerable_code_cannot_be_controlled_by_adversary': 'requires_environment',
                'inline_mitigations_already_exist': 'protected_by_mitigating_control'
            },
            'cyclonedx_to_openvex': {
                'code_not_present': 'vulnerable_code_not_present',
                'code_not_reachable': 'vulnerable_code_not_in_execute_path',
                'requires_configuration': 'vulnerable_code_cannot_be_controlled_by_adversary',
                'requires_dependency': 'component_not_present',
                'requires_environment': 'vulnerable_code_cannot_be_controlled_by_adversary',
                'protected_by_compiler': 'vulnerable_code_not_present',
                'protected_at_runtime': 'inline_mitigations_already_exist',
                'protected_at_perimeter': 'vulnerable_code_cannot_be_controlled_by_adversary',
                'protected_by_mitigating_control': 'inline_mitigations_already_exist'
            }
        }
        
        mapping_key = f"{source_format}_to_{target_format}"
        status_map = status_mappings.get(mapping_key, {})
        just_map = justification_mappings.get(mapping_key, {})
        
        # 통계 계산
        mapped_count = sum(1 for f in field_mappings if f['status'] == 'MAPPED')
        lost_count = sum(1 for f in field_mappings if f['status'] == 'LOST')
        total = len(field_mappings)
        
        return jsonify({
            'success': True,
            'sourceFormat': source_format,
            'targetFormat': target_format,
            'fieldMappings': field_mappings,
            'statistics': {
                'totalFields': total,
                'mappedFields': mapped_count,
                'lostFields': lost_count,
                'mappingRate': f"{(mapped_count / total * 100):.1f}%" if total > 0 else "0%"
            },
            'valueMappings': {
                'status': status_map,
                'justification': just_map
            },
            'conversionPath': f"{source_format.upper()} → CIM → {target_format.upper()}"
        })
        
    except Exception as e:
        import traceback
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500


@app.route('/api/download', methods=['POST'])
def download():
    """변환된 문서를 파일로 다운로드"""
    try:
        data = request.get_json()
        content = data.get('content')
        source_format = data.get('sourceFormat', 'unknown')
        target_format = data.get('targetFormat', 'unknown')
        
        if not content:
            return jsonify({'success': False, 'error': 'No content'}), 400
        
        # 파일명 생성: {source}_to_{target}_{timestamp}.json
        timestamp_str = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        filename = f"{source_format}_to_{target_format}_{timestamp_str}.json"
        
        # 임시 파일 생성
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
    """시스템 정보 가져오기"""
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