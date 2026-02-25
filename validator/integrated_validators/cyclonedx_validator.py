"""
CycloneDX VEX 검증기 v1.0.0
CycloneDX v1.5, v1.6, v1.7용 VEX 프로필 검증 규칙

참조:
- CycloneDX VEX 명세
- CISA VEX 최소 요구사항
- OpenVEX/CSAF VEX 프로필 상호 참조

규칙 카테고리:
1. 모든 버전 (v1.5/v1.6/v1.7) - 공통 규칙
2. v1.6+ 추가 규칙
3. v1.7 전용 규칙

심각도 수준:
- error: MUST 규칙 (검증 실패)
- warning: SHOULD 규칙 (권장사항)
"""

import re
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

try:
    import jsonschema
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False

# 최소 지원 버전
MINIMUM_SUPPORTED_VERSION = "1.5"

# 유효한 enum 값
VALID_STATES = ['resolved', 'resolved_with_pedigree', 'exploitable', 'in_triage', 'false_positive', 'not_affected']
VALID_JUSTIFICATIONS = [
    'code_not_present', 'code_not_reachable', 'requires_configuration',
    'requires_dependency', 'requires_environment', 'protected_by_compiler',
    'protected_at_runtime', 'protected_at_perimeter', 'protected_by_mitigating_control'
]
VALID_RESPONSES = ['can_not_fix', 'will_not_fix', 'update', 'rollback', 'workaround_available']
VALID_VERSION_STATUS = ['affected', 'unaffected', 'unknown']
VALID_COMPONENT_TYPES = [
    'application', 'framework', 'library', 'container', 'platform',
    'operating-system', 'device', 'device-driver', 'firmware', 'file',
    'machine-learning-model', 'data', 'cryptographic-asset'
]

# PURL 검증 패턴
PURL_PATTERN = re.compile(r'^pkg:[a-z]+/.+')

# serialNumber용 UUID v4 패턴
UUID_V4_PATTERN = re.compile(r'^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', re.IGNORECASE)


class CycloneDXValidator:
    """CycloneDX VEX 문서 검증기 - 포괄적 규칙 검사 지원"""
    
    VERSION = "1.0.0"
    
    def __init__(self, data: Dict[str, Any], schema: Optional[Dict] = None):
        self.data = data
        self.schema = schema  # Loaded schema dictionary, not path
        self.errors: List[Dict[str, Any]] = []
        self.warnings: List[Dict[str, Any]] = []
        self.spec_version = self._get_spec_version()
        self.all_bom_refs: set = set()
        self.component_bom_refs: set = set()
        self.defined_product_ids: set = set()
        
    def _get_spec_version(self) -> str:
        """문서에서 specVersion 추출"""
        return self.data.get('specVersion', '0.0')
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        """두 버전 문자열 비교. -1, 0, 1 반환"""
        def parse_version(v):
            parts = v.split('.')
            return [int(p) for p in parts[:2]]  # major.minor만 비교
        
        p1, p2 = parse_version(v1), parse_version(v2)
        if p1 < p2:
            return -1
        elif p1 > p2:
            return 1
        return 0
    
    def _is_version_at_least(self, required: str) -> bool:
        """스펙 버전이 최소 요구 버전 이상인지 확인"""
        return self._compare_versions(self.spec_version, required) >= 0
    
    def _add_error(self, rule_id: str, message: str, path: str = '', details: str = ''):
        """검증 오류 추가"""
        self.errors.append({
            'rule_id': rule_id,
            'severity': 'error',
            'message': message,
            'path': path,
            'details': details
        })
    
    def _add_warning(self, rule_id: str, message: str, path: str = '', details: str = ''):
        """검증 경고 추가"""
        self.warnings.append({
            'rule_id': rule_id,
            'severity': 'warning',
            'message': message,
            'path': path,
            'details': details
        })
    
    def _is_valid_iso8601(self, timestamp: str) -> bool:
        """ISO 8601 타임스탬프 형식 검증"""
        patterns = [
            r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$',
            r'^\d{4}-\d{2}-\d{2}$'
        ]
        return any(re.match(p, timestamp) for p in patterns)
    
    def _parse_timestamp(self, timestamp: str) -> Optional[datetime]:
        """ISO 8601 타임스탬프를 datetime으로 파싱"""
        try:
            if timestamp.endswith('Z'):
                timestamp = timestamp[:-1] + '+00:00'
            if 'T' in timestamp:
                if '.' in timestamp:
                    base = timestamp.split('.')[0]
                    tz = ''
                    if '+' in timestamp.split('.')[-1]:
                        tz = '+' + timestamp.split('+')[-1]
                    elif '-' in timestamp.split('.')[-1]:
                        parts = timestamp.split('.')[-1].split('-')
                        if len(parts) > 1:
                            tz = '-' + parts[-1]
                    timestamp = base + tz if tz else base
                return datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            return datetime.fromisoformat(timestamp)
        except:
            return None
    
    def _collect_bom_refs(self):
        """컴포넌트와 서비스에서 모든 bom-ref 값 수집"""
        def collect_from_components(components: List[Dict], path: str = 'components'):
            for i, comp in enumerate(components):
                if 'bom-ref' in comp:
                    ref = comp['bom-ref']
                    self.all_bom_refs.add(ref)
                    self.component_bom_refs.add(ref)
                    self.defined_product_ids.add(ref)
                if 'components' in comp:
                    collect_from_components(comp['components'], f'{path}[{i}].components')
        
        if 'components' in self.data:
            collect_from_components(self.data['components'])
        
        if 'services' in self.data:
            for i, svc in enumerate(self.data['services']):
                if 'bom-ref' in svc:
                    self.all_bom_refs.add(svc['bom-ref'])
                    self.defined_product_ids.add(svc['bom-ref'])
    
    def validate(self) -> Dict[str, Any]:
        """모든 검증 규칙 실행"""
        # JSON Schema 검증 먼저 수행 (MUST)
        self._validate_schema()
        
        # Check minimum version support
        if self._compare_versions(self.spec_version, MINIMUM_SUPPORTED_VERSION) < 0:
            self._add_error(
                'CDX-VERSION-UNSUPPORTED',
                f'CycloneDX v{self.spec_version} is NOT supported',
                'specVersion',
                f'Minimum supported version is v{MINIMUM_SUPPORTED_VERSION}. VEX timestamps require v1.5+'
            )
            return self._build_result()
        
        # bom-ref 먼저 수집
        self._collect_bom_refs()
        
        # 모든 검증 규칙 실행
        self._validate_common_rules()
        
        if self._is_version_at_least('1.6'):
            self._validate_v16_rules()
        
        if self._is_version_at_least('1.7'):
            self._validate_v17_rules()
        
        return self._build_result()
    
    def _validate_schema(self):
        """JSON Schema에 대해 검증 (MUST)"""
        if not self.schema:
            return
        
        if not HAS_JSONSCHEMA:
            self._add_warning(
                'CDX-SCHEMA-SKIP',
                'jsonschema library not available - schema validation skipped',
                '',
                'Install jsonschema: pip install jsonschema'
            )
            return
        
        try:
            validator = jsonschema.Draft7Validator(self.schema)
            schema_errors = list(validator.iter_errors(self.data))
            
            for error in schema_errors:
                path = '.'.join(str(p) for p in error.absolute_path) if error.absolute_path else '(root)'
                self._add_error(
                    'SCHEMA-CDX-001',
                    f'JSON Schema validation failed: {error.message}',
                    path,
                    f'Schema path: {list(error.schema_path)}'
                )
        except Exception as e:
            self._add_warning(
                'SCHEMA-CDX-ERROR',
                f'Schema validation error: {str(e)}',
                '',
                'Schema validation may be incomplete'
            )
    
    def _validate_common_rules(self):
        """모든 버전에 공통인 규칙 검증 (v1.5/v1.6/v1.7)"""
        
        # === BOM 식별 및 버전 관리 ===
        # CDX-BOM-001: serialNumber 권장
        serial = self.data.get('serialNumber')
        if not serial:
            self._add_warning(
                'CDX-BOM-001',
                'serialNumber SHOULD be present for document identification',
                'serialNumber',
                'All generated BOMs SHOULD have a unique serialNumber'
            )
        elif serial and not UUID_V4_PATTERN.match(serial):
            self._add_warning(
                'CDX-BOM-002',
                'serialNumber SHOULD be in URN UUID format',
                'serialNumber',
                f'Found: {serial}, Expected: urn:uuid:xxxxxxxx-xxxx-4xxx-xxxx-xxxxxxxxxxxx'
            )
        
        # CDX-BOM-003: version은 1 이상 권장
        version = self.data.get('version', 0)
        if version < 1:
            self._add_warning(
                'CDX-BOM-003',
                'version SHOULD be >= 1',
                'version',
                f'Current version: {version}'
            )
        
        # === 참조 무결성 ===
        # CDX-REF-001: bom-ref 고유성
        seen_refs = {}
        def check_ref_uniqueness(components: List[Dict], path: str = 'components'):
            for i, comp in enumerate(components):
                if 'bom-ref' in comp:
                    ref = comp['bom-ref']
                    if ref in seen_refs:
                        self._add_error(
                            'CDX-REF-001',
                            f'Duplicate bom-ref found: {ref}',
                            f'{path}[{i}].bom-ref',
                            f'First defined at: {seen_refs[ref]}'
                        )
                    else:
                        seen_refs[ref] = f'{path}[{i}]'
                    
                    # CDX-REF-002: bom-ref는 urn:cdx:로 시작하면 안 됨 (권장)
                    if ref.startswith('urn:cdx:'):
                        self._add_warning(
                            'CDX-REF-002',
                            'bom-ref SHOULD NOT start with urn:cdx: to avoid BOM-Link conflicts',
                            f'{path}[{i}].bom-ref',
                            f'Found: {ref}'
                        )
                
                if 'components' in comp:
                    check_ref_uniqueness(comp['components'], f'{path}[{i}].components')
        
        if 'components' in self.data:
            check_ref_uniqueness(self.data['components'])
        
        # CDX-REF-003: 컴포넌트 유형 분류
        def check_component_type(components: List[Dict], path: str = 'components'):
            for i, comp in enumerate(components):
                comp_type = comp.get('type')
                if not comp_type:
                    self._add_warning(
                        'CDX-REF-003',
                        'Component without type - SHOULD be classified as "library" if unclear',
                        f'{path}[{i}]',
                        f'Component: {comp.get("name", "unknown")}'
                    )
                if 'components' in comp:
                    check_component_type(comp['components'], f'{path}[{i}].components')
        
        if 'components' in self.data:
            check_component_type(self.data['components'])
        
        # === 취약점 검증 ===
        vulnerabilities = self.data.get('vulnerabilities', [])
        if not vulnerabilities:
            self._add_warning(
                'CDX-VEX-NOVULN',
                'No vulnerabilities section found - not a VEX document',
                'vulnerabilities',
                'VEX documents require at least one vulnerability entry'
            )
            return
        
        referenced_product_ids = set()
        product_status_map = {}  # vuln_id -> product_id -> [states]
        
        for v_idx, vuln in enumerate(vulnerabilities):
            v_path = f'vulnerabilities[{v_idx}]'
            vuln_id = vuln.get('id', f'vuln_{v_idx}')
            
            # CDX-VULN-001: 취약점 식별자 필수 (MUST)
            if not vuln.get('id'):
                self._add_error(
                    'CDX-VULN-001',
                    'Vulnerability MUST have an id field',
                    f'{v_path}.id',
                    'At least one vulnerability identifier is required for machine processing'
                )
            elif not vuln.get('id').strip():
                self._add_error(
                    'CDX-VULN-002',
                    'Vulnerability id MUST NOT be empty',
                    f'{v_path}.id',
                    'Empty identifier cannot be processed by automated tools'
                )
            
            # === 분석 섹션 ===
            analysis = vuln.get('analysis', {})
            if not analysis:
                self._add_error(
                    'CDX-VEX-ANALYSIS',
                    'VEX vulnerability SHOULD have analysis section',
                    f'{v_path}.analysis',
                    'Analysis section contains VEX status information'
                )
                continue
            
            a_path = f'{v_path}.analysis'
            state = analysis.get('state')
            justification = analysis.get('justification')
            detail = analysis.get('detail', '')
            responses = analysis.get('response', [])
            
            # CDX-VEX-STATE-001: State 필수
            if not state:
                self._add_error(
                    'CDX-VEX-STATE-001',
                    'analysis.state is REQUIRED',
                    f'{a_path}.state',
                    'VEX status must be explicitly declared'
                )
            elif state not in VALID_STATES:
                self._add_error(
                    'CDX-VEX-STATE-002',
                    f'Invalid analysis.state value: {state}',
                    f'{a_path}.state',
                    f'Valid values: {", ".join(VALID_STATES)}'
                )
            
            # === VEX 상태 로직 (MUST 규칙) ===
            
            # CDX-VEX-001: not_affected는 justification 필수 (MUST)
            if state == 'not_affected':
                if not justification and not detail:
                    self._add_error(
                        'CDX-VEX-001',
                        'not_affected status MUST have justification OR detail (impact statement)',
                        f'{a_path}',
                        'CSAF 2.1 VEX profile and OpenVEX require justification or impact_statement for not_affected'
                    )
                elif justification and justification not in VALID_JUSTIFICATIONS:
                    self._add_error(
                        'CDX-VEX-JUST-001',
                        f'Invalid justification value: {justification}',
                        f'{a_path}.justification',
                        f'Valid values: {", ".join(VALID_JUSTIFICATIONS)}'
                    )
                
                # CDX-VEX-003: detail이 기술적 세부사항을 제공해야 함 (SHOULD)
                if justification and not detail:
                    self._add_warning(
                        'CDX-VEX-003',
                        'not_affected with justification SHOULD include detail for technical specifics',
                        f'{a_path}.detail',
                        'detail field provides human-readable explanation of why component is not affected'
                    )
            
            # CDX-VEX-002: not_affected 상태에서 detail 권장 (SHOULD)
            # CycloneDX 공식 스펙: "If a vulnerability is not exploitable, this field should 
            # include specific details on why the component or service is not impacted"
            if state == 'not_affected':
                if not detail:
                    self._add_warning(
                        'CDX-VEX-002',
                        'not_affected status SHOULD have detail explaining why the vulnerability does not impact the component',
                        f'{a_path}.detail',
                        'Per CycloneDX spec: If not exploitable, detail should include specific reasons why the component is not impacted'
                    )
            
            # exploitable/affected는 response 권장 (SHOULD)
            if state in ['exploitable', 'affected']:
                has_response = bool(responses)
            
            # CDX-VEX-004: exploitable는 response 권장 (SHOULD - 강력 권장)
            if state == 'exploitable' and not responses:
                self._add_warning(
                    'CDX-VEX-004',
                    'exploitable status SHOULD have response (strongly encouraged)',
                    f'{a_path}.response',
                    'Vendor/supplier response is strongly recommended for exploitable vulnerabilities'
                )
            
            # response 값 검증
            if responses:
                for r_idx, resp in enumerate(responses):
                    if resp not in VALID_RESPONSES:
                        self._add_warning(
                            'CDX-VEX-RESP-001',
                            f'Invalid response value: {resp}',
                            f'{a_path}.response[{r_idx}]',
                            f'Valid values: {", ".join(VALID_RESPONSES)}'
                        )
            
            # === 타임스탬프 검증 (SHOULD - OpenVEX 변환 시 충족 어려움) ===
            first_issued = analysis.get('firstIssued')
            last_updated = analysis.get('lastUpdated')
            
            # CDX-TS-001: firstIssued 권장 (SHOULD)
            if not first_issued:
                self._add_warning(
                    'CDX-TS-001',
                    'analysis.firstIssued SHOULD be present',
                    f'{a_path}.firstIssued',
                    'VEX statements with timestamps enable better correlation with other information'
                )
            elif not self._is_valid_iso8601(first_issued):
                self._add_error(
                    'CDX-TS-002',
                    'firstIssued MUST be valid ISO 8601 format',
                    f'{a_path}.firstIssued',
                    f'Invalid format: {first_issued}'
                )
            
            # CDX-TS-003: lastUpdated 권장 (SHOULD)
            if not last_updated:
                self._add_warning(
                    'CDX-TS-003',
                    'analysis.lastUpdated SHOULD be present',
                    f'{a_path}.lastUpdated',
                    'VEX statements should track when they were last updated'
                )
            elif not self._is_valid_iso8601(last_updated):
                self._add_error(
                    'CDX-TS-004',
                    'lastUpdated MUST be valid ISO 8601 format',
                    f'{a_path}.lastUpdated',
                    f'Invalid format: {last_updated}'
                )
            
            # CDX-TS-005: firstIssued <= lastUpdated
            if first_issued and last_updated:
                fi_dt = self._parse_timestamp(first_issued)
                lu_dt = self._parse_timestamp(last_updated)
                if fi_dt and lu_dt and fi_dt > lu_dt:
                    self._add_error(
                        'CDX-TS-005',
                        'firstIssued cannot be later than lastUpdated',
                        f'{a_path}',
                        f'firstIssued: {first_issued}, lastUpdated: {last_updated}'
                    )
            
            # === Affects 섹션 검증 ===
            affects = vuln.get('affects', [])
            if not affects:
                self._add_error(
                    'CDX-VEX-AFFECTS',
                    'vulnerability.affects is REQUIRED and MUST NOT be empty',
                    f'{v_path}.affects',
                    'VEX must specify which products/components are affected'
                )
            
            for a_idx, affect in enumerate(affects):
                af_path = f'{v_path}.affects[{a_idx}]'
                ref = affect.get('ref')
                
                # CDX-REF-004: affects.ref 필수
                if not ref:
                    self._add_error(
                        'CDX-REF-004',
                        'affects[].ref is REQUIRED',
                        f'{af_path}.ref',
                        'Product reference must be specified'
                    )
                elif not ref.strip():
                    self._add_error(
                        'CDX-REF-005',
                        'affects[].ref MUST NOT be empty',
                        f'{af_path}.ref',
                        'Empty reference cannot identify product'
                    )
                else:
                    referenced_product_ids.add(ref)
                    
                    # 분리성 검사를 위한 제품 상태 추적
                    if vuln_id not in product_status_map:
                        product_status_map[vuln_id] = {}
                    if ref not in product_status_map[vuln_id]:
                        product_status_map[vuln_id][ref] = []
                    if state:
                        product_status_map[vuln_id][ref].append(state)
                    
                    # CDX-REF-006: 참조 무결성 (MUST)
                    if ref not in self.defined_product_ids:
                        self._add_error(
                            'CDX-REF-006',
                            f'affects[].ref references undefined bom-ref: {ref}',
                            f'{af_path}.ref',
                            'All referenced product IDs must be defined in components'
                        )
                
                # 버전이 있으면 검증
                versions = affect.get('versions', [])
                for ver_idx, ver in enumerate(versions):
                    ver_path = f'{af_path}.versions[{ver_idx}]'
                    
                    if not ver.get('version') and not ver.get('range'):
                        self._add_error(
                            'CDX-VER-001',
                            'versions entry MUST have version OR range',
                            ver_path,
                            'At least one of version or range must be specified'
                        )
                    
                    ver_status = ver.get('status')
                    if ver_status and ver_status not in VALID_VERSION_STATUS:
                        self._add_error(
                            'CDX-VER-002',
                            f'Invalid version status: {ver_status}',
                            f'{ver_path}.status',
                            f'Valid values: {", ".join(VALID_VERSION_STATUS)}'
                        )
        
        # CDX-REF-007: 제품 상태 분리성 (MUST)
        conflicting_states = {
            'not_affected': ['exploitable', 'affected'],
            'exploitable': ['not_affected', 'false_positive'],
            'false_positive': ['exploitable', 'affected'],
            'resolved': ['exploitable']
        }
        
        for vuln_id, products in product_status_map.items():
            for product_id, states in products.items():
                if len(states) > 1:
                    unique_states = set(states)
                    for s1 in unique_states:
                        for s2 in conflicting_states.get(s1, []):
                            if s2 in unique_states:
                                self._add_error(
                                    'CDX-REF-007',
                                    f'Product {product_id} has conflicting states: {s1} and {s2}',
                                    f'vulnerability[id={vuln_id}]',
                                    'Same product cannot be in mutually exclusive status groups'
                                )
        
        # === PURL/CPE 검증 ===
        def validate_identifiers(components: List[Dict], path: str = 'components'):
            for i, comp in enumerate(components):
                purl = comp.get('purl')
                if purl:
                    if not PURL_PATTERN.match(purl):
                        self._add_error(
                            'CDX-PURL-001',
                            f'Invalid PURL format: {purl}',
                            f'{path}[{i}].purl',
                            'PURL must match pattern: pkg:type/...'
                        )
                    # PURL에 이름 컴포넌트 있는지 확인
                    elif '/' in purl:
                        parts = purl.split('/')
                        if len(parts) < 2 or not parts[1].split('@')[0].split('?')[0]:
                            self._add_warning(
                                'CDX-PURL-002',
                                'PURL should have name component',
                                f'{path}[{i}].purl',
                                f'PURL: {purl}'
                            )
                
                cpe = comp.get('cpe')
                if cpe:
                    if not cpe.startswith('cpe:'):
                        self._add_error(
                            'CDX-CPE-001',
                            f'Invalid CPE format: {cpe}',
                            f'{path}[{i}].cpe',
                            'CPE must start with "cpe:"'
                        )
                
                if 'components' in comp:
                    validate_identifiers(comp['components'], f'{path}[{i}].components')
        
        if 'components' in self.data:
            validate_identifiers(self.data['components'])
    
    def _validate_v16_rules(self):
        """v1.6+ 전용 규칙 검증"""
        
        vulnerabilities = self.data.get('vulnerabilities', [])
        
        for v_idx, vuln in enumerate(vulnerabilities):
            v_path = f'vulnerabilities[{v_idx}]'
            
            # CDX-V16-001: 취약점 우선순위 결정을 위해 ratings 권장
            ratings = vuln.get('ratings', [])
            if not ratings:
                self._add_warning(
                    'CDX-V16-001',
                    'vulnerability ratings SHOULD be provided for prioritization',
                    f'{v_path}.ratings',
                    'Users should consider ratings when determining vulnerability priority'
                )
        
        # CDX-V16-002: Evidence identity 배열 형식
        def check_evidence(components: List[Dict], path: str = 'components'):
            for i, comp in enumerate(components):
                evidence = comp.get('evidence', {})
                identity = evidence.get('identity')
                
                if identity and not isinstance(identity, list):
                    self._add_warning(
                        'CDX-V16-002',
                        'evidence.identity SHOULD be an array of Identity Objects',
                        f'{path}[{i}].evidence.identity',
                        'Array format is recommended over single object for v1.6+'
                    )
                
                if 'components' in comp:
                    check_evidence(comp['components'], f'{path}[{i}].components')
        
        if 'components' in self.data:
            check_evidence(self.data['components'])
    
    def _validate_v17_rules(self):
        """v1.7 전용 규칙 검증"""
        
        def check_v17_components(components: List[Dict], path: str = 'components'):
            for i, comp in enumerate(components):
                comp_type = comp.get('type')
                comp_path = f'{path}[{i}]'
                
                # CDX-V17-001: machine-learning-model SHOULD have modelCard
                if comp_type == 'machine-learning-model':
                    if not comp.get('modelCard'):
                        self._add_warning(
                            'CDX-V17-001',
                            'machine-learning-model component SHOULD have modelCard object',
                            f'{comp_path}.modelCard',
                            'modelCard should describe model limitations and ethical considerations'
                        )
                
                # CDX-V17-002: data component SHOULD have data object
                if comp_type == 'data':
                    if not comp.get('data'):
                        self._add_warning(
                            'CDX-V17-002',
                            'data component SHOULD have data object',
                            f'{comp_path}.data',
                            'data object should describe data classification and governance'
                        )
                
                # CDX-V17-003: isExternal=false MUST NOT have versionRange
                external_refs = comp.get('externalReferences', [])
                for ref_idx, ext_ref in enumerate(external_refs):
                    is_external = ext_ref.get('isExternal', True)
                    version_range = ext_ref.get('versionRange')
                    
                    if is_external is False and version_range:
                        self._add_error(
                            'CDX-V17-003',
                            'Bundled component (isExternal=false) MUST NOT have versionRange',
                            f'{comp_path}.externalReferences[{ref_idx}]',
                            'versionRange is only valid for external (non-bundled) components'
                        )
                
                if 'components' in comp:
                    check_v17_components(comp['components'], f'{comp_path}.components')
        
        if 'components' in self.data:
            check_v17_components(self.data['components'])
        
        # CDX-V17-004: TLP distribution constraints recommended
        metadata = self.data.get('metadata', {})
        dist_constraints = metadata.get('distributionConstraints', {})
        tlp = dist_constraints.get('tlp')
        
        if not tlp:
            self._add_warning(
                'CDX-V17-004',
                'TLP classification (distributionConstraints.tlp) is recommended for v1.7',
                'metadata.distributionConstraints.tlp',
                'Similar to CSAF 2.1 TLP requirement for automated sharing control'
            )
    
    def _build_result(self) -> Dict[str, Any]:
        """검증 결과 생성"""
        is_valid = len(self.errors) == 0
        
        return {
            'valid': is_valid,
            'format': 'cyclonedx',
            'version': self.spec_version,
            'validator_version': self.VERSION,
            'summary': {
                'total_errors': len(self.errors),
                'total_warnings': len(self.warnings),
                'is_vex_compliant': is_valid
            },
            'errors': self.errors,
            'warnings': self.warnings
        }


def validate_cyclonedx(data: Dict[str, Any], schema: Optional[Dict] = None, doc_version: str = '') -> Tuple[bool, List[Dict], str]:
    """
    주요 검증 진입점
    
    Args:
        data: 검증할 문서 데이터
        schema: 로드된 JSON 스키마 딕셔너리 (경로 아님)
        doc_version: 감지된 문서 버전
    
    Returns:
        (is_valid, errors_list, detected_version) 튜플
    """
    validator = CycloneDXValidator(data, schema)
    result = validator.validate()
    
    # app.py 호환성을 위해 오류와 경고 결합
    all_issues = result['errors'] + result['warnings']
    
    return (result['valid'], all_issues, result['version'])


# UI용 규칙 문서
VALIDATION_RULES = {
    'common': [
        # BOM 식별 (SHOULD)
        {'id': 'CDX-BOM-001', 'severity': 'warning', 'desc': 'serialNumber SHOULD be present for document identification'},
        {'id': 'CDX-BOM-002', 'severity': 'warning', 'desc': 'serialNumber SHOULD be in URN UUID format'},
        {'id': 'CDX-BOM-003', 'severity': 'warning', 'desc': 'version SHOULD be >= 1'},
        
        # VEX 상태 로직 (MUST/SHOULD)
        {'id': 'CDX-VEX-001', 'severity': 'error', 'desc': '[MUST] not_affected status requires justification OR detail (impact statement)'},
        {'id': 'CDX-VEX-002', 'severity': 'warning', 'desc': '[SHOULD] not_affected status SHOULD have detail explaining why not impacted'},
        {'id': 'CDX-VEX-003', 'severity': 'warning', 'desc': 'not_affected with justification SHOULD include detail for technical specifics'},
        {'id': 'CDX-VEX-004', 'severity': 'warning', 'desc': 'exploitable status SHOULD have response (strongly encouraged)'},
        {'id': 'CDX-VEX-STATE-001', 'severity': 'error', 'desc': '[MUST] analysis.state is REQUIRED'},
        {'id': 'CDX-VEX-STATE-002', 'severity': 'error', 'desc': '[MUST] analysis.state MUST be valid enum value'},
        {'id': 'CDX-VEX-JUST-001', 'severity': 'error', 'desc': '[MUST] analysis.justification MUST be valid enum value'},
        {'id': 'CDX-VEX-RESP-001', 'severity': 'warning', 'desc': 'analysis.response SHOULD be valid enum values'},
        {'id': 'CDX-VEX-ANALYSIS', 'severity': 'warning', 'desc': '[SHOULD] VEX vulnerability SHOULD have analysis section'},
        {'id': 'CDX-VEX-AFFECTS', 'severity': 'error', 'desc': '[MUST] vulnerability.affects is REQUIRED and MUST NOT be empty'},
        
        # 참조 무결성 (MUST/SHOULD)
        {'id': 'CDX-REF-001', 'severity': 'error', 'desc': '[MUST] Duplicate bom-ref values found'},
        {'id': 'CDX-REF-002', 'severity': 'warning', 'desc': 'bom-ref SHOULD NOT start with urn:cdx: to avoid BOM-Link conflicts'},
        {'id': 'CDX-REF-003', 'severity': 'warning', 'desc': 'Component without type SHOULD be classified as "library" if unclear'},
        {'id': 'CDX-REF-004', 'severity': 'error', 'desc': '[MUST] affects[].ref is REQUIRED'},
        {'id': 'CDX-REF-005', 'severity': 'error', 'desc': '[MUST] affects[].ref MUST NOT be empty'},
        {'id': 'CDX-REF-006', 'severity': 'error', 'desc': '[MUST] affects[].ref must reference defined bom-ref (Reference Integrity)'},
        {'id': 'CDX-REF-007', 'severity': 'error', 'desc': '[MUST] Product status disjointness - same product cannot have conflicting states'},
        
        # 타임스탬프 (SHOULD - OpenVEX 변환 시 충족 어려움)
        {'id': 'CDX-TS-001', 'severity': 'warning', 'desc': '[SHOULD] analysis.firstIssued SHOULD be present'},
        {'id': 'CDX-TS-002', 'severity': 'error', 'desc': '[MUST] firstIssued MUST be valid ISO 8601 format'},
        {'id': 'CDX-TS-003', 'severity': 'warning', 'desc': '[SHOULD] analysis.lastUpdated SHOULD be present'},
        {'id': 'CDX-TS-004', 'severity': 'error', 'desc': '[MUST] lastUpdated MUST be valid ISO 8601 format'},
        {'id': 'CDX-TS-005', 'severity': 'error', 'desc': '[MUST] firstIssued cannot be later than lastUpdated'},
        
        # 취약점 식별자 (MUST)
        {'id': 'CDX-VULN-001', 'severity': 'error', 'desc': '[MUST] Vulnerability MUST have an id field'},
        {'id': 'CDX-VULN-002', 'severity': 'error', 'desc': '[MUST] Vulnerability id MUST NOT be empty'},
        
        # 버전 항목
        {'id': 'CDX-VER-001', 'severity': 'error', 'desc': '[MUST] versions entry MUST have version OR range'},
        {'id': 'CDX-VER-002', 'severity': 'error', 'desc': '[MUST] version.status MUST be valid enum value'},
        
        # PURL/CPE 검증
        {'id': 'CDX-PURL-001', 'severity': 'error', 'desc': '[MUST] PURL must match valid format (pkg:type/...)'},
        {'id': 'CDX-PURL-002', 'severity': 'warning', 'desc': 'PURL SHOULD have name component'},
        {'id': 'CDX-CPE-001', 'severity': 'error', 'desc': '[MUST] CPE must start with "cpe:"'},
        
        # 버전 지원
        {'id': 'CDX-VERSION-UNSUPPORTED', 'severity': 'error', 'desc': 'CycloneDX v1.4 and below NOT supported - minimum v1.5 required'},
    ],
    'v16': [
        {'id': 'CDX-V16-001', 'severity': 'warning', 'desc': '[v1.6+] vulnerability ratings SHOULD be provided for prioritization'},
        {'id': 'CDX-V16-002', 'severity': 'warning', 'desc': '[v1.6+] evidence.identity SHOULD be an array of Identity Objects'},
    ],
    'v17': [
        {'id': 'CDX-V17-001', 'severity': 'warning', 'desc': '[v1.7] machine-learning-model component SHOULD have modelCard'},
        {'id': 'CDX-V17-002', 'severity': 'warning', 'desc': '[v1.7] data component SHOULD have data object'},
        {'id': 'CDX-V17-003', 'severity': 'error', 'desc': '[v1.7] Bundled component (isExternal=false) MUST NOT have versionRange'},
        {'id': 'CDX-V17-004', 'severity': 'warning', 'desc': '[v1.7] TLP classification recommended for automated sharing control'},
    ]
}