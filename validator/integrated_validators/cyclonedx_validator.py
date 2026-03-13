"""
CycloneDX VEX 시맨틱 검증기 v2.0
CycloneDX v1.5, v1.6, v1.7 VEX 프로필 검증 규칙

검증 흐름:
  1단계: JSON 스키마 검증(구조적)
  2단계: 시맨틱 검증(명세 도출 규칙, 버전 게이팅)

네이밍 규칙:
  스키마 규칙   : SCHEMA_CDX_{NNN}
  시맨틱 MUST   : CDX_SEMANTIC_{CATEGORY}_{DESCRIPTION}  (severity=error)
  시맨틱 SHOULD : CDX_SEMANTIC_{CATEGORY}_{DESCRIPTION}  (severity=warning)

참조:
  - CycloneDX v1.5/v1.6/v1.7 명세
  - CISA VEX 최소 요구사항

주의:
  CycloneDX v1.5는 공식 근거 제약으로 스키마 검증만 지원
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
VALID_STATES = [
    'resolved', 'resolved_with_pedigree', 'exploitable',
    'in_triage', 'false_positive', 'not_affected'
]
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
UUID_V4_PATTERN = re.compile(
    r'^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
    re.IGNORECASE
)

# 상태 간 상호 배타 관계
CONFLICTING_STATES = {
    'not_affected': ['exploitable'],
    'exploitable': ['not_affected', 'false_positive'],
    'false_positive': ['exploitable'],
    'resolved': ['exploitable']
}


class CycloneDXValidator:
    """CycloneDX VEX 문서 검증기 - 스키마/시맨틱 분리 구조"""

    VERSION = "2.0.0"

    def __init__(self, data: Dict[str, Any], schema: Optional[Dict] = None):
        self.data = data
        self.schema = schema
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
            return [int(p) for p in parts[:2]]
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
        except Exception:
            return None
        
    BOM_LINK_PATTERN = re.compile(
    r'^urn:cdx:(?P<serial>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/(?P<version>[1-9]\d*)#(?P<bom_ref>.+)$'
)

    def _is_valid_bomlink_format(self, ref: str) -> bool:
        return bool(self.BOM_LINK_PATTERN.match(ref))

    def _parse_bomlink(self, ref: str):
        m = self.BOM_LINK_PATTERN.match(ref)
        if not m:
            return None
        return {
            "serial": m.group("serial"),
            "version": m.group("version"),
            "bom_ref": m.group("bom_ref"),
        }

    def _collect_bom_refs(self):
        """컴포넌트와 서비스에서 모든 bom-ref 값 수집"""
        def collect_from_components(components: List[Dict]):
            for comp in components:
                ref = comp.get('bom-ref')
                if ref:
                    self.all_bom_refs.add(ref)
                    self.component_bom_refs.add(ref)
                    self.defined_product_ids.add(ref)
                if 'components' in comp and isinstance(comp['components'], list):
                    collect_from_components(comp['components'])

        def collect_from_services(services: List[Dict]):
            for svc in services:
                ref = svc.get('bom-ref')
                if ref:
                    self.all_bom_refs.add(ref)
                    self.defined_product_ids.add(ref)
                if 'services' in svc and isinstance(svc['services'], list):
                    collect_from_services(svc['services'])

        if 'components' in self.data and isinstance(self.data['components'], list):
            collect_from_components(self.data['components'])

        if 'services' in self.data and isinstance(self.data['services'], list):
            collect_from_services(self.data['services'])

        # metadata.component bom-ref 추가 수집
        meta_comp = (self.data.get('metadata') or {}).get('component') or {}
        meta_ref = meta_comp.get('bom-ref')
        if meta_ref:
            self.all_bom_refs.add(meta_ref)
            self.component_bom_refs.add(meta_ref)
            self.defined_product_ids.add(meta_ref)

    # ====================================================================
    # 메인 검증 실행
    # ====================================================================

    def validate(self) -> Dict[str, Any]:
        """
        전체 검증 실행.
        1단계: 스키마 검증 → 2단계: 시맨틱 검증
        """
        # 1단계: 스키마 검증 (구조적)
        self._run_schema_validation()

        # 최소 버전 지원 확인
        if self._compare_versions(self.spec_version, MINIMUM_SUPPORTED_VERSION) < 0:
            self._add_error(
                'CDX_SEMANTIC_DOC_VERSION_UNSUPPORTED',
                f'CycloneDX v{self.spec_version} is NOT supported',
                'specVersion',
                f'Minimum supported version is v{MINIMUM_SUPPORTED_VERSION}. VEX timestamps require v1.5+'
            )
            return self._build_result()

        # bom-ref 사전 수집 (시맨틱 검증에 필요)
        self._collect_bom_refs()

        # 2단계: 시맨틱 검증 (스키마 검증 완료 전제)
        self._run_semantic_validation()

        return self._build_result()

    # ====================================================================
    # 1단계: 스키마 검증
    # ====================================================================

    def _run_schema_validation(self):
        """
        JSON Schema 기반 구조 검증.
        필수 필드, enum 멤버십, 타입 체크 등 구조적 규칙은 이 단계에서 처리된다.
        """
        if not self.schema:
            return

        if not HAS_JSONSCHEMA:
            self._add_warning(
                'SCHEMA_CDX_SKIP',
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
                    'SCHEMA_CDX_001',
                    f'JSON Schema validation failed: {error.message}',
                    path,
                    f'Schema path: {list(error.schema_path)}'
                )
        except Exception as e:
            self._add_warning(
                'SCHEMA_CDX_ERROR',
                f'Schema validation error: {str(e)}',
                '',
                'Schema validation may be incomplete'
            )

    # ====================================================================
    # 2단계: 시맨틱 검증
    # 스키마 검증이 완료된 상태를 전제로 실행된다.
    # ====================================================================

    def _run_semantic_validation(self):
        """
        CycloneDX 명세에서 도출한 시맨틱 규칙을 버전별로 실행한다.
        조건부 필수, 교차 필드 정합성, 참조 무결성 등을 검사한다.
        """
        # 모든 버전 공통 시맨틱 규칙
        self._validate_bom_identification()
        self._validate_bom_ref_integrity()
        self._validate_vulnerability_semantics()
        self._validate_identifier_semantics()

        # v1.6+ 추가 시맨틱 규칙
        if self._is_version_at_least('1.6'):
            self._validate_v16_semantics()

        # v1.7 전용 시맨틱 규칙
        if self._is_version_at_least('1.7'):
            self._validate_v17_semantics()

    # ====================================================================
    # BOM 식별 및 버전 관리 시맨틱 규칙
    # ====================================================================

    def _validate_bom_identification(self):
        """BOM 식별 관련 시맨틱 규칙"""

        # CDX_SEMANTIC_BOM_SERIAL_PRESENT: serialNumber 포함 권장
        # 명세(SHOULD): "모든 생성된 BOM은 고유한 serialNumber를 포함해야 한다"
        serial = self.data.get('serialNumber')
        if not serial:
            self._add_warning(
                'CDX_SEMANTIC_BOM_SERIAL_PRESENT',
                'serialNumber SHOULD be present for document identification',
                'serialNumber',
                'All generated BOMs SHOULD have a unique serialNumber'
            )
        elif not UUID_V4_PATTERN.match(serial):
            # CDX_SEMANTIC_BOM_SERIAL_FORMAT: serialNumber UUID 형식 권장
            # 명세(SHOULD): "RFC 4122 준수 UUID 형식을 사용해야 한다"
            self._add_warning(
                'CDX_SEMANTIC_BOM_SERIAL_FORMAT',
                'serialNumber SHOULD be in URN UUID format',
                'serialNumber',
                f'Found: {serial}, Expected: urn:uuid:xxxxxxxx-xxxx-4xxx-xxxx-xxxxxxxxxxxx'
            )

        # CDX_SEMANTIC_BOM_VERSION_MINIMUM: version은 1 이상 권장
        # 명세(SHOULD): "기존 BOM 수정 시 version 값을 이전보다 1 증가시켜야 한다"
        version = self.data.get('version', 0)
        if version < 1:
            self._add_warning(
                'CDX_SEMANTIC_BOM_VERSION_MINIMUM',
                'version SHOULD be >= 1',
                'version',
                f'Current version: {version}'
            )

    # ====================================================================
    # bom-ref 참조 무결성 시맨틱 규칙
    # ====================================================================

    def _validate_bom_ref_integrity(self):
        """bom-ref 참조 무결성 관련 시맨틱 규칙"""

        # CDX_SEMANTIC_REF_BOMREF_UNIQUE: bom-ref 고유성 (MUST)
        # 명세(MUST): "BOM 내의 모든 bom-ref 식별자는 문서 전체에서 반드시 유일해야 한다"
        seen_refs = {}

        def check_ref_uniqueness(components: List[Dict], path: str = 'components'):
            for i, comp in enumerate(components):
                if 'bom-ref' in comp:
                    ref = comp['bom-ref']
                    if ref in seen_refs:
                        self._add_error(
                            'CDX_SEMANTIC_REF_BOMREF_UNIQUE',
                            f'Duplicate bom-ref found: {ref}',
                            f'{path}[{i}].bom-ref',
                            f'First defined at: {seen_refs[ref]}'
                        )
                    else:
                        seen_refs[ref] = f'{path}[{i}]'

                    # CDX_SEMANTIC_REF_BOMREF_PREFIX: urn:cdx: 접두사 회피 권장
                    # 명세(SHOULD): "bom-ref 값은 BOM-Link와의 혼동을 피하기 위해
                    #               'urn:cdx:'로 시작하지 않아야 한다"
                    if ref.startswith('urn:cdx:'):
                        self._add_warning(
                            'CDX_SEMANTIC_REF_BOMREF_PREFIX',
                            'bom-ref SHOULD NOT start with urn:cdx: to avoid BOM-Link conflicts',
                            f'{path}[{i}].bom-ref',
                            f'Found: {ref}'
                        )

                if 'components' in comp:
                    check_ref_uniqueness(comp['components'], f'{path}[{i}].components')

        if 'components' in self.data:
            check_ref_uniqueness(self.data['components'])

        # CDX_SEMANTIC_REF_COMPONENT_TYPE: 컴포넌트 유형 분류 권장
        def check_component_type(components: List[Dict], path: str = 'components'):
            for i, comp in enumerate(components):
                comp_type = comp.get('type')
                if not comp_type:
                    self._add_warning(
                        'CDX_SEMANTIC_REF_COMPONENT_TYPE',
                        'Component without type SHOULD be classified as "library" if unclear',
                        f'{path}[{i}]',
                        f'Component: {comp.get("name", "unknown")}'
                    )
                if 'components' in comp:
                    check_component_type(comp['components'], f'{path}[{i}].components')

        if 'components' in self.data:
            check_component_type(self.data['components'])

    # ====================================================================
    # 취약점 시맨틱 규칙
    # ====================================================================

    def _validate_vulnerability_semantics(self):
        """취약점 관련 시맨틱 규칙: 상태 로직, 타임스탬프, 참조 무결성"""

        vulnerabilities = self.data.get('vulnerabilities', [])
        if not vulnerabilities:
            # CDX_SEMANTIC_VEX_NO_VULNERABILITIES: VEX 문서에 취약점 섹션 누락 경고
            self._add_warning(
                'CDX_SEMANTIC_VEX_NO_VULNERABILITIES',
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

            # CDX_SEMANTIC_VULN_ID_REQUIRED: 취약점 식별자 필수 (MUST)
            # 명세(MUST): "각 취약점은 반드시 식별자를 가져야 한다"
            if not vuln.get('id'):
                self._add_error(
                    'CDX_SEMANTIC_VULN_ID_REQUIRED',
                    'Vulnerability MUST have an id field',
                    f'{v_path}.id',
                    'At least one vulnerability identifier is required for machine processing'
                )
            elif not vuln.get('id').strip():
                # CDX_SEMANTIC_VULN_ID_NONEMPTY: 취약점 ID 비어있지 않아야 함 (MUST)
                self._add_error(
                    'CDX_SEMANTIC_VULN_ID_NONEMPTY',
                    'Vulnerability id MUST NOT be empty',
                    f'{v_path}.id',
                    'Empty identifier cannot be processed by automated tools'
                )

            # === 분석 섹션 시맨틱 규칙 ===
            analysis = vuln.get('analysis', {})
            if not analysis:
                # CDX_SEMANTIC_VEX_ANALYSIS_REQUIRED: VEX 문서에 분석 섹션 필수
                # 명세(SHOULD): "VEX 문서는 보고된 취약점이 제품에 미치는 영향에 대한
                #             분석 결과와 발견 사항을 포함해야 한다"
                self._add_warning(
                    'CDX_SEMANTIC_VEX_ANALYSIS_REQUIRED',
                    'VEX vulnerability SHOULD have analysis section',
                    f'{v_path}.analysis',
                    'Analysis section contains VEX status information'
                )
                # 분석 섹션이 없으면 관련 시맨틱 규칙 건너뜀
                self._validate_affects_section(vuln, v_path, vuln_id,
                                               None, referenced_product_ids,
                                               product_status_map)
                continue

            a_path = f'{v_path}.analysis'
            state = analysis.get('state')
            justification = analysis.get('justification')
            detail = analysis.get('detail', '')
            responses = analysis.get('response', [])

            # CDX_SEMANTIC_VEX_STATE_REQUIRED: analysis.state 필수 (MUST)
            if not state:
                self._add_error(
                    'CDX_SEMANTIC_VEX_STATE_REQUIRED',
                    'analysis.state is REQUIRED',
                    f'{a_path}.state',
                    'VEX status must be explicitly declared'
                )
            elif state not in VALID_STATES:
                # CDX_SEMANTIC_VEX_STATE_INVALID: 유효하지 않은 state 값 (MUST)
                self._add_error(
                    'CDX_SEMANTIC_VEX_STATE_INVALID',
                    f'Invalid analysis.state value: {state}',
                    f'{a_path}.state',
                    f'Valid values: {", ".join(VALID_STATES)}'
                )

            # === 상태별 조건부 필수 규칙 ===

            # CDX_SEMANTIC_VEX_NOTAFFECTED_JUSTIFICATION: not_affected → justification 필수
            # v1.7 명세(MUST): "분석 상태를 'not_affected'로 설정할 경우, 반드시
            #                  그 정당성(justification)을 명시해야 한다"
            # v1.5-v1.6: justification 또는 detail 중 하나 필수
            if state == 'not_affected':
                if self._is_version_at_least('1.7'):
                    # v1.7: justification 필수 (MUST)
                    if not justification:
                        self._add_error(
                            'CDX_SEMANTIC_VEX_NOTAFFECTED_JUSTIFICATION',
                            'not_affected status MUST have justification (v1.7 requirement)',
                            f'{a_path}',
                            'CycloneDX v1.7 requires justification for not_affected state'
                        )
                else:
                    # v1.5-v1.6: justification 또는 detail 권고
                    if not justification and not detail:
                        self._add_warning(
                            'CDX_SEMANTIC_VEX_NOTAFFECTED_JUSTIFICATION',
                            'not_affected status SHOULD have justification OR detail (impact statement)',
                            f'{a_path}',
                            'Justification or detail recommended for not_affected'
                        )

                # justification 값 유효성 검사
                if justification and justification not in VALID_JUSTIFICATIONS:
                    self._add_error(
                        'CDX_SEMANTIC_VEX_JUSTIFICATION_INVALID',
                        f'Invalid justification value: {justification}',
                        f'{a_path}.justification',
                        f'Valid values: {", ".join(VALID_JUSTIFICATIONS)}'
                    )

                # CDX_SEMANTIC_VEX_NOTAFFECTED_DETAIL: detail 포함 권장
                # 명세(SHOULD): "취약점이 악용될 수 없는 경우, detail에 구체적인 이유를 포함해야 한다"
                if not detail:
                    self._add_warning(
                        'CDX_SEMANTIC_VEX_NOTAFFECTED_DETAIL',
                        'not_affected status SHOULD have detail explaining why the vulnerability does not impact the component',
                        f'{a_path}.detail',
                        'Per CycloneDX spec: detail should include specific reasons why the component is not impacted'
                    )

                # CDX_SEMANTIC_VEX_NOTAFFECTED_JUSTIFICATION_DETAIL: justification과 함께 detail 권장
                if justification and not detail:
                    self._add_warning(
                        'CDX_SEMANTIC_VEX_NOTAFFECTED_JUSTIFICATION_DETAIL',
                        'not_affected with justification SHOULD include detail for technical specifics',
                        f'{a_path}.detail',
                        'detail field provides human-readable explanation'
                    )

            # CDX_SEMANTIC_VEX_EXPLOITABLE_RESPONSE: exploitable → response 권장
            # 명세(SHOULD): "분석 상태가 'exploitable'인 경우, 반드시 그에 대한
            #               대응 조치(response)를 포함할 것이 강력히 권장된다"
            if state == 'exploitable' and not responses:
                self._add_warning(
                    'CDX_SEMANTIC_VEX_EXPLOITABLE_RESPONSE',
                    'exploitable status SHOULD have response (strongly encouraged)',
                    f'{a_path}.response',
                    'Vendor/supplier response is strongly recommended for exploitable vulnerabilities'
                )

            # response 값 유효성 검사
            if responses:
                for r_idx, resp in enumerate(responses):
                    if resp not in VALID_RESPONSES:
                        self._add_warning(
                            'CDX_SEMANTIC_VEX_RESPONSE_INVALID',
                            f'Invalid response value: {resp}',
                            f'{a_path}.response[{r_idx}]',
                            f'Valid values: {", ".join(VALID_RESPONSES)}'
                        )

            # === 타임스탬프 시맨틱 규칙 ===
            self._validate_analysis_timestamps(analysis, a_path)

            # === Affects 섹션 시맨틱 규칙 ===
            self._validate_affects_section(vuln, v_path, vuln_id,
                                           state, referenced_product_ids,
                                           product_status_map)

        # === 교차 취약점 시맨틱 규칙 ===

        # CDX_SEMANTIC_VEX_STATUS_DISJOINT: 제품 상태 분리성 (MUST)
        # 명세(MUST): 동일 제품이 상호 배타적인 상태에 동시에 있을 수 없다
        for vid, products in product_status_map.items():
            for product_id, states in products.items():
                if len(states) > 1:
                    unique_states = set(states)
                    for s1 in unique_states:
                        for s2 in CONFLICTING_STATES.get(s1, []):
                            if s2 in unique_states:
                                self._add_error(
                                    'CDX_SEMANTIC_VEX_STATUS_DISJOINT',
                                    f'Product {product_id} has conflicting states: {s1} and {s2}',
                                    f'vulnerability[id={vid}]',
                                    'Same product cannot be in mutually exclusive status groups'
                                )

    def _validate_analysis_timestamps(self, analysis: Dict, a_path: str):
        """분석 섹션 타임스탬프 시맨틱 규칙"""
        first_issued = analysis.get('firstIssued')
        last_updated = analysis.get('lastUpdated')

        # CDX_SEMANTIC_TS_FIRSTISSUED_PRESENT: firstIssued 포함 권장
        if not first_issued:
            self._add_warning(
                'CDX_SEMANTIC_TS_FIRSTISSUED_PRESENT',
                'analysis.firstIssued SHOULD be present',
                f'{a_path}.firstIssued',
                'VEX statements with timestamps enable better correlation'
            )
        elif not self._is_valid_iso8601(first_issued):
            # CDX_SEMANTIC_TS_FIRSTISSUED_FORMAT: firstIssued ISO 8601 형식 (MUST)
            self._add_error(
                'CDX_SEMANTIC_TS_FIRSTISSUED_FORMAT',
                'firstIssued MUST be valid ISO 8601 format',
                f'{a_path}.firstIssued',
                f'Invalid format: {first_issued}'
            )

        # CDX_SEMANTIC_TS_LASTUPDATED_PRESENT: lastUpdated 포함 권장
        if not last_updated:
            self._add_warning(
                'CDX_SEMANTIC_TS_LASTUPDATED_PRESENT',
                'analysis.lastUpdated SHOULD be present',
                f'{a_path}.lastUpdated',
                'VEX statements should track when they were last updated'
            )
        elif not self._is_valid_iso8601(last_updated):
            # CDX_SEMANTIC_TS_LASTUPDATED_FORMAT: lastUpdated ISO 8601 형식 (MUST)
            self._add_error(
                'CDX_SEMANTIC_TS_LASTUPDATED_FORMAT',
                'lastUpdated MUST be valid ISO 8601 format',
                f'{a_path}.lastUpdated',
                f'Invalid format: {last_updated}'
            )

        # CDX_SEMANTIC_TS_ORDER_CONSISTENCY: firstIssued <= lastUpdated (MUST)
        if first_issued and last_updated:
            fi_dt = self._parse_timestamp(first_issued)
            lu_dt = self._parse_timestamp(last_updated)
            if fi_dt and lu_dt and fi_dt > lu_dt:
                self._add_error(
                    'CDX_SEMANTIC_TS_ORDER_CONSISTENCY',
                    'firstIssued cannot be later than lastUpdated',
                    f'{a_path}',
                    f'firstIssued: {first_issued}, lastUpdated: {last_updated}'
                )

    def _validate_affects_section(self, vuln: Dict, v_path: str,
                                  vuln_id: str, state: Optional[str],
                                  referenced_product_ids: set,
                                  product_status_map: Dict):
        """affects 섹션 시맨틱 규칙: 참조 무결성, 버전 검증"""

        affects = vuln.get('affects', [])
        if not affects:
            # CDX_SEMANTIC_VEX_AFFECTS_REQUIRED: affects 필수 (MUST)
            # 명세(MUST): "VEX는 어떤 제품/컴포넌트가 영향을 받는지 명시해야 한다"
            self._add_error(
                'CDX_SEMANTIC_VEX_AFFECTS_REQUIRED',
                'vulnerability.affects is REQUIRED and MUST NOT be empty',
                f'{v_path}.affects',
                'VEX must specify which products/components are affected'
            )

        for a_idx, affect in enumerate(affects):
            af_path = f'{v_path}.affects[{a_idx}]'
            ref = affect.get('ref')

            # CDX_SEMANTIC_REF_AFFECTS_REF_REQUIRED: affects[].ref 필수 (MUST)
            if not ref:
                self._add_error(
                    'CDX_SEMANTIC_REF_AFFECTS_REF_REQUIRED',
                    'affects[].ref is REQUIRED',
                    f'{af_path}.ref',
                    'Product reference must be specified'
                )
            elif not ref.strip():
                # CDX_SEMANTIC_REF_AFFECTS_REF_NONEMPTY: affects[].ref 비어있지 않아야 함 (MUST)
                self._add_error(
                    'CDX_SEMANTIC_REF_AFFECTS_REF_NONEMPTY',
                    'affects[].ref MUST NOT be empty',
                    f'{af_path}.ref',
                    'Empty reference cannot identify product'
                )
            else:
                referenced_product_ids.add(ref)

                # 제품 상태 추적 (분리성 검사용)
                if vuln_id not in product_status_map:
                    product_status_map[vuln_id] = {}
                if ref not in product_status_map[vuln_id]:
                    product_status_map[vuln_id][ref] = []
                if state:
                    product_status_map[vuln_id][ref].append(state)

                # CDX_SEMANTIC_REF_AFFECTS_INTEGRITY: 참조 무결성 (MUST)
                # 명세(MUST): "affects[].ref가 참조하는 bom-ref는 반드시 components에 정의되어 있어야 한다"
                if ref.startswith('urn:cdx:'):
                    if not self._is_valid_bomlink_format(ref):
                        self._add_error(
                            'CDX_SEMANTIC_REF_AFFECTS_INVALID_URN',
                            f'affects[].ref is not a valid BOM-Link URN: {ref}',
                            f'{af_path}.ref',
                            'BOM-Link references must follow the CycloneDX URN format'
                        )
                    else:
                        parsed = self._parse_bomlink(ref)
                        if not parsed:
                            self._add_error(
                                'CDX_SEMANTIC_REF_AFFECTS_INVALID_URN',
                                f'affects[].ref is not a valid BOM-Link URN: {ref}',
                                f'{af_path}.ref',
                                'BOM-Link references must follow the CycloneDX URN format'
                            )
                        else:
                            serial = self.data.get('serialNumber', '')
                            bom_version = self.data.get('version')

                            if (
                                parsed["serial"] == serial and
                                str(parsed["version"]) == str(bom_version) and
                                parsed["bom_ref"] and
                                parsed["bom_ref"] not in self.defined_product_ids
                            ):
                                self._add_error(
                                    'CDX_SEMANTIC_REF_AFFECTS_INTEGRITY',
                                    f'affects[].ref references undefined local bom-ref via BOM-Link: {ref}',
                                    f'{af_path}.ref',
                                    'BOM-Link to the same BOM must resolve to a defined bom-ref'
                                )
                else:
                    if ref not in self.defined_product_ids:
                        self._add_error(
                            'CDX_SEMANTIC_REF_AFFECTS_INTEGRITY',
                            f'affects[].ref references undefined local bom-ref: {ref}',
                            f'{af_path}.ref',
                            'Local references MUST point to a component/service defined in the same BOM'
                        )

            # 버전 항목 시맨틱 규칙
            versions = affect.get('versions', [])
            for ver_idx, ver in enumerate(versions):
                ver_path = f'{af_path}.versions[{ver_idx}]'

                # CDX_SEMANTIC_VER_ENTRY_REQUIRED: version 또는 range 필수 (MUST)
                if not ver.get('version') and not ver.get('range'):
                    self._add_error(
                        'CDX_SEMANTIC_VER_ENTRY_REQUIRED',
                        'versions entry MUST have version OR range',
                        ver_path,
                        'At least one of version or range must be specified'
                    )

                # CDX_SEMANTIC_VER_STATUS_INVALID: version.status 유효성 (MUST)
                ver_status = ver.get('status')
                if ver_status and ver_status not in VALID_VERSION_STATUS:
                    self._add_error(
                        'CDX_SEMANTIC_VER_STATUS_INVALID',
                        f'Invalid version status: {ver_status}',
                        f'{ver_path}.status',
                        f'Valid values: {", ".join(VALID_VERSION_STATUS)}'
                    )

                # CDX_SEMANTIC_VER_MUTUAL_EXCLUSION: version과 range 동시 존재 금지
                # 명세(MUST): "version과 versionRange가 동시에 존재하지 않도록 논리적으로 체크해야 한다"
                if ver.get('version') and ver.get('range'):
                    self._add_error(
                        'CDX_SEMANTIC_VER_MUTUAL_EXCLUSION',
                        'versions entry MUST NOT have both version AND range simultaneously',
                        ver_path,
                        'version and range are mutually exclusive fields'
                    )

    # ====================================================================
    # 식별자 시맨틱 규칙 (PURL/CPE)
    # ====================================================================

    def _validate_identifier_semantics(self):
        """PURL/CPE 식별자 시맨틱 규칙"""

        def validate_identifiers(components: List[Dict], path: str = 'components'):
            for i, comp in enumerate(components):
                purl = comp.get('purl')
                if purl:
                    # CDX_SEMANTIC_ID_PURL_FORMAT: PURL 형식 검증 (MUST)
                    if not PURL_PATTERN.match(purl):
                        self._add_error(
                            'CDX_SEMANTIC_ID_PURL_FORMAT',
                            f'Invalid PURL format: {purl}',
                            f'{path}[{i}].purl',
                            'PURL must match pattern: pkg:type/...'
                        )
                    elif '/' in purl:
                        # CDX_SEMANTIC_ID_PURL_NAME: PURL에 이름 컴포넌트 권장
                        parts = purl.split('/')
                        if len(parts) < 2 or not parts[1].split('@')[0].split('?')[0]:
                            self._add_warning(
                                'CDX_SEMANTIC_ID_PURL_NAME',
                                'PURL should have name component',
                                f'{path}[{i}].purl',
                                f'PURL: {purl}'
                            )

                cpe = comp.get('cpe')
                if cpe:
                    # CDX_SEMANTIC_ID_CPE_FORMAT: CPE 형식 검증 (MUST)
                    if not cpe.startswith('cpe:'):
                        self._add_error(
                            'CDX_SEMANTIC_ID_CPE_FORMAT',
                            f'Invalid CPE format: {cpe}',
                            f'{path}[{i}].cpe',
                            'CPE must start with "cpe:"'
                        )

                if 'components' in comp:
                    validate_identifiers(comp['components'], f'{path}[{i}].components')

        if 'components' in self.data:
            validate_identifiers(self.data['components'])

    # ====================================================================
    # v1.6+ 시맨틱 규칙
    # ====================================================================

    def _validate_v16_semantics(self):
        """v1.6+ 전용 시맨틱 규칙"""

        vulnerabilities = self.data.get('vulnerabilities', [])

        for v_idx, vuln in enumerate(vulnerabilities):
            v_path = f'vulnerabilities[{v_idx}]'

            # CDX_SEMANTIC_V16_RATINGS_RECOMMENDED: 취약점 등급 포함 권장
            # 명세(SHOULD): "취약점 우선순위 결정을 위해 ratings를 포함해야 한다"
            ratings = vuln.get('ratings', [])
            if not ratings:
                self._add_warning(
                    'CDX_SEMANTIC_V16_RATINGS_RECOMMENDED',
                    'vulnerability ratings SHOULD be provided for prioritization',
                    f'{v_path}.ratings',
                    'Ratings help determine vulnerability priority'
                )

        # CDX_SEMANTIC_V16_EVIDENCE_ARRAY: evidence.identity 배열 형식 권장
        # 명세(RECOMMENDED): "identity 근거 작성 시 단일 객체보다 배열 형태를 사용할 것을 권장한다"
        def check_evidence(components: List[Dict], path: str = 'components'):
            for i, comp in enumerate(components):
                evidence = comp.get('evidence', {})
                identity = evidence.get('identity')

                if identity and not isinstance(identity, list):
                    self._add_warning(
                        'CDX_SEMANTIC_V16_EVIDENCE_ARRAY',
                        'evidence.identity SHOULD be an array of Identity Objects',
                        f'{path}[{i}].evidence.identity',
                        'Array format is recommended over single object for v1.6+'
                    )

                if 'components' in comp:
                    check_evidence(comp['components'], f'{path}[{i}].components')

        if 'components' in self.data:
            check_evidence(self.data['components'])

    # ====================================================================
    # v1.7 전용 시맨틱 규칙
    # ====================================================================

    def _validate_v17_semantics(self):
        """v1.7 전용 시맨틱 규칙"""

        def check_v17_components(components: List[Dict], path: str = 'components'):
            for i, comp in enumerate(components):
                comp_type = comp.get('type')
                comp_path = f'{path}[{i}]'

                # CDX_SEMANTIC_V17_MODELCARD_RECOMMENDED: ML 모델 → modelCard 권장
                # 명세(SHOULD): "머신러닝 모델 타입 컴포넌트의 경우 투명성 확보를 위해
                #               반드시 modelCard를 작성해야 한다"
                if comp_type == 'machine-learning-model':
                    if not comp.get('modelCard'):
                        self._add_warning(
                            'CDX_SEMANTIC_V17_MODELCARD_RECOMMENDED',
                            'machine-learning-model component SHOULD have modelCard object',
                            f'{comp_path}.modelCard',
                            'modelCard should describe model limitations and ethical considerations'
                        )

                # CDX_SEMANTIC_V17_MODELCARD_RESTRICTION: 비ML 컴포넌트에 modelCard 금지
                # 명세(MUST): "컴포넌트 타입이 machine-learning-model이 아닌 경우
                #             modelCard 객체를 정의해서는 안 된다"
                if comp_type != 'machine-learning-model' and comp.get('modelCard'):
                    self._add_error(
                        'CDX_SEMANTIC_V17_MODELCARD_RESTRICTION',
                        'modelCard MUST NOT be defined for non machine-learning-model components',
                        f'{comp_path}.modelCard',
                        f'Component type is "{comp_type}", modelCard is only valid for machine-learning-model'
                    )

                # CDX_SEMANTIC_V17_DATA_RECOMMENDED: data 컴포넌트 → data 객체 권장
                if comp_type == 'data':
                    if not comp.get('data'):
                        self._add_warning(
                            'CDX_SEMANTIC_V17_DATA_RECOMMENDED',
                            'data component SHOULD have data object',
                            f'{comp_path}.data',
                            'data object should describe data classification and governance'
                        )

                if 'components' in comp:
                    check_v17_components(comp['components'], f'{comp_path}.components')

        if 'components' in self.data:
            check_v17_components(self.data['components'])

        # CDX_SEMANTIC_V17_TLP_RECOMMENDED: TLP 분류 권장
        metadata = self.data.get('metadata', {})
        dist_constraints = metadata.get('distributionConstraints', {})
        tlp = dist_constraints.get('tlp')

        if not tlp:
            self._add_warning(
                'CDX_SEMANTIC_V17_TLP_RECOMMENDED',
                'TLP classification (distributionConstraints.tlp) is recommended for v1.7',
                'metadata.distributionConstraints.tlp',
                'TLP classification enables automated sharing control'
            )

    # ====================================================================
    # 결과 생성
    # ====================================================================

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


# ========================================================================
# 공개 검증 인터페이스
# ========================================================================

def validate_cyclonedx(data: Dict[str, Any], schema: Optional[Dict] = None,
                       doc_version: str = '') -> Tuple[bool, List[Dict], str]:
    """
    CycloneDX VEX validation entry point.

    Args:
        data: Document data to validate
        schema: Loaded JSON Schema dictionary (not path)
        doc_version: Detected document version

    Returns:
        (is_valid, errors_list, detected_version)
    """
    validator = CycloneDXValidator(data, schema)
    result = validator.validate()

    # app.py 호환성을 위해 오류와 경고 결합
    all_issues = result['errors'] + result['warnings']

    return (result['valid'], all_issues, result['version'])


# ========================================================================
# UI용 규칙 문서 (통합 네이밍)
# ========================================================================

VALIDATION_RULES = {
    'schema': [
        {'id': 'SCHEMA_CDX_001', 'severity': 'error',
         'desc': '[Schema] JSON Schema validation failed'},
    ],
    'must': [
        {'id': 'CDX_SEMANTIC_DOC_VERSION_UNSUPPORTED', 'severity': 'error',
         'desc': '[MUST] CycloneDX v1.4 and below NOT supported - minimum v1.5 required'},
        {'id': 'CDX_SEMANTIC_REF_BOMREF_UNIQUE', 'severity': 'error',
         'desc': '[MUST] bom-ref values MUST be unique within the document'},
        {'id': 'CDX_SEMANTIC_VEX_STATE_REQUIRED', 'severity': 'error',
         'desc': '[MUST] analysis.state is REQUIRED'},
        {'id': 'CDX_SEMANTIC_VEX_STATE_INVALID', 'severity': 'error',
         'desc': '[MUST] analysis.state MUST be a valid enum value'},
        {'id': 'CDX_SEMANTIC_VEX_NOTAFFECTED_JUSTIFICATION', 'severity': 'error',
         'desc': '[v1.7 MUST] not_affected status requires justification'},
        {'id': 'CDX_SEMANTIC_VEX_JUSTIFICATION_INVALID', 'severity': 'error',
         'desc': '[MUST] analysis.justification MUST be a valid enum value'},
        {'id': 'CDX_SEMANTIC_VEX_AFFECTS_REQUIRED', 'severity': 'error',
         'desc': '[MUST] vulnerability.affects is REQUIRED and MUST NOT be empty'},
        {'id': 'CDX_SEMANTIC_REF_AFFECTS_REF_REQUIRED', 'severity': 'error',
         'desc': '[MUST] affects[].ref is REQUIRED'},
        {'id': 'CDX_SEMANTIC_REF_AFFECTS_REF_NONEMPTY', 'severity': 'error',
         'desc': '[MUST] affects[].ref MUST NOT be empty'},
        {'id': 'CDX_SEMANTIC_REF_AFFECTS_INVALID_URN', 'severity': 'error',
         'desc': '[MUST] affects[].ref BOM-Link URN MUST match CycloneDX format'},
        {'id': 'CDX_SEMANTIC_REF_AFFECTS_INTEGRITY', 'severity': 'error',
         'desc': '[MUST] affects[].ref MUST reference a defined bom-ref'},
        {'id': 'CDX_SEMANTIC_VEX_STATUS_DISJOINT', 'severity': 'error',
         'desc': '[MUST] Same product cannot have conflicting analysis states'},
        {'id': 'CDX_SEMANTIC_VULN_ID_REQUIRED', 'severity': 'error',
         'desc': '[MUST] Vulnerability MUST have an id field'},
        {'id': 'CDX_SEMANTIC_VULN_ID_NONEMPTY', 'severity': 'error',
         'desc': '[MUST] Vulnerability id MUST NOT be empty'},
        {'id': 'CDX_SEMANTIC_TS_FIRSTISSUED_FORMAT', 'severity': 'error',
         'desc': '[MUST] firstIssued MUST be valid ISO 8601 format'},
        {'id': 'CDX_SEMANTIC_TS_LASTUPDATED_FORMAT', 'severity': 'error',
         'desc': '[MUST] lastUpdated MUST be valid ISO 8601 format'},
        {'id': 'CDX_SEMANTIC_TS_ORDER_CONSISTENCY', 'severity': 'error',
         'desc': '[MUST] firstIssued cannot be later than lastUpdated'},
        {'id': 'CDX_SEMANTIC_VER_ENTRY_REQUIRED', 'severity': 'error',
         'desc': '[MUST] versions entry MUST have version OR range'},
        {'id': 'CDX_SEMANTIC_VER_STATUS_INVALID', 'severity': 'error',
         'desc': '[MUST] version.status MUST be a valid enum value'},
        {'id': 'CDX_SEMANTIC_VER_MUTUAL_EXCLUSION', 'severity': 'error',
         'desc': '[MUST] version and range MUST NOT coexist in the same entry'},
        {'id': 'CDX_SEMANTIC_ID_PURL_FORMAT', 'severity': 'error',
         'desc': '[MUST] PURL must match valid format (pkg:type/...)'},
        {'id': 'CDX_SEMANTIC_ID_CPE_FORMAT', 'severity': 'error',
         'desc': '[MUST] CPE must start with "cpe:"'},
        {'id': 'CDX_SEMANTIC_V17_MODELCARD_RESTRICTION', 'severity': 'error',
         'desc': '[v1.7 MUST] modelCard MUST NOT be defined for non ML model components'},
    ],
    'should': [
        {'id': 'CDX_SEMANTIC_VEX_ANALYSIS_REQUIRED', 'severity': 'warning',
         'desc': '[SHOULD] VEX vulnerability SHOULD have analysis section'},
        
        {'id': 'CDX_SEMANTIC_BOM_SERIAL_PRESENT', 'severity': 'warning',
         'desc': '[SHOULD] serialNumber SHOULD be present for document identification'},
        {'id': 'CDX_SEMANTIC_VEX_NOTAFFECTED_JUSTIFICATION', 'severity': 'warning',
         'desc': '[v1.5-v1.6 SHOULD] not_affected status should have justification or detail'},
        {'id': 'CDX_SEMANTIC_BOM_SERIAL_FORMAT', 'severity': 'warning',
         'desc': '[SHOULD] serialNumber SHOULD be in URN UUID format'},
        {'id': 'CDX_SEMANTIC_BOM_VERSION_MINIMUM', 'severity': 'warning',
         'desc': '[SHOULD] version SHOULD be >= 1'},
        {'id': 'CDX_SEMANTIC_REF_BOMREF_PREFIX', 'severity': 'warning',
         'desc': '[SHOULD] bom-ref SHOULD NOT start with urn:cdx: (BOM-Link conflict)'},
        {'id': 'CDX_SEMANTIC_REF_COMPONENT_TYPE', 'severity': 'warning',
         'desc': '[SHOULD] Component SHOULD have a type classification'},
        {'id': 'CDX_SEMANTIC_VEX_NOTAFFECTED_DETAIL', 'severity': 'warning',
         'desc': '[SHOULD] not_affected SHOULD have detail explaining non-impact'},
        {'id': 'CDX_SEMANTIC_VEX_NOTAFFECTED_JUSTIFICATION_DETAIL', 'severity': 'warning',
         'desc': '[SHOULD] not_affected with justification SHOULD include detail'},
        {'id': 'CDX_SEMANTIC_VEX_EXPLOITABLE_RESPONSE', 'severity': 'warning',
         'desc': '[SHOULD] exploitable status SHOULD have response'},
        {'id': 'CDX_SEMANTIC_VEX_RESPONSE_INVALID', 'severity': 'warning',
         'desc': '[SHOULD] analysis.response SHOULD be valid enum values'},
        {'id': 'CDX_SEMANTIC_TS_FIRSTISSUED_PRESENT', 'severity': 'warning',
         'desc': '[SHOULD] analysis.firstIssued SHOULD be present'},
        {'id': 'CDX_SEMANTIC_TS_LASTUPDATED_PRESENT', 'severity': 'warning',
         'desc': '[SHOULD] analysis.lastUpdated SHOULD be present'},
        {'id': 'CDX_SEMANTIC_ID_PURL_NAME', 'severity': 'warning',
         'desc': '[SHOULD] PURL SHOULD have name component'},
        {'id': 'CDX_SEMANTIC_V16_RATINGS_RECOMMENDED', 'severity': 'warning',
         'desc': '[v1.6+ SHOULD] vulnerability ratings SHOULD be provided'},
        {'id': 'CDX_SEMANTIC_V16_EVIDENCE_ARRAY', 'severity': 'warning',
         'desc': '[v1.6+ RECOMMENDED] evidence.identity SHOULD be an array'},
        {'id': 'CDX_SEMANTIC_V17_MODELCARD_RECOMMENDED', 'severity': 'warning',
         'desc': '[v1.7 SHOULD] machine-learning-model SHOULD have modelCard'},
        {'id': 'CDX_SEMANTIC_V17_DATA_RECOMMENDED', 'severity': 'warning',
         'desc': '[v1.7 SHOULD] data component SHOULD have data object'},
        {'id': 'CDX_SEMANTIC_V17_TLP_RECOMMENDED', 'severity': 'warning',
         'desc': '[v1.7 RECOMMENDED] TLP classification recommended'},
    ]
}
