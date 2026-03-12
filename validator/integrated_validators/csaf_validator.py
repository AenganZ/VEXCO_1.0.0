"""
CSAF VEX 프로필 시맨틱 검증기 v2.0
CSAF 2.0/2.1 필수 테스트(6.1.1-6.1.55) 및 프로필 테스트(6.1.27.1-6.1.27.19)

검증 흐름:
  1단계: JSON 스키마 검증(구조적)
  2단계: 시맨틱 검증
    - 일반 필수 테스트 (6.1.1-6.1.33 공통, 6.1.34-6.1.55 v2.1)
    - 프로필 테스트 (6.1.27.1-6.1.27.19)

네이밍 규칙:
  스키마 규칙   : SCHEMA_CSAF_{NNN}
  시맨틱 MUST   : CSAF_SEMANTIC_{CATEGORY}_{DESCRIPTION}  (severity=error)
  시맨틱 SHOULD : CSAF_SEMANTIC_{CATEGORY}_{DESCRIPTION}  (severity=warning)

버전 처리:
  [v2.0], [v2.1] 태그는 버전별 동작을 의미한다.
  테스트 6.1.34-6.1.55 및 6.1.27.12-6.1.27.19는 v2.1 전용이다.
  일부 공통 테스트(6.1.1, 6.1.4, 6.1.7, 6.1.8, 6.1.11, 6.1.13 등)는
  내부적으로 버전 게이팅된 경로 또는 로직을 가짐
"""

import re
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Set, Tuple

try:
    import jsonschema
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False

# 외부 데이터 헬퍼 (CVSS 계산, CWE 검증, SSVC Decision Points)
try:
    from vexco_external import CVSSHelper, CWEHelper, SSVCHelper
    HAS_EXTERNAL_HELPERS = True
except ImportError:
    HAS_EXTERNAL_HELPERS = False

# PURL 패턴
PURL_PATTERN = re.compile(r'^pkg:[a-z]+/.+')

# VEX Justification 라벨 (6.1.33)
VEX_JUSTIFICATION_LABELS = {
    'component_not_present', 'vulnerable_code_not_present',
    'vulnerable_code_cannot_be_controlled_by_adversary',
    'vulnerable_code_not_in_execute_path', 'inline_mitigations_already_exist'
}

# VEX 프로필 필수 상태 필드
VEX_STATUS_FIELDS = ['fixed', 'known_affected', 'known_not_affected', 'under_investigation']

# 상태 모순 그룹
AFFECTED_FIELDS = ['first_affected', 'known_affected', 'last_affected']
NOT_AFFECTED_FIELDS = ['known_not_affected']
FIXED_FIELDS = ['first_fixed', 'fixed']
UNDER_INVESTIGATION_FIELDS = ['under_investigation']

# 모든 product_status 필드
ALL_STATUS_FIELDS = [
    'fixed', 'known_affected', 'known_not_affected', 'under_investigation',
    'first_affected', 'first_fixed', 'last_affected', 'recommended'
]

# 6.1.26 금지 카테고리 스킵 대상
CSAF_20_SKIP_CATEGORIES = {
    'csaf_base', 'csaf_security_incident_response',
    'csaf_informational_advisory', 'csaf_security_advisory', 'csaf_vex'
}
CSAF_21_SKIP_CATEGORIES = CSAF_20_SKIP_CATEGORIES | {
    'csaf_deprecated_security_advisory', 'csaf_withdrawn', 'csaf_superseded'
}

# 6.1.26 프로필 이름 (정규화 후 비교용)
PROFILE_NAMES_NORMALIZED = {
    'securityincidentresponse', 'informationaladvisory',
    'securityadvisory', 'vex'
}
PROFILE_NAMES_21_NORMALIZED = PROFILE_NAMES_NORMALIZED | {
    'deprecatedsecurityadvisory', 'withdrawn', 'superseded'
}

# 6.1.31 금지 키워드
VERSION_RANGE_OPERATORS = ['<=', '>=', '<', '>']
VERSION_RANGE_KEYWORDS = {'after', 'all', 'before', 'earlier', 'later', 'prior', 'versions'}

# 6.1.35 모순 조치 쌍
REMEDIATION_CONTRADICTING_PAIRS = [
    ('no_fix_planned', 'vendor_fix'), ('no_fix_planned', 'fix_planned'),
    ('none_available', 'vendor_fix'),
]

# RFC 3339 날짜시간 패턴
DATETIME_PATTERN = re.compile(
    r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$'
)

# 버전 패턴
SEMVER_PATTERN = re.compile(r'^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?(\+[a-zA-Z0-9.]+)?$')
INTEGER_VERSION_PATTERN = re.compile(r'^\d+$')

# UUID 상수
MAX_UUID = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
NIL_UUID = '00000000-0000-0000-0000-000000000000'


class CSAFValidator:
    """CSAF 2.0/2.1 검증기 - 전체 Mandatory Tests 포함"""

    VERSION = "2.1.0"

    def __init__(self, data: Dict[str, Any], schema: Optional[Dict] = None):
        self.data = data
        self.schema = schema
        self.errors: List[Dict[str, Any]] = []
        self.doc_version = self._detect_version()
        self.category = self._detect_category()
        self.defined_product_ids: Set[str] = set()
        self.defined_group_ids: Set[str] = set()
        self.product_id_locations: Dict[str, List[str]] = {}
        self.group_id_locations: Dict[str, List[str]] = {}

    def _detect_version(self) -> str:
        return self.data.get('document', {}).get('csaf_version', '2.0')

    def _is_v21(self) -> bool:
        try:
            parts = self.doc_version.split('.')
            return int(parts[0]) >= 2 and int(parts[1]) >= 1
        except (IndexError, ValueError):
            return False

    def _detect_category(self) -> str:
        return self.data.get('document', {}).get('category', '').lower()

    def _add_error(self, rule_id, message, path, detail=''):
        self.errors.append({'rule_id': rule_id, 'severity': 'error',
                            'message': message, 'path': path, 'detail': detail})

    def _add_warning(self, rule_id, message, path, detail=''):
        self.errors.append({'rule_id': rule_id, 'severity': 'warning',
                            'message': message, 'path': path, 'detail': detail})

    def _parse_dt(self, ts):
        # ISO 8601 파싱 (타임존 인식)
        if not isinstance(ts, str):
            return None
        try:
            s = ts
            if s.endswith('Z'):
                s = s[:-1] + '+00:00'
            return datetime.fromisoformat(s)
        except Exception:
            return None

    def _get_tracking(self):
        return self.data.get('document', {}).get('tracking', {})

    def _get_revision_history_sorted(self):
        # 날짜+번호 오름차순 정렬
        rh = list(self._get_tracking().get('revision_history', []))
        def sk(item):
            dt = self._parse_dt(item.get('date', ''))
            return (dt or datetime.min.replace(tzinfo=timezone.utc), item.get('number', ''))
        rh.sort(key=sk)
        return rh

    def _get_newest_revision_date(self):
        rh = self._get_revision_history_sorted()
        return self._parse_dt(rh[-1].get('date', '')) if rh else None

    def _compare_version_strings(self, a, b):
        try:
            if INTEGER_VERSION_PATTERN.match(a) and INTEGER_VERSION_PATTERN.match(b):
                return (int(a) > int(b)) - (int(a) < int(b))
            pa = [int(x) for x in a.split('-')[0].split('+')[0].split('.')]
            pb = [int(x) for x in b.split('-')[0].split('+')[0].split('.')]
            return (pa > pb) - (pa < pb)
        except (ValueError, IndexError):
            return 0

    # ====================================================================
    # 메인 검증
    # ====================================================================
    def validate(self) -> Dict[str, Any]:
        self._run_schema_validation()
        self._collect_product_ids()
        self._collect_group_ids()
        self._run_semantic_validation()
        return self._build_result()

    def _run_schema_validation(self):
        if not self.schema or not HAS_JSONSCHEMA:
            return
        try:
            v = jsonschema.Draft7Validator(self.schema)
            for err in sorted(v.iter_errors(self.data), key=lambda e: e.path):
                path = "/" + "/".join(str(p) for p in err.path) if err.path else "/"
                self._add_error('SCHEMA_CSAF_001',
                                f'JSON Schema validation failed: {err.message}', path)
        except Exception as e:
            self._add_error('SCHEMA_CSAF_000', f'Schema validation error: {str(e)}', '/')

    def _collect_product_ids(self):
        pt = self.data.get('product_tree', {})
        def walk(branches, pp):
            for idx, b in enumerate(branches or []):
                bp = f'{pp}[{idx}]'
                prod = b.get('product', {})
                if prod and 'product_id' in prod:
                    pid = prod['product_id']
                    self.defined_product_ids.add(pid)
                    self.product_id_locations.setdefault(pid, []).append(f'{bp}/product/product_id')
                if 'branches' in b:
                    walk(b['branches'], f'{bp}/branches')
        walk(pt.get('branches', []), '/product_tree/branches')
        for idx, fpn in enumerate(pt.get('full_product_names', [])):
            if 'product_id' in fpn:
                pid = fpn['product_id']
                self.defined_product_ids.add(pid)
                self.product_id_locations.setdefault(pid, []).append(f'/product_tree/full_product_names[{idx}]/product_id')
        for idx, rel in enumerate(pt.get('relationships', [])):
            fpn = rel.get('full_product_name', {})
            if 'product_id' in fpn:
                pid = fpn['product_id']
                self.defined_product_ids.add(pid)
                self.product_id_locations.setdefault(pid, []).append(f'/product_tree/relationships[{idx}]/full_product_name/product_id')

    def _collect_group_ids(self):
        pt = self.data.get('product_tree', {})
        for idx, g in enumerate(pt.get('product_groups', [])):
            if 'group_id' in g:
                gid = g['group_id']
                self.defined_group_ids.add(gid)
                self.group_id_locations.setdefault(gid, []).append(f'/product_tree/product_groups[{idx}]/group_id')

    def _run_semantic_validation(self):
        # 6.1.1~6.1.33 공통
        for i in range(1, 34):
            fn = getattr(self, f'_test_6_1_{i}', None)
            if fn:
                fn()
        # 6.1.34~6.1.55 v2.1 전용
        if self._is_v21():
            for i in range(34, 56):
                fn = getattr(self, f'_test_6_1_{i}', None)
                if fn:
                    fn()

    # ====================================================================
    # 6.1.1 Missing Definition of Product ID
    # ====================================================================
    def _test_6_1_1(self):
        pt = self.data.get('product_tree', {})
        vulns = self.data.get('vulnerabilities', [])
        doc = self.data.get('document', {})
        R = 'CSAF_SEMANTIC_REF_PRODUCT_ID_DEFINED'

        def chk(pid, path):
            if pid not in self.defined_product_ids:
                self._add_error(R, f'Product ID "{pid}" not defined in product_tree', path)
        def chk_list(items, path):
            for i, pid in enumerate(items or []):
                chk(pid, f'{path}[{i}]')

        for g_idx, g in enumerate(pt.get('product_groups', [])):
            chk_list(g.get('product_ids', []), f'/product_tree/product_groups[{g_idx}]/product_ids')
        for r_idx, rel in enumerate(pt.get('relationships', [])):
            for fld in ['product_reference', 'relates_to_product_reference']:
                pid = rel.get(fld)
                if pid:
                    chk(pid, f'/product_tree/relationships[{r_idx}]/{fld}')
        # [v2.1] document/notes
        if self._is_v21():
            for n_idx, note in enumerate(doc.get('notes', [])):
                chk_list(note.get('product_ids', []), f'/document/notes[{n_idx}]/product_ids')
        for v_idx, vuln in enumerate(vulns):
            vp = f'/vulnerabilities[{v_idx}]'
            ps = vuln.get('product_status', {})
            for fld in ALL_STATUS_FIELDS:
                chk_list(ps.get(fld, []), f'{vp}/product_status/{fld}')
            for r_idx, rem in enumerate(vuln.get('remediations', [])):
                chk_list(rem.get('product_ids', []), f'{vp}/remediations[{r_idx}]/product_ids')
            for t_idx, th in enumerate(vuln.get('threats', [])):
                chk_list(th.get('product_ids', []), f'{vp}/threats[{t_idx}]/product_ids')
            if self._is_v21():
                for m_idx, m in enumerate(vuln.get('metrics', [])):
                    chk_list(m.get('products', []), f'{vp}/metrics[{m_idx}]/products')
                for i_idx, inv in enumerate(vuln.get('involvements', [])):
                    chk_list(inv.get('product_ids', []), f'{vp}/involvements[{i_idx}]/product_ids')
                for f_idx, fl in enumerate(vuln.get('flags', [])):
                    chk_list(fl.get('product_ids', []), f'{vp}/flags[{f_idx}]/product_ids')
                for n_idx, n in enumerate(vuln.get('notes', [])):
                    chk_list(n.get('product_ids', []), f'{vp}/notes[{n_idx}]/product_ids')
            else:
                for s_idx, sc in enumerate(vuln.get('scores', [])):
                    chk_list(sc.get('products', []), f'{vp}/scores[{s_idx}]/products')

    # ====================================================================
    # 6.1.2
    # ====================================================================
    def _test_6_1_2(self):
        for pid, locs in self.product_id_locations.items():
            if len(locs) > 1:
                self._add_error('CSAF_SEMANTIC_REF_PRODUCT_ID_UNIQUE',
                                f'Product ID "{pid}" defined {len(locs)} times', locs[0])

    # ====================================================================
    # 6.1.3
    # ====================================================================
    def _test_6_1_3(self):
        pt = self.data.get('product_tree', {})
        for r_idx, rel in enumerate(pt.get('relationships', [])):
            fpn = rel.get('full_product_name', {})
            new_pid = fpn.get('product_id', '')
            if new_pid and (new_pid == rel.get('product_reference') or new_pid == rel.get('relates_to_product_reference')):
                self._add_error('CSAF_SEMANTIC_REF_PRODUCT_ID_CIRCULAR',
                                f'Product ID "{new_pid}" has circular reference',
                                f'/product_tree/relationships[{r_idx}]/full_product_name/product_id')

    # ====================================================================
    # 6.1.4
    # ====================================================================
    def _test_6_1_4(self):
        vulns = self.data.get('vulnerabilities', [])
        doc = self.data.get('document', {})
        R = 'CSAF_SEMANTIC_REF_GROUP_ID_DEFINED'
        def chk(gid, path):
            if gid not in self.defined_group_ids:
                self._add_error(R, f'Group ID "{gid}" not defined', path)
        def chk_list(items, path):
            for i, gid in enumerate(items or []):
                chk(gid, f'{path}[{i}]')
        if self._is_v21():
            for n_idx, note in enumerate(doc.get('notes', [])):
                chk_list(note.get('group_ids', []), f'/document/notes[{n_idx}]/group_ids')
        for v_idx, vuln in enumerate(vulns):
            vp = f'/vulnerabilities[{v_idx}]'
            for r_idx, rem in enumerate(vuln.get('remediations', [])):
                chk_list(rem.get('group_ids', []), f'{vp}/remediations[{r_idx}]/group_ids')
            for t_idx, th in enumerate(vuln.get('threats', [])):
                chk_list(th.get('group_ids', []), f'{vp}/threats[{t_idx}]/group_ids')
            if self._is_v21():
                for f_idx, fl in enumerate(vuln.get('flags', [])):
                    chk_list(fl.get('group_ids', []), f'{vp}/flags[{f_idx}]/group_ids')
                for i_idx, inv in enumerate(vuln.get('involvements', [])):
                    chk_list(inv.get('group_ids', []), f'{vp}/involvements[{i_idx}]/group_ids')
                for n_idx, n in enumerate(vuln.get('notes', [])):
                    chk_list(n.get('group_ids', []), f'{vp}/notes[{n_idx}]/group_ids')

    # ====================================================================
    # 6.1.5
    # ====================================================================
    def _test_6_1_5(self):
        for gid, locs in self.group_id_locations.items():
            if len(locs) > 1:
                self._add_error('CSAF_SEMANTIC_REF_GROUP_ID_UNIQUE',
                                f'Group ID "{gid}" defined {len(locs)} times', locs[0])

    # ====================================================================
    # 6.1.6
    # ====================================================================
    def _test_6_1_6(self):
        for v_idx, vuln in enumerate(self.data.get('vulnerabilities', [])):
            ps = vuln.get('product_status', {})
            groups = []
            for label, fields in [('Affected', AFFECTED_FIELDS), ('Not Affected', NOT_AFFECTED_FIELDS),
                                  ('Fixed', FIXED_FIELDS), ('Under Investigation', UNDER_INVESTIGATION_FIELDS)]:
                s = set()
                for f in fields:
                    s.update(ps.get(f, []))
                groups.append((label, s))
            for i, (n1, s1) in enumerate(groups):
                for n2, s2 in groups[i+1:]:
                    for pid in s1 & s2:
                        self._add_error('CSAF_SEMANTIC_STATUS_CONTRADICTION',
                                        f'Product "{pid}": {n1} vs {n2}',
                                        f'/vulnerabilities[{v_idx}]/product_status')

    # ====================================================================
    # 6.1.7 [v2.0] scores[], [v2.1] metrics[] + source
    # ====================================================================
    def _test_6_1_7(self):
        for v_idx, vuln in enumerate(self.data.get('vulnerabilities', [])):
            vp = f'/vulnerabilities[{v_idx}]'
            pvs = {}
            if self._is_v21():
                for m_idx, m in enumerate(vuln.get('metrics', [])):
                    c = m.get('content', {})
                    src = m.get('source', '')
                    prods = m.get('products', [])
                    for ck in ['cvss_v2', 'cvss_v3', 'cvss_v4']:
                        obj = c.get(ck, {})
                        if obj:
                            ver = obj.get('version', ck)
                            for pid in prods:
                                pvs.setdefault((pid, ver, src), []).append(m_idx)
            else:
                for s_idx, sc in enumerate(vuln.get('scores', [])):
                    prods = sc.get('products', [])
                    for ck in ['cvss_v2', 'cvss_v3']:
                        obj = sc.get(ck, {})
                        if obj:
                            ver = obj.get('version', ck)
                            for pid in prods:
                                pvs.setdefault((pid, ver, ''), []).append(s_idx)
            for key, indices in pvs.items():
                if len(indices) > 1:
                    self._add_error('CSAF_SEMANTIC_SCORE_CVSS_DUPLICATE',
                                    f'Product "{key[0]}": {len(indices)} CVSS {key[1]} scores',
                                    f'{vp}/{"metrics" if self._is_v21() else "scores"}')

    # ====================================================================
    # 6.1.8 Invalid CVSS
    # ====================================================================
    def _test_6_1_8(self):
        # 기본 필수 필드 검사 (전체 스키마 검증은 외부 라이브러리 필요)
        for v_idx, vuln in enumerate(self.data.get('vulnerabilities', [])):
            vp = f'/vulnerabilities[{v_idx}]'
            items = vuln.get('metrics' if self._is_v21() else 'scores', [])
            kp = 'metrics' if self._is_v21() else 'scores'
            for s_idx, item in enumerate(items):
                container = item.get('content', item) if self._is_v21() else item
                cvss_keys = ['cvss_v2', 'cvss_v3'] + (['cvss_v4'] if self._is_v21() else [])
                for ck in cvss_keys:
                    obj = container.get(ck, {})
                    if not obj:
                        continue
                    cp = f'{vp}/{kp}[{s_idx}]'
                    if self._is_v21():
                        cp += '/content'
                    if ck == 'cvss_v3' and 'baseSeverity' not in obj:
                        self._add_error('CSAF_SEMANTIC_CVSS_INVALID',
                                        f'{ck} missing baseSeverity', f'{cp}/{ck}')

    # ====================================================================
    # 6.1.9 Invalid CVSS computation
    # vectorString에서 계산한 점수와 문서에 명시된 점수를 비교 (MUST)
    # ====================================================================
    def _test_6_1_9(self):
        if not HAS_EXTERNAL_HELPERS or not CVSSHelper.is_available():
            return  # cvss 라이브러리 없으면 건너뜀
        for v_idx, vuln in enumerate(self.data.get('vulnerabilities', [])):
            vp = f'/vulnerabilities[{v_idx}]'
            items = vuln.get('metrics' if self._is_v21() else 'scores', [])
            kp = 'metrics' if self._is_v21() else 'scores'
            for s_idx, item in enumerate(items):
                container = item.get('content', item) if self._is_v21() else item
                cp = f'{vp}/{kp}[{s_idx}]'
                if self._is_v21():
                    cp += '/content'
                # CVSS v3
                for ck in ['cvss_v3']:
                    obj = container.get(ck, {})
                    if not obj or not obj.get('vectorString'):
                        continue
                    issues = CVSSHelper.validate_v3_computation(obj)
                    for iss in issues:
                        self._add_error('CSAF_SEMANTIC_CVSS_COMPUTATION',
                                        f'{ck} {iss["field"]}: expected {iss["expected"]}, got {iss["actual"]}',
                                        f'{cp}/{ck}')
                # CVSS v2
                obj_v2 = container.get('cvss_v2', {})
                if obj_v2 and obj_v2.get('vectorString'):
                    issues = CVSSHelper.validate_v2_computation(obj_v2)
                    for iss in issues:
                        self._add_error('CSAF_SEMANTIC_CVSS_COMPUTATION',
                                        f'cvss_v2 {iss["field"]}: expected {iss["expected"]}, got {iss["actual"]}',
                                        f'{cp}/cvss_v2')

    # ====================================================================
    # 6.1.10 Inconsistent CVSS
    # CVSS 속성(attackVector 등)과 vectorString이 일관되는지 (MUST)
    # vectorString이 우선한다.
    # ====================================================================
    def _test_6_1_10(self):
        if not HAS_EXTERNAL_HELPERS or not CVSSHelper.is_available():
            return  # cvss 라이브러리 없으면 건너뜀
        for v_idx, vuln in enumerate(self.data.get('vulnerabilities', [])):
            vp = f'/vulnerabilities[{v_idx}]'
            items = vuln.get('metrics' if self._is_v21() else 'scores', [])
            kp = 'metrics' if self._is_v21() else 'scores'
            for s_idx, item in enumerate(items):
                container = item.get('content', item) if self._is_v21() else item
                cp = f'{vp}/{kp}[{s_idx}]'
                if self._is_v21():
                    cp += '/content'
                for ck in ['cvss_v3']:
                    obj = container.get(ck, {})
                    if not obj or not obj.get('vectorString'):
                        continue
                    issues = CVSSHelper.validate_v3_consistency(obj)
                    for iss in issues:
                        self._add_error('CSAF_SEMANTIC_CVSS_INCONSISTENT',
                                        f'{ck}.{iss["property"]}: vector has "{iss["vector_value"]}", JSON has "{iss["json_value"]}"',
                                        f'{cp}/{ck}')

    # ====================================================================
    # 6.1.11 CWE [v2.0] cwe, [v2.1] cwes[]
    # CWE 존재 및 이름 유효성 검증. 카테고리/뷰 참조 시 실패 (v2.1).
    # vexco_external.CWEHelper로 이름 검증 강화.
    # ====================================================================
    def _test_6_1_11(self):
        pat = re.compile(r'^CWE-\d+$')
        # 외부 헬퍼 사용 가능 여부
        use_helper = HAS_EXTERNAL_HELPERS and CWEHelper.is_database_loaded()

        for v_idx, vuln in enumerate(self.data.get('vulnerabilities', [])):
            vp = f'/vulnerabilities[{v_idx}]'
            if self._is_v21():
                # v2.1: cwes[] 배열 (버전 포함)
                for c_idx, cwe in enumerate(vuln.get('cwes', [])):
                    cwe_id = cwe.get('id', '')
                    cwe_name = cwe.get('name', '')
                    cwe_ver = cwe.get('version', '')
                    cpath = f'{vp}/cwes[{c_idx}]'
                    if not pat.match(cwe_id):
                        self._add_error('CSAF_SEMANTIC_ID_CWE_FORMAT',
                                        f'Invalid CWE ID: "{cwe_id}"', f'{cpath}/id')
                        continue
                    if use_helper:
                        # 외부 CWE DB로 이름/카테고리 검증
                        issues = CWEHelper.validate(cwe_id, cwe_name, cwe_ver)
                        for iss in issues:
                            if iss['type'] == 'is_category':
                                self._add_error('CSAF_SEMANTIC_ID_CWE_FORMAT',
                                                iss['detail'], f'{cpath}/id')
                            elif iss['type'] == 'name_mismatch':
                                self._add_error('CSAF_SEMANTIC_ID_CWE_FORMAT',
                                                iss['detail'], f'{cpath}/name')
                            elif iss['type'] == 'not_found':
                                self._add_error('CSAF_SEMANTIC_ID_CWE_FORMAT',
                                                iss['detail'], f'{cpath}/id')
            else:
                # v2.0: cwe 단수 객체
                cwe = vuln.get('cwe', {})
                if not cwe:
                    continue
                cwe_id = cwe.get('id', '')
                cwe_name = cwe.get('name', '')
                if not pat.match(cwe_id):
                    self._add_error('CSAF_SEMANTIC_ID_CWE_FORMAT',
                                    f'Invalid CWE ID: "{cwe_id}"', f'{vp}/cwe/id')
                    continue
                if use_helper:
                    issues = CWEHelper.validate(cwe_id, cwe_name)
                    for iss in issues:
                        if iss['type'] == 'name_mismatch':
                            self._add_error('CSAF_SEMANTIC_ID_CWE_FORMAT',
                                            iss['detail'], f'{vp}/cwe/name')
                        elif iss['type'] == 'not_found':
                            self._add_error('CSAF_SEMANTIC_ID_CWE_FORMAT',
                                            iss['detail'], f'{vp}/cwe/id')

    # ====================================================================
    # 6.1.12 Language
    # ====================================================================
    def _test_6_1_12(self):
        pat = re.compile(r'^[a-zA-Z]{2,3}(-[a-zA-Z0-9]+)*$')
        doc = self.data.get('document', {})
        for fld in ['lang', 'source_lang']:
            val = doc.get(fld)
            if val and not pat.match(val):
                self._add_error('CSAF_SEMANTIC_DOC_LANG_INVALID',
                                f'Invalid language code: "{val}"', f'/document/{fld}')

    # ====================================================================
    # 6.1.13 PURL [v2.0] purl, [v2.1] purls[]
    # ====================================================================
    def _test_6_1_13(self):
        pt = self.data.get('product_tree', {})
        def check_pih(pih, path):
            purl = pih.get('purl')
            if purl and not PURL_PATTERN.match(purl):
                self._add_error('CSAF_SEMANTIC_ID_PURL_FORMAT', f'Invalid PURL: "{purl}"', f'{path}/purl')
            for idx, p in enumerate(pih.get('purls', [])):
                if not PURL_PATTERN.match(p):
                    self._add_error('CSAF_SEMANTIC_ID_PURL_FORMAT', f'Invalid PURL: "{p}"', f'{path}/purls[{idx}]')
        def walk(branches, pp):
            for idx, b in enumerate(branches or []):
                bp = f'{pp}[{idx}]'
                prod = b.get('product', {})
                pih = prod.get('product_identification_helper', {})
                if pih:
                    check_pih(pih, f'{bp}/product/product_identification_helper')
                if 'branches' in b:
                    walk(b['branches'], f'{bp}/branches')
        walk(pt.get('branches', []), '/product_tree/branches')
        for idx, fpn in enumerate(pt.get('full_product_names', [])):
            pih = fpn.get('product_identification_helper', {})
            if pih:
                check_pih(pih, f'/product_tree/full_product_names[{idx}]/product_identification_helper')
        for idx, rel in enumerate(pt.get('relationships', [])):
            pih = rel.get('full_product_name', {}).get('product_identification_helper', {})
            if pih:
                check_pih(pih, f'/product_tree/relationships[{idx}]/full_product_name/product_identification_helper')

    # ====================================================================
    # 6.1.14 Sorted Revision History
    # ====================================================================
    def _test_6_1_14(self):
        rh = self._get_revision_history_sorted()
        for i in range(len(rh) - 1):
            a, b = rh[i].get('number', ''), rh[i+1].get('number', '')
            if self._compare_version_strings(a, b) > 0:
                self._add_error('CSAF_SEMANTIC_DOC_REVISION_ORDER',
                                f'Revision history not sorted: "{a}" > "{b}"',
                                '/document/tracking/revision_history')

    # ====================================================================
    # 6.1.15 Translator
    # ====================================================================
    def _test_6_1_15(self):
        doc = self.data.get('document', {})
        if doc.get('publisher', {}).get('category') == 'translator' and not doc.get('source_lang'):
            self._add_error('CSAF_SEMANTIC_DOC_TRANSLATOR_LANG',
                            'source_lang required for translator', '/document/source_lang')

    # ====================================================================
    # 6.1.16 Latest Document Version
    # ====================================================================
    def _test_6_1_16(self):
        t = self._get_tracking()
        dv = t.get('version', '')
        rh = self._get_revision_history_sorted()
        if not rh or not dv:
            return
        ln = rh[-1].get('number', '')
        dc, lc = dv.split('+')[0], ln.split('+')[0]
        if t.get('status') == 'draft':
            dc, lc = dc.split('-')[0], lc.split('-')[0]
        if dc != lc:
            self._add_error('CSAF_SEMANTIC_DOC_VERSION_MATCH',
                            f'Version "{dv}" != latest revision "{ln}"', '/document/tracking/version')

    # ====================================================================
    # 6.1.17 Document Status Draft
    # ====================================================================
    def _test_6_1_17(self):
        t = self._get_tracking()
        v, s = t.get('version', ''), t.get('status', '')
        if not v or not s:
            return
        is_zero = v == '0' or v.startswith('0.')
        has_pre = '-' in v.split('+')[0]
        if (is_zero or has_pre) and s != 'draft':
            self._add_error('CSAF_SEMANTIC_DOC_STATUS_DRAFT',
                            f'Version "{v}" requires draft status, got "{s}"', '/document/tracking/status')

    # ====================================================================
    # 6.1.18 Released Revision History
    # ====================================================================
    def _test_6_1_18(self):
        t = self._get_tracking()
        if t.get('status') not in ('final', 'interim'):
            return
        for r_idx, item in enumerate(t.get('revision_history', [])):
            num = item.get('number', '')
            if num == '0' or (num.startswith('0.') and '.' in num):
                self._add_error('CSAF_SEMANTIC_DOC_RELEASED_HISTORY',
                                f'Draft version "{num}" in released document',
                                f'/document/tracking/revision_history[{r_idx}]/number')

    # ====================================================================
    # 6.1.19 Pre-release in Revision History
    # ====================================================================
    def _test_6_1_19(self):
        for r_idx, item in enumerate(self._get_tracking().get('revision_history', [])):
            num = item.get('number', '')
            if '-' in num.split('+')[0]:
                self._add_error('CSAF_SEMANTIC_DOC_REVISION_PRERELEASE',
                                f'Pre-release in revision number "{num}"',
                                f'/document/tracking/revision_history[{r_idx}]/number')

    # ====================================================================
    # 6.1.20 Non-draft Document Version
    # ====================================================================
    def _test_6_1_20(self):
        t = self._get_tracking()
        v, s = t.get('version', ''), t.get('status', '')
        if s in ('final', 'interim') and '-' in v.split('+')[0]:
            self._add_error('CSAF_SEMANTIC_DOC_VERSION_PRERELEASE',
                            f'Pre-release in {s} version "{v}"', '/document/tracking/version')

    # ====================================================================
    # 6.1.21 Missing Item in Revision History
    # ====================================================================
    def _test_6_1_21(self):
        rh = self._get_revision_history_sorted()
        nums = [item.get('number', '') for item in rh if item.get('number')]
        if not nums:
            return
        if all(INTEGER_VERSION_PATTERN.match(n) for n in nums):
            ints = sorted(int(n) for n in nums)
            if ints and ints[0] not in (0, 1):
                self._add_error('CSAF_SEMANTIC_DOC_REVISION_VERSION_MISSING',
                                f'First version must be 0 or 1', '/document/tracking/revision_history')
            for i in range(len(ints) - 1):
                if ints[i+1] - ints[i] > 1:
                    self._add_error('CSAF_SEMANTIC_DOC_REVISION_VERSION_MISSING',
                                    f'Missing version between {ints[i]} and {ints[i+1]}',
                                    '/document/tracking/revision_history')
        elif all(SEMVER_PATTERN.match(n) for n in nums):
            majors = sorted(set(int(n.split('.')[0]) for n in nums))
            if majors and majors[0] not in (0, 1):
                self._add_error('CSAF_SEMANTIC_DOC_REVISION_VERSION_MISSING',
                                f'First major version must be 0 or 1', '/document/tracking/revision_history')
            for i in range(len(majors) - 1):
                if majors[i+1] - majors[i] > 1:
                    self._add_error('CSAF_SEMANTIC_DOC_REVISION_VERSION_MISSING',
                                    f'Missing major version between {majors[i]} and {majors[i+1]}',
                                    '/document/tracking/revision_history')

    # ====================================================================
    # 6.1.22 Multiple Definition in Revision History
    # ====================================================================
    def _test_6_1_22(self):
        seen = {}
        for r_idx, item in enumerate(self._get_tracking().get('revision_history', [])):
            num = item.get('number', '')
            if num in seen:
                self._add_error('CSAF_SEMANTIC_DOC_REVISION_VERSION_DUPLICATE',
                                f'Duplicate version "{num}"',
                                f'/document/tracking/revision_history[{r_idx}]/number')
            else:
                seen[num] = r_idx

    # ====================================================================
    # 6.1.23 Multiple Use of Same CVE
    # ====================================================================
    def _test_6_1_23(self):
        cves: Dict[str, List[int]] = {}
        for v_idx, vuln in enumerate(self.data.get('vulnerabilities', [])):
            cve = vuln.get('cve')
            if cve:
                cves.setdefault(cve, []).append(v_idx)
        for cve, idx_list in cves.items():
            if len(idx_list) > 1:
                self._add_error('CSAF_SEMANTIC_VULN_CVE_UNIQUE',
                                f'CVE "{cve}" used {len(idx_list)} times',
                                f'/vulnerabilities[{idx_list[0]}]/cve')

    # ====================================================================
    # 6.1.24 Multiple Definition in Involvements
    # ====================================================================
    def _test_6_1_24(self):
        for v_idx, vuln in enumerate(self.data.get('vulnerabilities', [])):
            seen = set()
            for i_idx, inv in enumerate(vuln.get('involvements', [])):
                key = (inv.get('party', ''), inv.get('date', ''))
                if key[0] and key in seen:
                    self._add_error('CSAF_SEMANTIC_VULN_INVOLVEMENT_DUPLICATE',
                                    f'Duplicate involvement: party={key[0]} date={key[1]}',
                                    f'/vulnerabilities[{v_idx}]/involvements[{i_idx}]')
                seen.add(key)

    # ====================================================================
    # 6.1.25 Multiple Use of Same Hash Algorithm
    # ====================================================================
    def _test_6_1_25(self):
        pt = self.data.get('product_tree', {})
        def check_pih(pih, path):
            for h_idx, h in enumerate(pih.get('hashes', [])):
                algos = set()
                for fh_idx, fh in enumerate(h.get('file_hashes', [])):
                    algo = fh.get('algorithm', '')
                    if algo in algos:
                        self._add_error('CSAF_SEMANTIC_ID_HASH_DUPLICATE',
                                        f'Duplicate hash algorithm "{algo}"',
                                        f'{path}/hashes[{h_idx}]/file_hashes[{fh_idx}]')
                    algos.add(algo)
        def walk(branches, pp):
            for idx, b in enumerate(branches or []):
                bp = f'{pp}[{idx}]'
                pih = b.get('product', {}).get('product_identification_helper', {})
                if pih:
                    check_pih(pih, f'{bp}/product/product_identification_helper')
                if 'branches' in b:
                    walk(b['branches'], f'{bp}/branches')
        walk(pt.get('branches', []), '/product_tree/branches')
        for idx, fpn in enumerate(pt.get('full_product_names', [])):
            pih = fpn.get('product_identification_helper', {})
            if pih:
                check_pih(pih, f'/product_tree/full_product_names[{idx}]/product_identification_helper')
        for idx, rel in enumerate(pt.get('relationships', [])):
            pih = rel.get('full_product_name', {}).get('product_identification_helper', {})
            if pih:
                check_pih(pih, f'/product_tree/relationships[{idx}]/full_product_name/product_identification_helper')

    # ====================================================================
    # 6.1.26 Prohibited Document Category Name
    # ====================================================================
    def _test_6_1_26(self):
        cat = self.data.get('document', {}).get('category', '')
        cl = cat.lower()
        skip = CSAF_21_SKIP_CATEGORIES if self._is_v21() else CSAF_20_SKIP_CATEGORIES
        if cl in skip:
            return
        if cl.startswith('csaf_') and cl != 'csaf_base':
            self._add_error('CSAF_SEMANTIC_DOC_CATEGORY_PROHIBITED',
                            f'Category "{cat}" starts with reserved prefix csaf_', '/document/category')
            return
        norm = re.sub(r'[-_\s]+', '', cl)
        pnames = PROFILE_NAMES_21_NORMALIZED if self._is_v21() else PROFILE_NAMES_NORMALIZED
        if norm in pnames:
            self._add_error('CSAF_SEMANTIC_DOC_CATEGORY_PROHIBITED',
                            f'Category "{cat}" matches profile name', '/document/category')

    # ====================================================================
    # 6.1.27 Profile Tests (내부에서 카테고리별 분기)
    # ====================================================================
    def _test_6_1_27(self):
        self._t27_1(); self._t27_2(); self._t27_3(); self._t27_4(); self._t27_5()
        self._t27_6(); self._t27_7(); self._t27_8(); self._t27_9(); self._t27_10(); self._t27_11()
        if self._is_v21():
            self._t27_12(); self._t27_13(); self._t27_14(); self._t27_15()
            self._t27_16(); self._t27_17(); self._t27_18(); self._t27_19()

    def _t27_1(self):
        # 6.1.27.1 Document Notes (informational/incident)
        if self.category not in ('csaf_informational_advisory', 'csaf_security_incident_response'):
            return
        valid = {'description', 'details', 'general', 'summary'}
        if not any(n.get('category') in valid for n in self.data.get('document', {}).get('notes', [])):
            self._add_error('CSAF_SEMANTIC_PROFILE_DOC_NOTES',
                            'Document notes must contain description/details/general/summary', '/document/notes')

    def _t27_2(self):
        # 6.1.27.2 Document References
        if self.category not in ('csaf_informational_advisory', 'csaf_security_incident_response'):
            return
        if not any(r.get('category') == 'external' for r in self.data.get('document', {}).get('references', [])):
            self._add_error('CSAF_SEMANTIC_PROFILE_DOC_REFERENCES',
                            'External document reference required', '/document/references')

    def _t27_3(self):
        # 6.1.27.3 Vulnerabilities must not exist
        applicable = {'csaf_informational_advisory'}
        if self._is_v21():
            applicable |= {'csaf_withdrawn', 'csaf_superseded'}
        if self.category in applicable and self.data.get('vulnerabilities'):
            self._add_error('CSAF_SEMANTIC_PROFILE_NO_VULNERABILITIES',
                            'Vulnerabilities must not exist', '/vulnerabilities')

    def _t27_4(self):
        # 6.1.27.4 Product Tree required
        applicable = {'csaf_security_advisory', 'csaf_vex'}
        if self._is_v21():
            applicable.add('csaf_deprecated_security_advisory')
        if self.category in applicable and 'product_tree' not in self.data:
            self._add_error('CSAF_SEMANTIC_VEX_PRODUCT_TREE_REQUIRED',
                            'Product tree required', '/product_tree')

    def _t27_5(self):
        # 6.1.27.5 Vulnerability Notes
        applicable = {'csaf_security_advisory', 'csaf_vex'}
        if self._is_v21():
            applicable.add('csaf_deprecated_security_advisory')
        if self.category not in applicable:
            return
        for v_idx, vuln in enumerate(self.data.get('vulnerabilities', [])):
            if not vuln.get('notes'):
                self._add_error('CSAF_SEMANTIC_VEX_VULN_NOTES_REQUIRED',
                                'Vulnerability notes required', f'/vulnerabilities[{v_idx}]/notes')

    def _t27_6(self):
        # 6.1.27.6 Product Status required (security_advisory)
        applicable = {'csaf_security_advisory'}
        if self._is_v21():
            applicable.add('csaf_deprecated_security_advisory')
        if self.category not in applicable:
            return
        for v_idx, vuln in enumerate(self.data.get('vulnerabilities', [])):
            if not vuln.get('product_status'):
                self._add_error('CSAF_SEMANTIC_PROFILE_PRODUCT_STATUS',
                                'product_status required', f'/vulnerabilities[{v_idx}]/product_status')

    def _t27_7(self):
        # 6.1.27.7 VEX Product Status
        if self.category != 'csaf_vex':
            return
        for v_idx, vuln in enumerate(self.data.get('vulnerabilities', [])):
            ps = vuln.get('product_status', {})
            if not any(ps.get(f) for f in VEX_STATUS_FIELDS):
                self._add_error('CSAF_SEMANTIC_VEX_STATUS_REQUIRED',
                                'VEX requires product status', f'/vulnerabilities[{v_idx}]/product_status')

    def _t27_8(self):
        # 6.1.27.8 Vulnerability ID
        if self.category != 'csaf_vex':
            return
        for v_idx, vuln in enumerate(self.data.get('vulnerabilities', [])):
            if not vuln.get('cve') and not vuln.get('ids'):
                self._add_error('CSAF_SEMANTIC_VEX_VULN_ID_REQUIRED',
                                'VEX requires cve or ids', f'/vulnerabilities[{v_idx}]')

    def _t27_9(self):
        # 6.1.27.9 Impact Statement
        if self.category != 'csaf_vex':
            return
        g2p = _build_group_to_products_map(self.data.get('product_tree', {}))
        for v_idx, vuln in enumerate(self.data.get('vulnerabilities', [])):
            kna = set(vuln.get('product_status', {}).get('known_not_affected', []))
            if not kna:
                continue
            covered = set()
            for fl in vuln.get('flags', []):
                covered.update(fl.get('product_ids', []))
                for gid in fl.get('group_ids', []):
                    covered.update(g2p.get(gid, set()))
            for th in vuln.get('threats', []):
                if th.get('category') == 'impact':
                    covered.update(th.get('product_ids', []))
                    for gid in th.get('group_ids', []):
                        covered.update(g2p.get(gid, set()))
            for pid in kna - covered:
                self._add_error('CSAF_SEMANTIC_VEX_IMPACT_STATEMENT_REQUIRED',
                                f'No impact statement for known_not_affected "{pid}"',
                                f'/vulnerabilities[{v_idx}]/product_status/known_not_affected')

    def _t27_10(self):
        # 6.1.27.10 Action Statement
        if self.category != 'csaf_vex':
            return
        g2p = _build_group_to_products_map(self.data.get('product_tree', {}))
        for v_idx, vuln in enumerate(self.data.get('vulnerabilities', [])):
            ka = set(vuln.get('product_status', {}).get('known_affected', []))
            if not ka:
                continue
            covered = set()
            for rem in vuln.get('remediations', []):
                covered.update(rem.get('product_ids', []))
                for gid in rem.get('group_ids', []):
                    covered.update(g2p.get(gid, set()))
            for pid in ka - covered:
                self._add_error('CSAF_SEMANTIC_VEX_ACTION_STATEMENT_REQUIRED',
                                f'No action statement for known_affected "{pid}"',
                                f'/vulnerabilities[{v_idx}]/product_status/known_affected')

    def _t27_11(self):
        # 6.1.27.11 Vulnerabilities required
        applicable = {'csaf_security_advisory', 'csaf_vex'}
        if self._is_v21():
            applicable.add('csaf_deprecated_security_advisory')
        if self.category in applicable and not self.data.get('vulnerabilities'):
            self._add_error('CSAF_SEMANTIC_VEX_VULNERABILITIES_REQUIRED',
                            'Vulnerabilities required', '/vulnerabilities')

    # --- v2.1 전용 프로필 테스트 ---
    def _t27_12(self):
        # [v2.1] 6.1.27.12 Affected Products
        if self.category != 'csaf_security_advisory':
            return
        for v_idx, vuln in enumerate(self.data.get('vulnerabilities', [])):
            if not vuln.get('product_status', {}).get('known_affected'):
                self._add_error('CSAF_SEMANTIC_PROFILE_AFFECTED_PRODUCTS',
                                'known_affected required', f'/vulnerabilities[{v_idx}]/product_status/known_affected')

    def _t27_13(self):
        # [v2.1] 6.1.27.13 Corresponding Affected Products
        if self.category != 'csaf_security_advisory':
            return
        for v_idx, vuln in enumerate(self.data.get('vulnerabilities', [])):
            ps = vuln.get('product_status', {})
            fixed = set(ps.get('fixed', []))
            affected = set()
            for f in AFFECTED_FIELDS:
                affected.update(ps.get(f, []))
            if fixed and not affected:
                self._add_error('CSAF_SEMANTIC_PROFILE_CORRESPONDING_AFFECTED',
                                'Fixed products must have corresponding affected versions',
                                f'/vulnerabilities[{v_idx}]/product_status/known_affected')

    def _t27_14(self):
        # [v2.1] 6.1.27.14 Document Notes (withdrawn/superseded)
        if self.category not in ('csaf_withdrawn', 'csaf_superseded'):
            return
        if not any(n.get('category') == 'description' for n in self.data.get('document', {}).get('notes', [])):
            self._add_error('CSAF_SEMANTIC_PROFILE_DOC_NOTES_DESC',
                            'Description note required', '/document/notes')

    def _t27_15(self):
        # [v2.1] 6.1.27.15 Product Tree must not exist
        if self.category not in ('csaf_withdrawn', 'csaf_superseded'):
            return
        if self.data.get('product_tree'):
            self._add_error('CSAF_SEMANTIC_PROFILE_NO_PRODUCT_TREE',
                            'product_tree must not exist', '/product_tree')

    def _t27_16(self):
        # [v2.1] 6.1.27.16 Revision History min 2
        if self.category not in ('csaf_withdrawn', 'csaf_superseded'):
            return
        if len(self._get_tracking().get('revision_history', [])) < 2:
            self._add_error('CSAF_SEMANTIC_PROFILE_REVISION_MIN_TWO',
                            'Min 2 revision history entries required', '/document/tracking/revision_history')

    def _t27_17(self):
        # [v2.1] 6.1.27.17 Reasoning for Withdrawal
        if self.category != 'csaf_withdrawn':
            return
        lang = self.data.get('document', {}).get('lang', '')
        if lang and not lang.lower().startswith('en'):
            return
        notes = self.data.get('document', {}).get('notes', [])
        if len([n for n in notes if n.get('title') == 'Reasoning for Withdrawal' and n.get('category') == 'description']) != 1:
            self._add_error('CSAF_SEMANTIC_PROFILE_WITHDRAWAL_REASONING',
                            'Requires note "Reasoning for Withdrawal" with category "description"', '/document/notes')

    def _t27_18(self):
        # [v2.1] 6.1.27.18 Reasoning for Supersession
        if self.category != 'csaf_superseded':
            return
        lang = self.data.get('document', {}).get('lang', '')
        if lang and not lang.lower().startswith('en'):
            return
        notes = self.data.get('document', {}).get('notes', [])
        if len([n for n in notes if n.get('title') == 'Reasoning for Supersession' and n.get('category') == 'description']) != 1:
            self._add_error('CSAF_SEMANTIC_PROFILE_SUPERSESSION_REASONING',
                            'Requires note "Reasoning for Supersession" with category "description"', '/document/notes')

    def _t27_19(self):
        # [v2.1] 6.1.27.19 Reference to Superseding Document
        if self.category != 'csaf_superseded':
            return
        lang = self.data.get('document', {}).get('lang', '')
        if lang and not lang.lower().startswith('en'):
            return
        refs = self.data.get('document', {}).get('references', [])
        if not any(r.get('category') == 'external' and isinstance(r.get('summary', ''), str)
                   and r['summary'].startswith('Superseding Document') for r in refs):
            self._add_error('CSAF_SEMANTIC_PROFILE_SUPERSEDING_REFERENCE',
                            'External reference "Superseding Document" required', '/document/references')

    # ====================================================================
    # 6.1.28 Translation
    # ====================================================================
    def _test_6_1_28(self):
        doc = self.data.get('document', {})
        lang, sl = doc.get('lang', ''), doc.get('source_lang', '')
        if lang and sl and lang == sl:
            self._add_error('CSAF_SEMANTIC_DOC_TRANSLATION_SAME_LANG',
                            f'lang and source_lang are the same: "{lang}"', '/document/lang')

    # ====================================================================
    # 6.1.29 Remediation without Product Reference
    # ====================================================================
    def _test_6_1_29(self):
        for v_idx, vuln in enumerate(self.data.get('vulnerabilities', [])):
            for r_idx, rem in enumerate(vuln.get('remediations', [])):
                if not rem.get('product_ids') and not rem.get('group_ids'):
                    self._add_error('CSAF_SEMANTIC_VEX_REMEDIATION_PRODUCT_REF',
                                    'Remediation without product reference',
                                    f'/vulnerabilities[{v_idx}]/remediations[{r_idx}]')

    # ====================================================================
    # 6.1.30 Mixed Integer and Semantic Versioning
    # ====================================================================
    def _test_6_1_30(self):
        t = self._get_tracking()
        vers = [item.get('number', '') for item in t.get('revision_history', []) if item.get('number')]
        dv = t.get('version', '')
        if dv:
            vers.append(dv)
        if not vers:
            return
        has_int = any(INTEGER_VERSION_PATTERN.match(v) for v in vers)
        has_sem = any(SEMVER_PATTERN.match(v) for v in vers)
        if has_int and has_sem:
            self._add_error('CSAF_SEMANTIC_DOC_VERSION_FORMAT_MIXED',
                            'Mixed integer and semantic versioning', '/document/tracking')

    # ====================================================================
    # 6.1.31 Version Range in Product Version
    # ====================================================================
    def _test_6_1_31(self):
        pt = self.data.get('product_tree', {})
        def walk(branches, pp):
            for idx, b in enumerate(branches or []):
                bp = f'{pp}[{idx}]'
                if b.get('category') == 'product_version':
                    name = (b.get('name', '') or '').lower()
                    for op in VERSION_RANGE_OPERATORS:
                        if op in name:
                            self._add_error('CSAF_SEMANTIC_PROD_VERSION_RANGE_BRANCH',
                                            f'Version range operator "{op}" in product_version', f'{bp}/name')
                            break
                    else:
                        words = set(name.split())
                        found = words & VERSION_RANGE_KEYWORDS
                        if found:
                            self._add_error('CSAF_SEMANTIC_PROD_VERSION_RANGE_BRANCH',
                                            f'Version range keyword in product_version', f'{bp}/name')
                if 'branches' in b:
                    walk(b['branches'], f'{bp}/branches')
        walk(pt.get('branches', []), '/product_tree/branches')

    # ====================================================================
    # 6.1.32 Flag without Product Reference
    # ====================================================================
    def _test_6_1_32(self):
        for v_idx, vuln in enumerate(self.data.get('vulnerabilities', [])):
            for f_idx, fl in enumerate(vuln.get('flags', [])):
                if not fl.get('product_ids') and not fl.get('group_ids'):
                    self._add_error('CSAF_SEMANTIC_VEX_FLAG_PRODUCT_REF',
                                    'Flag without product reference',
                                    f'/vulnerabilities[{v_idx}]/flags[{f_idx}]')

    # ====================================================================
    # 6.1.33 Multiple Flags per Product
    # ====================================================================
    def _test_6_1_33(self):
        g2p = _build_group_to_products_map(self.data.get('product_tree', {}))
        for v_idx, vuln in enumerate(self.data.get('vulnerabilities', [])):
            pf: Dict[str, List[str]] = {}
            for fl in vuln.get('flags', []):
                label = fl.get('label', '')
                if label not in VEX_JUSTIFICATION_LABELS:
                    continue
                for pid in fl.get('product_ids', []):
                    pf.setdefault(pid, []).append(label)
                for gid in fl.get('group_ids', []):
                    for pid in g2p.get(gid, set()):
                        pf.setdefault(pid, []).append(label)
            for pid, labels in pf.items():
                if len(labels) > 1:
                    self._add_error('CSAF_SEMANTIC_VEX_FLAG_DUPLICATE_PER_PRODUCT',
                                    f'Product "{pid}" has multiple justification flags',
                                    f'/vulnerabilities[{v_idx}]/flags')

    # ====================================================================
    # 6.1.34~6.1.55: v2.1 전용
    # ====================================================================
    def _test_6_1_34(self):
        # [v2.1] Branches Recursion Depth <= 30
        def walk(branches, depth, pp):
            if depth > 30:
                self._add_error('CSAF_SEMANTIC_PROD_BRANCH_DEPTH',
                                f'Branch depth > 30', pp)
                return
            for idx, b in enumerate(branches or []):
                bp = f'{pp}[{idx}]'
                if 'branches' in b:
                    walk(b['branches'], depth + 1, f'{bp}/branches')
        walk(self.data.get('product_tree', {}).get('branches', []), 1, '/product_tree/branches')

    def _test_6_1_35(self):
        # [v2.1] Contradicting Remediations
        g2p = _build_group_to_products_map(self.data.get('product_tree', {}))
        for v_idx, vuln in enumerate(self.data.get('vulnerabilities', [])):
            pc: Dict[str, List[str]] = {}
            for rem in vuln.get('remediations', []):
                cat = rem.get('category', '')
                pids = set(rem.get('product_ids', []))
                for gid in rem.get('group_ids', []):
                    pids.update(g2p.get(gid, set()))
                for pid in pids:
                    pc.setdefault(pid, []).append(cat)
            for pid, cats in pc.items():
                cs = set(cats)
                for c1, c2 in REMEDIATION_CONTRADICTING_PAIRS:
                    if c1 in cs and c2 in cs:
                        self._add_error('CSAF_SEMANTIC_VEX_REMEDIATION_CONTRADICTION',
                                        f'Product "{pid}": contradicting remediations {c1} and {c2}',
                                        f'/vulnerabilities[{v_idx}]/remediations')

    def _test_6_1_36(self):
        # [v2.1] Status-Remediation Contradiction
        g2p = _build_group_to_products_map(self.data.get('product_tree', {}))
        contra = {'vendor_fix': {'known_not_affected'}, 'fix_planned': {'known_not_affected'}}
        for v_idx, vuln in enumerate(self.data.get('vulnerabilities', [])):
            kna = set(vuln.get('product_status', {}).get('known_not_affected', []))
            if not kna:
                continue
            for r_idx, rem in enumerate(vuln.get('remediations', [])):
                cat = rem.get('category', '')
                if cat not in contra:
                    continue
                pids = set(rem.get('product_ids', []))
                for gid in rem.get('group_ids', []):
                    pids.update(g2p.get(gid, set()))
                for pid in pids & kna:
                    self._add_error('CSAF_SEMANTIC_VEX_STATUS_REMEDIATION_CONTRADICTION',
                                    f'Product "{pid}": {cat} contradicts known_not_affected',
                                    f'/vulnerabilities[{v_idx}]/remediations[{r_idx}]')

    def _test_6_1_37(self):
        # [v2.1] Date and Time format
        paths = []
        t = self._get_tracking()
        for fld in ['current_release_date', 'initial_release_date']:
            v = t.get(fld)
            if v:
                paths.append((v, f'/document/tracking/{fld}'))
        gen_d = t.get('generator', {}).get('date')
        if gen_d:
            paths.append((gen_d, '/document/tracking/generator/date'))
        for r_idx, item in enumerate(t.get('revision_history', [])):
            d = item.get('date')
            if d:
                paths.append((d, f'/document/tracking/revision_history[{r_idx}]/date'))
        for v_idx, vuln in enumerate(self.data.get('vulnerabilities', [])):
            vp = f'/vulnerabilities[{v_idx}]'
            for fld in ['disclosure_date', 'discovery_date']:
                v = vuln.get(fld)
                if v:
                    paths.append((v, f'{vp}/{fld}'))
        for val, path in paths:
            if isinstance(val, str) and not DATETIME_PATTERN.match(val):
                self._add_error('CSAF_SEMANTIC_DOC_DATETIME_FORMAT',
                                f'Invalid date-time: "{val}"', path)

    def _test_6_1_38(self):
        # [v2.1] Non-Public Sharing Group with Max UUID
        dist = self.data.get('document', {}).get('distribution', {})
        sg_id = dist.get('sharing_group', {}).get('id', '')
        tlp = dist.get('tlp', {}).get('label', '').upper()
        if sg_id == MAX_UUID and tlp != 'CLEAR':
            self._add_error('CSAF_SEMANTIC_DOC_SHARING_MAX_UUID_TLP',
                            f'Max UUID requires TLP:CLEAR, got {tlp}', '/document/distribution/tlp/label')

    def _test_6_1_39(self):
        # [v2.1] Public Sharing Group with no Max UUID
        dist = self.data.get('document', {}).get('distribution', {})
        sg_id = dist.get('sharing_group', {}).get('id', '')
        tlp = dist.get('tlp', {}).get('label', '').upper()
        status = self._get_tracking().get('status', '')
        if tlp == 'CLEAR' and sg_id:
            if sg_id == NIL_UUID and status == 'draft':
                return
            if sg_id != MAX_UUID:
                self._add_error('CSAF_SEMANTIC_DOC_SHARING_CLEAR_UUID',
                                'TLP:CLEAR must use Max UUID', '/document/distribution/sharing_group/id')

    def _test_6_1_40(self):
        # [v2.1] Invalid Sharing Group Name
        dist = self.data.get('document', {}).get('distribution', {})
        sg = dist.get('sharing_group', {})
        if sg.get('name') == 'Public' and sg.get('id', '') != MAX_UUID:
            self._add_error('CSAF_SEMANTIC_DOC_SHARING_NAME_INVALID',
                            '"Public" reserved for Max UUID', '/document/distribution/sharing_group/name')

    def _test_6_1_41(self):
        # [v2.1] Missing Sharing Group Name
        dist = self.data.get('document', {}).get('distribution', {})
        sg = dist.get('sharing_group', {})
        if sg.get('id') == MAX_UUID and sg.get('name') != 'Public':
            self._add_error('CSAF_SEMANTIC_DOC_SHARING_NAME_MISSING',
                            'Max UUID must have name "Public"', '/document/distribution/sharing_group/name')

    def _test_6_1_42(self):
        # [v2.1] PURL Qualifiers
        pt = self.data.get('product_tree', {})
        def check_purls(pih, path):
            purls = pih.get('purls', [])
            if len(purls) < 2:
                return
            bases = set(p.split('?')[0].split('#')[0] for p in purls)
            if len(bases) > 1:
                self._add_error('CSAF_SEMANTIC_ID_PURL_QUALIFIERS',
                                'PURLs differ beyond qualifiers', f'{path}/purls')
        def walk(branches, pp):
            for idx, b in enumerate(branches or []):
                bp = f'{pp}[{idx}]'
                pih = b.get('product', {}).get('product_identification_helper', {})
                if pih:
                    check_purls(pih, f'{bp}/product/product_identification_helper')
                if 'branches' in b:
                    walk(b['branches'], f'{bp}/branches')
        walk(pt.get('branches', []), '/product_tree/branches')
        for idx, fpn in enumerate(pt.get('full_product_names', [])):
            pih = fpn.get('product_identification_helper', {})
            if pih:
                check_purls(pih, f'/product_tree/full_product_names[{idx}]/product_identification_helper')

    def _test_6_1_43(self):
        self._check_multi_stars('model_numbers', 'CSAF_SEMANTIC_PROD_MULTI_STAR_MODEL')

    def _test_6_1_44(self):
        self._check_multi_stars('serial_numbers', 'CSAF_SEMANTIC_PROD_MULTI_STAR_SERIAL')

    def _check_multi_stars(self, field, rule):
        # [v2.1] 다중 * 검사
        def walk(branches, pp):
            for idx, b in enumerate(branches or []):
                bp = f'{pp}[{idx}]'
                pih = b.get('product', {}).get('product_identification_helper', {})
                for vi, val in enumerate(pih.get(field, [])):
                    if len(re.findall(r'(?<!\\)\*', val)) > 1:
                        self._add_error(rule, f'Multiple stars in {field}: "{val}"',
                                        f'{bp}/product/product_identification_helper/{field}[{vi}]')
                if 'branches' in b:
                    walk(b['branches'], f'{bp}/branches')
        walk(self.data.get('product_tree', {}).get('branches', []), '/product_tree/branches')

    def _test_6_1_45(self):
        # [v2.1] Inconsistent Disclosure Date
        dist = self.data.get('document', {}).get('distribution', {})
        tlp = dist.get('tlp', {}).get('label', '').upper()
        status = self._get_tracking().get('status', '')
        if tlp != 'CLEAR' or status not in ('final', 'interim'):
            return
        newest = self._get_newest_revision_date()
        if not newest:
            return
        for v_idx, vuln in enumerate(self.data.get('vulnerabilities', [])):
            dd = vuln.get('disclosure_date')
            if dd:
                dt = self._parse_dt(dd)
                if dt and dt > newest:
                    self._add_error('CSAF_SEMANTIC_VULN_DISCLOSURE_DATE',
                                    'disclosure_date > latest revision', f'/vulnerabilities[{v_idx}]/disclosure_date')

    def _test_6_1_46(self):
        # [v2.1] Invalid SSVC - 기본 필수 필드
        for v_idx, vuln in enumerate(self.data.get('vulnerabilities', [])):
            for m_idx, m in enumerate(vuln.get('metrics', [])):
                ssvc = m.get('content', {}).get('ssvc_v1', {})
                if ssvc and not ssvc.get('selections'):
                    self._add_error('CSAF_SEMANTIC_SSVC_INVALID',
                                    'SSVC missing "selections"',
                                    f'/vulnerabilities[{v_idx}]/metrics[{m_idx}]/content/ssvc_v1')

    def _test_6_1_47(self):
        # [v2.1] Inconsistent SSVC ID
        vuln_count = len(self.data.get('vulnerabilities', []))
        tid = self._get_tracking().get('id', '')
        for v_idx, vuln in enumerate(self.data.get('vulnerabilities', [])):
            valid_ids = set()
            if vuln.get('cve'):
                valid_ids.add(vuln['cve'])
            for i in vuln.get('ids', []):
                if i.get('text'):
                    valid_ids.add(i['text'])
            for m_idx, m in enumerate(vuln.get('metrics', [])):
                ssvc = m.get('content', {}).get('ssvc_v1', {})
                sid = ssvc.get('id', '')
                if not sid:
                    continue
                if sid == tid and vuln_count > 1:
                    self._add_error('CSAF_SEMANTIC_SSVC_ID_INCONSISTENT',
                                    f'SSVC ID = tracking ID but multiple vulns',
                                    f'/vulnerabilities[{v_idx}]/metrics[{m_idx}]/content/ssvc_v1/id')
                elif sid != tid and sid not in valid_ids:
                    self._add_error('CSAF_SEMANTIC_SSVC_ID_INCONSISTENT',
                                    f'SSVC ID "{sid}" does not match CVE/IDs',
                                    f'/vulnerabilities[{v_idx}]/metrics[{m_idx}]/content/ssvc_v1/id')

    def _test_6_1_48(self):
        # [v2.1] 6.1.48 SSVC Decision Points - 등록 네임스페이스의 decision point 유효성
        if not HAS_EXTERNAL_HELPERS:
            return
        for v_idx, vuln in enumerate(self.data.get('vulnerabilities', [])):
            for m_idx, m in enumerate(vuln.get('metrics', [])):
                ssvc = m.get('content', {}).get('ssvc_v1', {})
                if not ssvc:
                    continue
                for s_idx, sel in enumerate(ssvc.get('selections', [])):
                    name = sel.get('name', '')
                    ns = sel.get('namespace', '')
                    ver = sel.get('version', '')
                    vals = sel.get('values', [])
                    issues = SSVCHelper.validate_selection(name, ns, ver, vals)
                    for iss in issues:
                        self._add_error('CSAF_SEMANTIC_SSVC_DECISION_POINTS',
                                        iss['detail'],
                                        f'/vulnerabilities[{v_idx}]/metrics[{m_idx}]/content/ssvc_v1/selections[{s_idx}]')

    def _test_6_1_49(self):
        # [v2.1] SSVC Timestamp
        status = self._get_tracking().get('status', '')
        if status not in ('final', 'interim'):
            return
        newest = self._get_newest_revision_date()
        if not newest:
            return
        for v_idx, vuln in enumerate(self.data.get('vulnerabilities', [])):
            for m_idx, m in enumerate(vuln.get('metrics', [])):
                ts = m.get('content', {}).get('ssvc_v1', {}).get('timestamp')
                if ts:
                    dt = self._parse_dt(ts)
                    if dt and dt > newest:
                        self._add_error('CSAF_SEMANTIC_SSVC_TIMESTAMP',
                                        'SSVC timestamp > latest revision',
                                        f'/vulnerabilities[{v_idx}]/metrics[{m_idx}]/content/ssvc_v1/timestamp')

    def _test_6_1_50(self):
        # [v2.1] 6.1.50 Product Version Range Rules
        # product_version_range 브랜치의 name이 vers 또는 vls 형식인지 검증 (MUST)
        pt = self.data.get('product_tree', {})

        def walk(branches, pp):
            for idx, b in enumerate(branches or []):
                bp = f'{pp}[{idx}]'
                if b.get('category') == 'product_version_range':
                    name = b.get('name', '')
                    issues = _validate_version_range_name(name)
                    for iss in issues:
                        self._add_error('CSAF_SEMANTIC_PROD_VERSION_RANGE_RULES',
                                        iss, f'{bp}/name')
                if 'branches' in b:
                    walk(b['branches'], f'{bp}/branches')

        walk(pt.get('branches', []), '/product_tree/branches')

    def _test_6_1_51(self):
        # [v2.1] EPSS Timestamp
        status = self._get_tracking().get('status', '')
        if status not in ('final', 'interim'):
            return
        newest = self._get_newest_revision_date()
        if not newest:
            return
        for v_idx, vuln in enumerate(self.data.get('vulnerabilities', [])):
            for m_idx, m in enumerate(vuln.get('metrics', [])):
                ts = m.get('content', {}).get('epss', {}).get('timestamp')
                if ts:
                    dt = self._parse_dt(ts)
                    if dt and dt > newest:
                        self._add_error('CSAF_SEMANTIC_EPSS_TIMESTAMP',
                                        'EPSS timestamp > latest revision',
                                        f'/vulnerabilities[{v_idx}]/metrics[{m_idx}]/content/epss/timestamp')

    def _test_6_1_52(self):
        # [v2.1] First Known Exploitation Dates
        status = self._get_tracking().get('status', '')
        if status not in ('final', 'interim'):
            return
        newest = self._get_newest_revision_date()
        if not newest:
            return
        for v_idx, vuln in enumerate(self.data.get('vulnerabilities', [])):
            for e_idx, item in enumerate(vuln.get('first_known_exploitation_dates', [])):
                for fld in ['date', 'exploitation_date']:
                    val = item.get(fld)
                    if val:
                        dt = self._parse_dt(val)
                        if dt and dt > newest:
                            self._add_error('CSAF_SEMANTIC_EXPLOITATION_DATE_INCONSISTENT',
                                            f'{fld} > latest revision',
                                            f'/vulnerabilities[{v_idx}]/first_known_exploitation_dates[{e_idx}]/{fld}')

    def _test_6_1_53(self):
        # [v2.1] Exploitation Date Order
        for v_idx, vuln in enumerate(self.data.get('vulnerabilities', [])):
            for e_idx, item in enumerate(vuln.get('first_known_exploitation_dates', [])):
                ed, d = item.get('exploitation_date'), item.get('date')
                if ed and d:
                    ed_dt, d_dt = self._parse_dt(ed), self._parse_dt(d)
                    if ed_dt and d_dt and ed_dt > d_dt:
                        self._add_error('CSAF_SEMANTIC_EXPLOITATION_DATE_ORDER',
                                        'exploitation_date > date',
                                        f'/vulnerabilities[{v_idx}]/first_known_exploitation_dates[{e_idx}]/exploitation_date')

    def _test_6_1_54(self):
        # [v2.1] License Expression - 간이 검사
        le = self.data.get('document', {}).get('license_expression')
        if le and isinstance(le, str) and (len(le) > 200 or '\n' in le):
            self._add_error('CSAF_SEMANTIC_DOC_LICENSE_EXPRESSION',
                            'Appears to be license text, not SPDX expression', '/document/license_expression')

    def _test_6_1_55(self):
        # [v2.1] License Text
        doc = self.data.get('document', {})
        le = doc.get('license_expression', '')
        if not le or 'LicenseRef-' not in le:
            return
        lang = doc.get('lang', '')
        if lang and not lang.lower().startswith('en'):
            return
        notes = doc.get('notes', [])
        if len([n for n in notes if n.get('title') == 'License' and n.get('category') == 'legal_disclaimer']) != 1:
            self._add_error('CSAF_SEMANTIC_DOC_LICENSE_TEXT',
                            'Custom license requires "License" note with category "legal_disclaimer"', '/document/notes')

    # ====================================================================
    # 결과 생성
    # ====================================================================
    def _build_result(self) -> Dict[str, Any]:
        has_errors = any(e['severity'] == 'error' for e in self.errors)
        return {
            'valid': not has_errors,
            'version': self.doc_version,
            'errors': self.errors,
            'error_count': sum(1 for e in self.errors if e['severity'] == 'error'),
            'warning_count': sum(1 for e in self.errors if e['severity'] == 'warning')
        }


# ========================================================================
# 유틸리티 함수
# ========================================================================
def _build_group_to_products_map(pt: Dict) -> Dict[str, Set[str]]:
    g2p: Dict[str, Set[str]] = {}
    for group in pt.get('product_groups', []):
        gid = group.get('group_id')
        if gid:
            g2p[gid] = set(group.get('product_ids', []))
    return g2p


# vers 형식 패턴: vers:<scheme>/<constraints>
_VERS_PATTERN = re.compile(r'^vers:([a-z][a-z0-9]*)/(.+)$')

# vers "all versions" 특수 문자열
_VERS_ALL = 'vers:all/*'

# 유효한 비교 연산자
_VALID_COMPARATORS = {'<', '>', '<=', '>=', '!=', '='}

# 단일 version-constraint 패턴: [comparator]version
_CONSTRAINT_PATTERN = re.compile(r'^(<=|>=|!=|<|>|=)?(.+)$')


def _validate_version_range_name(name: str) -> List[str]:
    """
    product_version_range 브랜치의 name이 vers 또는 vls 형식을 따르는지 검증한다.

    CSAF 2.1 명세 3.1.2.3.2:
      1. vers (Version Range Specifier): vers:<scheme>/<constraints>
         - vers:all/* 은 "all versions"
         - canonical form 필수
      2. vls (Vers-like Specifier): <constraints>만 사용 (scheme 없음)
         - vers: 접두사, scheme 부분이 없어야 함

    Returns:
        오류 메시지 목록 (빈 리스트 = 유효)
    """
    if not name or not isinstance(name, str):
        return ['product_version_range name is empty']

    name = name.strip()

    # vers:all/* 특수 케이스
    if name == _VERS_ALL:
        return []

    # vers 형식 시도
    vers_match = _VERS_PATTERN.match(name)
    if vers_match:
        return _validate_vers_format(name, vers_match.group(1), vers_match.group(2))

    # vers: 접두사가 있지만 형식이 잘못된 경우
    if name.startswith('vers:'):
        return [f'Invalid vers format: must be "vers:<scheme>/<constraints>", got "{name}"']

    # vls 형식 시도 (vers: 접두사 없는 constraint만)
    return _validate_vls_format(name)


def _validate_vers_format(full: str, scheme: str, constraints: str) -> List[str]:
    """
    vers 형식 검증: vers:<scheme>/<constraints>

    - scheme은 소문자 알파벳+숫자
    - constraints는 '|'로 분리된 version-constraint 목록
    - 각 constraint는 [comparator]version
    """
    issues = []

    # scheme 검증
    if not re.match(r'^[a-z][a-z0-9]*$', scheme):
        issues.append(f'Invalid vers scheme: "{scheme}" (must be lowercase alphanumeric)')

    # constraints 검증
    if not constraints:
        issues.append('vers constraints part is empty')
        return issues

    constraint_issues = _validate_constraints(constraints)
    issues.extend(constraint_issues)

    # canonical form 검증: 중복 제거, 정렬 등
    # 기본적으로 constraints가 비어있지 않으면 허용
    # (전체 canonical form 정규화는 vers 명세 구현체에서 수행)

    return issues


def _validate_vls_format(name: str) -> List[str]:
    """
    vls 형식 검증: <version-constraints>만 (scheme 없음)

    - vers: 접두사 없어야 함
    - URI 형식 불가
    """
    issues = []

    # URI가 포함되어 있으면 vls가 아님
    if '://' in name:
        issues.append(f'vls format must not contain URI: "{name}"')
        return issues

    # constraints 파싱
    constraint_issues = _validate_constraints(name)
    issues.extend(constraint_issues)

    return issues


def _validate_constraints(constraints_str: str) -> List[str]:
    """
    '|'로 분리된 version-constraint 목록을 검증한다.
    각 constraint: [comparator]version
    comparator: <, >, <=, >=, !=, = (또는 생략 = exact match)
    """
    issues = []

    if not constraints_str:
        issues.append('Empty constraints')
        return issues

    parts = constraints_str.split('|')
    if not parts:
        issues.append('No constraints found')
        return issues

    for i, part in enumerate(parts):
        part = part.strip()
        if not part:
            issues.append(f'Empty constraint at position {i}')
            continue

        # * 는 vers:all/* 에서만 유효 (이미 상위에서 처리)
        if part == '*' and len(parts) == 1:
            continue

        match = _CONSTRAINT_PATTERN.match(part)
        if not match:
            issues.append(f'Invalid constraint format: "{part}"')
            continue

        comparator = match.group(1) or ''
        version = match.group(2)

        # 비교 연산자 유효성
        if comparator and comparator not in _VALID_COMPARATORS:
            issues.append(f'Invalid comparator "{comparator}" in constraint "{part}"')

        # 버전 부분이 비어있으면 안 됨
        if not version or not version.strip():
            issues.append(f'Empty version in constraint "{part}"')

    return issues


# ========================================================================
# 공개 검증 인터페이스
# ========================================================================
def validate_csaf(data: Dict[str, Any], schema: Optional[Dict] = None,
                  doc_version: str = '') -> Tuple[bool, List[Dict], str]:
    validator = CSAFValidator(data, schema)
    result = validator.validate()
    return result['valid'], result['errors'], result['version']


# ========================================================================
# UI용 규칙 문서 (통합 네이밍)
# ========================================================================
VALIDATION_RULES = {
    'schema': [
        {'id': 'SCHEMA_CSAF_001', 'section': 'Schema', 'desc': '[Schema] JSON Schema validation failed'},
    ],
    'mandatory_common': [
        {'id': 'CSAF_SEMANTIC_REF_PRODUCT_ID_DEFINED', 'section': '6.1.1', 'desc': '[6.1.1] Product ID not defined'},
        {'id': 'CSAF_SEMANTIC_REF_PRODUCT_ID_UNIQUE', 'section': '6.1.2', 'desc': '[6.1.2] Duplicate Product ID'},
        {'id': 'CSAF_SEMANTIC_REF_PRODUCT_ID_CIRCULAR', 'section': '6.1.3', 'desc': '[6.1.3] Circular Product ID'},
        {'id': 'CSAF_SEMANTIC_REF_GROUP_ID_DEFINED', 'section': '6.1.4', 'desc': '[6.1.4] Group ID not defined'},
        {'id': 'CSAF_SEMANTIC_REF_GROUP_ID_UNIQUE', 'section': '6.1.5', 'desc': '[6.1.5] Duplicate Group ID'},
        {'id': 'CSAF_SEMANTIC_STATUS_CONTRADICTION', 'section': '6.1.6', 'desc': '[6.1.6] Contradicting status'},
        {'id': 'CSAF_SEMANTIC_SCORE_CVSS_DUPLICATE', 'section': '6.1.7', 'desc': '[6.1.7] Duplicate CVSS score'},
        {'id': 'CSAF_SEMANTIC_CVSS_INVALID', 'section': '6.1.8', 'desc': '[6.1.8] Invalid CVSS'},
        {'id': 'CSAF_SEMANTIC_CVSS_COMPUTATION', 'section': '6.1.9', 'desc': '[6.1.9] Invalid CVSS computation'},
        {'id': 'CSAF_SEMANTIC_CVSS_INCONSISTENT', 'section': '6.1.10', 'desc': '[6.1.10] Inconsistent CVSS'},
        {'id': 'CSAF_SEMANTIC_ID_CWE_FORMAT', 'section': '6.1.11', 'desc': '[6.1.11] Invalid CWE'},
        {'id': 'CSAF_SEMANTIC_DOC_LANG_INVALID', 'section': '6.1.12', 'desc': '[6.1.12] Invalid language'},
        {'id': 'CSAF_SEMANTIC_ID_PURL_FORMAT', 'section': '6.1.13', 'desc': '[6.1.13] Invalid PURL'},
        {'id': 'CSAF_SEMANTIC_DOC_REVISION_ORDER', 'section': '6.1.14', 'desc': '[6.1.14] Unsorted revision history'},
        {'id': 'CSAF_SEMANTIC_DOC_TRANSLATOR_LANG', 'section': '6.1.15', 'desc': '[6.1.15] Translator requires source_lang'},
        {'id': 'CSAF_SEMANTIC_DOC_VERSION_MATCH', 'section': '6.1.16', 'desc': '[6.1.16] Version mismatch'},
        {'id': 'CSAF_SEMANTIC_DOC_STATUS_DRAFT', 'section': '6.1.17', 'desc': '[6.1.17] Draft version requires draft status'},
        {'id': 'CSAF_SEMANTIC_DOC_RELEASED_HISTORY', 'section': '6.1.18', 'desc': '[6.1.18] Draft in released history'},
        {'id': 'CSAF_SEMANTIC_DOC_REVISION_PRERELEASE', 'section': '6.1.19', 'desc': '[6.1.19] Pre-release in revision'},
        {'id': 'CSAF_SEMANTIC_DOC_VERSION_PRERELEASE', 'section': '6.1.20', 'desc': '[6.1.20] Pre-release in non-draft'},
        {'id': 'CSAF_SEMANTIC_DOC_REVISION_VERSION_MISSING', 'section': '6.1.21', 'desc': '[6.1.21] Missing version'},
        {'id': 'CSAF_SEMANTIC_DOC_REVISION_VERSION_DUPLICATE', 'section': '6.1.22', 'desc': '[6.1.22] Duplicate version'},
        {'id': 'CSAF_SEMANTIC_VULN_CVE_UNIQUE', 'section': '6.1.23', 'desc': '[6.1.23] Duplicate CVE'},
        {'id': 'CSAF_SEMANTIC_VULN_INVOLVEMENT_DUPLICATE', 'section': '6.1.24', 'desc': '[6.1.24] Duplicate involvement'},
        {'id': 'CSAF_SEMANTIC_ID_HASH_DUPLICATE', 'section': '6.1.25', 'desc': '[6.1.25] Duplicate hash algorithm'},
        {'id': 'CSAF_SEMANTIC_DOC_CATEGORY_PROHIBITED', 'section': '6.1.26', 'desc': '[6.1.26] Prohibited category'},
        {'id': 'CSAF_SEMANTIC_DOC_TRANSLATION_SAME_LANG', 'section': '6.1.28', 'desc': '[6.1.28] Same lang/source_lang'},
        {'id': 'CSAF_SEMANTIC_VEX_REMEDIATION_PRODUCT_REF', 'section': '6.1.29', 'desc': '[6.1.29] Remediation without product'},
        {'id': 'CSAF_SEMANTIC_DOC_VERSION_FORMAT_MIXED', 'section': '6.1.30', 'desc': '[6.1.30] Mixed versioning'},
        {'id': 'CSAF_SEMANTIC_PROD_VERSION_RANGE_BRANCH', 'section': '6.1.31', 'desc': '[6.1.31] Version range in product_version'},
        {'id': 'CSAF_SEMANTIC_VEX_FLAG_PRODUCT_REF', 'section': '6.1.32', 'desc': '[6.1.32] Flag without product'},
        {'id': 'CSAF_SEMANTIC_VEX_FLAG_DUPLICATE_PER_PRODUCT', 'section': '6.1.33', 'desc': '[6.1.33] Multiple flags per product'},
    ],
    'mandatory_v21': [
        {'id': 'CSAF_SEMANTIC_PROD_BRANCH_DEPTH', 'section': '6.1.34', 'desc': '[v2.1] [6.1.34] Branch depth > 30'},
        {'id': 'CSAF_SEMANTIC_VEX_REMEDIATION_CONTRADICTION', 'section': '6.1.35', 'desc': '[v2.1] [6.1.35] Contradicting remediations'},
        {'id': 'CSAF_SEMANTIC_VEX_STATUS_REMEDIATION_CONTRADICTION', 'section': '6.1.36', 'desc': '[v2.1] [6.1.36] Status-remediation contradiction'},
        {'id': 'CSAF_SEMANTIC_DOC_DATETIME_FORMAT', 'section': '6.1.37', 'desc': '[v2.1] [6.1.37] Invalid date-time'},
        {'id': 'CSAF_SEMANTIC_DOC_SHARING_MAX_UUID_TLP', 'section': '6.1.38', 'desc': '[v2.1] [6.1.38] Max UUID requires TLP:CLEAR'},
        {'id': 'CSAF_SEMANTIC_DOC_SHARING_CLEAR_UUID', 'section': '6.1.39', 'desc': '[v2.1] [6.1.39] TLP:CLEAR requires Max UUID'},
        {'id': 'CSAF_SEMANTIC_DOC_SHARING_NAME_INVALID', 'section': '6.1.40', 'desc': '[v2.1] [6.1.40] Invalid sharing group name'},
        {'id': 'CSAF_SEMANTIC_DOC_SHARING_NAME_MISSING', 'section': '6.1.41', 'desc': '[v2.1] [6.1.41] Missing sharing group name'},
        {'id': 'CSAF_SEMANTIC_ID_PURL_QUALIFIERS', 'section': '6.1.42', 'desc': '[v2.1] [6.1.42] PURLs differ beyond qualifiers'},
        {'id': 'CSAF_SEMANTIC_PROD_MULTI_STAR_MODEL', 'section': '6.1.43', 'desc': '[v2.1] [6.1.43] Multiple stars in model number'},
        {'id': 'CSAF_SEMANTIC_PROD_MULTI_STAR_SERIAL', 'section': '6.1.44', 'desc': '[v2.1] [6.1.44] Multiple stars in serial number'},
        {'id': 'CSAF_SEMANTIC_VULN_DISCLOSURE_DATE', 'section': '6.1.45', 'desc': '[v2.1] [6.1.45] Inconsistent disclosure date'},
        {'id': 'CSAF_SEMANTIC_SSVC_INVALID', 'section': '6.1.46', 'desc': '[v2.1] [6.1.46] Invalid SSVC'},
        {'id': 'CSAF_SEMANTIC_SSVC_ID_INCONSISTENT', 'section': '6.1.47', 'desc': '[v2.1] [6.1.47] Inconsistent SSVC ID'},
        {'id': 'CSAF_SEMANTIC_SSVC_DECISION_POINTS', 'section': '6.1.48', 'desc': '[v2.1] [6.1.48] SSVC decision points'},
        {'id': 'CSAF_SEMANTIC_SSVC_TIMESTAMP', 'section': '6.1.49', 'desc': '[v2.1] [6.1.49] SSVC timestamp'},
        {'id': 'CSAF_SEMANTIC_PROD_VERSION_RANGE_RULES', 'section': '6.1.50', 'desc': '[v2.1] [6.1.50] Product version range rules'},
        {'id': 'CSAF_SEMANTIC_EPSS_TIMESTAMP', 'section': '6.1.51', 'desc': '[v2.1] [6.1.51] EPSS timestamp'},
        {'id': 'CSAF_SEMANTIC_EXPLOITATION_DATE_INCONSISTENT', 'section': '6.1.52', 'desc': '[v2.1] [6.1.52] Exploitation dates inconsistent'},
        {'id': 'CSAF_SEMANTIC_EXPLOITATION_DATE_ORDER', 'section': '6.1.53', 'desc': '[v2.1] [6.1.53] Exploitation date order'},
        {'id': 'CSAF_SEMANTIC_DOC_LICENSE_EXPRESSION', 'section': '6.1.54', 'desc': '[v2.1] [6.1.54] Invalid license expression'},
        {'id': 'CSAF_SEMANTIC_DOC_LICENSE_TEXT', 'section': '6.1.55', 'desc': '[v2.1] [6.1.55] Missing license text note'},
    ],
    'profile_common': [
        {'id': 'CSAF_SEMANTIC_PROFILE_DOC_NOTES', 'section': '6.1.27.1', 'desc': '[6.1.27.1] Document notes'},
        {'id': 'CSAF_SEMANTIC_PROFILE_DOC_REFERENCES', 'section': '6.1.27.2', 'desc': '[6.1.27.2] Document references'},
        {'id': 'CSAF_SEMANTIC_PROFILE_NO_VULNERABILITIES', 'section': '6.1.27.3', 'desc': '[6.1.27.3] No vulnerabilities'},
        {'id': 'CSAF_SEMANTIC_VEX_PRODUCT_TREE_REQUIRED', 'section': '6.1.27.4', 'desc': '[6.1.27.4] Product tree required'},
        {'id': 'CSAF_SEMANTIC_VEX_VULN_NOTES_REQUIRED', 'section': '6.1.27.5', 'desc': '[6.1.27.5] Vulnerability notes'},
        {'id': 'CSAF_SEMANTIC_PROFILE_PRODUCT_STATUS', 'section': '6.1.27.6', 'desc': '[6.1.27.6] Product status required'},
        {'id': 'CSAF_SEMANTIC_VEX_STATUS_REQUIRED', 'section': '6.1.27.7', 'desc': '[6.1.27.7] VEX product status'},
        {'id': 'CSAF_SEMANTIC_VEX_VULN_ID_REQUIRED', 'section': '6.1.27.8', 'desc': '[6.1.27.8] cve or ids required'},
        {'id': 'CSAF_SEMANTIC_VEX_IMPACT_STATEMENT_REQUIRED', 'section': '6.1.27.9', 'desc': '[6.1.27.9] Impact statement'},
        {'id': 'CSAF_SEMANTIC_VEX_ACTION_STATEMENT_REQUIRED', 'section': '6.1.27.10', 'desc': '[6.1.27.10] Action statement'},
        {'id': 'CSAF_SEMANTIC_VEX_VULNERABILITIES_REQUIRED', 'section': '6.1.27.11', 'desc': '[6.1.27.11] Vulnerabilities required'},
    ],
    'profile_v21': [
        {'id': 'CSAF_SEMANTIC_PROFILE_AFFECTED_PRODUCTS', 'section': '6.1.27.12', 'desc': '[v2.1] [6.1.27.12] Affected products'},
        {'id': 'CSAF_SEMANTIC_PROFILE_CORRESPONDING_AFFECTED', 'section': '6.1.27.13', 'desc': '[v2.1] [6.1.27.13] Corresponding affected'},
        {'id': 'CSAF_SEMANTIC_PROFILE_DOC_NOTES_DESC', 'section': '6.1.27.14', 'desc': '[v2.1] [6.1.27.14] Description note'},
        {'id': 'CSAF_SEMANTIC_PROFILE_NO_PRODUCT_TREE', 'section': '6.1.27.15', 'desc': '[v2.1] [6.1.27.15] No product tree'},
        {'id': 'CSAF_SEMANTIC_PROFILE_REVISION_MIN_TWO', 'section': '6.1.27.16', 'desc': '[v2.1] [6.1.27.16] Min 2 revisions'},
        {'id': 'CSAF_SEMANTIC_PROFILE_WITHDRAWAL_REASONING', 'section': '6.1.27.17', 'desc': '[v2.1] [6.1.27.17] Withdrawal reasoning'},
        {'id': 'CSAF_SEMANTIC_PROFILE_SUPERSESSION_REASONING', 'section': '6.1.27.18', 'desc': '[v2.1] [6.1.27.18] Supersession reasoning'},
        {'id': 'CSAF_SEMANTIC_PROFILE_SUPERSEDING_REFERENCE', 'section': '6.1.27.19', 'desc': '[v2.1] [6.1.27.19] Superseding document ref'},
    ]
}