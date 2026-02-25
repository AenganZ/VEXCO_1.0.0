"""
CSAF VEX 프로필 검증기 v1.0.0
CSAF 2.0 명세 기반 VEX 프로필 검증 규칙

참조:
- CSAF 2.0 명세서 Section 4.5 (VEX Profile)
- CSAF 2.0 명세서 Section 6.1 (Mandatory Tests)

Mandatory Tests:
- 6.1.1~26: 일반 필수 테스트
- 6.1.27.4~11: VEX 프로필 전용 테스트

심각도:
- error: MUST 규칙 (검증 실패)
- warning: SHOULD 규칙 (권장사항)
"""

import re
from datetime import datetime
from typing import Dict, List, Any, Optional, Set, Tuple

try:
    import jsonschema
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False

# PURL 패턴
PURL_PATTERN = re.compile(r'^pkg:[a-z]+/.+')

# VEX Justification 라벨 (6.1.33)
VEX_JUSTIFICATION_LABELS = {
    'component_not_present',
    'vulnerable_code_not_present',
    'vulnerable_code_cannot_be_controlled_by_adversary',
    'vulnerable_code_not_in_execute_path',
    'inline_mitigations_already_exist'
}


class CSAFValidator:
    """CSAF 2.0 VEX 프로필 검증기"""
    
    VERSION = "1.0.0"
    
    def __init__(self, data: Dict[str, Any], schema: Optional[Dict] = None):
        self.data = data
        self.schema = schema
        self.errors: List[Dict[str, Any]] = []
        self.doc_version = self._detect_version()
        
        # Product ID/Group ID 수집
        self.defined_product_ids: Set[str] = set()
        self.defined_group_ids: Set[str] = set()
        self.product_id_locations: Dict[str, List[str]] = {}
        self.group_id_locations: Dict[str, List[str]] = {}
        
    def _detect_version(self) -> str:
        """CSAF 버전 감지"""
        doc = self.data.get('document', {})
        return doc.get('csaf_version', '2.0')
    
    def _add_error(self, rule_id: str, message: str, path: str, detail: str = ''):
        """에러 추가"""
        self.errors.append({
            'rule_id': rule_id,
            'severity': 'error',
            'message': message,
            'path': path,
            'detail': detail
        })
    
    def _add_warning(self, rule_id: str, message: str, path: str, detail: str = ''):
        """경고 추가"""
        self.errors.append({
            'rule_id': rule_id,
            'severity': 'warning',
            'message': message,
            'path': path,
            'detail': detail
        })
    
    def validate(self) -> Dict[str, Any]:
        """전체 검증 실행"""
        
        # 1단계: JSON Schema 검증
        self._validate_schema()
        
        # 2단계: Product ID/Group ID 수집
        self._collect_product_ids()
        self._collect_group_ids()
        
        # 3단계: 일반 Mandatory Tests (6.1.1~26)
        self._test_6_1_1_missing_product_id()
        self._test_6_1_2_multiple_product_id()
        self._test_6_1_4_missing_group_id()
        self._test_6_1_5_multiple_group_id()
        self._test_6_1_6_contradicting_status()
        self._test_6_1_13_purl()
        self._test_6_1_23_multiple_cve()
        self._test_6_1_29_remediation_without_product()
        self._test_6_1_32_flag_without_product()
        self._test_6_1_33_multiple_flags_per_product()
        
        # 4단계: VEX 프로필 테스트 (6.1.27.4~11)
        self._test_vex_category()
        self._test_6_1_27_4_product_tree()
        self._test_6_1_27_5_vulnerability_notes()
        self._test_6_1_27_7_vex_product_status()
        self._test_6_1_27_8_vulnerability_id()
        self._test_6_1_27_9_impact_statement()
        self._test_6_1_27_10_action_statement()
        self._test_6_1_27_11_vulnerabilities()
        
        return self._build_result()
    
    def _validate_schema(self):
        """JSON Schema 검증"""
        if not self.schema or not HAS_JSONSCHEMA:
            return
        
        try:
            validator = jsonschema.Draft7Validator(self.schema)
            schema_errors = sorted(validator.iter_errors(self.data), key=lambda e: e.path)
            
            for error in schema_errors:
                path = "/" + "/".join(str(p) for p in error.path) if error.path else "/"
                self._add_error(
                    'SCHEMA-CSAF-001',
                    f'JSON Schema validation failed: {error.message}',
                    path,
                    ''
                )
        except Exception as e:
            self._add_error(
                'SCHEMA-CSAF-000',
                f'Schema validation error: {str(e)}',
                '/',
                ''
            )
    
    def _collect_product_ids(self):
        """Product ID 정의 위치 수집 (6.1.1, 6.1.2용)"""
        pt = self.data.get('product_tree', {})
        
        def collect_from_branches(branches, path_prefix):
            for idx, branch in enumerate(branches or []):
                branch_path = f'{path_prefix}[{idx}]'
                
                # branch.product.product_id
                product = branch.get('product', {})
                if product and 'product_id' in product:
                    pid = product['product_id']
                    self.defined_product_ids.add(pid)
                    if pid not in self.product_id_locations:
                        self.product_id_locations[pid] = []
                    self.product_id_locations[pid].append(f'{branch_path}/product/product_id')
                
                # 재귀적으로 하위 branches 처리
                if 'branches' in branch:
                    collect_from_branches(branch['branches'], f'{branch_path}/branches')
        
        # /product_tree/branches
        collect_from_branches(pt.get('branches', []), '/product_tree/branches')
        
        # /product_tree/full_product_names
        for idx, fpn in enumerate(pt.get('full_product_names', [])):
            if 'product_id' in fpn:
                pid = fpn['product_id']
                self.defined_product_ids.add(pid)
                if pid not in self.product_id_locations:
                    self.product_id_locations[pid] = []
                self.product_id_locations[pid].append(f'/product_tree/full_product_names[{idx}]/product_id')
        
        # /product_tree/relationships
        for idx, rel in enumerate(pt.get('relationships', [])):
            fpn = rel.get('full_product_name', {})
            if 'product_id' in fpn:
                pid = fpn['product_id']
                self.defined_product_ids.add(pid)
                if pid not in self.product_id_locations:
                    self.product_id_locations[pid] = []
                self.product_id_locations[pid].append(f'/product_tree/relationships[{idx}]/full_product_name/product_id')
    
    def _collect_group_ids(self):
        """Product Group ID 정의 위치 수집 (6.1.4, 6.1.5용)"""
        pt = self.data.get('product_tree', {})
        
        for idx, group in enumerate(pt.get('product_groups', [])):
            if 'group_id' in group:
                gid = group['group_id']
                self.defined_group_ids.add(gid)
                if gid not in self.group_id_locations:
                    self.group_id_locations[gid] = []
                self.group_id_locations[gid].append(f'/product_tree/product_groups[{idx}]/group_id')
    
    # =========================================================================
    # 6.1.1 Missing Definition of Product ID
    # =========================================================================
    def _test_6_1_1_missing_product_id(self):
        """6.1.1: 참조된 Product ID가 product_tree에 정의되어 있는지 검증"""
        pt = self.data.get('product_tree', {})
        vulns = self.data.get('vulnerabilities', [])
        
        # product_groups의 product_ids 검사
        for g_idx, group in enumerate(pt.get('product_groups', [])):
            for p_idx, pid in enumerate(group.get('product_ids', [])):
                if pid not in self.defined_product_ids:
                    self._add_error(
                        'CSAF-6.1.1',
                        f'Product ID "{pid}" is not defined in product_tree',
                        f'/product_tree/product_groups[{g_idx}]/product_ids[{p_idx}]',
                        'All referenced Product IDs must be defined in product_tree'
                    )
        
        # relationships의 product_reference, relates_to_product_reference 검사
        for r_idx, rel in enumerate(pt.get('relationships', [])):
            for field in ['product_reference', 'relates_to_product_reference']:
                pid = rel.get(field)
                if pid and pid not in self.defined_product_ids:
                    self._add_error(
                        'CSAF-6.1.1',
                        f'Product ID "{pid}" is not defined in product_tree',
                        f'/product_tree/relationships[{r_idx}]/{field}',
                        ''
                    )
        
        # vulnerabilities의 product_status, remediations, threats, scores 검사
        status_fields = ['fixed', 'known_affected', 'known_not_affected', 'under_investigation',
                         'first_affected', 'first_fixed', 'last_affected', 'recommended']
        
        for v_idx, vuln in enumerate(vulns):
            v_path = f'/vulnerabilities[{v_idx}]'
            
            # product_status
            ps = vuln.get('product_status', {})
            for field in status_fields:
                for p_idx, pid in enumerate(ps.get(field, [])):
                    if pid not in self.defined_product_ids:
                        self._add_error(
                            'CSAF-6.1.1',
                            f'Product ID "{pid}" is not defined in product_tree',
                            f'{v_path}/product_status/{field}[{p_idx}]',
                            ''
                        )
            
            # remediations[].product_ids
            for r_idx, rem in enumerate(vuln.get('remediations', [])):
                for p_idx, pid in enumerate(rem.get('product_ids', [])):
                    if pid not in self.defined_product_ids:
                        self._add_error(
                            'CSAF-6.1.1',
                            f'Product ID "{pid}" is not defined in product_tree',
                            f'{v_path}/remediations[{r_idx}]/product_ids[{p_idx}]',
                            ''
                        )
            
            # threats[].product_ids
            for t_idx, threat in enumerate(vuln.get('threats', [])):
                for p_idx, pid in enumerate(threat.get('product_ids', [])):
                    if pid not in self.defined_product_ids:
                        self._add_error(
                            'CSAF-6.1.1',
                            f'Product ID "{pid}" is not defined in product_tree',
                            f'{v_path}/threats[{t_idx}]/product_ids[{p_idx}]',
                            ''
                        )
            
            # scores[].products
            for s_idx, score in enumerate(vuln.get('scores', [])):
                for p_idx, pid in enumerate(score.get('products', [])):
                    if pid not in self.defined_product_ids:
                        self._add_error(
                            'CSAF-6.1.1',
                            f'Product ID "{pid}" is not defined in product_tree',
                            f'{v_path}/scores[{s_idx}]/products[{p_idx}]',
                            ''
                        )
    
    # =========================================================================
    # 6.1.2 Multiple Definition of Product ID
    # =========================================================================
    def _test_6_1_2_multiple_product_id(self):
        """6.1.2: Product ID 중복 정의 검사"""
        for pid, locations in self.product_id_locations.items():
            if len(locations) > 1:
                self._add_error(
                    'CSAF-6.1.2',
                    f'Product ID "{pid}" is defined {len(locations)} times',
                    locations[0],
                    f'Locations: {", ".join(locations)}'
                )
    
    # =========================================================================
    # 6.1.4 Missing Definition of Product Group ID
    # =========================================================================
    def _test_6_1_4_missing_group_id(self):
        """6.1.4: 참조된 Group ID가 정의되어 있는지 검증"""
        vulns = self.data.get('vulnerabilities', [])
        
        for v_idx, vuln in enumerate(vulns):
            v_path = f'/vulnerabilities[{v_idx}]'
            
            # remediations[].group_ids
            for r_idx, rem in enumerate(vuln.get('remediations', [])):
                for g_idx, gid in enumerate(rem.get('group_ids', [])):
                    if gid not in self.defined_group_ids:
                        self._add_error(
                            'CSAF-6.1.4',
                            f'Group ID "{gid}" is not defined in product_tree',
                            f'{v_path}/remediations[{r_idx}]/group_ids[{g_idx}]',
                            ''
                        )
            
            # threats[].group_ids
            for t_idx, threat in enumerate(vuln.get('threats', [])):
                for g_idx, gid in enumerate(threat.get('group_ids', [])):
                    if gid not in self.defined_group_ids:
                        self._add_error(
                            'CSAF-6.1.4',
                            f'Group ID "{gid}" is not defined in product_tree',
                            f'{v_path}/threats[{t_idx}]/group_ids[{g_idx}]',
                            ''
                        )
    
    # =========================================================================
    # 6.1.5 Multiple Definition of Product Group ID
    # =========================================================================
    def _test_6_1_5_multiple_group_id(self):
        """6.1.5: Group ID 중복 정의 검사"""
        for gid, locations in self.group_id_locations.items():
            if len(locations) > 1:
                self._add_error(
                    'CSAF-6.1.5',
                    f'Group ID "{gid}" is defined {len(locations)} times',
                    locations[0],
                    f'Locations: {", ".join(locations)}'
                )
    
    # =========================================================================
    # 6.1.6 Contradicting Product Status
    # =========================================================================
    def _test_6_1_6_contradicting_status(self):
        """6.1.6: 모순되는 Product Status 검사"""
        vulns = self.data.get('vulnerabilities', [])
        
        # 모순 그룹 정의
        affected_fields = ['first_affected', 'known_affected', 'last_affected']
        not_affected_fields = ['known_not_affected']
        fixed_fields = ['first_fixed', 'fixed']
        under_investigation_fields = ['under_investigation']
        
        for v_idx, vuln in enumerate(vulns):
            v_path = f'/vulnerabilities[{v_idx}]'
            ps = vuln.get('product_status', {})
            
            # 각 그룹별 Product ID 수집
            affected = set()
            for f in affected_fields:
                affected.update(ps.get(f, []))
            
            not_affected = set()
            for f in not_affected_fields:
                not_affected.update(ps.get(f, []))
            
            fixed = set()
            for f in fixed_fields:
                fixed.update(ps.get(f, []))
            
            under_inv = set()
            for f in under_investigation_fields:
                under_inv.update(ps.get(f, []))
            
            # 모순 검사
            groups = [
                ('Affected', affected),
                ('Not Affected', not_affected),
                ('Fixed', fixed),
                ('Under Investigation', under_inv)
            ]
            
            for i, (name1, set1) in enumerate(groups):
                for name2, set2 in groups[i+1:]:
                    overlap = set1 & set2
                    for pid in overlap:
                        self._add_error(
                            'CSAF-6.1.6',
                            f'Product ID "{pid}" has contradicting status: {name1} and {name2}',
                            f'{v_path}/product_status',
                            ''
                        )
    
    # =========================================================================
    # 6.1.13 PURL
    # =========================================================================
    def _test_6_1_13_purl(self):
        """6.1.13: PURL 형식 검증"""
        pt = self.data.get('product_tree', {})
        
        def check_pih(pih: Dict, path: str):
            purl = pih.get('purl')
            if purl:
                if not PURL_PATTERN.match(purl):
                    self._add_error(
                        'CSAF-6.1.13',
                        f'Invalid PURL format: "{purl}"',
                        f'{path}/purl',
                        'PURL must start with "pkg:" followed by type and path'
                    )
            
            # purls 배열도 검사
            for idx, p in enumerate(pih.get('purls', [])):
                if not PURL_PATTERN.match(p):
                    self._add_error(
                        'CSAF-6.1.13',
                        f'Invalid PURL format: "{p}"',
                        f'{path}/purls[{idx}]',
                        ''
                    )
        
        def check_branches(branches, path_prefix):
            for idx, branch in enumerate(branches or []):
                branch_path = f'{path_prefix}[{idx}]'
                product = branch.get('product', {})
                if product:
                    pih = product.get('product_identification_helper', {})
                    check_pih(pih, f'{branch_path}/product/product_identification_helper')
                
                if 'branches' in branch:
                    check_branches(branch['branches'], f'{branch_path}/branches')
        
        # branches 검사
        check_branches(pt.get('branches', []), '/product_tree/branches')
        
        # full_product_names 검사
        for idx, fpn in enumerate(pt.get('full_product_names', [])):
            pih = fpn.get('product_identification_helper', {})
            check_pih(pih, f'/product_tree/full_product_names[{idx}]/product_identification_helper')
        
        # relationships 검사
        for idx, rel in enumerate(pt.get('relationships', [])):
            fpn = rel.get('full_product_name', {})
            pih = fpn.get('product_identification_helper', {})
            check_pih(pih, f'/product_tree/relationships[{idx}]/full_product_name/product_identification_helper')
    
    # =========================================================================
    # 6.1.23 Multiple Use of Same CVE
    # =========================================================================
    def _test_6_1_23_multiple_cve(self):
        """6.1.23: 동일 CVE 중복 사용 검사"""
        vulns = self.data.get('vulnerabilities', [])
        cve_locations: Dict[str, List[int]] = {}
        
        for v_idx, vuln in enumerate(vulns):
            cve = vuln.get('cve')
            if cve:
                if cve not in cve_locations:
                    cve_locations[cve] = []
                cve_locations[cve].append(v_idx)
        
        for cve, indices in cve_locations.items():
            if len(indices) > 1:
                self._add_error(
                    'CSAF-6.1.23',
                    f'CVE "{cve}" is used in multiple vulnerability entries',
                    f'/vulnerabilities[{indices[0]}]/cve',
                    f'Indices: {indices}'
                )
    
    # =========================================================================
    # 6.1.29 Remediation without Product Reference
    # =========================================================================
    def _test_6_1_29_remediation_without_product(self):
        """6.1.29: product_ids 또는 group_ids 없는 remediation 검사"""
        vulns = self.data.get('vulnerabilities', [])
        
        for v_idx, vuln in enumerate(vulns):
            v_path = f'/vulnerabilities[{v_idx}]'
            
            for r_idx, rem in enumerate(vuln.get('remediations', [])):
                has_products = bool(rem.get('product_ids'))
                has_groups = bool(rem.get('group_ids'))
                
                if not has_products and not has_groups:
                    self._add_error(
                        'CSAF-6.1.29',
                        'Remediation has no product_ids or group_ids',
                        f'{v_path}/remediations[{r_idx}]',
                        'Target products must be specified'
                    )
    
    # =========================================================================
    # 6.1.32 Flag without Product Reference
    # =========================================================================
    def _test_6_1_32_flag_without_product(self):
        """6.1.32: product_ids 또는 group_ids 없는 flag 검사"""
        vulns = self.data.get('vulnerabilities', [])
        
        for v_idx, vuln in enumerate(vulns):
            v_path = f'/vulnerabilities[{v_idx}]'
            
            for f_idx, flag in enumerate(vuln.get('flags', [])):
                has_products = bool(flag.get('product_ids'))
                has_groups = bool(flag.get('group_ids'))
                
                if not has_products and not has_groups:
                    self._add_error(
                        'CSAF-6.1.32',
                        'Flag has no product_ids or group_ids',
                        f'{v_path}/flags[{f_idx}]',
                        'Target products must be specified'
                    )
    
    # =========================================================================
    # 6.1.33 Multiple Flags with VEX Justification Codes per Product
    # =========================================================================
    def _test_6_1_33_multiple_flags_per_product(self):
        """6.1.33: 동일 Product에 대한 다중 VEX Justification Flag 검사"""
        vulns = self.data.get('vulnerabilities', [])
        pt = self.data.get('product_tree', {})
        
        # Group ID → Product IDs 매핑
        group_to_products: Dict[str, Set[str]] = {}
        for group in pt.get('product_groups', []):
            gid = group.get('group_id')
            if gid:
                group_to_products[gid] = set(group.get('product_ids', []))
        
        for v_idx, vuln in enumerate(vulns):
            v_path = f'/vulnerabilities[{v_idx}]'
            
            # Product ID → Flag 라벨 매핑
            product_flags: Dict[str, List[str]] = {}
            
            for f_idx, flag in enumerate(vuln.get('flags', [])):
                label = flag.get('label', '')
                
                # VEX justification 라벨만 검사
                if label not in VEX_JUSTIFICATION_LABELS:
                    continue
                
                # 직접 참조된 product_ids
                for pid in flag.get('product_ids', []):
                    if pid not in product_flags:
                        product_flags[pid] = []
                    product_flags[pid].append(label)
                
                # group_ids를 통한 간접 참조
                for gid in flag.get('group_ids', []):
                    for pid in group_to_products.get(gid, []):
                        if pid not in product_flags:
                            product_flags[pid] = []
                        product_flags[pid].append(label)
            
            # 다중 flag 검사
            for pid, labels in product_flags.items():
                if len(labels) > 1:
                    self._add_error(
                        'CSAF-6.1.33',
                        f'Product "{pid}" has multiple VEX justification flags',
                        f'{v_path}/flags',
                        f'Labels: {", ".join(labels)}'
                    )
    
    # =========================================================================
    # VEX Profile - Category (4.5)
    # =========================================================================
    def _test_vex_category(self):
        """4.5: VEX 프로필은 category가 csaf_vex여야 함"""
        doc = self.data.get('document', {})
        category = doc.get('category', '')
        
        if category.lower() != 'csaf_vex':
            self._add_error(
                'CSAF-VEX-CAT',
                'VEX profile document.category must be "csaf_vex"',
                '/document/category',
                f'Current value: "{category}"'
            )
    
    # =========================================================================
    # 6.1.27.4 Product Tree
    # =========================================================================
    def _test_6_1_27_4_product_tree(self):
        """6.1.27.4: VEX 프로필은 product_tree 필수"""
        if 'product_tree' not in self.data:
            self._add_error(
                'CSAF-6.1.27.4',
                'VEX profile requires product_tree',
                '/product_tree',
                ''
            )
    
    # =========================================================================
    # 6.1.27.5 Vulnerability Notes
    # =========================================================================
    def _test_6_1_27_5_vulnerability_notes(self):
        """6.1.27.5: VEX 프로필은 vulnerabilities[]/notes 필수"""
        vulns = self.data.get('vulnerabilities', [])
        
        for v_idx, vuln in enumerate(vulns):
            if 'notes' not in vuln or not vuln['notes']:
                self._add_warning(
                    'CSAF-6.1.27.5',
                    'VEX profile recommends vulnerabilities[]/notes',
                    f'/vulnerabilities[{v_idx}]/notes',
                    'It is recommended to include detailed information in notes'
                )
    
    # =========================================================================
    # 6.1.27.7 VEX Product Status
    # =========================================================================
    def _test_6_1_27_7_vex_product_status(self):
        """6.1.27.7: VEX 프로필은 fixed/known_affected/known_not_affected/under_investigation 중 하나 필수"""
        vulns = self.data.get('vulnerabilities', [])
        vex_status_fields = ['fixed', 'known_affected', 'known_not_affected', 'under_investigation']
        
        for v_idx, vuln in enumerate(vulns):
            v_path = f'/vulnerabilities[{v_idx}]'
            ps = vuln.get('product_status', {})
            
            has_vex_status = any(ps.get(f) for f in vex_status_fields)
            
            if not has_vex_status:
                self._add_error(
                    'CSAF-6.1.27.7',
                    'VEX profile requires product_status with fixed/known_affected/known_not_affected/under_investigation',
                    f'{v_path}/product_status',
                    ''
                )
    
    # =========================================================================
    # 6.1.27.8 Vulnerability ID
    # =========================================================================
    def _test_6_1_27_8_vulnerability_id(self):
        """6.1.27.8: VEX 프로필은 cve 또는 ids 중 하나 필수"""
        vulns = self.data.get('vulnerabilities', [])
        
        for v_idx, vuln in enumerate(vulns):
            v_path = f'/vulnerabilities[{v_idx}]'
            
            has_cve = 'cve' in vuln and vuln['cve']
            has_ids = 'ids' in vuln and vuln['ids']
            
            if not has_cve and not has_ids:
                self._add_error(
                    'CSAF-6.1.27.8',
                    'VEX profile requires cve or ids',
                    v_path,
                    ''
                )
    
    # =========================================================================
    # 6.1.27.9 Impact Statement
    # =========================================================================
    def _test_6_1_27_9_impact_statement(self):
        """6.1.27.9: known_not_affected 제품에 대해 impact statement 필수"""
        vulns = self.data.get('vulnerabilities', [])
        pt = self.data.get('product_tree', {})
        
        # Group ID → Product IDs 매핑
        group_to_products: Dict[str, Set[str]] = {}
        for group in pt.get('product_groups', []):
            gid = group.get('group_id')
            if gid:
                group_to_products[gid] = set(group.get('product_ids', []))
        
        for v_idx, vuln in enumerate(vulns):
            v_path = f'/vulnerabilities[{v_idx}]'
            ps = vuln.get('product_status', {})
            
            kna_products = set(ps.get('known_not_affected', []))
            if not kna_products:
                continue
            
            # flags에서 커버된 제품 수집
            covered_by_flags = set()
            for flag in vuln.get('flags', []):
                for pid in flag.get('product_ids', []):
                    covered_by_flags.add(pid)
                for gid in flag.get('group_ids', []):
                    covered_by_flags.update(group_to_products.get(gid, []))
            
            # threats[category=impact]에서 커버된 제품 수집
            covered_by_threats = set()
            for threat in vuln.get('threats', []):
                if threat.get('category') == 'impact':
                    for pid in threat.get('product_ids', []):
                        covered_by_threats.add(pid)
                    for gid in threat.get('group_ids', []):
                        covered_by_threats.update(group_to_products.get(gid, []))
            
            # 커버되지 않은 제품 검사
            covered = covered_by_flags | covered_by_threats
            uncovered = kna_products - covered
            
            for pid in uncovered:
                self._add_error(
                    'CSAF-6.1.27.9',
                    f'No impact statement for known_not_affected product "{pid}"',
                    f'{v_path}/product_status/known_not_affected',
                    'Must be defined in flags or threats[category=impact]'
                )
    
    # =========================================================================
    # 6.1.27.10 Action Statement
    # =========================================================================
    def _test_6_1_27_10_action_statement(self):
        """6.1.27.10: known_affected 제품에 대해 action statement(remediation) 필수"""
        vulns = self.data.get('vulnerabilities', [])
        pt = self.data.get('product_tree', {})
        
        # Group ID → Product IDs 매핑
        group_to_products: Dict[str, Set[str]] = {}
        for group in pt.get('product_groups', []):
            gid = group.get('group_id')
            if gid:
                group_to_products[gid] = set(group.get('product_ids', []))
        
        for v_idx, vuln in enumerate(vulns):
            v_path = f'/vulnerabilities[{v_idx}]'
            ps = vuln.get('product_status', {})
            
            ka_products = set(ps.get('known_affected', []))
            if not ka_products:
                continue
            
            # remediations에서 커버된 제품 수집
            covered = set()
            for rem in vuln.get('remediations', []):
                for pid in rem.get('product_ids', []):
                    covered.add(pid)
                for gid in rem.get('group_ids', []):
                    covered.update(group_to_products.get(gid, []))
            
            # 커버되지 않은 제품 검사
            uncovered = ka_products - covered
            
            for pid in uncovered:
                self._add_error(
                    'CSAF-6.1.27.10',
                    f'No action statement for known_affected product "{pid}"',
                    f'{v_path}/product_status/known_affected',
                    'Must be defined in remediations'
                )
    
    # =========================================================================
    # 6.1.27.11 Vulnerabilities
    # =========================================================================
    def _test_6_1_27_11_vulnerabilities(self):
        """6.1.27.11: VEX 프로필은 vulnerabilities 필수"""
        if 'vulnerabilities' not in self.data or not self.data['vulnerabilities']:
            self._add_error(
                'CSAF-6.1.27.11',
                'VEX profile requires vulnerabilities',
                '/vulnerabilities',
                ''
            )
    
    def _build_result(self) -> Dict[str, Any]:
        """검증 결과 빌드"""
        has_errors = any(e['severity'] == 'error' for e in self.errors)
        
        return {
            'valid': not has_errors,
            'version': self.doc_version,
            'errors': self.errors,
            'error_count': sum(1 for e in self.errors if e['severity'] == 'error'),
            'warning_count': sum(1 for e in self.errors if e['severity'] == 'warning')
        }


def validate_csaf(data: Dict[str, Any], schema: Optional[Dict] = None, doc_version: str = '') -> Tuple[bool, List[Dict], str]:
    """
    CSAF VEX 프로필 검증 (app.py 호환 인터페이스)
    
    Returns:
        (is_valid, errors, detected_version)
    """
    validator = CSAFValidator(data, schema)
    result = validator.validate()
    
    return result['valid'], result['errors'], result['version']


# UI용 규칙 문서
VALIDATION_RULES = {
    'mandatory': [
        {'id': 'SCHEMA-CSAF-001', 'section': 'Schema', 'desc': 'JSON Schema validation failed'},
        {'id': 'CSAF-6.1.1', 'section': '6.1.1', 'desc': 'Referenced Product ID not defined in product_tree'},
        {'id': 'CSAF-6.1.2', 'section': '6.1.2', 'desc': 'Multiple definition of Product ID'},
        {'id': 'CSAF-6.1.4', 'section': '6.1.4', 'desc': 'Referenced Group ID not defined in product_tree'},
        {'id': 'CSAF-6.1.5', 'section': '6.1.5', 'desc': 'Multiple definition of Group ID'},
        {'id': 'CSAF-6.1.6', 'section': '6.1.6', 'desc': 'Contradicting Product Status'},
        {'id': 'CSAF-6.1.13', 'section': '6.1.13', 'desc': 'Invalid PURL format'},
        {'id': 'CSAF-6.1.23', 'section': '6.1.23', 'desc': 'Multiple use of same CVE'},
        {'id': 'CSAF-6.1.29', 'section': '6.1.29', 'desc': 'Remediation without product reference'},
        {'id': 'CSAF-6.1.32', 'section': '6.1.32', 'desc': 'Flag without product reference'},
        {'id': 'CSAF-6.1.33', 'section': '6.1.33', 'desc': 'Multiple VEX justification flags per product'},
    ],
    'vex_profile': [
        {'id': 'CSAF-VEX-CAT', 'section': '4.5', 'desc': 'VEX profile category must be "csaf_vex"'},
        {'id': 'CSAF-6.1.27.4', 'section': '6.1.27.4', 'desc': 'product_tree required'},
        {'id': 'CSAF-6.1.27.5', 'section': '6.1.27.5', 'desc': 'vulnerabilities[]/notes recommended'},
        {'id': 'CSAF-6.1.27.7', 'section': '6.1.27.7', 'desc': 'VEX Product Status required'},
        {'id': 'CSAF-6.1.27.8', 'section': '6.1.27.8', 'desc': 'cve or ids required'},
        {'id': 'CSAF-6.1.27.9', 'section': '6.1.27.9', 'desc': 'Impact statement required for known_not_affected'},
        {'id': 'CSAF-6.1.27.10', 'section': '6.1.27.10', 'desc': 'Action statement required for known_affected'},
        {'id': 'CSAF-6.1.27.11', 'section': '6.1.27.11', 'desc': 'vulnerabilities required'},
    ]
}