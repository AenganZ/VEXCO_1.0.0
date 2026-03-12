"""
VEXco 외부 데이터 헬퍼 v1.0
CVSS 계산, CWE 검증, SSVC 의사결정 포인트 검증

의존성:
  - cvss (pip install cvss) : CVSS v2/v3 점수 계산 및 벡터 파싱
  - requests (선택)         : NVD API / CWE 다운로드

NVD API 키:
  이 파일 기준 상대 경로 ../../../NVD_API_KEY 또는
  환경 변수 NVD_API_KEY 에서 로드

사용 예:
  from vexco_external import CVSSHelper, CWEHelper, SSVCHelper
"""

import os
import re
import json
import logging
from decimal import Decimal
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger(__name__)

# ========================================================================
# CVSS Helper - 6.1.9 (computation) / 6.1.10 (inconsistency)
# ========================================================================

# cvss 라이브러리 로드 시도
try:
    from cvss import CVSS2, CVSS3
    HAS_CVSS_LIB = True
except ImportError:
    HAS_CVSS_LIB = False
    logger.warning("cvss library not available. Install: pip install cvss")

# CVSS v3 JSON 속성 → 벡터 약어 매핑
CVSS3_PROPERTY_TO_METRIC = {
    'attackVector': 'AV',
    'attackComplexity': 'AC',
    'privilegesRequired': 'PR',
    'userInteraction': 'UI',
    'scope': 'S',
    'confidentialityImpact': 'C',
    'integrityImpact': 'I',
    'availabilityImpact': 'A',
}

# CVSS v3 속성값 → 벡터 코드 매핑
CVSS3_VALUE_TO_CODE = {
    # attackVector
    'NETWORK': 'N', 'ADJACENT_NETWORK': 'A', 'LOCAL': 'L', 'PHYSICAL': 'P',
    # attackComplexity
    'LOW': 'L', 'HIGH': 'H',
    # privilegesRequired
    'NONE': 'N',
    # userInteraction
    'REQUIRED': 'R',
    # scope
    'UNCHANGED': 'U', 'CHANGED': 'C',
    # impact
}

# CVSS v3 baseSeverity 매핑
CVSS3_SEVERITY_MAP = {
    (0.0, 0.0): 'NONE',
    (0.1, 3.9): 'LOW',
    (4.0, 6.9): 'MEDIUM',
    (7.0, 8.9): 'HIGH',
    (9.0, 10.0): 'CRITICAL',
}


class CVSSHelper:
    """CVSS 점수 계산 및 벡터 일관성 검증"""

    @staticmethod
    def is_available() -> bool:
        return HAS_CVSS_LIB

    @staticmethod
    def compute_v3_scores(vector_string: str) -> Optional[Dict[str, Any]]:
        """
        CVSS v3 vectorString에서 점수와 severity를 계산한다.

        Returns:
            {'baseScore': float, 'baseSeverity': str,
             'temporalScore': float, 'environmentalScore': float,
             'metrics': dict} or None
        """
        if not HAS_CVSS_LIB:
            return None
        try:
            c = CVSS3(vector_string)
            sevs = c.severities()
            return {
                'baseScore': float(c.base_score),
                'baseSeverity': sevs[0].upper() if sevs else '',
                'temporalScore': float(c.temporal_score),
                'environmentalScore': float(c.environmental_score),
                'metrics': dict(c.metrics),
            }
        except Exception as e:
            logger.debug(f"CVSS3 parse error: {e}")
            return None

    @staticmethod
    def compute_v2_scores(vector_string: str) -> Optional[Dict[str, Any]]:
        """
        CVSS v2 vectorString에서 점수를 계산한다.

        Returns:
            {'baseScore': float, 'temporalScore': float,
             'environmentalScore': float} or None
        """
        if not HAS_CVSS_LIB:
            return None
        try:
            c = CVSS2(vector_string)
            return {
                'baseScore': float(c.base_score),
                'temporalScore': float(c.temporal_score),
                'environmentalScore': float(c.environmental_score),
            }
        except Exception as e:
            logger.debug(f"CVSS2 parse error: {e}")
            return None

    @staticmethod
    def validate_v3_computation(cvss_obj: Dict) -> List[Dict[str, str]]:
        """
        6.1.9: CVSS v3 객체의 점수가 vectorString에서 계산한 값과 일치하는지 검증.

        Returns:
            오류 목록 [{'field': str, 'expected': str, 'actual': str}, ...]
        """
        if not HAS_CVSS_LIB:
            return []

        vs = cvss_obj.get('vectorString', '')
        if not vs:
            return []

        computed = CVSSHelper.compute_v3_scores(vs)
        if not computed:
            return []

        issues = []

        # baseScore 비교
        doc_base = cvss_obj.get('baseScore')
        if doc_base is not None and abs(float(doc_base) - computed['baseScore']) > 0.05:
            issues.append({
                'field': 'baseScore',
                'expected': str(computed['baseScore']),
                'actual': str(doc_base)
            })

        # baseSeverity 비교
        doc_sev = cvss_obj.get('baseSeverity', '').upper()
        comp_sev = computed['baseSeverity']
        if doc_sev and comp_sev and doc_sev != comp_sev:
            issues.append({
                'field': 'baseSeverity',
                'expected': comp_sev,
                'actual': doc_sev
            })

        # temporalScore 비교 (있으면)
        doc_temp = cvss_obj.get('temporalScore')
        if doc_temp is not None and abs(float(doc_temp) - computed['temporalScore']) > 0.05:
            issues.append({
                'field': 'temporalScore',
                'expected': str(computed['temporalScore']),
                'actual': str(doc_temp)
            })

        # environmentalScore 비교 (있으면)
        doc_env = cvss_obj.get('environmentalScore')
        if doc_env is not None and abs(float(doc_env) - computed['environmentalScore']) > 0.05:
            issues.append({
                'field': 'environmentalScore',
                'expected': str(computed['environmentalScore']),
                'actual': str(doc_env)
            })

        return issues

    @staticmethod
    def validate_v3_consistency(cvss_obj: Dict) -> List[Dict[str, str]]:
        """
        6.1.10: CVSS v3 속성이 vectorString과 일관되는지 검증.
        vectorString이 우선한다.

        Returns:
            불일치 목록 [{'property': str, 'vector_value': str, 'json_value': str}, ...]
        """
        if not HAS_CVSS_LIB:
            return []

        vs = cvss_obj.get('vectorString', '')
        if not vs:
            return []

        computed = CVSSHelper.compute_v3_scores(vs)
        if not computed:
            return []

        metrics = computed['metrics']
        issues = []

        for json_prop, metric_key in CVSS3_PROPERTY_TO_METRIC.items():
            json_val = cvss_obj.get(json_prop)
            if json_val is None:
                continue

            # JSON 값을 벡터 코드로 변환
            json_code = CVSS3_VALUE_TO_CODE.get(json_val.upper(), json_val[0].upper() if json_val else '')
            vector_code = metrics.get(metric_key, '')

            if json_code and vector_code and json_code != vector_code:
                issues.append({
                    'property': json_prop,
                    'vector_value': vector_code,
                    'json_value': json_val
                })

        return issues

    @staticmethod
    def validate_v2_computation(cvss_obj: Dict) -> List[Dict[str, str]]:
        """6.1.9: CVSS v2 점수 검증"""
        if not HAS_CVSS_LIB:
            return []

        vs = cvss_obj.get('vectorString', '')
        if not vs:
            return []

        computed = CVSSHelper.compute_v2_scores(vs)
        if not computed:
            return []

        issues = []
        doc_base = cvss_obj.get('baseScore')
        if doc_base is not None and abs(float(doc_base) - computed['baseScore']) > 0.05:
            issues.append({
                'field': 'baseScore',
                'expected': str(computed['baseScore']),
                'actual': str(doc_base)
            })

        return issues


# ========================================================================
# CWE Helper - 6.1.11 (CWE 존재 및 유효성)
# ========================================================================

# 빌트인 CWE 간이 목록 (주요 ID만 포함, 전체 DB는 런타임 로드)
# 런타임에 _load_cwe_database()로 확장 가능
_CWE_CACHE: Dict[str, str] = {}
_CWE_LOADED = False

# CWE 카테고리/뷰 ID (v2.1: 이들은 실패해야 함)
_CWE_CATEGORIES_AND_VIEWS = set()


def _find_nvd_api_key() -> Optional[str]:
    """NVD API 키를 파일 또는 환경변수에서 검색"""
    # 환경변수 우선
    key = os.environ.get('NVD_API_KEY', '').strip()
    if key:
        return key

    # 파일 경로 탐색: csaf_validator.py 기준 ../../../NVD_API_KEY
    try:
        base = Path(__file__).resolve().parent
        for relative in ['../../../NVD_API_KEY', '../../NVD_API_KEY', '../NVD_API_KEY', 'NVD_API_KEY']:
            candidate = base / relative
            if candidate.exists():
                content = candidate.read_text().strip()
                if content:
                    return content
    except Exception:
        pass

    return None


def _load_cwe_database(force: bool = False) -> bool:
    """
    CWE 데이터베이스를 로드한다.
    1순위: 로컬 캐시 파일 (cwe_cache.json)
    2순위: MITRE CWE 목록 다운로드 (간이)

    Returns:
        True if loaded successfully
    """
    global _CWE_CACHE, _CWE_LOADED

    if _CWE_LOADED and not force:
        return True

    # 로컬 캐시 파일 확인
    try:
        base = Path(__file__).resolve().parent
        cache_path = base / 'cwe_cache.json'
        if cache_path.exists():
            with open(cache_path, 'r') as f:
                data = json.load(f)
                _CWE_CACHE = data.get('weaknesses', {})
                _CWE_CATEGORIES_AND_VIEWS.update(data.get('categories_and_views', []))
                _CWE_LOADED = True
                logger.info(f"CWE cache loaded: {len(_CWE_CACHE)} entries")
                return True
    except Exception as e:
        logger.debug(f"CWE cache load failed: {e}")

    # 캐시가 없으면 빈 상태로 진행 (ID 형식만 검증)
    _CWE_LOADED = True
    return False


class CWEHelper:
    """CWE 유효성 검증"""

    @staticmethod
    def validate(cwe_id: str, cwe_name: str, cwe_version: str = '') -> List[Dict[str, str]]:
        """
        CWE ID와 이름의 유효성을 검증한다.

        Returns:
            오류 목록 [{'type': 'not_found'|'name_mismatch'|'is_category', 'detail': str}, ...]
        """
        _load_cwe_database()

        issues = []

        # ID 형식 검사
        if not re.match(r'^CWE-\d+$', cwe_id):
            issues.append({'type': 'invalid_format', 'detail': f'Invalid CWE ID format: {cwe_id}'})
            return issues

        # 카테고리/뷰 검사 (v2.1: MUST fail)
        if cwe_id in _CWE_CATEGORIES_AND_VIEWS:
            issues.append({'type': 'is_category',
                           'detail': f'{cwe_id} is a CWE Category or View, not a Weakness'})

        # 이름 일치 검사 (캐시가 있을 때만)
        if _CWE_CACHE:
            expected_name = _CWE_CACHE.get(cwe_id)
            if expected_name is None:
                issues.append({'type': 'not_found', 'detail': f'{cwe_id} not found in CWE database'})
            elif cwe_name and expected_name.lower() != cwe_name.lower():
                issues.append({
                    'type': 'name_mismatch',
                    'detail': f'{cwe_id} name should be "{expected_name}", got "{cwe_name}"'
                })

        return issues

    @staticmethod
    def is_database_loaded() -> bool:
        return _CWE_LOADED and bool(_CWE_CACHE)


# ========================================================================
# SSVC Helper - 6.1.48 (Decision Points)
# ========================================================================

# SSVC 등록 네임스페이스
SSVC_REGISTERED_NAMESPACES = {'ssvc', 'cvss', 'nciss'}

# SSVC 주요 Decision Points (namespace=ssvc) - 버전별 유효한 값
# 출처: https://github.com/CERTCC/SSVC
SSVC_DECISION_POINTS = {
    'ssvc': {
        'Exploitation': {
            '1.1.0': ['None', 'PoC', 'Active'],
            '1.0.0': ['None', 'PoC', 'Active'],
        },
        'Automatable': {
            '1.0.0': ['No', 'Yes'],
        },
        'Technical Impact': {
            '1.0.0': ['Partial', 'Total'],
        },
        'Mission Prevalence': {
            '1.0.0': ['Minimal', 'Support', 'Essential'],
        },
        'Public Well-being Impact': {
            '1.0.0': ['Minimal', 'Material', 'Irreversible'],
        },
        'Mission Impact': {
            '1.0.0': ['None', 'Degraded', 'MEF Support Crippled', 'MEF Failure', 'Mission Failure'],
        },
        'Safety Impact': {
            '1.0.0': ['None', 'Minor', 'Major', 'Hazardous', 'Catastrophic'],
        },
        'System Exposure': {
            '1.0.0': ['Small', 'Controlled', 'Open'],
        },
        'Value Density': {
            '1.0.0': ['Diffuse', 'Concentrated'],
        },
        'Human Impact': {
            '1.0.0': ['Low', 'Medium', 'High', 'Very High'],
        },
        'Utility': {
            '1.0.0': ['Laborious', 'Efficient', 'Super Effective'],
        },
    }
}


class SSVCHelper:
    """SSVC Decision Point 유효성 검증"""

    @staticmethod
    def validate_selection(name: str, namespace: str, version: str,
                           values: List[str]) -> List[Dict[str, str]]:
        """
        SSVC selection 항목을 검증한다.

        Returns:
            오류 목록 [{'type': str, 'detail': str}, ...]
        """
        issues = []

        # 미등록 네임스페이스는 패스
        if namespace not in SSVC_REGISTERED_NAMESPACES:
            return issues

        ns_points = SSVC_DECISION_POINTS.get(namespace, {})
        point_def = ns_points.get(name)

        if point_def is None:
            issues.append({
                'type': 'unknown_decision_point',
                'detail': f'Decision point "{name}" not found in namespace "{namespace}"'
            })
            return issues

        valid_values = point_def.get(version)
        if valid_values is None:
            # 알려진 버전이 없으면 경고만
            known_versions = list(point_def.keys())
            issues.append({
                'type': 'unknown_version',
                'detail': f'Version "{version}" not known for "{name}". Known: {known_versions}'
            })
            return issues

        # 값 유효성 검사
        for val in values:
            if val not in valid_values:
                issues.append({
                    'type': 'invalid_value',
                    'detail': f'Value "{val}" not valid for "{name}" v{version}. Valid: {valid_values}'
                })

        # 순서 검사: values의 순서가 정의 순서와 일치해야 함
        if len(values) > 1:
            indices = []
            for val in values:
                if val in valid_values:
                    indices.append(valid_values.index(val))
            if indices != sorted(indices):
                issues.append({
                    'type': 'wrong_order',
                    'detail': f'Values for "{name}" must follow definition order: {valid_values}'
                })

        return issues


# ========================================================================
# NVD API Key 로더
# ========================================================================

class NVDAPIKey:
    """NVD API 키 관리"""
    _key: Optional[str] = None
    _loaded: bool = False

    @classmethod
    def get(cls) -> Optional[str]:
        if not cls._loaded:
            cls._key = _find_nvd_api_key()
            cls._loaded = True
            if cls._key:
                logger.info("NVD API key loaded")
            else:
                logger.info("NVD API key not found (CWE name validation will be limited)")
        return cls._key

    @classmethod
    def is_available(cls) -> bool:
        return cls.get() is not None