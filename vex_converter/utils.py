"""
VEX Converter 유틸리티 함수
"""
import json
import re
import uuid
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple, Any
from .models import Subject, Identifier

# ===== 제품 ID 유틸리티 =====

def validate_purl(purl: str) -> Tuple[bool, Optional[str]]:
    """
    공식 PURL 스펙에 대해 패키지 URL 검증.
    반환: (is_valid, error_message)

    PURL 형식: pkg:type/namespace/name@version?qualifiers#subpath
    """
    if not purl or not isinstance(purl, str):
        return False, "PURL cannot be empty"

    # 기본 패턴 검사
    if not purl.startswith("pkg:"):
        return False, "PURL must start with 'pkg:'"

    # pkg: 접두사 제거
    remainder = purl[4:]

    # type 추출 (필수)
    if "/" not in remainder:
        return False, "PURL must have format pkg:type/..."

    parts = remainder.split("/", 1)
    pkg_type = parts[0]

    # type은 점, 대시, 플러스가 있는 소문자 영숫자여야 함
    if not re.match(r'^[a-z0-9.\-+]+$', pkg_type):
        return False, f"Invalid package type: {pkg_type} (must be lowercase)"

    if len(parts) < 2:
        return False, "PURL must have name component"

    # name 및 선택적 컴포넌트 추출
    rest = parts[1]

    # 빈 세그먼트 확인
    if "//" in purl:
        return False, "PURL cannot have empty segments"

    # version, qualifiers, subpath 추출
    name_part = rest.split("@")[0].split("?")[0].split("#")[0]

    if not name_part:
        return False, "PURL must have name component"

    # name에서 유효하지 않은 문자 확인
    # name에는 문자, 숫자, 점, 대시, 밑줄, /가 포함될 수 있음
    if not re.match(r'^[a-zA-Z0-9.\-_/]+$', name_part):
        return False, f"Invalid characters in name: {name_part}"

    return True, None

def normalize_purl(purl: str) -> str:
    """
    PURL을 정규 형식으로 정규화.
    - type을 소문자로
    - 추가 슬래시 제거
    - 형식 검증
    """
    if not purl:
        return purl

    # 먼저 검증
    is_valid, error = validate_purl(purl)
    if not is_valid:
        # 유효하지 않으면 그대로 반환 (호출자가 처리해야 함)
        return purl

    # type을 소문자로
    if purl.startswith("pkg:"):
        parts = purl[4:].split("/", 1)
        if parts:
            pkg_type = parts[0].lower()
            if len(parts) > 1:
                purl = f"pkg:{pkg_type}/{parts[1]}"
            else:
                purl = f"pkg:{pkg_type}"

    return purl

def generate_bomlink(serial_number: str, version: int, component_ref: str) -> str:
    """
    CycloneDX 스펙에 따라 bomlink URN 생성.

    형식: urn:cdx:{uuid}/{version}#{component-ref}

    예:
        serial_number: urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79
        version: 1
        component_ref: pkg:npm/lodash@4.17.21

        결과: urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#pkg:npm/lodash@4.17.21
    """
    # serial_number에서 UUID 추출
    uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    uuid_match = re.search(uuid_pattern, serial_number, re.IGNORECASE)

    if uuid_match:
        uuid_val = uuid_match.group(0).lower()
    else:
        # 찾지 못하면 새 UUID 생성
        uuid_val = str(uuid.uuid4())

    # component_ref 정리 (기존 urn:cdx 접두사 제거)
    if component_ref.startswith("urn:cdx:"):
        # # 뒤의 컴포넌트 부분만 추출
        if "#" in component_ref:
            component_ref = component_ref.split("#")[-1]

    return f"urn:cdx:{uuid_val}/{version}#{component_ref}"

def create_product_identification_helper(subject: "Subject", serial_number: Optional[str] = None) -> Optional[Dict]:
    """
    CSAF 2.1용 포괄적 제품 식별 헬퍼 생성.

    모든 CSAF 2.1 헬퍼 필드 지원:
    - purl: 패키지 URL
    - cpe: 공통 플랫폼 열거
    - hashes: 파일 해시 (sha256 등)
    - model_numbers: 하드웨어/소프트웨어 모델 번호
    - sbom_urls: SBOM 문서 URL
    - serial_numbers: 시리얼 번호
    - skus: 재고 관리 단위
    - x_generic_uris: 일반 URI (예: bomlink)
    """
    helper = {}

    # 표준 식별자
    purl = next((i.value for i in subject.identifiers if i.type == "purl"), None)
    if purl:
        helper["purls"] = [normalize_purl(purl)]

    cpe = next((i.value for i in subject.identifiers if i.type == "cpe"), None)
    if cpe:
        helper["cpe"] = cpe

    # 확장 필드
    # 컨테이너 이미지(pkg:oci)의 경우, 다이제스트를 hashes 필드 대신 PURL 한정자에 포함
    # CSAF hashes 필드는 파일 해시용이지 컨테이너 다이제스트용이 아님
    if subject.hashes:
        purl_val = helper.get("purls", [None])[0] if helper.get("purls") else None
        is_oci = purl_val and purl_val.startswith("pkg:oci/")
        
        if is_oci and subject.hashes:
            # OCI 이미지: 다이제스트를 PURL 한정자로 추가
            # 예: pkg:oci/containertech/runtime@3.2.1?digest=sha256:a1b2...
            for h in subject.hashes:
                alg = h.get("algorithm", "").replace("-", "")  # sha-256 → sha256
                val = h.get("value")
                if alg and val and purl_val:
                    # PURL에 다이제스트 한정자 추가
                    if "?" not in purl_val:
                        purl_val = f"{purl_val}?digest={alg}:{val}"
                    else:
                        purl_val = f"{purl_val}&digest={alg}:{val}"
                    helper["purls"] = [purl_val]
                    break  # 첫 번째 해시만 다이제스트로 추가
        else:
            # 비OCI: 표준 hashes 필드 사용 (파일 해시용)
            # 참고: 실제로 파일 해시 데이터인 경우에만 포함, 컨테이너 다이제스트가 아님
            # 의미론적 불일치를 피하기 위해 hashes 필드 완전히 건너뛰기
            pass

    if subject.model_numbers:
        helper["model_numbers"] = subject.model_numbers

    if subject.sbom_urls:
        helper["sbom_urls"] = subject.sbom_urls

    if subject.serial_numbers:
        helper["serial_numbers"] = subject.serial_numbers

    if subject.skus:
        helper["skus"] = subject.skus

    # x_generic_uris: 원본 데이터에 존재하는 URI만 포함
    # BOM Link 자동 생성하지 않음 - 원본 데이터 무결성이 우선
    x_generic_uris = []
    
    # original_id가 소스 데이터의 적절한 URN/URI인 경우에만 추가 (pkg:는 PURL이므로 제외)
    if subject.original_id and subject.original_id.startswith("urn:"):
        uri = subject.original_id
        namespace = None
        
        # URI 형식에 따라 네임스페이스 분류
        if uri.startswith("urn:cdx:"):
            # CycloneDX BOM-Link (원본에 있는 경우에만)
            namespace = "https://cyclonedx.org/capabilities/bomlink/"
        elif "#SPDXRef-" in uri or uri.startswith("https://spdx.org"):
            # SPDX
            namespace = "https://spdx.github.io/spdx-spec/latest/document-creation-information/#65-spdx-document-namespace-field"
        else:
            # 일반 URN/URI
            namespace = "https://www.iana.org/assignments/urn-namespaces/urn-namespaces.xhtml"
        
        x_generic_uris.append({
            "namespace": namespace,
            "uri": uri
        })
    
    # 참고: PURL에서 BOM Link 자동 생성 제거
    # 원본 문서에 BOM Link가 없으면 생성하지 않음
    # 원칙: "원본에 없는 데이터를 생성하지 않음"
    
    if x_generic_uris:
        helper["x_generic_uris"] = x_generic_uris

    return helper if helper else None

def parse_version_range(version_str: str) -> Dict:
    """
    버전 범위 문자열을 구조화된 형식으로 파싱.

    지원:
    - 단일 버전: "2.4" → {"version": "2.4"}
    - 연산자가 있는 범위: ">=1.0|<=2.3" → {"range": "vers:generic/>=1.0|<=2.3"}
    - 와일드카드: "*" → {"range": "vers:generic/*"}

    'version' 또는 'range' 키가 있는 dict 반환.
    """
    if not version_str or version_str == "*":
        return {"range": "vers:generic/*"}

    version_str = version_str.strip()

    # 범위 연산자 확인
    range_operators = [">=", "<=", ">", "<", "|", "-"]
    has_range = any(op in version_str for op in range_operators)

    if has_range:
        # 범위임
        return {"range": f"vers:generic/{version_str}"}

    # 단일 버전
    return {"version": version_str}

def extract_version_from_product_id(product_id: str) -> Optional[str]:
    """
    제품 ID에서 버전 정보 추출 (있는 경우).

    예:
        "npm-lodash-4.17.21" → "4.17.21"
        "product-ABC:v2.0" → "2.0"
        "simple-product" → None
    """
    # 패턴 1: product:vVERSION
    if ":v" in product_id:
        return product_id.split(":v")[-1]

    # 패턴 2: package-name-VERSION (VERSION이 버전처럼 보이는 경우)
    parts = product_id.split("-")
    if len(parts) >= 2:
        last_part = parts[-1]
        # 마지막 부분이 버전처럼 보이는지 확인 (숫자와 점 포함)
        if re.match(r'^\d+(\.\d+)*', last_part):
            return last_part

    return None

def simplify_product_id(identifier: str, name: str = "") -> str:
    """
    제품 ID를 짧지만 고유하게 단순화.

    예:
        pkg:npm/lodash@4.17.21 → npm-lodash-4.17.21
        pkg:apk/alpine/busybox@1.2.3 → apk-busybox-1.2.3
        cpe:2.3:a:vendor:product:1.0 → vendor-product-1.0
        urn:cdx:uuid/1#product-ABC → product-ABC

    폴백: 짧은 해시 기반 ID 생성
    """
    if not identifier:
        if name:
            # name을 기반으로 사용
            clean_name = re.sub(r'[^\w\-\.]', '-', name)[:50]
            return f"prod-{clean_name}"
        return f"prod-{uuid.uuid4().hex[:8]}"

    # PURL 처리: pkg:npm/lodash@4.17.21
    if identifier.startswith("pkg:"):
        try:
            # type/namespace/name@version 추출
            parts = identifier[4:].split("/")
            pkg_type = parts[0]

            if len(parts) > 1:
                # 네임스페이스 있음
                rest = "/".join(parts[1:])
                name_version = rest.split("@")[0].split("?")[0]
                name_only = name_version.split("/")[-1]  # 마지막 부분 가져오기

                # 버전 가져오기 (있는 경우)
                version = ""
                if "@" in rest:
                    version = rest.split("@")[1].split("?")[0]
                    return f"{pkg_type}-{name_only}-{version}"
                return f"{pkg_type}-{name_only}"
        except:
            pass

    # CPE 처리: cpe:2.3:a:vendor:product:version
    if identifier.startswith("cpe:"):
        try:
            parts = identifier.split(":")
            if len(parts) >= 5:
                vendor = parts[3]
                product = parts[4]
                version = parts[5] if len(parts) > 5 and parts[5] != "*" else ""
                if version:
                    return f"{vendor}-{product}-{version}"
                return f"{vendor}-{product}"
        except:
            pass

    # URN 처리: urn:cdx:uuid/1#product-ABC
    if "#" in identifier:
        after_hash = identifier.split("#")[-1]
        if after_hash:
            return after_hash

    # 폴백: 짧은 해시 생성
    id_hash = hashlib.sha256(identifier.encode()).hexdigest()[:12]
    if name:
        clean_name = re.sub(r'[^\w\-\.]', '-', name)[:30]
        return f"{clean_name}-{id_hash[:6]}"
    return f"prod-{id_hash}"

# ===== NVD API =====

# ===== 유틸리티 =====

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def dt_to_iso_z(dt: datetime) -> str:
    if not dt: dt = now_utc()
    return dt.replace(microsecond=0).isoformat().replace('+00:00', 'Z')

def safe_str(s) -> str:
    return str(s) if s is not None else ""

def unique_list(items):
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result

def normalize_identifier(s: str) -> str:
    s = safe_str(s).strip()
    if not s.startswith("urn:") and not s.startswith("pkg:") and not s.startswith("cpe:"):
        s = re.sub(r'\s+', '-', s)
    return s

def normalize_purl(purl: str) -> str:
    if not purl or not purl.startswith("pkg:"): return purl
    return re.sub(r'\s+', '', purl)

def ensure_urn_uuid(s: Optional[str]) -> str:
    if s and s.startswith("urn:uuid:"): return s
    return f"urn:uuid:{uuid.uuid4()}"

def encode_structured_text(data: dict) -> str:
    """자유 텍스트 필드에 포함하기 위해 구조화된 데이터 인코딩"""
    if not data: return ""
    parts = []
    for key, value in data.items():
        json_str = json.dumps(value, ensure_ascii=False, separators=(',', ':'))
        parts.append(f"[{key}:{json_str}]")
    return " || ".join(parts)

def decode_structured_text(text: str) -> dict:
    """자유 텍스트 필드에서 구조화된 데이터 디코딩"""
    if not text: return {}
    result = {}
    pattern = r'\[([a-zA-Z_]+):(.+?)\](?:\s*\|\|\s*|\s*$)'
    for match in re.finditer(pattern, text):
        key, value_str = match.groups()
        try:
            result[key] = json.loads(value_str)
        except json.JSONDecodeError:
            pass
    return result

# ===== EXTENSION DATA 헬퍼 =====

def set_extension_field(obj: Any, namespace: str, field_path: str, value: Any):
    """네임스페이스와 함께 extension_data에 필드 설정
    
    Args:
        obj: extension_data 속성이 있는 객체
        namespace: 형식 네임스페이스 (cyclonedx, openvex, csaf)
        field_path: 점으로 구분된 필드 경로 (예: "document.aggregate_severity.text")
        value: 저장할 값
    
    예:
        set_extension_field(metadata, "csaf", "document.aggregate_severity.namespace", "https://...")
    """
    if not hasattr(obj, 'extension_data'):
        return
    
    full_key = f"{namespace}.{field_path}"
    obj.extension_data[full_key] = value

def get_extension_field(obj: Any, namespace: str, field_path: str, default: Any = None) -> Any:
    """네임스페이스와 함께 extension_data에서 필드 가져오기
    
    Args:
        obj: extension_data 속성이 있는 객체
        namespace: 형식 네임스페이스 (cyclonedx, openvex, csaf)
        field_path: 점으로 구분된 필드 경로
        default: 찾지 못한 경우 기본값
    
    Returns:
        저장된 값 또는 기본값
    """
    if not hasattr(obj, 'extension_data'):
        return default
    
    full_key = f"{namespace}.{field_path}"
    return obj.extension_data.get(full_key, default)

def get_all_extension_fields(obj: Any, namespace: str) -> Dict[str, Any]:
    """특정 네임스페이스의 모든 extension 필드 가져오기
    
    Args:
        obj: extension_data 속성이 있는 객체
        namespace: 형식 네임스페이스 (cyclonedx, openvex, csaf)
    
    Returns:
        field_path -> value 매핑이 있는 딕셔너리 (네임스페이스 접두사 없이)
    """
    if not hasattr(obj, 'extension_data'):
        return {}
    
    prefix = f"{namespace}."
    result = {}
    
    for key, value in obj.extension_data.items():
        if key.startswith(prefix):
            field_path = key[len(prefix):]
            result[field_path] = value
    
    return result

def set_nested_dict_value(data: dict, path: str, value: Any):
    """점 표기법을 사용하여 중첩된 딕셔너리에 값 설정
    
    Args:
        data: 수정할 딕셔너리
        path: 점으로 구분된 경로 (예: "document.aggregate_severity.text")
        value: 설정할 값
    
    예:
        set_nested_dict_value(doc, "document.aggregate_severity.text", "critical")
        → doc["document"]["aggregate_severity"]["text"] = "critical"
    """
    keys = path.split('.')
    current = data
    
    for key in keys[:-1]:
        if key not in current:
            current[key] = {}
        current = current[key]
    
    current[keys[-1]] = value

def get_nested_dict_value(data: dict, path: str, default: Any = None) -> Any:
    """점 표기법을 사용하여 중첩된 딕셔너리에서 값 가져오기
    
    Args:
        data: 읽을 딕셔너리
        path: 점으로 구분된 경로
        default: 경로를 찾지 못한 경우 기본값
    
    Returns:
        경로의 값 또는 기본값
    """
    keys = path.split('.')
    current = data
    
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default
    
    return current

def filter_placeholder_ratings(ratings: List[Dict]) -> List[Dict]:
    """플레이스홀더 CVSS 등급 제거 (score 0, severity none)"""
    return [r for r in ratings if not (
        r.get("score") == 0.0 and 
        r.get("severity") == "none" and 
        "CR:X/IR:X/AR:X" in r.get("vector", "")
    )]

def dedupe_ratings(ratings: List[Dict]) -> List[Dict]:
    """중복 CVSS 등급 제거"""
    seen = set()
    result = []
    for r in ratings:
        key = (r.get("method"), r.get("vector"), r.get("score"))
        if key not in seen:
            seen.add(key)
            result.append(r)
    return result

def extract_all_fields(data: Any, prefix: str = "", max_depth: int = 10) -> set:
    """데이터 구조에서 모든 필드 경로를 재귀적으로 추출"""
    if max_depth <= 0:
        return set()

    fields = set()

    if isinstance(data, dict):
        for key, value in data.items():
            field_path = f"{prefix}.{key}" if prefix else key
            fields.add(field_path)

            # 중첩 구조로 재귀
            if isinstance(value, (dict, list)):
                nested_fields = extract_all_fields(value, field_path, max_depth - 1)
                fields.update(nested_fields)

    elif isinstance(data, list) and data:
        # 리스트의 경우 첫 번째 항목의 구조 확인
        if isinstance(data[0], dict):
            nested_fields = extract_all_fields(data[0], prefix, max_depth - 1)
            fields.update(nested_fields)

    return fields

def normalize_field_path(path: str) -> str:
    """비교를 위해 필드 경로 정규화 (배열 인덱스 패턴 제거)"""
    # 이미 인덱스 없는 경로지만 일관성을 위해 유지
    return path

def dedupe_references(refs: List[Dict]) -> List[Dict]:
    """중복 참조 제거"""
    seen = set()
    result = []
    for r in refs:
        # CSAF 형식(최상위 url)과 CycloneDX 형식(source 내 url) 모두 지원
        url = r.get("url") or (r.get("source", {}).get("url") if isinstance(r.get("source"), dict) else None)
        if url and url not in seen:
            seen.add(url)
            result.append(r)
    return result

def dedupe_components(components: List[Dict]) -> Tuple[List[Dict], Dict[str, str]]:
    """컴포넌트 중복 제거 및 이전 ref에서 새 ref로의 매핑 반환.
    
    중요: PURL이 다른 컴포넌트는 CPE가 같아도 중복이 아님.
    Multiple PURL 케이스 처리 (같은 제품, 다른 패키지 형식).
    """
    seen_purls, seen_cpes = {}, {}
    deduplicated, ref_mapping = [], {}

    for c in components:
        purl = normalize_purl(c.get("purl", ""))
        cpe = c.get("cpe", "")
        original_ref = c.get("bom-ref")
        
        # 보조 패키지 형식인지 확인 (Multiple PURL 케이스)
        # 보조 컴포넌트는 cdx:package:primary = "false"를 가짐
        is_secondary = False
        for prop in c.get("properties", []):
            if prop.get("name") == "cdx:package:primary" and prop.get("value") == "false":
                is_secondary = True
                break
        
        # 보조 컴포넌트(Multiple PURL)의 경우 PURL만으로 중복 확인
        # 같은 제품이 다른 패키지 형식으로 같은 CPE를 가질 수 있으므로 CPE는 확인하지 않음
        if is_secondary:
            if purl and purl in seen_purls:
                ref_mapping[original_ref] = seen_purls[purl]
            else:
                if purl: seen_purls[purl] = original_ref
                deduplicated.append(c)
        else:
            # 기본 컴포넌트에 대한 일반 중복 제거
            if purl and purl in seen_purls:
                ref_mapping[original_ref] = seen_purls[purl]
            elif cpe and cpe in seen_cpes:
                ref_mapping[original_ref] = seen_cpes[cpe]
            else:
                if purl: seen_purls[purl] = original_ref
                if cpe: seen_cpes[cpe] = original_ref
                deduplicated.append(c)

    return deduplicated, ref_mapping

# 컴포넌트 타입 분류
def classify_component_type(identifier: str, name: str = "") -> str:
    """
    PURL, CPE 또는 이름 패턴을 기반으로 컴포넌트 타입 분류.
    CycloneDX 컴포넌트 타입 반환.
    """
    id_lower = identifier.lower()
    name_lower = name.lower() if name else ""
    combined = id_lower + " " + name_lower

    # 소스 코드 파일
    source_extensions = [
        ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx",
        ".java", ".class", ".py", ".pyx", ".go", ".rs",
        ".js", ".ts", ".jsx", ".tsx", ".php", ".rb", ".swift",
        ".kt", ".kts", ".cs", ".m", ".mm", ".s", ".asm",
        ".sh", ".bash",
    ]
    if any(combined.endswith(ext) for ext in source_extensions):
        return "file"
    
    if "/" in id_lower and any(combined.endswith(ext) for ext in source_extensions + [".txt", ".md", ".rst", ".log"]):
        return "file"

    # 컨테이너 타입
    if any(pattern in id_lower for pattern in ["pkg:oci/", "pkg:docker/", "pkg:container/"]):
        return "container"

    # 패키지 매니저 → 라이브러리
    pkg_managers = ["pkg:apk/", "pkg:rpm/", "pkg:deb/", "pkg:npm/", "pkg:pypi/", 
                    "pkg:maven/", "pkg:golang/", "pkg:nuget/", "pkg:cargo/",
                    "pkg:composer/", "pkg:cran/", "pkg:hex/"]
    if any(pm in id_lower for pm in pkg_managers):
        return "library"

    # 프레임워크
    if "pkg:generic/" in id_lower and "framework" in combined:
        return "framework"
    if any(fw in combined for fw in ["spring", "django", "rails"]):
        return "framework"

    # 플랫폼/런타임
    if any(platform in combined for platform in ["nodejs", "python", "jvm", "java*runtime", "dotnet*runtime"]):
        return "platform"
    if any(k8s in combined for k8s in ["kubernetes", "openshift"]):
        return "platform"

    # 운영 체제
    if any(os in combined for os in ["alpine", "ubuntu", "debian", "rhel", "centos", "windows"]):
        return "operating-system"

    # 애플리케이션
    if any(app in combined for app in ["server", "service", "backend", "frontend"]):
        return "application"

    # 펌웨어
    if any(fw in combined for fw in ["firmware", ".bin"]):
        return "firmware"

    # 디바이스 드라이버
    if any(drv in combined for drv in ["driver", ".ko"]):
        return "device-driver"

    # 디바이스/하드웨어
    if any(dev in combined for dev in ["cpu", "chip", "soc"]):
        return "device"

    # 설정/데이터 파일
    if any(combined.endswith(ext) for ext in [".yaml", ".yml", ".json", ".xml"]):
        return "file"

    # ML 모델
    if any(combined.endswith(ext) for ext in [".onnx", ".pt", ".pkl"]):
        return "machine-learning-model"

    # 데이터 파일
    if any(combined.endswith(ext) for ext in [".csv", ".parquet"]):
        return "data"

    # 암호화 자산
    crypto_patterns = [".pem", ".crt", ".cer", ".key", "token", "secret"]
    if any(pattern in combined for pattern in crypto_patterns):
        return "cryptographic-asset"

    # 기본값
    return "library"



def detect_format(data: dict) -> str:
    """
    데이터 구조에서 VEX 문서 형식 감지.
    
    반환: 'openvex', 'cyclonedx', 또는 'csaf'
    """
    if not isinstance(data, dict):
        raise ValueError("Data must be a dictionary")
    
    # OpenVEX 확인
    if "@context" in data or "statements" in data:
        return "openvex"
    
    # CycloneDX 확인
    if data.get("bomFormat") == "CycloneDX" or "specVersion" in data:
        return "cyclonedx"
    
    # CSAF 확인
    if "document" in data or "csaf_version" in data.get("document", {}):
        return "csaf"
    
    # 폴백: 구조에서 감지 시도
    if "vulnerabilities" in data:
        if "components" in data:
            return "cyclonedx"
        elif "product_tree" in data:
            return "csaf"
    
    raise ValueError("Could not detect document format")