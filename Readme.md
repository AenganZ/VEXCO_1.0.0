# VEX Converter

VEX 문서를 서로 다른 형식으로 변환하는 Python 패키지


## 개요

CIM(Common Intermediate Model)을 중간 표현으로 사용하여 세 가지 VEX 형식 간 양방향 변환을 지원한다.

지원 형식
- OpenVEX v0.2.0
- CycloneDX VEX 1.4 - 1.7
- CSAF VEX Profile 2.0 / 2.1
- VDR (Vulnerability Disclosure Report)


## 디렉토리 구조

```
vex_converter/
  __init__.py       패키지 초기화 및 클래스 export
  models.py         CIM 데이터 모델 정의
  constants.py      상수 및 매핑 테이블
  to_cim.py         소스 형식을 CIM으로 변환
  from_cim.py       CIM을 타겟 형식으로 변환
  utils.py          유틸리티 함수
  validator.py      내부 검증 로직
  vdr.py            VDR 변환 기능
  nvd_client.py     NVD API 클라이언트
```


## 변환 구조

```
OpenVEX                              OpenVEX
CycloneDX   -->  to_cim.py  -->  CIM  -->  from_cim.py  -->  CycloneDX
CSAF                                 CSAF / VDR
```

모든 변환은 CIM을 거쳐 수행된다. 이를 통해 N:N 변환을 N:1 + 1:N 구조로 단순화한다.


## 핵심 파일 설명

### models.py

CIM 데이터 구조를 정의한다.

| 클래스 | 설명 |
|--------|------|
| CIM | 최상위 문서 모델 |
| Subject | 제품/컴포넌트 정보 |
| VEXStatement | 취약점-제품 상태 선언 |
| Vulnerability | 취약점 메타데이터 |
| VulnerabilityStatus | 상태값 (AFFECTED, NOT_AFFECTED, FIXED, UNDER_INVESTIGATION) |

### to_cim.py

소스 문서를 파싱하여 CIM 객체를 생성한다.

| 클래스 | 입력 | 출력 |
|--------|------|------|
| OpenVEXToCIM | OpenVEX JSON | CIM |
| CycloneDXToCIM | CycloneDX JSON | CIM |
| CSAFToCIM | CSAF JSON | CIM |

### from_cim.py

CIM 객체를 타겟 형식으로 직렬화한다.

| 클래스 | 입력 | 출력 |
|--------|------|------|
| CIMToOpenVEX | CIM | OpenVEX JSON |
| CIMToCycloneDX | CIM | CycloneDX JSON |
| CIMToCSAF | CIM | CSAF JSON |


## 사용 예시

### Python 코드에서 사용

```python
from vex_converter import (
    CycloneDXToCIM, CIMToCSAF, ConversionOptions
)

# 옵션 설정
options = ConversionOptions(reversible=False)

# CycloneDX를 CSAF로 변환
cim = CycloneDXToCIM(options).convert(cyclonedx_json)
csaf = CIMToCSAF(options).convert(cim)
```

### CLI에서 사용

```bash
python convert.py input.json --target csaf --output result.json
```


## 변환 옵션

| 옵션 | 설명 |
|------|------|
| reversible | True시 원본 복원용 메타데이터 보존 |
| restore | True시 보존된 메타데이터로 원본 복원 시도 |


## 상태 매핑

| CIM 상태 | OpenVEX | CycloneDX | CSAF |
|----------|---------|-----------|------|
| NOT_AFFECTED | not_affected | not_affected | known_not_affected |
| AFFECTED | affected | exploitable | known_affected |
| FIXED | fixed | resolved | fixed |
| UNDER_INVESTIGATION | under_investigation | in_triage | under_investigation |


## VDR 변환

VDR은 CycloneDX 형식 기반의 취약점 공개 보고서이다.

```python
from vex_converter.vdr import vex_to_vdr

vdr = vex_to_vdr(cim)
```

VDR은 다음 필드에 중점을 둔다.
- detail (상세 설명)
- recommendation (권장 조치)
- workaround (임시 완화책)
- proofOfConcept (개념 증명)
- credits (발견자 정보)


## NVD API 연동

NVD API를 통해 CVE 정보를 보강할 수 있다.

```python
from vex_converter.vdr import enhance_vdr_with_nvd

cim = enhance_vdr_with_nvd(cim, api_key="your-api-key")
```

환경 변수 NVD_API_KEY를 설정하면 자동으로 적용된다.