# VEX Validator

VEX 문서의 스키마 및 비즈니스 규칙을 검증하는 Flask 웹 애플리케이션


## 개요

세 가지 VEX 형식에 대한 통합 검증 도구를 제공한다.

- OpenVEX v0.2.0
- CycloneDX VEX 1.4 - 1.7
- CSAF VEX Profile 2.0 / 2.1


## 디렉토리 구조

```
validator/
  integrated_validators/
    csaf_validator.py         CSAF 검증 로직
    cyclonedx_validator.py    CycloneDX 검증 로직
    openvex_validator.py      OpenVEX 검증 로직
  schemas/                    JSON Schema 파일
  static/css/
    style.css                 웹 UI 스타일
  templates/
    index.html                웹 UI 템플릿
  app.py                      Flask 메인 서버
```


## 실행 방법

```bash
cd validator
pip install -r requirements.txt
python app.py
```

브라우저에서 http://localhost:5000 접속


## API 엔드포인트

| 경로 | 메서드 | 설명 |
|------|--------|------|
| / | GET | 웹 UI 페이지 |
| /api/validate | POST | VEX 문서 검증 |
| /api/convert | POST | VEX 형식 변환 |
| /api/preview | POST | 변환 미리보기 |
| /api/analyze-field-mappings | POST | 필드 매핑 분석 |


## 검증 요청 예시

```bash
curl -X POST http://localhost:5000/api/validate \
  -H "Content-Type: application/json" \
  -d '{"content": {...}, "format": "openvex"}'
```


## 검증 결과 형식

```json
{
  "success": true,
  "results": {
    "schema_valid": true,
    "errors": [],
    "warnings": [],
    "info": []
  }
}
```


## 검증 규칙 분류

각 검증기는 다음 세 단계로 검증을 수행한다.

1. Schema Validation - JSON Schema 기반 구조 검증
2. Business Rules - 형식별 필수 규칙 검증 (MUST)
3. Best Practices - 권장 사항 검증 (SHOULD)


## 검증기별 주요 규칙

### OpenVEX

- context 필드 필수
- statement에 status 필수
- not_affected 상태시 justification 필수

### CycloneDX

- bomFormat이 CycloneDX여야 함
- vulnerabilities 배열 필수
- affects에 ref 필수

### CSAF

- document.category가 csaf_vex여야 함
- product_tree 필수
- vulnerabilities 배열 필수
- VEX Profile 준수 여부 검증