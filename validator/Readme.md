# Enhanced VEX Validator v2.0

[![Version](https://img.shields.io/badge/version-2.0-blue.svg)](https://github.com)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)

OpenVEX, CSAF, CycloneDX VEX 문서를 검증하는 통합 Validator입니다.

## Table of Contents

- [Features](#features)
- [Supported Formats](#supported-formats)
- [Installation](#installation)
- [Usage](#usage)
- [Validation Rules](#validation-rules)
- [Web Interface](#web-interface)

## Features

- JSON Schema 검증
- 시맨틱 규칙 검증(MUST/SHOULD 분리)
- 포맷 자동 감지(OpenVEX/CSAF/CycloneDX)
- 상세 오류 리포트(rule_id, path, severity)
- 웹 UI 제공

## Supported Formats

| Format | Version | Support |
|---|---|---|
| OpenVEX | 0.2.0 | Full |
| CSAF | 2.0 / 2.1 | Full |
| CycloneDX | 1.5 / 1.6 / 1.7 | 1.6+ Full, 1.5 Schema-only |

참고:
- CycloneDX 1.5는 공식 근거 제약으로 스키마 검증만 지원합니다.
- CycloneDX 시맨틱 검증은 1.6 이상 문서에 대해 적용됩니다.

## Installation

### Prerequisites

- Python 3.8+
- pip

### Install
```bash
pip install -r requirements.txt
```

필수 패키지:
jsonschema>=4.0.0
Flask>=2.0.0 (웹 UI 사용 시)

## Usage

Web UI
```bash
python app.py
```

기본 흐름:
- JSON 파일 업로드
- 포맷 자동 감지
- 검증 실행
- 오류/경고 확인

결과 해석
- error: MUST 위반(문서 invalid)
- warning: SHOULD/RECOMMENDED 위반(문서는 valid 가능)

## Validation Rules
**OpenVEX 0.2.0**
- 문서 수준: @id, version, author, timestamp 관련 규칙
- Statement 수준: status 조건부 필드, vulnerability, products addressable 규칙
- 교차 규칙: 동일 대상/취약점/시점 충돌 검출

**CSAF 2.0/2.1**
- Mandatory tests 및 profile tests 기반 규칙
- product_tree 참조 무결성
- vulnerability/product_status 정합성
- 일정/타임라인 검증

**CycloneDX 1.5/1.6/1.7**
- 1.5: Schema validation only
- 1.6+: VEX 시맨틱 규칙 적용
- 1.7: 강화 규칙(예: not_affected 관련 조건, modelCard 제약 등)

## Web Interface
제공 기능:
- Drag & Drop 업로드
- 포맷 자동 감지
- 규칙 목록 조회
- severity별 결과 표시