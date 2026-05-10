# VEX Validator
A unified validator for OpenVEX, CSAF, and CycloneDX VEX documents.

## Overview
VEX Validator performs schema validation and semantic rule validation for multiple VEX formats. It detects the document format automatically and reports validation results with rule IDs, severity, and document paths.

## Features
- Schema validation
- Semantic rule validation
- Automatic format detection
- Structured error reporting (`rule_id`, `path`, `severity`)
- Optional web interface

## Supported Formats
| Format | Versions | Support |
| --- | --- | --- |
| OpenVEX | 0.2.0 | Full |
| CSAF | 2.0, 2.1 | Full |
| CycloneDX VEX | 1.5, 1.6, 1.7 | 1.6+ full, 1.5 schema-only |

Notes:
- CycloneDX 1.5 is validated against schema only.
- Semantic validation for CycloneDX VEX is applied to version 1.6 and later.

## Installation
Requirements:
- Python 3.8+
- `pip`

Install dependencies:
```
pip install -r requirements.txt
```

Core dependencies:
jsonschema
Flask (only required for the web UI)

## Usage
Run the web UI:
```
python app.py
```

Typical workflow:
1. Upload a JSON document
2. Detect the VEX format automatically
3. Run validation
4. Review errors and warnings

Result levels:
error: violation of required rules
warning: violation of recommended rules

## Validation Scope
### OpenVEX
- Document-level field validation
- Statement-level semantic checks
- Cross-statement conflict detection

### CycloneDX VEX
- Schema validation for all supported versions
- Semantic VEX validation for 1.6+
- Additional constraints for newer versions where applicable

### CSAF
- Mandatory and profile-based checks
- product_tree reference integrity
- Vulnerability and product status consistency
- Timeline and date validation