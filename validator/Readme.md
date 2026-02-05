# 🛡️ Enhanced VEX Validator v2.2

[![Version](https://img.shields.io/badge/version-2.2-blue.svg)](https://github.com)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)

**Complete VEX validation toolkit with comprehensive business rules**

A professional-grade validator for **OpenVEX 0.2.0**, **CSAF 2.1**, and **CycloneDX 1.7** documents, implementing all official specifications and best practices.

---

## 📋 Table of Contents

- [Features](#-features)
- [Supported Formats](#-supported-formats)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Usage](#-usage)
- [Validation Rules](#-validation-rules)
- [Web Interface](#-web-interface)
- [API Documentation](#-api-documentation)
- [Examples](#-examples)
- [Development](#-development)
- [Changelog](#-changelog)
- [License](#-license)

---

## ✨ Features

### 🎯 Complete Validation
- **JSON Schema Validation** - Full compliance with official schemas
- **VEX Business Rules** - 52 comprehensive rules across all formats
- **Severity Classification** - MUST (errors) vs SHOULD (warnings)
- **Reference Integrity** - Cross-reference validation
- **Conflict Detection** - Duplicate and contradictory statements

### 🚀 Professional Grade
- **Web Interface** - Beautiful, responsive UI with real-time validation
- **Command Line** - Scriptable validators for CI/CD integration
- **REST API** - Flask-based API for integration
- **Detailed Reports** - Clear error messages with rule IDs and paths
- **Production Ready** - Battle-tested with comprehensive error handling

### 📊 Advanced Features
- **Auto-detection** - Automatic format detection
- **Batch Processing** - Validate multiple documents
- **Rule Reference** - Interactive documentation of all rules
- **Visual Feedback** - Color-coded results (success/warning/error)
- **Export Results** - JSON output for automation

---

## 🎨 Supported Formats

| Format | Version | Rules | Status |
|--------|---------|-------|--------|
| **OpenVEX** | 0.2.0 | 16 rules (9 MUST · 7 SHOULD) | ✅ Full Support |
| **CSAF** | 2.1 | 17 rules (14 MUST · 3 SHOULD) | ✅ Full Support |
| **CycloneDX** | 1.7 | 19 rules (6 MUST · 13 SHOULD) | ✅ Full Support |

**Total: 52 comprehensive validation rules**

---

## 🚀 Quick Start

### 1. Web Interface (Recommended)

```bash
# Extract package
tar -xzf enhanced_web_validator_v2.2.tar.gz
cd enhanced_web_validator

# Install dependencies
pip install -r requirements.txt

# Start server
python app.py

# Open browser
# → http://localhost:5000
```

### 2. Command Line

```bash
# Validate OpenVEX document
python enhanced_validators/openvex_validator.py \
  schemas/openvex-0.2.0-schema.json \
  samples/openvex-valid.json

# Validate CSAF document
python enhanced_validators/csaf_validator.py \
  schemas/csaf_2.1_json_schema.json \
  samples/csaf-valid.json

# Validate CycloneDX document
python enhanced_validators/cyclonedx_validator.py \
  schemas/bom-1.7-schema.json \
  samples/cyclonedx-valid.json
```

### 3. Python API

```python
from enhanced_validators.openvex_validator import validate_openvex
import json

# Load schema and document
with open('schemas/openvex-0.2.0-schema.json') as f:
    schema = json.load(f)

with open('my-vex-document.json') as f:
    document = json.load(f)

# Validate
is_valid, errors = validate_openvex(document, schema)

if is_valid:
    print("✓ Valid document")
else:
    for error in errors:
        print(f"[{error['rule_id']}] {error['message']}")
```

---

## 📦 Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Install Dependencies

```bash
pip install -r requirements.txt
```

**Dependencies:**
- `jsonschema>=4.0.0` - JSON Schema validation
- `Flask>=2.0.0` - Web server (web interface only)

### Manual Installation

```bash
# Clone or extract
git clone <repository-url>
cd enhanced-vex-validator

# Install in development mode
pip install -e .
```

---

## 🎯 Usage

### Web Interface

**Start Server:**
```bash
python app.py
```

**Features:**
- 📤 **Drag & drop** file upload
- 🔍 **Auto-detection** of document format
- 📋 **Rule reference** with interactive documentation
- 🎨 **Visual results** with color-coded severity
- 📊 **Detailed reports** with error paths and messages

**Workflow:**
1. Upload JSON file (or drag & drop)
2. Format is auto-detected
3. Click "Start Validation"
4. View results with color coding:
   - 🟢 **Green** = Perfect (no errors, no warnings)
   - 🟠 **Orange** = Valid with warnings (MUST passed, SHOULD recommendations)
   - 🔴 **Red** = Failed (MUST violations)

### Command Line

**Basic Usage:**
```bash
# Syntax
python enhanced_validators/<format>_validator.py <schema> <document>

# Example
python enhanced_validators/openvex_validator.py \
  schemas/openvex-0.2.0-schema.json \
  my-document.json
```

**Output:**
```
✓ Valid OpenVEX document
  - JSON Schema: ✓
  - VEX Rules: ✓

✗ Invalid OpenVEX document
  Errors (2):
    [OVX-STATE-001] /statements/0
      status 'not_affected' MUST include justification OR impact_statement
    [OVX-IDENT-001] /statements/0/products/0
      Product MUST have @id OR identifiers

  Warnings (1):
    [OVX-VULNID-002] /statements/0/vulnerability/name
      vulnerability name should follow standard format (CVE-YYYY-NNNNN)
```

### REST API

**Start Server:**
```bash
python app.py
```

**Endpoints:**

```bash
# Validate document
POST /api/validate
Content-Type: application/json

{
  "content": {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "statements": [...]
  }
}

# Response
{
  "success": true,
  "schemaType": "openvex",
  "isValid": true,
  "errors": [],
  "errorCount": 0,
  "validationLevels": {
    "schema": true,
    "vexRules": true,
    "schemaErrorCount": 0,
    "vexRuleErrorCount": 0,
    "schemaWarningCount": 0,
    "vexRuleWarningCount": 0
  },
  "severityBreakdown": {
    "errors": 0,
    "warnings": 0
  }
}
```

```bash
# Get validation rules
GET /api/rules/<format>

# Example
curl http://localhost:5000/api/rules/openvex
```

---

## 📖 Validation Rules

### OpenVEX 0.2.0 (16 rules)

#### 🔴 MUST Requirements (9 rules)

| Rule ID | Description |
|---------|-------------|
| **OVX-CTX-001** | @context must start with https://openvex.dev/ns/ |
| **OVX-TS-001** | Document timestamp format validation |
| **OVX-TS-002** | last_updated format and logic validation |
| **OVX-TS-004** | Statement timestamps format validation |
| **OVX-STATE-001** | not_affected → justification OR impact_statement |
| **OVX-STATE-002** | affected → action_statement |
| **OVX-IDENT-001** | Product MUST have @id OR identifiers |
| **OVX-IDENT-002** | identifiers must contain purl/cpe22/cpe23 |
| **OVX-VULNID-001** | Vulnerability name not empty |
| **OVX-DUP-001** | No conflicting statements for same product+vulnerability |

#### 🟠 SHOULD Recommendations (7 rules)

| Rule ID | Description |
|---------|-------------|
| **OVX-TS-003** | last_updated must be >= timestamp |
| **OVX-STATE-003** | under_investigation → detail recommended |
| **OVX-VULNID-002** | Vulnerability ID should follow standard format |
| **OVX-HASH-001** | Hash algorithm should be recognized |
| **OVX-HASH-002** | Hash value length should match algorithm |
| **OVX-REFER-001** | External reference URL format validation |

### CSAF 2.1 (17 rules)

#### 🔴 MUST Requirements (14 rules)

| Rule ID | Description |
|---------|-------------|
| **CSAF-PROD-001** | VEX requires product_tree |
| **CSAF-PROD-002** | product_tree must contain products |
| **CSAF-PROD-003** | Product references must exist in product_tree |
| **CSAF-VULN-REQ-001** | VEX requires vulnerabilities array |
| **CSAF-VULNID-001** | Vulnerability MUST have cve OR ids |
| **CSAF-PSTAT-001** | Vulnerability MUST have product_status |
| **CSAF-PSTAT-002** | Must have at least one VEX status |
| **CSAF-KNA-001** | known_not_affected → impact statement |
| **CSAF-KA-001** | known_affected → action statement |
| **CSAF-GROUP-001** | Product group product_ids must exist |
| **CSAF-GROUP-002** | Group references must be defined |
| **CSAF-REMED-STRUCT-001** | Remediation MUST have category |
| **CSAF-REMED-STRUCT-002** | Remediation MUST have details OR url |
| **CSAF-REMED-STRUCT-003** | Remediation MUST have product_ids OR group_ids |
| **CSAF-TIMELINE-003** | current_release_date >= initial_release_date |

#### 🟠 SHOULD Recommendations (3 rules)

| Rule ID | Description |
|---------|-------------|
| **CSAF-TIMELINE-001** | initial_release_date should not be in the future |
| **CSAF-TIMELINE-002** | current_release_date should not be in the future |

### CycloneDX 1.7 (19 rules)

#### 🔴 MUST Requirements (6 rules)

| Rule ID | Description |
|---------|-------------|
| **CDX-ID-002** | Vulnerability id not empty |
| **CDX-JUST-VAL-001** | Justification must be valid enum value |
| **CDX-RESP-VAL-001** | Response must be valid enum value |
| **CDX-REF-001** | affects.ref is required |
| **CDX-REF-002** | affects.ref not empty |
| **CDX-REF-003** | affects.ref must point to existing component |
| **CDX-VERSIONS-001** | Version entry MUST have version OR range |
| **CDX-TIMESTAMP-001** | firstIssued format validation |
| **CDX-TIMESTAMP-002** | lastUpdated format validation |

#### 🟠 SHOULD Recommendations (13 rules)

| Rule ID | Description |
|---------|-------------|
| **CDX-ID-001** | Vulnerability SHOULD have id field |
| **CDX-ID-003** | Vulnerability ID should follow standard format |
| **CDX-AN-STATE-001** | not_affected → justification recommended |
| **CDX-AN-STATE-002** | not_affected → detail recommended |
| **CDX-AN-STATE-003** | detail should be meaningful |
| **CDX-AN-STATE-004** | exploitable → response recommended |
| **CDX-AN-STATE-005** | exploitable → detail recommended |
| **CDX-AN-STATE-006** | in_triage → detail recommended |
| **CDX-AN-STATE-007** | false_positive → detail recommended |
| **CDX-TIMESTAMP-003** | lastUpdated must be >= firstIssued |

---

## 🌐 Web Interface

### Features

#### 📤 File Upload
- Drag & drop support
- Click to select file
- Auto-detection of format
- Visual format indicator

#### 🔍 Validation Process
```
Upload → Auto-detect → Validate → Display Results
   ↓         ↓            ↓            ↓
JSON     OpenVEX     Schema +    Color-coded
File     CSAF        VEX Rules   Report
         CycloneDX
```

#### 📊 Result Display

**Perfect Document (🟢 Green):**
```
✓ Validation Passed
✓ Schema
✓ VEX Rules

✓ Valid OPENVEX Document
No errors or warnings found. The document is production-ready!
```

**Valid with Warnings (🟠 Orange):**
```
⚠ Validation Passed with Warnings
✓ Schema
✓ VEX Rules
⚠ Warnings (2)

⚠ Valid CSAF Document (with recommendations)
All MUST requirements are met, but there are 2 SHOULD recommendations.

⚠️ Recommendations - SHOULD Improvements (2)
[CSAF-TIMELINE-001] SHOULD
/document/tracking/initial_release_date
initial_release_date should not be in the future (clock sync issue)
```

**Failed Document (🔴 Red):**
```
✗ Validation Failed (2 errors)
✗ Schema (1)
✗ VEX Rules (1)
⚠ Warnings (1)

🚨 Errors - MUST Requirements (2)
[SCHEMA-001] ERROR
/statements/0/status
'in_progress' is not one of ['affected', 'fixed', 'under_investigation', 'not_affected']

[OVX-STATE-001] MUST
/statements/0
status 'not_affected' MUST include justification OR impact_statement

⚠️ Warnings - SHOULD Recommendations (1)
[OVX-VULNID-002] SHOULD
/statements/0/vulnerability/name
vulnerability name should follow standard format (CVE-YYYY-NNNNN)
```

#### 📖 Rule Reference

Click "📖 View Validation Rules" to see:
- All 52 rules organized by format
- MUST vs SHOULD classification
- Rule descriptions
- Expandable/collapsible sections

---

## 🔧 API Documentation

### Endpoints

#### POST /api/validate

**Request:**
```json
{
  "content": {
    // Your VEX document here
  }
}
```

**Response:**
```json
{
  "success": true,
  "schemaType": "openvex",
  "isValid": true,
  "errors": [
    {
      "path": "/statements/0",
      "message": "status 'not_affected' MUST include justification OR impact_statement",
      "schema_path": "/statements/0",
      "severity": "error",
      "rule_id": "OVX-STATE-001"
    }
  ],
  "errorCount": 1,
  "validationLevels": {
    "schema": true,
    "vexRules": false,
    "schemaErrorCount": 0,
    "vexRuleErrorCount": 1,
    "schemaWarningCount": 0,
    "vexRuleWarningCount": 0
  },
  "severityBreakdown": {
    "errors": 1,
    "warnings": 0
  }
}
```

#### GET /api/rules/{format}

**Formats:** `openvex`, `csaf`, `cyclonedx`

**Response:**
```json
{
  "format": "openvex",
  "version": "0.2.0",
  "rules": [
    {
      "id": "OVX-STATE-001",
      "severity": "error",
      "description": "not_affected → justification OR impact_statement (MUST)"
    }
  ],
  "summary": {
    "total": 16,
    "must": 9,
    "should": 7
  }
}
```

#### GET /api/schemas

**Response:**
```json
{
  "schemas": ["openvex", "csaf", "cyclonedx"],
  "versions": {
    "openvex": "0.2.0",
    "csaf": "2.1",
    "cyclonedx": "1.7"
  }
}
```

---

## 📚 Examples

### Valid OpenVEX Document

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.com/vex/2024-001",
  "author": "Security Team",
  "role": "Vendor",
  "timestamp": "2024-01-15T10:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "@id": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
        "name": "CVE-2024-12345"
      },
      "timestamp": "2024-01-15T10:00:00Z",
      "products": [
        {
          "@id": "pkg:maven/com.example/product@1.0.0"
        }
      ],
      "status": "not_affected",
      "justification": "component_not_present"
    }
  ]
}
```

### Valid CSAF Document (Minimal)

```json
{
  "document": {
    "category": "csaf_vex",
    "csaf_version": "2.1",
    "publisher": {
      "category": "vendor",
      "name": "Example Corp",
      "namespace": "https://example.com"
    },
    "title": "Example VEX",
    "tracking": {
      "id": "example-2024-001",
      "initial_release_date": "2024-01-15T10:00:00Z",
      "current_release_date": "2024-01-15T10:00:00Z",
      "revision_history": [
        {
          "number": "1",
          "date": "2024-01-15T10:00:00Z",
          "summary": "Initial"
        }
      ],
      "status": "final",
      "version": "1"
    }
  },
  "product_tree": {
    "full_product_names": [
      {
        "product_id": "PROD-001",
        "name": "Product 1.0.0"
      }
    ]
  },
  "vulnerabilities": [
    {
      "cve": "CVE-2024-12345",
      "product_status": {
        "known_not_affected": ["PROD-001"]
      },
      "flags": [
        {
          "product_ids": ["PROD-001"],
          "label": "component_not_present"
        }
      ]
    }
  ]
}
```

### Valid CycloneDX Document (Minimal)

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "version": 1,
  "metadata": {
    "timestamp": "2024-01-15T10:00:00Z"
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-1",
      "name": "example-lib"
    }
  ],
  "vulnerabilities": [
    {
      "id": "CVE-2024-12345",
      "analysis": {
        "state": "not_affected",
        "justification": "code_not_present"
      },
      "affects": [
        {
          "ref": "comp-1"
        }
      ]
    }
  ]
}
```

---

## 🛠️ Development

### Project Structure

```
enhanced_web_validator/
├── app.py                          # Flask web server
├── validator.html                  # Web interface
├── requirements.txt                # Python dependencies
├── README.md                       # This file
├── enhanced_validators/
│   ├── openvex_validator.py        # OpenVEX validator
│   ├── csaf_validator.py           # CSAF validator
│   ├── cyclonedx_validator.py      # CycloneDX validator
│   └── README.md                   # Validator documentation
├── schemas/
│   ├── openvex-0.2.0-schema.json   # OpenVEX schema
│   ├── csaf_2.1_json_schema.json   # CSAF schema
│   └── bom-1.7-schema.json         # CycloneDX schema
└── samples/
    ├── openvex-valid.json          # Example documents
    ├── csaf-valid.json
    └── cyclonedx-valid.json
```

### Running Tests

```bash
# Test OpenVEX validator
python enhanced_validators/openvex_validator.py \
  schemas/openvex-0.2.0-schema.json \
  samples/openvex-valid.json

# Test CSAF validator
python enhanced_validators/csaf_validator.py \
  schemas/csaf_2.1_json_schema.json \
  samples/csaf-valid.json

# Test CycloneDX validator
python enhanced_validators/cyclonedx_validator.py \
  schemas/bom-1.7-schema.json \
  samples/cyclonedx-valid.json
```

### Adding Custom Rules

```python
# In validator file (e.g., openvex_validator.py)

def _validate_custom_rule(data, errors):
    """Custom validation rule"""
    if condition_not_met:
        errors.append({
            "path": "/path/to/field",
            "message": "[VEX-Custom] Your error message",
            "schema_path": "/path/to/field",
            "severity": "warning",  # or "error"
            "rule_id": "CUSTOM-001"
        })

# Add to main validation function
def validate_openvex(data, schema):
    errors = []
    # ... existing validation ...
    _validate_custom_rule(data, errors)
    # ...
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

---

## 📝 Changelog

### v2.2 (2026-01-23)
- 🔧 Fixed CSAF TIMELINE rules (14 MUST · 3 SHOULD)
- 🎨 Improved warning badge display
- 📝 Updated rule descriptions
- ✅ All validators now spec-compliant

### v2.1 (2026-01-23)
- 🎨 Added warning severity visualization (orange alerts)
- 📊 Added total warnings badge
- 🔧 Fixed badge display (numbers only, no E/W)
- 📝 Improved rule reference UI

### v2.0 (2026-01-22)
- ✨ Initial release with 52 comprehensive rules
- 🌐 Web interface with drag & drop
- 📖 Interactive rule reference
- 🎯 Severity classification (MUST/SHOULD)
- 📊 Detailed validation reports

---

## 🤝 Support

### Documentation
- **Official Specs:**
  - [OpenVEX 0.2.0](https://github.com/openvex/spec)
  - [CSAF 2.1](https://docs.oasis-open.org/csaf/csaf/v2.1/)
  - [CycloneDX 1.7](https://cyclonedx.org/docs/)

### Issues
- Report bugs or request features via GitHub Issues
- Include validator version, input document, and error message

### Community
- Join discussions about VEX standards
- Share examples and best practices

---

## 📄 License

MIT License

Copyright (c) 2026 Enhanced VEX Validator Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

## 🙏 Acknowledgments

- **OASIS CSAF TC** - CSAF 2.1 specification
- **OpenVEX Community** - OpenVEX 0.2.0 specification
- **CycloneDX Community** - CycloneDX 1.7 specification
- **JSON Schema** - Validation framework

---

## 🚀 Get Started

```bash
# Download and extract
tar -xzf enhanced_web_validator_v2.2.tar.gz
cd enhanced_web_validator

# Install and run
pip install -r requirements.txt
python app.py

# Open http://localhost:5000
```

**Happy Validating! 🎉**