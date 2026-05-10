# VEX Converter
A Python package for converting VEX documents across multiple formats.

## Overview
VEX Converter uses a Common Intermediate Model (CIM) as an internal representation to support bidirectional conversion between major VEX formats.

## Supported Formats
- OpenVEX 0.2.0
- CycloneDX VEX 1.5 - 1.7
- CSAF VEX Profile 2.0 / 2.1
- CycloneDX VDR (Vulnerability Disclosure Report)

## Conversion Model
All conversions pass through a Common Intermediate Model (CIM).
- Source formats are first normalized into CIM
- Target documents are then generated from CIM

This hub-based design simplifies format conversion from direct pairwise mappings to a normalized `N:1: N` workflow.

## Package Layout
vex_converter/
  __init__.py
  models.py
  constants.py
  to_cim.py
  from_cim.py
  utils.py
  validator.py
  vdr.py
  nvd_client.py

## Core Components
models.py
Defines the CIM data model, including:
document model
product/component subjects
vulnerability records
VEX statements
normalized status values

## to_cim.py
Parses source documents into CIM objects:
OpenVEX -> CIM
CycloneDX -> CIM
CSAF -> CIM

## from_cim.py
Serializes CIM objects into target formats:
CIM -> OpenVEX
CIM -> CycloneDX
CIM -> CSAF

### Example
from vex_converter import CycloneDXToCIM, CIMToCSAF, ConversionOptions

options = ConversionOptions(reversible=False)

cim = CycloneDXToCIM(options).convert(cyclonedx_json)
csaf = CIMToCSAF(options).convert(cim)

### CLI
python convert.py input.json --target csaf --output result.json

### Conversion Options
Option	Description
reversible	Preserve metadata needed for round-trip restoration
restore	Attempt to restore the original representation from preserved metadata

## Status Mapping
| CIM | OpenVEX | CycloneDX | CSAF |
| --- | --- | --- | --- |
| `NOT_AFFECTED` | `not_affected` | `not_affected` | `known_not_affected` |
| `AFFECTED` | `affected` | `exploitable` | `known_affected` |
| `FIXED` | `fixed` | `resolved` | `fixed` |
| `UNDER_INVESTIGATION` | `under_investigation` | `in_triage` | `under_investigation` |

### VDR Support
The converter can also generate CycloneDX VDR output from the CIM model.

### Optional NVD Enrichment
NVD data can be used to enrich vulnerability metadata when generating VDR output.