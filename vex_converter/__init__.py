"""
VEX Converter Package
OpenVEX ↔ CycloneDX ↔ CSAF
"""

__version__ = "1.0.0"

from .models import (
    DocumentFormat, VulnerabilityStatus, Justification,
    ConversionOptions, ConversionMetadata, TrackingTable,
    CIM, Subject, Vulnerability, VEXStatement, Metadata, Publisher,
    StatusInfo, Identifier, CvssRating, Reference, MappingRecord
)

from .to_cim import OpenVEXToCIM, CycloneDXToCIM, CSAFToCIM
from .from_cim import CIMToOpenVEX, CIMToCycloneDX, CIMToCSAF
from .validator import Validator, LossAnalyzer
from .nvd_client import NVDAPIClient

__all__ = [
    # Version
    "__version__",
    # Models
    "DocumentFormat", "VulnerabilityStatus", "Justification",
    "ConversionOptions", "ConversionMetadata", "TrackingTable",
    "CIM", "Subject", "Vulnerability", "VEXStatement", "Metadata", "Publisher",
    "StatusInfo", "Identifier", "CvssRating", "Reference", "MappingRecord",
    # Converters
    "OpenVEXToCIM", "CycloneDXToCIM", "CSAFToCIM",
    "CIMToOpenVEX", "CIMToCycloneDX", "CIMToCSAF",
    # Utilities
    "Validator", "LossAnalyzer", "NVDAPIClient"
]
