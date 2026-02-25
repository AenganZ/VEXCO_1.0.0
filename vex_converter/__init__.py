"""
VEX Converter Package
OpenVEX <-> CycloneDX <-> CSAF
v1.0.0 - Group 3 fixes: title/desc separation, remediation 1:1 mapping, EPSS, multiple PURL
"""

__version__ = "1.0.0"

from .models import (
    CIM, Metadata, Publisher, Subject, Vulnerability, VEXStatement,
    StatusInfo, Identifier, CvssRating, Reference, DocumentFormat,
    VulnerabilityStatus, Justification, ConversionOptions, ConversionMetadata,
    TrackingTable, MappingRecord
)
from .to_cim import OpenVEXToCIM, CycloneDXToCIM, CSAFToCIM
from .from_cim import CIMToOpenVEX, CIMToCycloneDX, CIMToCSAF
from .constants import (
    MAPPING_TABLE, 
    map_openvex_justification_str_to_enum,
    map_cyclonedx_justification_to_enum,
    justification_enum_to_openvex_str,
    justification_enum_to_cyclonedx_str,
    justification_enum_to_csaf_flag,
    csaf_flag_to_justification_enum,
    get_alias_system_name,
    get_cwe_name
)
from .utils import (
    dt_to_iso_z, now_utc, ensure_urn_uuid, normalize_purl,
    create_product_identification_helper, detect_format,
    encode_structured_text, decode_structured_text,
    set_extension_field, get_extension_field,
    dedupe_components, generate_bomlink, safe_str,
    dedupe_ratings, filter_placeholder_ratings,
    dedupe_references, unique_list, normalize_identifier,
    simplify_product_id
)
from .validator import Validator, LossAnalyzer


def convert(source_data: dict, target_format: str, options: ConversionOptions = None) -> dict:
    """
    Convert VEX document between formats.
    
    Args:
        source_data: Source VEX document as dict
        target_format: Target format ('openvex', 'cyclonedx', 'csaf')
        options: Conversion options
        
    Returns:
        Converted VEX document as dict
    """
    if options is None:
        options = ConversionOptions()
    
    # Detect source format
    source_format = detect_format(source_data)
    
    if source_format == target_format:
        return source_data
    
    # Convert to CIM first
    if source_format == "openvex":
        cim = OpenVEXToCIM(options).convert(source_data)
    elif source_format == "cyclonedx":
        cim = CycloneDXToCIM(options).convert(source_data)
    elif source_format == "csaf":
        cim = CSAFToCIM(options).convert(source_data)
    else:
        raise ValueError(f"Unknown source format: {source_format}")
    
    # Convert from CIM to target format
    tracking = TrackingTable()
    if target_format == "openvex":
        result = CIMToOpenVEX(options, tracking).convert(cim)
    elif target_format == "cyclonedx":
        result = CIMToCycloneDX(options, tracking).convert(cim)
    elif target_format == "csaf":
        result = CIMToCSAF(options, tracking).convert(cim)
    else:
        raise ValueError(f"Unknown target format: {target_format}")
    
    return result


def convert_with_tracking(source_data: dict, target_format: str, options: ConversionOptions = None):
    """
    Convert VEX document between formats with field tracking.
    
    Returns:
        Tuple of (converted document, tracking table)
    """
    if options is None:
        options = ConversionOptions()
    
    # Detect source format
    source_format = detect_format(source_data)
    
    if source_format == target_format:
        return source_data, TrackingTable()
    
    # Convert to CIM first
    if source_format == "openvex":
        cim = OpenVEXToCIM(options).convert(source_data)
    elif source_format == "cyclonedx":
        cim = CycloneDXToCIM(options).convert(source_data)
    elif source_format == "csaf":
        cim = CSAFToCIM(options).convert(source_data)
    else:
        raise ValueError(f"Unknown source format: {source_format}")
    
    # Convert from CIM to target format with tracking
    tracking = TrackingTable()
    if target_format == "openvex":
        result = CIMToOpenVEX(options, tracking).convert(cim)
    elif target_format == "cyclonedx":
        result = CIMToCycloneDX(options, tracking).convert(cim)
    elif target_format == "csaf":
        result = CIMToCSAF(options, tracking).convert(cim)
    else:
        raise ValueError(f"Unknown target format: {target_format}")
    
    return result, tracking


__all__ = [
    '__version__',
    'CIM', 'Metadata', 'Publisher', 'Subject', 'Vulnerability', 'VEXStatement',
    'StatusInfo', 'Identifier', 'CvssRating', 'Reference', 'DocumentFormat',
    'VulnerabilityStatus', 'Justification', 'ConversionOptions', 'ConversionMetadata',
    'TrackingTable', 'MappingRecord',
    'OpenVEXToCIM', 'CycloneDXToCIM', 'CSAFToCIM',
    'CIMToOpenVEX', 'CIMToCycloneDX', 'CIMToCSAF',
    'Validator', 'LossAnalyzer',
    'MAPPING_TABLE',
    'map_openvex_justification_str_to_enum',
    'map_cyclonedx_justification_to_enum',
    'justification_enum_to_openvex_str',
    'justification_enum_to_cyclonedx_str',
    'justification_enum_to_csaf_flag',
    'csaf_flag_to_justification_enum',
    'get_alias_system_name',
    'get_cwe_name',
    'dt_to_iso_z', 'now_utc', 'ensure_urn_uuid', 'normalize_purl',
    'create_product_identification_helper', 'detect_format',
    'encode_structured_text', 'decode_structured_text',
    'set_extension_field', 'get_extension_field',
    'dedupe_components', 'generate_bomlink', 'safe_str',
    'dedupe_ratings', 'filter_placeholder_ratings',
    'dedupe_references', 'unique_list', 'normalize_identifier',
    'simplify_product_id',
    'convert', 'convert_with_tracking'
]