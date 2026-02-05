"""
VEX Converter Utility Functions
"""
import json
import re
import uuid
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple, Any
from .models import Subject, Identifier

# ===== PRODUCT ID UTILITIES =====

def validate_purl(purl: str) -> Tuple[bool, Optional[str]]:
    """
    Validate package URL against official PURL spec.
    Returns (is_valid, error_message)

    PURL format: pkg:type/namespace/name@version?qualifiers#subpath
    """
    if not purl or not isinstance(purl, str):
        return False, "PURL cannot be empty"

    # Basic pattern check
    if not purl.startswith("pkg:"):
        return False, "PURL must start with 'pkg:'"

    # Remove pkg: prefix
    remainder = purl[4:]

    # Extract type (required)
    if "/" not in remainder:
        return False, "PURL must have format pkg:type/..."

    parts = remainder.split("/", 1)
    pkg_type = parts[0]

    # Type must be lowercase alphanumeric with dots, dashes, plus
    if not re.match(r'^[a-z0-9.\-+]+$', pkg_type):
        return False, f"Invalid package type: {pkg_type} (must be lowercase)"

    if len(parts) < 2:
        return False, "PURL must have name component"

    # Extract name and optional components
    rest = parts[1]

    # Check for empty segments
    if "//" in purl:
        return False, "PURL cannot have empty segments"

    # Extract version, qualifiers, subpath
    name_part = rest.split("@")[0].split("?")[0].split("#")[0]

    if not name_part:
        return False, "PURL must have name component"

    # Check for invalid characters in name
    # Name can have letters, numbers, dots, dashes, underscores, /
    if not re.match(r'^[a-zA-Z0-9.\-_/]+$', name_part):
        return False, f"Invalid characters in name: {name_part}"

    return True, None

def normalize_purl(purl: str) -> str:
    """
    Normalize PURL to canonical form.
    - Type to lowercase
    - Remove extra slashes
    - Validate format
    """
    if not purl:
        return purl

    # Validate first
    is_valid, error = validate_purl(purl)
    if not is_valid:
        # Return as-is if invalid (caller should handle)
        return purl

    # Type to lowercase
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
    Generate bomlink URN according to CycloneDX specification.

    Format: urn:cdx:{uuid}/{version}#{component-ref}

    Example:
        serial_number: urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79
        version: 1
        component_ref: pkg:npm/lodash@4.17.21

        Result: urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#pkg:npm/lodash@4.17.21
    """
    # Extract UUID from serial_number
    uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    uuid_match = re.search(uuid_pattern, serial_number, re.IGNORECASE)

    if uuid_match:
        uuid_val = uuid_match.group(0).lower()
    else:
        # Generate new UUID if not found
        uuid_val = str(uuid.uuid4())

    # Clean component_ref (remove any existing urn:cdx prefix)
    if component_ref.startswith("urn:cdx:"):
        # Extract just the component part after #
        if "#" in component_ref:
            component_ref = component_ref.split("#")[-1]

    return f"urn:cdx:{uuid_val}/{version}#{component_ref}"

def create_product_identification_helper(subject: "Subject", serial_number: Optional[str] = None) -> Optional[Dict]:
    """
    Create comprehensive product identification helper for CSAF 2.1.

    Supports all CSAF 2.1 helper fields:
    - purl: Package URL
    - cpe: Common Platform Enumeration
    - hashes: File hashes (sha256, etc.)
    - model_numbers: Hardware/software model numbers
    - sbom_urls: URLs to SBOM documents
    - serial_numbers: Serial numbers
    - skus: Stock keeping units
    - x_generic_uris: Generic URIs (e.g., bomlink)
    """
    helper = {}

    # Standard identifiers
    purl = next((i.value for i in subject.identifiers if i.type == "purl"), None)
    if purl:
        helper["purls"] = [normalize_purl(purl)]

    cpe = next((i.value for i in subject.identifiers if i.type == "cpe"), None)
    if cpe:
        helper["cpe"] = cpe

    # Extended fields
    if subject.hashes:
        # CSAF 2.1 hashes format:
        # [{
        #   "file_hashes": [{"algorithm": "sha256", "value": "..."}],
        #   "filename": "..."
        # }]
        # CIM hashes format: [{"algorithm": "sha-256", "value": "..."}]
        
        # Group all hashes into one file_hashes array
        file_hashes = []
        for h in subject.hashes:
            alg = h.get("algorithm", "").replace("sha-", "sha")  # sha-256 → sha256
            val = h.get("value")
            if alg and val:
                file_hashes.append({"algorithm": alg, "value": val})
        
        if file_hashes:
            # Use subject name as filename if available, otherwise "unknown"
            filename = subject.name if subject.name else "unknown"
            helper["hashes"] = [{
                "file_hashes": file_hashes,
                "filename": filename
            }]

    if subject.model_numbers:
        helper["model_numbers"] = subject.model_numbers

    if subject.sbom_urls:
        helper["sbom_urls"] = subject.sbom_urls

    if subject.serial_numbers:
        helper["serial_numbers"] = subject.serial_numbers

    if subject.skus:
        helper["skus"] = subject.skus

    # Generate x_generic_uris with auto-detected namespace
    x_generic_uris = []
    
    # Add original_id as x_generic_uri if it's a URN
    if subject.original_id and (subject.original_id.startswith("urn:") or subject.original_id.startswith("pkg:") or "#SPDXRef-" in subject.original_id):
        uri = subject.original_id
        namespace = None
        
        # Classify namespace based on URI format
        if uri.startswith("urn:cdx:"):
            # CycloneDX BOM-Link
            namespace = "https://cyclonedx.org/capabilities/bomlink/"
        elif "#SPDXRef-" in uri or uri.startswith("https://spdx.org"):
            # SPDX
            namespace = "https://spdx.github.io/spdx-spec/latest/document-creation-information/#65-spdx-document-namespace-field"
        elif uri.startswith("pkg:"):
            # Package URL - use PURL namespace
            namespace = "https://github.com/package-url/purl-spec"
        else:
            # Generic URN/URI
            namespace = "https://www.iana.org/assignments/urn-namespaces/urn-namespaces.xhtml"
        
        x_generic_uris.append({
            "namespace": namespace,
            "uri": uri
        })
    
    # Generate bomlink for PURL if available
    if purl and serial_number:
        bomlink = generate_bomlink(serial_number, 1, purl)
        # Only add if not already present
        if not any(u["uri"] == bomlink for u in x_generic_uris):
            x_generic_uris.append({
                "namespace": "https://cyclonedx.org/capabilities/bomlink/",
                "uri": bomlink
            })
    
    if x_generic_uris:
        helper["x_generic_uris"] = x_generic_uris

    return helper if helper else None

def parse_version_range(version_str: str) -> Dict:
    """
    Parse version range string to structured format.

    Supports:
    - Single version: "2.4" → {"version": "2.4"}
    - Range with operators: ">=1.0|<=2.3" → {"range": "vers:generic/>=1.0|<=2.3"}
    - Wildcard: "*" → {"range": "vers:generic/*"}

    Returns dict with either 'version' or 'range' key.
    """
    if not version_str or version_str == "*":
        return {"range": "vers:generic/*"}

    version_str = version_str.strip()

    # Check for range operators
    range_operators = [">=", "<=", ">", "<", "|", "-"]
    has_range = any(op in version_str for op in range_operators)

    if has_range:
        # It's a range
        return {"range": f"vers:generic/{version_str}"}

    # Single version
    return {"version": version_str}

def extract_version_from_product_id(product_id: str) -> Optional[str]:
    """
    Extract version information from product ID if present.

    Examples:
        "npm-lodash-4.17.21" → "4.17.21"
        "product-ABC:v2.0" → "2.0"
        "simple-product" → None
    """
    # Pattern 1: product:vVERSION
    if ":v" in product_id:
        return product_id.split(":v")[-1]

    # Pattern 2: package-name-VERSION (where VERSION looks like version)
    parts = product_id.split("-")
    if len(parts) >= 2:
        last_part = parts[-1]
        # Check if last part looks like version (contains digits and dots)
        if re.match(r'^\d+(\.\d+)*', last_part):
            return last_part

    return None

def simplify_product_id(identifier: str, name: str = "") -> str:
    """
    Simplify product IDs to be shorter but still unique.

    Examples:
        pkg:npm/lodash@4.17.21 → npm-lodash-4.17.21
        pkg:apk/alpine/busybox@1.2.3 → apk-busybox-1.2.3
        cpe:2.3:a:vendor:product:1.0 → vendor-product-1.0
        urn:cdx:uuid/1#product-ABC → product-ABC

    Fallback: Generate short hash-based ID
    """
    if not identifier:
        if name:
            # Use name as base
            clean_name = re.sub(r'[^\w\-\.]', '-', name)[:50]
            return f"prod-{clean_name}"
        return f"prod-{uuid.uuid4().hex[:8]}"

    # Handle PURL: pkg:npm/lodash@4.17.21
    if identifier.startswith("pkg:"):
        try:
            # Extract type/namespace/name@version
            parts = identifier[4:].split("/")
            pkg_type = parts[0]

            if len(parts) > 1:
                # Has namespace
                rest = "/".join(parts[1:])
                name_version = rest.split("@")[0].split("?")[0]
                name_only = name_version.split("/")[-1]  # Take last part

                # Get version if present
                version = ""
                if "@" in rest:
                    version = rest.split("@")[1].split("?")[0]
                    return f"{pkg_type}-{name_only}-{version}"
                return f"{pkg_type}-{name_only}"
        except:
            pass

    # Handle CPE: cpe:2.3:a:vendor:product:version
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

    # Handle URN: urn:cdx:uuid/1#product-ABC
    if "#" in identifier:
        after_hash = identifier.split("#")[-1]
        if after_hash:
            return after_hash

    # Fallback: create short hash
    id_hash = hashlib.sha256(identifier.encode()).hexdigest()[:12]
    if name:
        clean_name = re.sub(r'[^\w\-\.]', '-', name)[:30]
        return f"{clean_name}-{id_hash[:6]}"
    return f"prod-{id_hash}"

# ===== NVD API =====

# ===== UTILITIES =====

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
    """Encode structured data for embedding in free-text fields"""
    if not data: return ""
    parts = []
    for key, value in data.items():
        json_str = json.dumps(value, ensure_ascii=False, separators=(',', ':'))
        parts.append(f"[{key}:{json_str}]")
    return " || ".join(parts)

def decode_structured_text(text: str) -> dict:
    """Decode structured data from free-text fields"""
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

# ===== EXTENSION DATA HELPERS =====

def set_extension_field(obj: Any, namespace: str, field_path: str, value: Any):
    """Set a field in extension_data with namespace
    
    Args:
        obj: Object with extension_data attribute
        namespace: Format namespace (cyclonedx, openvex, csaf)
        field_path: Dot-separated field path (e.g., "document.aggregate_severity.text")
        value: Value to store
    
    Example:
        set_extension_field(metadata, "csaf", "document.aggregate_severity.namespace", "https://...")
    """
    if not hasattr(obj, 'extension_data'):
        return
    
    full_key = f"{namespace}.{field_path}"
    obj.extension_data[full_key] = value

def get_extension_field(obj: Any, namespace: str, field_path: str, default: Any = None) -> Any:
    """Get a field from extension_data with namespace
    
    Args:
        obj: Object with extension_data attribute
        namespace: Format namespace (cyclonedx, openvex, csaf)
        field_path: Dot-separated field path
        default: Default value if not found
    
    Returns:
        Stored value or default
    """
    if not hasattr(obj, 'extension_data'):
        return default
    
    full_key = f"{namespace}.{field_path}"
    return obj.extension_data.get(full_key, default)

def get_all_extension_fields(obj: Any, namespace: str) -> Dict[str, Any]:
    """Get all extension fields for a specific namespace
    
    Args:
        obj: Object with extension_data attribute
        namespace: Format namespace (cyclonedx, openvex, csaf)
    
    Returns:
        Dictionary with field_path -> value mappings (without namespace prefix)
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
    """Set a value in a nested dictionary using dot notation
    
    Args:
        data: Dictionary to modify
        path: Dot-separated path (e.g., "document.aggregate_severity.text")
        value: Value to set
    
    Example:
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
    """Get a value from a nested dictionary using dot notation
    
    Args:
        data: Dictionary to read from
        path: Dot-separated path
        default: Default value if path not found
    
    Returns:
        Value at path or default
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
    """Remove placeholder CVSS ratings (score 0, severity none)"""
    return [r for r in ratings if not (
        r.get("score") == 0.0 and 
        r.get("severity") == "none" and 
        "CR:X/IR:X/AR:X" in r.get("vector", "")
    )]

def dedupe_ratings(ratings: List[Dict]) -> List[Dict]:
    """Remove duplicate CVSS ratings"""
    seen = set()
    result = []
    for r in ratings:
        key = (r.get("method"), r.get("vector"), r.get("score"))
        if key not in seen:
            seen.add(key)
            result.append(r)
    return result

def extract_all_fields(data: Any, prefix: str = "", max_depth: int = 10) -> set:
    """Recursively extract all field paths from a data structure"""
    if max_depth <= 0:
        return set()

    fields = set()

    if isinstance(data, dict):
        for key, value in data.items():
            field_path = f"{prefix}.{key}" if prefix else key
            fields.add(field_path)

            # Recurse into nested structures
            if isinstance(value, (dict, list)):
                nested_fields = extract_all_fields(value, field_path, max_depth - 1)
                fields.update(nested_fields)

    elif isinstance(data, list) and data:
        # For lists, check the first item's structure
        if isinstance(data[0], dict):
            nested_fields = extract_all_fields(data[0], prefix, max_depth - 1)
            fields.update(nested_fields)

    return fields

def normalize_field_path(path: str) -> str:
    """Normalize field path for comparison (remove array indices patterns)"""
    # This is already a path without indices, but keep for consistency
    return path

def dedupe_references(refs: List[Dict]) -> List[Dict]:
    """Remove duplicate references"""
    seen = set()
    result = []
    for r in refs:
        # Support both CSAF format (url at top level) and CycloneDX format (url in source)
        url = r.get("url") or (r.get("source", {}).get("url") if isinstance(r.get("source"), dict) else None)
        if url and url not in seen:
            seen.add(url)
            result.append(r)
    return result

def dedupe_components(components: List[Dict]) -> Tuple[List[Dict], Dict[str, str]]:
    """Deduplicate components and return mapping of old refs to new refs"""
    seen_purls, seen_cpes = {}, {}
    deduplicated, ref_mapping = [], {}

    for c in components:
        purl = normalize_purl(c.get("purl", ""))
        cpe = c.get("cpe", "")
        original_ref = c.get("bom-ref")

        if purl and purl in seen_purls:
            ref_mapping[original_ref] = seen_purls[purl]
        elif cpe and cpe in seen_cpes:
            ref_mapping[original_ref] = seen_cpes[cpe]
        else:
            if purl: seen_purls[purl] = original_ref
            if cpe: seen_cpes[cpe] = original_ref
            deduplicated.append(c)

    return deduplicated, ref_mapping

# Component type classification
def classify_component_type(identifier: str, name: str = "") -> str:
    """
    Classify component type based on PURL, CPE, or name patterns.
    Returns CycloneDX component type.
    """
    id_lower = identifier.lower()
    name_lower = name.lower() if name else ""
    combined = id_lower + " " + name_lower

    # Source code files
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

    # Container types
    if any(pattern in id_lower for pattern in ["pkg:oci/", "pkg:docker/", "pkg:container/"]):
        return "container"

    # Package managers → library
    pkg_managers = ["pkg:apk/", "pkg:rpm/", "pkg:deb/", "pkg:npm/", "pkg:pypi/", 
                    "pkg:maven/", "pkg:golang/", "pkg:nuget/", "pkg:cargo/",
                    "pkg:composer/", "pkg:cran/", "pkg:hex/"]
    if any(pm in id_lower for pm in pkg_managers):
        return "library"

    # Frameworks
    if "pkg:generic/" in id_lower and "framework" in combined:
        return "framework"
    if any(fw in combined for fw in ["spring", "django", "rails"]):
        return "framework"

    # Platforms/Runtimes
    if any(platform in combined for platform in ["nodejs", "python", "jvm", "java*runtime", "dotnet*runtime"]):
        return "platform"
    if any(k8s in combined for k8s in ["kubernetes", "openshift"]):
        return "platform"

    # Operating systems
    if any(os in combined for os in ["alpine", "ubuntu", "debian", "rhel", "centos", "windows"]):
        return "operating-system"

    # Applications
    if any(app in combined for app in ["server", "service", "backend", "frontend"]):
        return "application"

    # Firmware
    if any(fw in combined for fw in ["firmware", ".bin"]):
        return "firmware"

    # Device drivers
    if any(drv in combined for drv in ["driver", ".ko"]):
        return "device-driver"

    # Devices/Hardware
    if any(dev in combined for dev in ["cpu", "chip", "soc"]):
        return "device"

    # Config/Data files
    if any(combined.endswith(ext) for ext in [".yaml", ".yml", ".json", ".xml"]):
        return "file"

    # ML models
    if any(combined.endswith(ext) for ext in [".onnx", ".pt", ".pkl"]):
        return "machine-learning-model"

    # Data files
    if any(combined.endswith(ext) for ext in [".csv", ".parquet"]):
        return "data"

    # Cryptographic assets
    crypto_patterns = [".pem", ".crt", ".cer", ".key", "token", "secret"]
    if any(pattern in combined for pattern in crypto_patterns):
        return "cryptographic-asset"

    # Default
    return "library"