"""
VEX Converter Constants and Mappings
"""
from typing import Optional
from .models import Justification

# ===== MAPPING TABLES =====

MAPPING_TABLE = {
    "cyclonedx_state_to_openvex_status": {
        "exploitable": "affected",
        "in_triage": "under_investigation",
        "not_affected": "not_affected",
        "resolved": "fixed",
        "false_positive": "not_affected",  # Special: preserve original
        "resolved_with_pedigree": "fixed"   # Special: preserve pedigree
    },
    "openvex_status_to_cyclonedx_state": {
        "affected": "exploitable",
        "not_affected": "not_affected",
        "fixed": "resolved",
        "under_investigation": "in_triage"
    },
    "openvex_justification_to_cyclonedx": {
        "component_not_present": "code_not_present",
        "vulnerable_code_not_present": "code_not_present",  # Can also be protected_by_compiler
        "vulnerable_code_not_in_execute_path": "code_not_reachable",
        "vulnerable_code_cannot_be_controlled_by_adversary": "requires_configuration",  # Can also be requires_environment or protected_at_perimeter
        "inline_mitigations_already_exist": "protected_by_mitigating_control"  # Can also be protected_at_runtime
    },
    "cyclonedx_justification_to_openvex": {
        "code_not_present": "component_not_present",
        "code_not_reachable": "vulnerable_code_not_in_execute_path",
        "requires_configuration": "vulnerable_code_cannot_be_controlled_by_adversary",
        "requires_dependency": "inline_mitigations_already_exist",
        "requires_environment": "vulnerable_code_cannot_be_controlled_by_adversary",
        "protected_by_compiler": "vulnerable_code_not_present",  # Changed: more accurate semantic match
        "protected_at_runtime": "inline_mitigations_already_exist",
        "protected_at_perimeter": "vulnerable_code_cannot_be_controlled_by_adversary",  # Changed: perimeter protection is about adversary control
        "protected_by_mitigating_control": "inline_mitigations_already_exist"
    },
    "csaf_flag_to_openvex_justification": {
        "component_not_present": "component_not_present",
        "vulnerable_code_not_present": "vulnerable_code_not_present",
        "vulnerable_code_not_in_execute_path": "vulnerable_code_not_in_execute_path",
        "vulnerable_code_cannot_be_controlled_by_adversary": "vulnerable_code_cannot_be_controlled_by_adversary",
        "inline_mitigations_already_exist": "inline_mitigations_already_exist"
    }
}

def map_openvex_justification_str_to_enum(s: str) -> Optional[Justification]:
    mapping = {
        "component_not_present": Justification.COMPONENT_NOT_PRESENT,
        "vulnerable_code_not_present": Justification.VULNERABLE_CODE_NOT_PRESENT,
        "vulnerable_code_not_in_execute_path": Justification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
        "vulnerable_code_cannot_be_controlled_by_adversary": Justification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY,
        "inline_mitigations_already_exist": Justification.INLINE_MITIGATIONS_ALREADY_EXIST
    }
    return mapping.get(s)

def map_cyclonedx_justification_to_enum(s: str) -> Optional[Justification]:
    openvex_just = MAPPING_TABLE["cyclonedx_justification_to_openvex"].get(s)
    return map_openvex_justification_str_to_enum(openvex_just) if openvex_just else None

def justification_enum_to_openvex_str(j: Justification) -> str:
    return j.value

def justification_enum_to_cyclonedx_str(j: Justification) -> Optional[str]:
    # Use openvex_justification_to_cyclonedx mapping (not the reverse)
    return MAPPING_TABLE["openvex_justification_to_cyclonedx"].get(j.value)

def justification_enum_to_csaf_flag(j: Justification) -> Optional[str]:
    return j.value

def csaf_flag_to_justification_enum(flag: str) -> Optional[Justification]:
    return map_openvex_justification_str_to_enum(
        MAPPING_TABLE["csaf_flag_to_openvex_justification"].get(flag)
    )

# Component type classification based on identifier patterns
def classify_component_type(identifier: str, name: str = "") -> str:
    """
    Classify component type based on PURL, CPE, or name patterns.
    Returns CycloneDX component type.
    """
    id_lower = identifier.lower()
    name_lower = name.lower() if name else ""
    combined = id_lower + " " + name_lower

    # Source code files - check first before other rules
    source_extensions = [
        ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx",  # C/C++
        ".java", ".class",  # Java
        ".py", ".pyx",  # Python
        ".go",  # Go
        ".rs",  # Rust
        ".js", ".ts", ".jsx", ".tsx",  # JavaScript/TypeScript
        ".php",  # PHP
        ".rb",  # Ruby
        ".swift",  # Swift
        ".kt", ".kts",  # Kotlin
        ".cs",  # C#
        ".m", ".mm",  # Objective-C
        ".s", ".asm",  # Assembly
        ".sh", ".bash",  # Shell scripts
    ]
    if any(combined.endswith(ext) for ext in source_extensions):
        return "file"
    
    # Check if it's a file path (contains / and has extension)
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
