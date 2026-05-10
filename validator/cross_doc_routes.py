"""
cross_doc_routes.py
Cross-document validation API 엔드포인트.
Flask Blueprint로 분리하여 기존 app.py에 최소 변경으로 연결한다.

기존 app.py에 추가할 코드 (2줄):
    from cross_doc_routes import cross_doc_bp
    app.register_blueprint(cross_doc_bp)
"""
from flask import Blueprint, request, jsonify
import cross_validator

cross_doc_bp = Blueprint("cross_doc", __name__)


@cross_doc_bp.route("/api/validate-with-bom", methods=["POST"])
def api_validate_with_bom():
    """
    VEX + BOM cross-document validation.
    기존 /api/validate와 동일한 JSON body 규격에 bom 필드 추가:
    { content: vexDocObj, bom: bomDocObj }

    응답: 기존 /api/validate 응답에 bom_validation, cross_validation, final_verdict 추가
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "error": "No JSON body"}), 400

    vex_doc = data.get("content")
    bom_doc = data.get("bom")
    if not vex_doc:
        return jsonify({"success": False, "error": "No VEX content provided"}), 400
    if not bom_doc:
        return jsonify({"success": False, "error": "No BOM content provided"}), 400

    # 1. VEX format-native validation (schema + semantic)
    vex_result = _call_existing_validate(vex_doc)

    # 2. BOM schema validation
    bom_validation = _validate_bom_schema(bom_doc)

    # 3. Cross-document validation
    try:
        cross_result = cross_validator.validate_cross(vex_doc, bom_doc)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": f"Cross-validation error: {e}"}), 500

    # 기존 validation의 verdict 추출
    existing_verdict = "valid"
    if vex_result.get("validationLevels", {}).get("native_validation_skipped"):
        existing_verdict = "warning"
    elif vex_result.get("errors"):
        has_errors = any(e.get("severity") == "error" for e in vex_result["errors"])
        if has_errors:
            existing_verdict = "invalid"
        elif vex_result["errors"]:
            existing_verdict = "warning"

    # BOM 스키마 검증 결과를 verdict에 반영
    bom_verdict = "valid"
    if not bom_validation.get("isValid", True):
        bom_schema_errors = [e for e in bom_validation.get("errors", [])
                             if e.get("severity") == "error"]
        if bom_schema_errors:
            bom_verdict = "invalid"  # BOM 스키마 위반은 invalid로

    final = _combine_verdicts(
        _combine_verdicts(existing_verdict, cross_result.get("verdict", "valid"))["verdict"],
        bom_verdict,
    )

    # 응답 조합
    vex_result["bom_validation"] = bom_validation
    vex_result["cross_validation"] = cross_result
    vex_result["final_verdict"] = final
    return jsonify(vex_result)


def _call_existing_validate(vex_doc):
    """기존 /api/validate를 내부적으로 호출하는 대신, 동일한 로직을 재현.
    import 실패 시 validation_skipped를 명시한다."""
    fmt = _detect_format(vex_doc)

    # 기존 validator를 직접 import하여 호출
    try:
        from integrated_validators import validate_openvex, validate_csaf, validate_cyclonedx
        import json
        import os

        # 스키마 로드
        schema_dir = os.path.join(os.path.dirname(__file__), "schemas")
        schema_map = {
            "openvex": "openvex-0.2.0.json",
            "csaf": "csaf-2.1.json",
            "cyclonedx": "cyclonedx-1.7.json",
        }

        schema_file = schema_map.get(fmt)
        if not schema_file:
            return _skipped_response(fmt, f"No schema mapping for format: {fmt}")

        schema_path = os.path.join(schema_dir, schema_file)
        if not os.path.exists(schema_path):
            return _skipped_response(fmt, f"Schema file not found: {schema_file}")

        with open(schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)

        # 버전 감지
        doc_version = _detect_version(vex_doc, fmt)
        # 버전별 스키마 재로드
        versioned_file = None
        if fmt == "csaf" and doc_version:
            versioned_file = f"csaf-{doc_version}.json"
        elif fmt == "cyclonedx" and doc_version:
            versioned_file = f"cyclonedx-{doc_version}.json"
        if versioned_file:
            vp = os.path.join(schema_dir, versioned_file)
            if os.path.exists(vp):
                with open(vp, "r", encoding="utf-8") as f:
                    schema = json.load(f)

        if fmt == "openvex":
            is_valid, errors = validate_openvex(vex_doc, schema)
            detected_version = "0.2.0"
        elif fmt == "csaf":
            is_valid, errors, detected_version = validate_csaf(vex_doc, schema, doc_version)
        elif fmt == "cyclonedx":
            is_valid, errors, detected_version = validate_cyclonedx(vex_doc, schema, doc_version)
        else:
            return _skipped_response(fmt, f"No validator for format: {fmt}")

        # 오류 분류
        schema_errors = [e for e in errors
                         if e.get("rule_id", "").startswith("SCHEMA") and e.get("severity") == "error"]
        vex_errors = [e for e in errors
                      if not e.get("rule_id", "").startswith("SCHEMA") and e.get("severity") == "error"]

        return {
            "success": True,
            "isValid": is_valid,
            "schemaType": fmt,
            "schemaVersion": detected_version,
            "errors": errors,
            "errorCount": len(errors),
            "validationLevels": {
                "schema": len(schema_errors) == 0,
                "vexRules": len(vex_errors) == 0,
            },
        }
    except ImportError as e:
        return _skipped_response(fmt, f"integrated_validators import failed: {e}")
    except Exception as e:
        return _skipped_response(fmt, f"Validation call failed: {e}")


def _validate_bom_schema(bom_doc):
    """BOM 문서의 스키마 검증을 수행한다.
    CycloneDX BOM: 버전별 JSON Schema 검증
    SPDX: 스키마 파일이 있으면 검증, 없으면 skipped
    """
    import json
    import os

    bom_fmt = _detect_bom_format(bom_doc)

    if bom_fmt == "unknown":
        return {
            "success": True,
            "isValid": False,
            "bomFormat": "unknown",
            "errors": [{
                "rule_id": "BOM-DETECT-001",
                "severity": "error",
                "message": "Could not detect BOM format (CycloneDX or SPDX)",
                "path": "/",
            }],
            "errorCount": 1,
        }

    schema_dir = os.path.join(os.path.dirname(__file__), "schemas")

    # 스키마 파일 결정
    schema = None
    detected_version = ""

    if bom_fmt == "cyclonedx":
        spec_version = bom_doc.get("specVersion", "")
        detected_version = spec_version

        # 버전별 스키마 파일 시도
        version_candidates = []
        if spec_version:
            # 정확한 버전 매칭 (1.6, 1.5 등)
            major_minor = ".".join(spec_version.split(".")[:2])
            version_candidates.append(f"cyclonedx-{major_minor}.json")
        # 기본 fallback
        version_candidates.extend([
            "cyclonedx-1.6.json",
            "cyclonedx-1.5.json",
            "cyclonedx-1.4.json",
        ])

        for candidate in version_candidates:
            candidate_path = os.path.join(schema_dir, candidate)
            if os.path.exists(candidate_path):
                try:
                    with open(candidate_path, "r", encoding="utf-8") as f:
                        schema = json.load(f)
                    break
                except Exception:
                    continue

    elif bom_fmt == "spdx":
        detected_version = bom_doc.get("spdxVersion", "")
        # SPDX 스키마 파일 시도
        spdx_candidates = ["spdx-2.3.json", "spdx-3.0.1.json"]
        for candidate in spdx_candidates:
            candidate_path = os.path.join(schema_dir, candidate)
            if os.path.exists(candidate_path):
                try:
                    with open(candidate_path, "r", encoding="utf-8") as f:
                        schema = json.load(f)
                    break
                except Exception:
                    continue

    # 스키마 파일이 없으면 skipped
    if schema is None:
        return {
            "success": True,
            "isValid": True,
            "bomFormat": bom_fmt,
            "bomVersion": detected_version,
            "errors": [{
                "rule_id": "BOM-SCHEMA-SKIPPED",
                "severity": "info",
                "message": f"No schema file available for BOM validation ({bom_fmt} {detected_version}). Schema validation skipped.",
                "path": "/",
            }],
            "errorCount": 0,
            "schemaValidated": False,
        }

    # jsonschema 검증 수행
    try:
        import jsonschema
        errors = []
        validator_cls = jsonschema.Draft7Validator
        # CycloneDX 1.5+는 Draft 2020-12를 사용하지만, jsonschema 호환성을 위해 최선 선택
        json_schema_draft = schema.get("$schema", "")
        if "2020-12" in json_schema_draft:
            try:
                validator_cls = jsonschema.Draft202012Validator
            except AttributeError:
                validator_cls = jsonschema.Draft7Validator
        elif "draft-07" in json_schema_draft:
            validator_cls = jsonschema.Draft7Validator
        elif "draft-04" in json_schema_draft:
            validator_cls = jsonschema.Draft4Validator

        v = validator_cls(schema)
        for error in sorted(v.iter_errors(bom_doc), key=lambda e: list(e.path)):
            path = "/" + "/".join(str(p) for p in error.absolute_path) if error.absolute_path else "/"
            errors.append({
                "rule_id": "BOM-SCHEMA-001",
                "severity": "error",
                "message": error.message[:200],
                "path": path,
            })

        return {
            "success": True,
            "isValid": len(errors) == 0,
            "bomFormat": bom_fmt,
            "bomVersion": detected_version,
            "errors": errors,
            "errorCount": len(errors),
            "schemaValidated": True,
        }

    except ImportError:
        return {
            "success": True,
            "isValid": True,
            "bomFormat": bom_fmt,
            "bomVersion": detected_version,
            "errors": [{
                "rule_id": "BOM-SCHEMA-SKIPPED",
                "severity": "info",
                "message": "jsonschema library not available. BOM schema validation skipped.",
                "path": "/",
            }],
            "errorCount": 0,
            "schemaValidated": False,
        }
    except Exception as e:
        return {
            "success": True,
            "isValid": True,
            "bomFormat": bom_fmt,
            "bomVersion": detected_version,
            "errors": [{
                "rule_id": "BOM-SCHEMA-ERROR",
                "severity": "warning",
                "message": f"BOM schema validation failed unexpectedly: {e}",
                "path": "/",
            }],
            "errorCount": 0,
            "schemaValidated": False,
        }


def _detect_bom_format(doc):
    """BOM 문서 형식을 감지한다."""
    if doc.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    if doc.get("spdxVersion"):
        return "spdx"
    return "unknown"


def _skipped_response(fmt, reason):
    """format-native validation이 수행되지 않았음을 명시하는 응답."""
    return {
        "success": True,
        "isValid": False,
        "schemaType": fmt,
        "errors": [{
            "rule_id": "NATIVE-VALIDATION-SKIPPED",
            "severity": "warning",
            "message": f"Format-native validation was not performed: {reason}",
            "path": "/",
        }],
        "validationLevels": {
            "schema": False,
            "vexRules": False,
            "native_validation_skipped": True,
            "skip_reason": reason,
        },
    }


def _detect_format(doc):
    """VEX 문서 형식을 감지한다."""
    if doc.get("@context") and "openvex" in str(doc.get("@context", "")):
        return "openvex"
    if doc.get("statements") and "@id" in doc:
        return "openvex"
    if doc.get("document", {}).get("tracking"):
        return "csaf"
    if doc.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    return "unknown"


def _detect_version(doc, fmt):
    """문서 버전을 감지한다."""
    if fmt == "csaf":
        csv = doc.get("document", {}).get("csaf_version", "")
        if csv.startswith("2.1"):
            return "2.1"
        if csv.startswith("2.0"):
            return "2.0"
        return "2.1"
    if fmt == "cyclonedx":
        sv = doc.get("specVersion", "")
        if sv.startswith("1.7"):
            return "1.7"
        if sv.startswith("1.6"):
            return "1.6"
        if sv.startswith("1.5"):
            return "1.5"
        if sv.startswith("1.4"):
            return "1.4"
        return "1.7"
    return ""


def _combine_verdicts(vex_verdict, cross_verdict):
    """VEX native verdict와 cross-document verdict를 결합한다.
    우선순위: invalid > unverifiable > warning > valid"""
    priority = {"invalid": 0, "unverifiable": 1, "warning": 2, "valid": 3}
    v1 = priority.get(vex_verdict, 3)
    v2 = priority.get(cross_verdict, 3)
    final = vex_verdict if v1 <= v2 else cross_verdict
    reasons = []
    if vex_verdict != "valid":
        reasons.append(f"VEX validation: {vex_verdict}")
    if cross_verdict != "valid":
        reasons.append(f"Cross-document validation: {cross_verdict}")
    return {
        "verdict": final,
        "vex_verdict": vex_verdict,
        "cross_verdict": cross_verdict,
        "reasons": reasons,
    }