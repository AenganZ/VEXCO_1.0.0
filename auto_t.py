#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import sys
from pathlib import Path

# =========================
# 기본 설정
# =========================

CONVERTER = Path("convert.py")
NVD_API_KEY = "6d72fcf5-16f6-4542-914b-7584a52d0bc9"
OUTPUT_DIR = Path("test2")

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# =========================
# 변환 정의
# =========================
# (input_file, target_format, output_file)

CONVERSIONS = [
    ("./examples/openvex_test.json", "CycloneDX", "openvex_to_cyclonedx.json"),
    ("./examples/openvex_test.json", "CSAF", "openvex_to_csaf.json"),

    ("./examples/cyclonedx_test.json", "OpenVEX", "cyclonedx_to_openvex.json"),
    ("./examples/cyclonedx_test.json", "CSAF", "cyclonedx_to_csaf.json"),

    ("./examples/csaf_test.json", "OpenVEX", "csaf_to_openvex.json"),
    ("./examples/csaf_test.json", "CycloneDX", "csaf_to_cyclonedx.json")
]

# =========================
# 실행 로직
# =========================

def run_conversion(input_file: str, target: str, output_file: str) -> bool:
    cmd = [
        sys.executable,
        str(CONVERTER),
        input_file,
        "--target", target,
        "-o", str(OUTPUT_DIR / output_file),
        "--nvd-api-key", NVD_API_KEY,
        #"--restore",
        #"--reversible",
    ]

    print("\n" + "=" * 80)
    print(f"[+] Converting: {input_file} -> {target}")
    print(f"[+] Output    : {OUTPUT_DIR / output_file}")
    print(f"[+] Command   : {' '.join(cmd)}")

    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode == 0:
        print("[✓] SUCCESS")
        if result.stdout:
            print(result.stdout)
        return True
    else:
        print("[✗] FAILED")
        if result.stdout:
            print("STDOUT:")
            print(result.stdout)
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
        return False


def main():
    success = 0
    failure = 0

    for input_file, target, output_file in CONVERSIONS:
        if run_conversion(input_file, target, output_file):
            success += 1
        else:
            failure += 1

    print("\n" + "=" * 80)
    print("Conversion Summary")
    print(f"  Success: {success}")
    print(f"  Failed : {failure}")
    print("=" * 80)

    if failure > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
