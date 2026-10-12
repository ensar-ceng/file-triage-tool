import re
import json
from pathlib import Path
import hashlib
import math
from collections import Counter

suspicious_keywords = [
    "powershell",
    "cmd.exe",
    "CreateProcess",
    "http://",
    "https://"
]

suspicious_strings = []

file_signatures = {
    b"MZ": "PE/EXE",
    b"%PDF": "PDF",
    b"\x89PNG": "PNG",
    b"PK\x03\x04": "ZIP/OOXML",
    b"\xFF\xD8\xFF": "JPEG",
    b"\x7FELF": "ELF",
    b"%!": "PostScript",
    b"\xD0\xCF\x11\xE0": "OLE/Legacy Office",
    b"Rar!\x1A\x07\x00": "RAR",
    b"\x1F\x8B": "GZIP"
}

extension_types = {
    ".exe": "PE/EXE",
    ".pdf": "PDF",
    ".png": "PNG",
    ".jpg": "JPEG",
    ".jpeg": "JPEG",
    ".zip": "ZIP/OOXML",
    ".gz": "GZIP",
    ".rar": "RAR"
}

file_path = Path("sample.bin")
file_name = file_path.name
size_bytes = file_path.stat().st_size

def calculate_entropy(data):
    if not data:
        return 0.0

    byte_counts = Counter(data)
    entropy = 0.0

    for count in byte_counts.values():
        probability = count / len(data)
        entropy -= probability * math.log2(probability)
    return entropy

def calculate_sha256(file_path):
    hash_object = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            hash_object.update(chunk)
    return hash_object.hexdigest()

def classify_entropy(entropy):
    if entropy < 5:
        return "Low"
    elif entropy < 7:
        return "Medium"
    else:
        return "High"

def detect_file_type(data):
    header = data[:8]
    for signature, file_type in file_signatures.items():
        if header.startswith(signature):
            return file_type
    return "Unknown"

def check_extension_mismatch(extension, detected_type):
    if extension in extension_types:
        expected_type = extension_types[extension]
        if detected_type != expected_type:
            return True, expected_type, detected_type
    return False, None, None

sha256 = calculate_sha256(file_path)

with open(file_path, "rb") as f:
    data = f.read()

entropy = calculate_entropy(data)
detected_type = detect_file_type(data)
extension = file_path.suffix.lower()
extension_mismatch, expected_type, actual_type = check_extension_mismatch(extension, detected_type)
strings = re.findall(b'[ -~]{4,}', data)

for item in strings:
    text = item.decode("ascii" , errors = "ignore")
    for keyword in suspicious_keywords:
        if keyword.lower() in text.lower():
            suspicious_strings.append(
                {
                    "text": text,
                    "keyword": keyword
                }
            )

report = {
    "file_name": file_name,
    "size_bytes": size_bytes,
    "sha256": sha256,
    "file_type": detected_type,
    "extension": extension,
    "extension_mismatch": extension_mismatch,
    "expected_type": expected_type,
    "entropy": entropy,
    "entropy_classification": classify_entropy(entropy),
    "suspicious_strings": suspicious_strings
}

with open("triage_report.json", "w") as f:
    json.dump(report, f, indent=4)