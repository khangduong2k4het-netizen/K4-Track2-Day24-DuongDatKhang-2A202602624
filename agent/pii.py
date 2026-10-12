"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re

# Thứ tự ưu tiên: recognizer cụ thể hơn chạy trước; span đã nhận thì
# recognizer sau không nhận lại (tránh 12 số sau "STK" bị gọi là CCCD).
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("EMAIL", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    # Số tài khoản cần ngữ cảnh "STK"/"số tài khoản"; chỉ lấy nhóm chữ số.
    ("VN_BANK_ACCOUNT", re.compile(
        r"(?:\bSTK|s[ốo]\s+t[àa]i\s+kho[ảa]n)\s*[:#]?\s*(?P<v>(?<!\d)\d{8,16}(?!\d))",
        re.IGNORECASE)),
    ("VN_CCCD", re.compile(r"(?<!\d)\d{12}(?!\d)")),
    ("VN_PHONE", re.compile(r"(?<!\d)(?:\+84|0)\d{2,3}[\s.-]?\d{3}[\s.-]?\d{3,4}(?!\d)")),
]


def detect(text: str) -> list[dict]:
    entities: list[dict] = []
    for entity_type, pattern in _PATTERNS:
        for match in pattern.finditer(text):
            group = "v" if "v" in pattern.groupindex else 0
            start, end = match.span(group)
            if any(start < e["end"] and e["start"] < end for e in entities):
                continue
            entities.append({"type": entity_type, "start": start, "end": end})
    return sorted(entities, key=lambda e: e["start"])


def redact(text: str) -> str:
    for entity in sorted(detect(text), key=lambda e: e["start"], reverse=True):
        text = text[: entity["start"]] + f"[REDACTED_{entity['type']}]" + text[entity["end"]:]
    return text
