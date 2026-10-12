# Verification — điền trước khi nộp

- OS / Python / Gitleaks version:
- `python -m pytest tests/ -q`:
- `pre-commit run --all-files`:
- Ledger verify:
- Các lỗi còn lại:
- PII gate (`python -m pytest tests/test_pii.py -s`): gold=118 pred=118 tp=118, precision=1.000, recall=1.000 (regex: EMAIL → STK có ngữ cảnh → CCCD 12 số → SĐT).
- Ledger tamper demo (thủ công, file tạm): 3 dòng hash chain → `verify()` = True; sửa `decision` ở dòng giữa không tính lại hash → `verify()` = False. Giới hạn: không phát hiện xoá dòng cuối hoặc viết lại toàn bộ chuỗi khi thiếu mốc tin cậy bên ngoài.
