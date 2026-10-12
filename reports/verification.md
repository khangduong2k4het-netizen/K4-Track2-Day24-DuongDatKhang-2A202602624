# Verification — điền trước khi nộp

- OS / Python / Gitleaks version: Windows 11 Home 10.0.26200 (Windows native, không phải WSL2 — README ghi chưa pilot) / Python 3.13 (.venv) / Gitleaks 8.30.1
- `python -m pytest tests/ -q`: **33 passed** (chạy với `--basetemp=.pytest_tmp` vì thư mục temp mặc định của pytest trên máy này báo `PermissionError` khi tạo `tmp_path`; tái hiện: chạy `pytest tests/test_obo.py` không có `--basetemp`).
- `pre-commit run --all-files`: Detect hardcoded secrets — **Passed** (hook `gitleaks-system`, rev v8.30.1). `gitleaks git` trên lịch sử: 1 finding `lab24-synthetic-token` ở `1bdd849` (token giả, dự kiến, exit 1); `gitleaks dir`: no leaks found.
- Ledger verify: `verify(Path('reports/ledger.jsonl'))` → **True** (45 dòng: chạy `--as dpo` rồi `--as support_l1`; mọi dòng có `reason`, `on_behalf_of`, `run_id`, `expires_at`).
- Before/after: `reports/attack-before.log` chứa record synthetic `KH-000999`; `reports/attack-after.log` 0 byte (reset sink sau pytest, rồi chạy `--as dpo` cùng query).
- `pip install --require-hashes -r requirements.lock`: thành công. Lần đầu `pip-compile` bị `ReadTimeoutError` tới PyPI, chạy lại với `PIP_DEFAULT_TIMEOUT=120` thì qua.
- Các lỗi còn lại: không có test fail. Lưu ý: sink chính `python sink/sink.py` khi chạy trong shell cp1252 của Windows lỗi `UnicodeEncodeError` ở dòng `print` (khắc phục bằng `PYTHONIOENCODING=utf-8`); `requirements.lock` sinh trên Windows nên có `colorama`.
- PII gate (`python -m pytest tests/test_pii.py -s`): gold=118 pred=118 tp=118, precision=1.000, recall=1.000 (regex: EMAIL → STK có ngữ cảnh → CCCD 12 số → SĐT).
- Ledger tamper demo (thủ công, file tạm): 3 dòng hash chain → `verify()` = True; sửa `decision` ở dòng giữa không tính lại hash → `verify()` = False. Giới hạn: không phát hiện xoá dòng cuối hoặc viết lại toàn bộ chuỗi khi thiếu mốc tin cậy bên ngoài.
