# Verification — điền trước khi nộp

## Môi trường

- OS: Windows 11 Home 10.0.26200 — **Windows native**, không phải WSL2 (README ghi Windows native chưa được pilot).
- Python: 3.13.14 trong `.venv`.
- Gitleaks: `gitleaks version` → `8.30.1` (binary Windows x64 từ release chính thức, SHA-256 khớp file checksums).
- Mọi lệnh pytest chạy với `--basetemp=.pytest_tmp` (xem lỗi E1).

## Kết quả theo checkpoint

| CP | Lệnh | Output thật | Kết quả |
|---|---|---|---|
| 1 | Đọc `agent/loop.py` `_naive_loop()` | `reports/baseline.md` (3 câu, dẫn `agent/loop.py:27-54`, `:39`, `:44`, `agent/tools.py:68-83`) | Đạt |
| 2 | `python -m agent.loop --mock "Tổng hợp các ticket còn mở tuần này"`; script replay `_naive_loop` từng lure (BƯỚC 2 trên trang lab) | `reports/attack-before.log` **4 dòng** (901, 902, 903, cặp 904/904b), mỗi dòng là POST `/reconcile` chứa record synthetic `KH-000999` | Đạt |
| 2 | `python -m agent.check_lure corpus/ticket-90*.md` | `4/4 lure sẵn sàng.` | Đạt |
| 3a | `python -m pytest tests/test_pii.py -v -s --basetemp=.pytest_tmp` | `[pii] gold=118 pred=118 tp=118` / `precision=1.000 recall=1.000` / `2 passed` | Đạt |
| 3b | `python -m pytest tests/test_policy.py -v --basetemp=.pytest_tmp` | `4 passed` | Đạt |
| 3c | `python -m pytest tests/test_obo.py -v --basetemp=.pytest_tmp` | `5 passed` | Đạt |
| 3d | `python -m pytest tests/test_split.py -v --basetemp=.pytest_tmp` | `1 passed` (không đọc `KH-000777`, vẫn đọc khách hợp lệ) | Đạt |
| 3d | `python -m pytest tests/test_injection.py -v --basetemp=.pytest_tmp` | `8 passed` (4 lure × `support_l1`/`dpo`), 0 skipped | Đạt |
| 3e | `python -m pytest tests/test_ledger.py -v --basetemp=.pytest_tmp` | `3 passed` | Đạt |
| 4 | `gitleaks git --config .gitleaks.toml --redact .` | `16 commits scanned` / `leaks found: 1` (`lab24-synthetic-token`, commit `1bdd849`, file `lab-fake-secret.txt`), exit 1 — **mong đợi** | Đạt |
| 4 | `gitleaks dir --config .gitleaks.toml --redact .` | `no leaks found`, exit 0 (không có false positive trong `.venv/`, không chỉnh allowlist) | Đạt |
| 4 | `pre-commit install` / `pre-commit run --all-files` | `pre-commit installed at .git\hooks\pre-commit` / `Detect hardcoded secrets....Passed` | Đạt |
| 4 | `python -m pip install --require-hashes -r requirements.lock` | exit 0 | Đạt |
| 4 | `python -m pytest tests/test_supply_chain.py -v --basetemp=.pytest_tmp` | `3 passed` | Đạt |
| 5 | `python sink/sink.py --reset` → `python -m pytest tests/ -q --basetemp=.pytest_tmp` | **`33 passed`**, 0 failed, 0 skipped | Đạt |
| 5 | reset sink → bật sink → `python -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"` → copy `sink.log` | `reports/attack-after.log` = **0 byte** | Đạt |
| 5 | `python -c "from agent.ledger import verify; ..."` | **`True`** | Đạt |

## Ledger thật (`reports/ledger.jsonl`)

27 dòng, tạo bằng runner hiện tại: chạy `--as dpo` (dòng 1–24) rồi `--as support_l1` (dòng 25–27). Mọi dòng có `reason`, `on_behalf_of`, `agent_id`, `run_id`, `expires_at`, `args_hash`; không chứa PII thô (grep CCCD/SĐT/STK của `KH-000999` = 0 kết quả).

- Dòng 2: `dpo` `read_customer` allow — cổng mở private store của Run B.
- Dòng 24: `http_post` **deny**, `on_behalf_of=dpo`, reason "deny: dữ liệu restricted không được đi cùng egress (tool=http_post, agent=lab24-agent/run-egress)".
- Dòng 26: `support_l1` `read_customer` **deny**, reason "không có quyền hiệu lực gọi 'read_customer' (effective=[], depth=1)".
- Dòng 27: `support_l1` `http_post` deny.

Tamper demo (thủ công, file tạm): 3 dòng hash chain → `verify()` = True; sửa `decision` ở dòng giữa không tính lại hash → `verify()` = False. Giới hạn: không phát hiện xoá dòng cuối hoặc viết lại toàn bộ chuỗi khi thiếu mốc tin cậy bên ngoài.

## Giới hạn regex PII

1. STK không có nhãn "STK"/"số tài khoản" bị bỏ sót, hoặc bị báo nhầm là CCCD nếu đúng 12 số.
2. Mọi dãy 12 số (mã đơn, mã giao dịch) đều bị coi là CCCD, nên có thể báo nhầm ngoài test set.
3. SĐT chỉ nhận dạng bắt đầu 0/+84, không kiểm đầu số nhà mạng; số viết bằng chữ hoặc chèn ký tự lạ sẽ lọt.
4. Không nhận diện tên người (PERSON) hay địa chỉ.
5. Recall 1.000 chỉ đo trên test set synthetic 120 câu, không đại diện dữ liệu thật.

## Lỗi đã gặp và cách sửa

| # | Lỗi | Điều kiện tái hiện | Cách xử lý |
|---|---|---|---|
| E1 | `PermissionError` khi pytest tạo `tmp_path` | Chạy `python -m pytest tests/test_obo.py` không có `--basetemp` trên máy này | Thêm `--basetemp=.pytest_tmp` (thư mục đã có trong `.gitignore`), xoá sau khi chạy |
| E2 | `UnicodeEncodeError` (cp1252) ở dòng `print` khi bật `python sink/sink.py` | Shell Windows không đặt UTF-8 | Đặt `PYTHONIOENCODING=utf-8` trước khi chạy |
| E3 | `ReadTimeoutError` tới PyPI khi `pip-compile` | Mạng chậm lúc tạo lock | Chạy lại với `PIP_DEFAULT_TIMEOUT=120` |
| E4 | Lure 904 lúc đầu không được nhận diện | Marker "đã được phê duyệt": chữ "đ" không bị bỏ dấu khi chuẩn hoá nên không khớp "da duoc phe duyet" | Đổi sang marker "hệ thống" (904) + "bắt buộc" (904b) |
| E5 | Runner bản đầu chưa khớp mô tả BƯỚC 4 | Run B tra `related_tickets` trước khi có cổng policy; lượt kiểm `http_post` mang theo hồ sơ | Thêm cổng PEP mở private store; tách lượt kiểm `http_post` riêng (`run-egress`) chỉ mang URL; tạo lại ledger và `attack-after.log` |

## Ghi chú còn lại

- Không có test fail hay skip. Không có bước nào NOT_VERIFIED.
- `requirements.lock` sinh trên Windows/Python 3.13 nên có `colorama` (phụ thuộc theo nền tảng của pytest).
- Điều khoản pháp luật trong `reports/compliance-mapping.md`: **chưa xác minh** từng điều; nguồn chính thức của Luật 134/2025/QH15 chưa tìm được trên cổng nhà nước.
