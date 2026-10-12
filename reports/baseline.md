# Baseline — điền trong checkpoint 1

1. Agent có identity mỗi run chưa? Dẫn file/hàm:
   **Chưa.** `agent/loop.py` hàm `_naive_loop()` (dòng 27–54) không tạo `agent_id`/`run_id` nào, không nhận principal; `run_once()` (dòng 57) có tham số `principal_id` nhưng chỉ chuyển cho `runner.handle()`, còn nhánh baseline (dòng 74) gọi `_naive_loop(message, llm)` bỏ qua hoàn toàn principal — mọi tool call chạy với cùng một quyền ẩn danh.

2. Ai cho phép `http_post`? Dẫn file/hàm:
   **Không ai.** Trong `_naive_loop()` dòng 34–44, chính nội dung document (`llm.find_injection(combined_text)`) quyết định gọi `tools.read_customer` (dòng 39) rồi `tools.http_post(injected.target_url, ...)` (dòng 44) — ticket vốn là dữ liệu nhưng baseline xử lý chỉ thị bên trong như lệnh, và không có PEP/`policy.check()` nào kiểm mục đích, quyền hay loại dữ liệu ở giữa. Rào duy nhất là allowlist cứng `127.0.0.1:10024` trong `agent/tools.py` `http_post()` dòng 68–83, vốn là rào an toàn cho lab chứ không phải quyết định cấp quyền.

3. Nếu gửi sai PII ra sink, bằng chứng ở đâu? Dẫn file/hàm:
   Body POST được tạo tại `agent/loop.py:44`: `{"records": collected}`, trong đó `collected` là các record đầy đủ (CCCD, SĐT, STK, email) do `tools.read_customer` trả về ở dòng 39. Bằng chứng **chỉ ở phía người nhận**: agent không ghi ledger/audit nào (không có lời gọi `ledger.append` trong `_naive_loop`). Bằng chứng duy nhất là `reports/sink.log` do `sink/sink.py` `do_POST()` (dòng 42) ghi — tức là phía attacker, không phải phía hệ thống; bản copy là `reports/attack-before.log` ở checkpoint 2 (4 dòng: 901, 902, 903, cặp 904/904b).
