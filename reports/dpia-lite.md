# DPIA-lite — điền trong checkpoint 5

1. Loại dữ liệu và phân loại:
   - `corpus/ticket-*.md`: nội dung ticket hỗ trợ — **internal**, nhưng là *untrusted content* (attacker có thể cài chỉ thị, vd. `ticket-901..904b`) và có thể lẫn PII (STK, SĐT trong ticket thường).
   - `data/customers.json`: họ tên, CCCD, SĐT, STK, email, `related_tickets` — **restricted** (CCCD và STK là dữ liệu nhạy cảm cao).
   - `data/principals.json`: principal mô phỏng, `allowed_tools`, `purposes`.
   - Toàn bộ là dữ liệu **synthetic**; không có PII thật.

2. Mục đích xử lý và principal:
   - `summarize-tickets`: tóm tắt ticket cho người dùng (Run A, `search_docs`).
   - `support-reply`: tra hồ sơ khách gắn với ticket để trả lời (Run B, `read_customer`) — chỉ `dpo` (và `billing` với purpose riêng) có `read_customer`; `support_l1` bị deny.
   - Không có purpose nào cho phép gửi dữ liệu restricted ra ngoài.

3. Dữ liệu đi qua những run/tool nào, endpoint nào:
   - **Run A** (`lab24-agent/run-a`, scope `search_docs`): đọc `corpus/`, không egress. Chỉ chuyển sang Run B `list[int]` ticket ID lấy từ tên file và một cờ bool "có chỉ thị injection". Text gửi tóm tắt đã qua `pii.redact()`.
   - **Run B** (`lab24-agent/run-b`, scope `read_customer`, `http_post`): suy `customer_id` từ `related_tickets`, gọi `read_customer` sau PEP. Nếu Run A báo có chỉ thị, Run B *thử* `http_post` tới `http://127.0.0.1:10024/reconcile` (hằng số trong code) — PEP deny vì restricted + egress.
   - Endpoint duy nhất: sink local `127.0.0.1:10024` (allowlist cứng trong `agent/tools.py`). Không có egress Internet.
   - Ledger `reports/ledger.jsonl` chỉ chứa `args_hash`, không chứa PII thô.

4. Bằng chứng deny/allow và giới hạn của mock:
   - Trước containment: `reports/attack-before.log` chứa record synthetic của `KH-000999` (CCCD, SĐT, STK).
   - Sau containment (`--as dpo`, cùng query/payload): `reports/attack-after.log` rỗng; `reports/ledger.jsonl` dòng 23 `http_post` **deny** — reason "dữ liệu restricted không được đi cùng egress", `on_behalf_of=dpo`; dòng 25–26 trở đi `support_l1` `read_customer` **deny**. `verify()` = True trên 45 dòng.
   - Giới hạn:
     - Mock LLM phát hiện chỉ thị bằng marker cố định; model thật có thể hành xử khác (vd. lộ thông tin qua câu tóm tắt) — kết quả không chứng minh an toàn với model thật.
     - `--as` là principal mô phỏng, không có xác thực; TTL 5 phút là giá trị lab.
     - `dpo` vẫn đọc hợp lệ hồ sơ `KH-000999` vì ticket 901–905 gắn với khách này; chỉ PEP egress ngăn rò rỉ. Nếu attacker cài lure vào ticket gắn với một khách, split không chặn việc *đọc* hồ sơ đó.
     - Regex PII chỉ đo trên test set synthetic; không phát hiện tên người.
     - Ledger không phát hiện cắt dòng cuối/viết lại toàn chuỗi khi thiếu mốc tin cậy bên ngoài.
