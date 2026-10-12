"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, pii, tools
from agent.policy import PolicyContext, check

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

AGENT_ID = "lab24-agent"
RUN_TTL = timedelta(minutes=5)
ORCHESTRATOR_SCOPES = ("search_docs", "read_customer")
RUN_A_SCOPES = ("search_docs",)
RUN_B_SCOPES = ("read_customer",)
EGRESS_SCOPES = ("http_post",)
# Chỉ tên file dạng ticket-<số>.md mới thành ticket ID; free text không bao giờ.
_TICKET_FILE_RE = re.compile(r"^ticket-(\d+)\.md$")
SINK_URL = f"http://{tools.ALLOWED_EGRESS_HOST}:{tools.ALLOWED_EGRESS_PORT}/reconcile"


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


class _Run:
    """Một run con hành động thay `principal_id`, với scope và TTL riêng."""

    def __init__(self, name: str, principal_id: str, scopes: tuple[str, ...],
                 expires_at: str, ledger_path: Path):
        self.run_id = f"{name}-{uuid.uuid4().hex[:12]}"
        self.agent_id = f"{AGENT_ID}/{name}"
        self.principal_id = principal_id
        self.scopes = scopes
        self.expires_at = expires_at
        self.ledger_path = ledger_path

    def authorize(self, tool: str, args: dict, *, classification: str, purpose: str,
                  egress: bool = False) -> bool:
        """PEP: policy.check() rồi ghi ledger (cả allow lẫn deny). Không chạy tool."""
        context = PolicyContext(
            data_classification=classification,
            request_purpose=purpose,
            agent_owner=self.agent_id,
            delegation_depth=1,
            egress_enabled=egress,
            principal_id=self.principal_id,
            requested_tool=tool,
            agent_scopes=self.scopes,
            parent_scopes=ORCHESTRATOR_SCOPES,
            expires_at=self.expires_at,
        )
        allowed, reason = check(context)
        ledger.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": self.agent_id,
            "run_id": self.run_id,
            "on_behalf_of": self.principal_id,
            "expires_at": self.expires_at,
            "tool": tool,
            # Chỉ lưu hash của args, không ghi PII thô vào ledger.
            "args_hash": hashlib.sha256(
                json.dumps(args, sort_keys=True, ensure_ascii=False).encode("utf-8")
            ).hexdigest(),
            "classification": classification,
            "purpose": purpose,
            "egress": egress,
            "decision": "allow" if allowed else "deny",
            "reason": reason,
        }, self.ledger_path)
        return allowed

    def call(self, tool: str, args: dict, *, classification: str, purpose: str,
             egress: bool = False):
        """authorize() TRƯỚC khi tool chạy. Trả (allowed, result); deny thì tool không chạy."""
        if not self.authorize(tool, args, classification=classification,
                              purpose=purpose, egress=egress):
            return False, None
        return True, getattr(tools, tool)(**args)


def _customers_for_tickets(ticket_ids: list[int]) -> list[str]:
    """Map ticket_id -> customer_id qua `related_tickets` (nguồn tin cậy).

    Chỉ dùng customer_id/related_tickets làm chỉ mục; record đầy đủ chỉ được
    đọc qua `read_customer` sau khi PEP allow.
    """
    wanted = set(ticket_ids)
    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    return [c["customer_id"] for c in customers
            if wanted.intersection(c.get("related_tickets", ()))]


def _run_a(message: str, llm, principal_id: str, expires_at: str,
           ledger_path: Path) -> tuple[list[dict], list[int], bool] | None:
    """Run A: chạm untrusted content, KHÔNG private data, KHÔNG egress.

    Output qua boundary chỉ là dữ liệu có kiểu: list[int] ticket ID lấy từ
    TÊN FILE, và một bool cho biết có chỉ thị injection. Text đã redact
    chỉ dùng để tóm tắt cho người dùng, không đi sang Run B.
    """
    run = _Run("run-a", principal_id, RUN_A_SCOPES, expires_at, ledger_path)
    ok, docs = run.call("search_docs", {"query": message},
                        classification="internal", purpose="summarize-tickets")
    if not ok:
        return None
    ticket_ids = sorted({int(m.group(1)) for d in docs
                         if (m := _TICKET_FILE_RE.match(d["id"]))})
    # Phát hiện injection chỉ để ghi nhận; customer_id/URL trong đó bị bỏ.
    injected = llm.find_injection("\n\n".join(d["text"] for d in docs)) is not None
    redacted = [{"id": d["id"], "text": pii.redact(d["text"])} for d in docs]
    return redacted, ticket_ids, injected


def _run_b(ticket_ids: list[int], principal_id: str, expires_at: str,
           ledger_path: Path) -> list[dict]:
    """Run B: private data, chỉ nhận list[int] từ Run A, không egress."""
    run = _Run("run-b", principal_id, RUN_B_SCOPES, expires_at, ledger_path)
    # Cổng mở private store: deny thì không tra cả chỉ mục related_tickets.
    if not run.authorize("read_customer", {"ticket_ids": ticket_ids},
                         classification="restricted", purpose="support-reply"):
        return []
    records = []
    for customer_id in _customers_for_tickets(ticket_ids):
        # OBO kiểm lại ngay TRƯỚC mỗi read_customer, không đọc rồi mới lọc.
        ok, record = run.call("read_customer", {"customer_id": customer_id},
                              classification="restricted", purpose="support-reply")
        if ok:
            records.append(record)
    return records


def _egress_check(records: list[dict], principal_id: str, expires_at: str,
                  ledger_path: Path) -> None:
    """Lượt kiểm http_post riêng khi lure đòi gửi dữ liệu.

    Context chỉ mang URL (hằng số trong code, không lấy URL từ free text);
    tools.http_post chỉ chạy nếu PEP allow — restricted + egress luôn deny.
    """
    run = _Run("run-egress", principal_id, EGRESS_SCOPES, expires_at, ledger_path)
    if run.authorize("http_post", {"url": SINK_URL},
                     classification="restricted", purpose="support-reply", egress=True):
        tools.http_post(SINK_URL, {"records": records})


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    ledger_path = (log_dir / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH
    expires_at = (datetime.now(timezone.utc) + RUN_TTL).isoformat()

    result_a = _run_a(message, llm, principal_id, expires_at, ledger_path)
    if result_a is None:
        return "Yêu cầu bị từ chối: principal không có quyền đọc ticket."
    docs, ticket_ids, injected = result_a

    records = _run_b(ticket_ids, principal_id, expires_at, ledger_path)
    if injected:
        _egress_check(records, principal_id, expires_at, ledger_path)
    return llm.summarize(docs)
