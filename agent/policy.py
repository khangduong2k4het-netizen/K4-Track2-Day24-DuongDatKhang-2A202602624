"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PRINCIPALS_FILE = Path(__file__).resolve().parent.parent / "data" / "principals.json"


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


_CLASSIFICATIONS = ("public", "internal", "restricted")


def load_principals(path: Path | None = None) -> dict:
    """Nguồn tin cậy MÔ PHỎNG — không phải xác thực danh tính production."""
    return json.loads((path or PRINCIPALS_FILE).read_text(encoding="utf-8"))


def _parse_expiry(value: str) -> datetime | None:
    try:
        expiry = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None
    return expiry if expiry.tzinfo else None


def effective_scopes(context: PolicyContext, principal: dict) -> set[str]:
    scopes = set(principal.get("allowed_tools", ())) & set(context.agent_scopes)
    if context.delegation_depth > 0:
        scopes &= set(context.parent_scopes)
    return scopes


def check(context: PolicyContext) -> tuple[bool, str]:
    """Mọi nhánh đều trả reason non-empty; mặc định deny khi không rõ."""
    classification = context.data_classification
    if classification not in _CLASSIFICATIONS:
        return False, f"deny: classification không xác định {classification!r} (fail closed)"

    # Rule tối thiểu: chạy trước mọi rule khác, không principal nào vượt được.
    if classification == "restricted" and context.egress_enabled:
        return False, ("deny: dữ liệu restricted không được đi cùng egress "
                       f"(tool={context.requested_tool or '?'}, agent={context.agent_owner})")

    # OBO: agent chỉ hành động trong phạm vi quyền của người ra lệnh.
    principal = load_principals().get(context.principal_id)
    if principal is None:
        return False, f"deny: principal không xác định {context.principal_id!r}"

    expiry = _parse_expiry(context.expires_at)
    if expiry is None:
        return False, f"deny: expires_at thiếu hoặc sai định dạng {context.expires_at!r}"
    if expiry <= datetime.now(timezone.utc):
        return False, f"deny: phiên ủy quyền đã hết hạn lúc {context.expires_at}"

    if context.request_purpose not in principal.get("purposes", ()):
        return False, (f"deny: purpose {context.request_purpose!r} không nằm trong purposes "
                       f"của {context.principal_id}")

    scopes = effective_scopes(context, principal)
    if context.requested_tool not in scopes:
        return False, (f"deny: {context.principal_id} không có quyền hiệu lực gọi "
                       f"{context.requested_tool!r} (effective={sorted(scopes)}, "
                       f"depth={context.delegation_depth})")

    return True, (f"allow: {context.principal_id} gọi {context.requested_tool} cho "
                  f"{context.request_purpose}, {classification} data, egress={context.egress_enabled}, "
                  f"agent={context.agent_owner}")
