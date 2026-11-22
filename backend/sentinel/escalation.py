"""L1 / L2 / L3 security-operations escalation tiers for alert triage (v0.35).

Maps Sentinel's existing operator roles onto the standard SOC tiering model
and decides which tier may close a given alert. This governs *triage
authorization only* — it does not change detection, scoring, or evidence.

Tier model:
  L1 (viewer)  — monitoring / first look. Read-only: can see alerts, evidence
                 and history, but cannot change alert state. This matches
                 Sentinel's existing "viewer" invariant and is unchanged by
                 this module; L1 is listed here only for naming and reporting.
  L2 (analyst) — investigates and triages. Can acknowledge (open ->
                 investigating), close low/medium-severity alerts, and send a
                 closed alert back for re-investigation.
  L3 (admin)   — required to close a HIGH-severity alert. An L2 analyst who
                 reaches that point must hand off to an L3 operator; Sentinel
                 enforces this by rejecting the close (403), not by paging or
                 ticketing anyone itself.

Unknown or future severities fail closed to the highest tier (L3) rather than
being silently closeable by L2.
"""
Transition = tuple[str, str]

TIER_OF_ROLE: dict[str, int] = {"viewer": 1, "analyst": 2, "admin": 3}
TIER_NAME: dict[int, str] = {1: "L1", 2: "L2", 3: "L3"}

#: Tier required to close an alert of this severity (investigating -> resolved).
_CLOSE_TIER_BY_SEVERITY: dict[str, int] = {"low": 2, "medium": 2, "high": 3}

#: Tier required for every OTHER supported transition, regardless of severity.
#: Unchanged from Sentinel's pre-existing analyst/admin-only triage gate.
_FIXED_TRANSITION_TIER: dict[Transition, int] = {
    ("open", "investigating"): 2,
    ("resolved", "investigating"): 2,
}

#: The full set of transitions the triage endpoint accepts. Kept here (not just
#: in app.py) so authorization and the state machine can never drift apart.
SUPPORTED_TRANSITIONS: frozenset[Transition] = frozenset(
    {("investigating", "resolved"), *_FIXED_TRANSITION_TIER}
)


def operator_tier(role: str) -> int:
    """Lowest tier (0) for an unrecognized role, never a guess upward."""
    return TIER_OF_ROLE.get(role, 0)


def required_tier(transition: Transition, severity: str) -> int:
    if transition == ("investigating", "resolved"):
        return _CLOSE_TIER_BY_SEVERITY.get(severity, 3)
    return _FIXED_TRANSITION_TIER[transition]


def tier_name(tier: int) -> str:
    return TIER_NAME.get(tier, "unknown")
