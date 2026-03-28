"""FastAPI web dashboard for Home Network Analyzer."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from home_net_analyzer.config import get_settings
from home_net_analyzer.rules import RulesEngine, Rule, RuleAction, RuleTarget
from home_net_analyzer.storage.packet_store import PacketStore


# ---------------------------------------------------------------------------
# Request/Response models
# ---------------------------------------------------------------------------

class RuleCreate(BaseModel):
    action: str  # "block" | "allow" | "reject"
    target: str  # "ip" | "subnet" | "port" | "protocol" | "mac"
    value: str
    direction: str = "both"
    interface: Optional[str] = None
    protocol: str = "any"
    enabled: bool = True
    priority: int = 100
    description: Optional[str] = None


class RuleUpdate(BaseModel):
    action: Optional[str] = None
    target: Optional[str] = None
    value: Optional[str] = None
    direction: Optional[str] = None
    interface: Optional[str] = None
    protocol: Optional[str] = None
    enabled: Optional[bool] = None
    priority: Optional[int] = None
    description: Optional[str] = None


class RuleResponse(BaseModel):
    id: Optional[int]
    action: str
    target: str
    value: str
    direction: str
    interface: Optional[str]
    protocol: str
    enabled: bool
    priority: int
    description: Optional[str]
    created_at: Optional[str]


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app(
    *,
    db_path: Optional[Path | str] = None,
    rules_backend: Optional[str] = None,
) -> FastAPI:
    """Create and configure the FastAPI app.

    Args:
        db_path: Override database path.
        rules_backend: Backend for rules engine: "nftables", "iptables", or "noop".
            If None, reads from HNA_RULES_BACKEND env var (default: "noop").
    """

    app = FastAPI(
        title="Home Network Analyzer Dashboard",
        description="Dashboard for viewing packets and managing firewall rules.",
        version="0.1.0",
    )

    settings = get_settings()
    db_file = db_path or settings.get_database_path()

    # Resolve backend
    import os
    backend = rules_backend or os.environ.get("HNA_RULES_BACKEND", "noop")

    # Storage
    def get_store() -> PacketStore:
        return PacketStore(db_file)

    # Rules engine (configurable backend via arg or env)
    _rules_engine: RulesEngine | None = None

    def get_engine() -> RulesEngine:
        nonlocal _rules_engine
        if _rules_engine is None:
            _rules_engine = RulesEngine(backend=backend)
        return _rules_engine

    # Templates
    templates_dir = Path(__file__).parent / "templates"
    templates_dir.mkdir(parents=True, exist_ok=True)
    templates = Jinja2Templates(directory=str(templates_dir))

    # -------------------------------------------------------------------------
    # Dashboard HTML
    # -------------------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request) -> HTMLResponse:
        # Render template; pass request for URL generation
        html = templates.get_template("dashboard.html").render(request=request)
        return HTMLResponse(content=html)

    # -------------------------------------------------------------------------
    # Packets API
    # -------------------------------------------------------------------------

    @app.get("/api/packets")
    def list_packets(limit: int = 100) -> dict[str, Any]:
        with get_store() as store:
            rows = store.recent(limit=limit)
            return {
                "count": len(rows),
                "packets": [r.to_dict() for r in rows],
            }

    @app.get("/api/packets/count")
    def count_packets() -> dict[str, int]:
        with get_store() as store:
            return {"count": store.count()}

    @app.get("/api/packets/query")
    def query_packets(
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        proto: Optional[str] = None,
        app_proto: Optional[str] = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        with get_store() as store:
            rows = store.db.query(
                src_ip=src_ip,
                dst_ip=dst_ip,
                transport_protocol=proto,
                application_protocol=app_proto,
                limit=limit,
            )
            return {"count": len(rows), "packets": [r.to_dict() for r in rows]}

    # -------------------------------------------------------------------------
    # Rules API
    # -------------------------------------------------------------------------

    @app.get("/api/rules")
    def list_rules() -> dict[str, Any]:
        engine = get_engine()
        rules = engine.list_rules()
        return {"count": len(rules), "rules": [r.to_dict() for r in rules]}

    @app.get("/api/rules/{rule_id}")
    def get_rule(rule_id: int) -> dict[str, Any]:
        engine = get_engine()
        r = engine.get_rule(rule_id)
        if r is None:
            raise HTTPException(status_code=404, detail="Rule not found")
        return r.to_dict()

    @app.post("/api/rules", status_code=201)
    def create_rule(payload: RuleCreate) -> dict[str, Any]:
        engine = get_engine()
        try:
            action = RuleAction(payload.action)
            target = RuleTarget(payload.target)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        rule = Rule(
            action=action,
            target=target,
            value=payload.value,
            direction=payload.direction,
            interface=payload.interface,
            protocol=payload.protocol,
            enabled=payload.enabled,
            priority=payload.priority,
            description=payload.description,
        )
        rid = engine.add_rule(rule)
        created = engine.get_rule(rid)
        return created.to_dict() if created else {"id": rid}

    @app.put("/api/rules/{rule_id}")
    def update_rule(rule_id: int, payload: RuleUpdate) -> dict[str, Any]:
        engine = get_engine()
        existing = engine.get_rule(rule_id)
        if existing is None:
            raise HTTPException(status_code=404, detail="Rule not found")

        # Merge updates
        data = existing.to_dict()
        for k, v in payload.model_dump(exclude_unset=True).items():
            if v is not None:
                data[k] = v

        # Re-create rule object with updated data
        try:
            new_rule = Rule(**data)
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

        # Remove old and add new
        engine.remove_rule(rule_id)
        new_rule.id = rule_id  # preserve id
        engine.add_rule(new_rule)
        updated = engine.get_rule(rule_id)
        return updated.to_dict() if updated else {"id": rule_id}

    @app.delete("/api/rules/{rule_id}")
    def delete_rule(rule_id: int) -> dict[str, Any]:
        engine = get_engine()
        ok = engine.remove_rule(rule_id)
        if not ok:
            raise HTTPException(status_code=404, detail="Rule not found")
        return {"deleted": rule_id}

    @app.post("/api/rules/{rule_id}/enable")
    def enable_rule(rule_id: int) -> dict[str, Any]:
        engine = get_engine()
        ok = engine.enable_rule(rule_id)
        if not ok:
            raise HTTPException(status_code=404, detail="Rule not found")
        return {"enabled": rule_id}

    @app.post("/api/rules/{rule_id}/disable")
    def disable_rule(rule_id: int) -> dict[str, Any]:
        engine = get_engine()
        ok = engine.disable_rule(rule_id)
        if not ok:
            raise HTTPException(status_code=404, detail="Rule not found")
        return {"disabled": rule_id}

    return app


# Convenience: default app instance
app = create_app()
