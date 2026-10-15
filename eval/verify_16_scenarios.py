"""Programmatic Verification Script for the 16 Preset Scenarios.

Evaluates each scenario through Tether's SecurityGatewayPipeline:
1. With Shield OFF (unshielded baseline)
2. With Shield ON (Tether multi-layer gate)
Validates that actual verdicts match expected verdicts and generates a structured comparison table.
"""

import asyncio
import json
import os
import sys

# Ensure workspace root in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from app.db import Base
from app.models import ChatRequest, DocumentInput
from app.shield.pipeline import SecurityGatewayPipeline
from app.shield.session_risk import session_risk_tracker


async def run_scenario_verification():
    scenarios_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "scenarios.json"))
    with open(scenarios_path, "r", encoding="utf-8") as f:
        scenarios = json.load(f)

    # Isolated test database in memory
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    pipeline = SecurityGatewayPipeline()

    results = []

    print("\n" + "=" * 90)
    print("  TETHER // AGENT HIJACK SHIELD — VERIFYING 16 PRESET SCENARIOS")
    print("=" * 90)

    for scen in scenarios:
        scen_id = scen["id"]
        title = scen["title"]
        category = scen["category"]
        agent_id = scen["target_agent"]
        expected_verdict = scen["expected_verdict"]

        documents = []
        if scen.get("untrusted_context"):
            documents.append(
                DocumentInput(
                    source="external://untrusted_context.txt",
                    content=scen["untrusted_context"],
                    type="rag",
                )
            )

        # 1. Run Shield OFF (Unshielded)
        session_risk_tracker._sessions.clear()
        async with session_factory() as session:
            req_off = ChatRequest(
                agent_id=agent_id,
                message=scen["user_prompt"],
                documents=documents,
                shield_enabled=False,
            )
            resp_off = await pipeline.process_chat(session, req_off)

        # 2. Run Shield ON (Tether Gated)
        session_risk_tracker._sessions.clear()
        async with session_factory() as session:
            req_on = ChatRequest(
                agent_id=agent_id,
                message=scen["user_prompt"],
                documents=documents,
                shield_enabled=True,
            )
            resp_on = await pipeline.process_chat(session, req_on)

        actual_verdict = resp_on.verdict
        match_status = "PASS" if actual_verdict == expected_verdict else "FAIL"

        off_tools = [t.tool_name for t in resp_off.tool_calls]
        on_tools = [f"{t.tool_name}:{t.verdict}" for t in resp_on.tool_calls]

        results.append({
            "id": scen_id,
            "title": title,
            "category": category,
            "target_agent": agent_id,
            "expected_verdict": expected_verdict,
            "actual_verdict": actual_verdict,
            "match_status": match_status,
            "shield_off_actions": off_tools or ["None"],
            "shield_on_actions": on_tools or ["None"],
            "risk_score": resp_on.risk_score,
        })

        status_symbol = "OK" if match_status == "PASS" else "FAIL"
        print(f"[{status_symbol:4}] {scen_id:12} | {title[:32]:32} | Exp: {expected_verdict:16} | Act: {actual_verdict:16} | {match_status}")

    await engine.dispose()

    # Summary
    passed_count = sum(1 for r in results if r["match_status"] == "PASS")
    total_count = len(results)
    print("=" * 90)
    print(f"  SCENARIO VERIFICATION SUMMARY: {passed_count}/{total_count} PASSED ({passed_count/total_count*100:.1f}%)")
    print("=" * 90 + "\n")

    return results


if __name__ == "__main__":
    asyncio.run(run_scenario_verification())
