"""
SWA / SNMK AI — Enterprise Agent Memory & Context Management Store
Implements Working, Episodic, and Semantic memory tiers with automated secret scrubbing,
token budgeting, compression, and strict project/workspace isolation.
"""

from __future__ import annotations

import re
import uuid
import json
import logging
import datetime
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from core.database import db

logger = logging.getLogger("snmk.agent_memory")


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


# Regex patterns for detecting and redacting sensitive credentials in memory
SECRET_PATTERNS = [
    re.compile(r"(sk-[a-zA-Z0-9_\-]{20,})", re.IGNORECASE),
    re.compile(r"(ghp_[a-zA-Z0-9]{30,})", re.IGNORECASE),
    re.compile(r"(xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24})", re.IGNORECASE),
    re.compile(r"(Bearer\s+[a-zA-Z0-9\._\-]{20,})", re.IGNORECASE),
    re.compile(r"(password\s*[:=]\s*['\"][^'\"]+['\"])", re.IGNORECASE),
    re.compile(r"(api[_\-]?key\s*[:=]\s*['\"][^'\"]+['\"])", re.IGNORECASE),
]


def redact_secrets_from_text(text: str) -> str:
    """Detects and scrubs raw API keys and secrets before storing into agent memory."""
    if not text:
        return text
    scrubbed = text
    for pattern in SECRET_PATTERNS:
        scrubbed = pattern.sub("[REDACTED_SECRET]", scrubbed)
    return scrubbed


def init_agent_memory_schema() -> None:
    """Initializes persistent episodic and semantic agent memory tables."""
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS agent_memory_records (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            project_id TEXT NOT NULL DEFAULT 'proj_default',
            memory_tier TEXT NOT NULL, -- 'working', 'episodic', 'semantic'
            role TEXT NOT NULL, -- 'user', 'assistant', 'system', 'tool'
            content TEXT NOT NULL,
            metadata_json TEXT,
            token_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_mem_session ON agent_memory_records(session_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_mem_agent ON agent_memory_records(agent_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_mem_project ON agent_memory_records(project_id)")
        conn.commit()


class MemoryRecord(BaseModel):
    id: str = Field(default_factory=lambda: f"mem_{uuid.uuid4().hex[:10]}")
    session_id: str
    agent_id: str
    project_id: str = "proj_default"
    memory_tier: str = "episodic"
    role: str = "assistant"
    content: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    token_count: int = 0
    created_at: str = Field(default_factory=_utc_now)


class AgentMemoryStore:
    """Manages short-term working context, episodic action logs, and semantic memory."""

    def __init__(self, max_context_tokens: int = 4000):
        self.max_context_tokens = max_context_tokens
        init_agent_memory_schema()

    def record_turn(
        self,
        session_id: str,
        agent_id: str,
        role: str,
        content: str,
        memory_tier: str = "episodic",
        project_id: str = "proj_default",
        metadata: Optional[Dict[str, Any]] = None
    ) -> MemoryRecord:
        """Records an interaction turn with automatic secret scrubbing and token accounting."""
        clean_content = redact_secrets_from_text(content)
        # Approximate token count: 1 token ~= 4 chars or 0.75 words
        token_count = max(1, len(clean_content) // 4)
        mem_id = f"mem_{uuid.uuid4().hex[:10]}"
        now = _utc_now()
        meta = metadata or {}

        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO agent_memory_records (id, session_id, agent_id, project_id, memory_tier, role, content, metadata_json, token_count, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                mem_id,
                session_id,
                agent_id,
                project_id,
                memory_tier,
                role,
                clean_content,
                json.dumps(meta),
                token_count,
                now
            ))
            conn.commit()

        logger.debug("Recorded %s memory turn %s for session %s (Tokens: %d)", memory_tier, mem_id, session_id, token_count)
        return MemoryRecord(
            id=mem_id,
            session_id=session_id,
            agent_id=agent_id,
            project_id=project_id,
            memory_tier=memory_tier,
            role=role,
            content=clean_content,
            metadata=meta,
            token_count=token_count,
            created_at=now
        )

    def get_session_history(
        self,
        session_id: str,
        project_id: str = "proj_default",
        limit: int = 20,
        budget_tokens: Optional[int] = None
    ) -> List[MemoryRecord]:
        """Retrieves conversational and episodic memory for a session within token budget."""
        budget = budget_tokens or self.max_context_tokens

        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT id, session_id, agent_id, project_id, memory_tier, role, content, metadata_json, token_count, created_at
            FROM agent_memory_records
            WHERE session_id = ? AND project_id = ?
            ORDER BY created_at DESC
            LIMIT ?
            """, (session_id, project_id, limit))
            rows = cursor.fetchall()

        records: List[MemoryRecord] = []
        cumulative_tokens = 0
        for r in rows:
            tokens = r["token_count"] or 1
            if cumulative_tokens + tokens > budget and records:
                break
            cumulative_tokens += tokens
            records.append(MemoryRecord(
                id=r["id"],
                session_id=r["session_id"],
                agent_id=r["agent_id"],
                project_id=r["project_id"],
                memory_tier=r["memory_tier"],
                role=r["role"],
                content=r["content"],
                metadata=json.loads(r["metadata_json"] or "{}"),
                token_count=tokens,
                created_at=r["created_at"]
            ))

        # Return chronologically ascending for LLM context feeding
        records.reverse()
        return records

    def format_llm_messages(
        self,
        session_id: str,
        system_prompt: str,
        current_user_message: str,
        project_id: str = "proj_default"
    ) -> List[Dict[str, str]]:
        """Compiles clean, scrubbed message list with system prompt, history, and current turn."""
        history = self.get_session_history(session_id, project_id=project_id, limit=10)
        messages: List[Dict[str, str]] = [{"role": "system", "content": system_prompt}]

        for h in history:
            messages.append({"role": h.role, "content": h.content})

        messages.append({"role": "user", "content": redact_secrets_from_text(current_user_message)})
        return messages

    def clear_session(self, session_id: str, project_id: str = "proj_default") -> int:
        """Purges memory for a completed session."""
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM agent_memory_records WHERE session_id = ? AND project_id = ?", (session_id, project_id))
            deleted = cursor.rowcount
            conn.commit()
        return deleted


agent_memory_store = AgentMemoryStore()
