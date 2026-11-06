"""
Verification test suite for Enterprise RAG Knowledge Engine & Agent Memory Store.
Tests ingestion, chunking, BM25 retrieval, citation grounding, secret scrubbing, and REST API routes.
"""

import pytest
from fastapi.testclient import TestClient
from web.server import app
from core.rag_engine import rag_engine
from core.agent_memory import agent_memory_store, redact_secrets_from_text

client = TestClient(app)


def test_secret_scrubbing_in_memory():
    """Verify that credentials (OpenAI, GitHub, Bearer, passwords) are scrubbed before storage."""
    raw_prompt = "User credentials: password='SuperSecretPassword123!', key=sk-proj-1234567890abcdef1234567890, and token Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    scrubbed = redact_secrets_from_text(raw_prompt)
    assert "SuperSecretPassword123!" not in scrubbed
    assert "sk-proj-1234567890abcdef1234567890" not in scrubbed
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in scrubbed
    assert "[REDACTED_SECRET]" in scrubbed


def test_agent_memory_lifecycle():
    """Verify multi-tier memory record, token budgeting, and session retrieval."""
    session_id = "test_sess_cyber_01"
    agent_memory_store.clear_session(session_id)

    # Record turns
    rec1 = agent_memory_store.record_turn(
        session_id=session_id,
        agent_id="recon_agent",
        role="user",
        content="Target scope includes api.corp.internal with exposed ports 80, 443, 8080."
    )
    assert rec1.id.startswith("mem_")
    assert rec1.token_count > 0

    rec2 = agent_memory_store.record_turn(
        session_id=session_id,
        agent_id="recon_agent",
        role="assistant",
        content="Identified Nginx 1.24 reverse proxy and Spring Boot actuator endpoints."
    )
    assert rec2.token_count > 0

    # Retrieve history
    history = agent_memory_store.get_session_history(session_id)
    assert len(history) == 2
    assert history[0].role == "user"
    assert history[1].role == "assistant"

    # Format for LLM
    formatted = agent_memory_store.format_llm_messages(
        session_id=session_id,
        system_prompt="You are SWA AI Security Copilot.",
        current_user_message="Verify actuator endpoint /actuator/env for credential exposure."
    )
    assert len(formatted) == 4
    assert formatted[0]["role"] == "system"
    assert formatted[-1]["role"] == "user"

    # Clean up
    deleted = agent_memory_store.clear_session(session_id)
    assert deleted == 2


def test_rag_document_ingestion_and_chunking():
    """Verify document chunking, sparse TF-IDF calculation, and document indexing."""
    title = "CVE-2026-9011 - Spring Boot Remote Code Execution Advisory"
    body = """
    A critical vulnerability in Spring Cloud Function routing allows remote unauthenticated attackers
    to execute arbitrary commands via crafted SpEL expressions in the spring.cloud.function.routing-expression HTTP header.
    Affected versions: 3.1.6 to 3.2.2.
    Mitigation: Upgrade to Spring Cloud Function 3.2.3 or set spring.cloud.function.routing-expression validation rules.
    Workaround: Enforce WAF rule blocking suspicious SpEL syntax in routing headers.
    """
    doc = rag_engine.ingest_document(
        title=title,
        content=body,
        source_type="cve_advisory",
        project_id="proj_test_rag"
    )
    assert doc.id.startswith("doc_")
    assert doc.chunk_count >= 1

    # Verify retrieval
    results = rag_engine.retrieve(query="SpEL routing-expression remote code execution", project_id="proj_test_rag", top_k=3)
    assert len(results) > 0
    assert "Spring" in results[0].text or "SpEL" in results[0].text
    assert results[0].score > 0
    assert results[0].citation.startswith("[")

    # Verify context assembly
    grounded = rag_engine.assemble_grounded_context(query="Spring SpEL mitigation", project_id="proj_test_rag")
    assert grounded["grounded"] is True
    assert "VERIFIED REPOSITORY SECURITY CONTEXT" in grounded["context_text"]
    assert len(grounded["citations"]) > 0

    # Cleanup
    deleted = rag_engine.delete_document(doc.id, project_id="proj_test_rag")
    assert deleted is True


def test_rag_rest_api_endpoints():
    """Verify end-to-end REST API routes for RAG ingestion, querying, and reasoning."""
    # 1. Ingest via API
    ingest_payload = {
        "title": "OWASP API Security Top 10 - BOLA Guideline",
        "content": "Broken Object Level Authorization (BOLA) occurs when an application exposes user identifiers directly in endpoints (e.g. /api/users/{id}/financials) without validating that the authenticated session owns the object.",
        "source_type": "owasp_guideline",
        "project_id": "proj_api_test"
    }
    r_ingest = client.post("/api/ai/rag/ingest", json=ingest_payload)
    assert r_ingest.status_code == 200
    data_ingest = r_ingest.json()
    assert data_ingest["status"] == "INGESTED"
    doc_id = data_ingest["document"]["id"]

    # 2. Query via API
    query_payload = {
        "query": "Broken Object Level Authorization user identifiers",
        "project_id": "proj_api_test",
        "top_k": 3
    }
    r_query = client.post("/api/ai/rag/query", json=query_payload)
    assert r_query.status_code == 200
    data_query = r_query.json()
    assert data_query["grounded"] is True
    assert data_query["results_count"] > 0
    assert len(data_query["citations"]) > 0

    # 3. List documents
    r_list = client.get("/api/ai/rag/documents?project_id=proj_api_test")
    assert r_list.status_code == 200
    assert r_list.json()["total"] >= 1

    # 4. Reason with RAG grounding
    reason_payload = {
        "prompt": "How do we prevent BOLA vulnerability in user finance endpoints?",
        "project_id": "proj_api_test",
        "use_rag": True,
        "rag_query": "Broken Object Level Authorization"
    }
    r_reason = client.post("/api/ai/reason", json=reason_payload)
    assert r_reason.status_code == 200
    assert "response" in r_reason.json()
    assert r_reason.json()["rag_used"] is True

    # 5. Delete document
    r_del = client.delete(f"/api/ai/rag/documents/{doc_id}?project_id=proj_api_test")
    assert r_del.status_code == 200
    assert r_del.json()["deleted"] is True
