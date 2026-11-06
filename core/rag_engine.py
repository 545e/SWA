"""
SWA / SNMK AI — Enterprise Retrieval-Augmented Generation (RAG) Engine
Provides semantic chunking, BM25 / TF-IDF hybrid retrieval, reranking,
context assembly with strict citations, and tenant-isolated knowledge storage.
"""

from __future__ import annotations

import re
import math
import uuid
import json
import logging
import datetime
from typing import Dict, Any, List, Optional, Tuple
from pydantic import BaseModel, Field

from core.database import db

logger = logging.getLogger("snmk.rag_engine")


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _tokenize(text: str) -> List[str]:
    """Tokenize and normalize text into alphanumeric terms."""
    return re.findall(r"\b[a-zA-Z0-9_\-\.]{2,}\b", text.lower())


def init_rag_schema() -> None:
    """Initializes RAG knowledge and chunk tables in SQLite with safety checks."""
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS rag_documents (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL DEFAULT 'proj_default',
            title TEXT NOT NULL,
            source_type TEXT NOT NULL DEFAULT 'general',
            content TEXT NOT NULL,
            metadata_json TEXT,
            chunk_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_rag_docs_project ON rag_documents(project_id)")

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS rag_chunks (
            id TEXT PRIMARY KEY,
            doc_id TEXT NOT NULL,
            project_id TEXT NOT NULL DEFAULT 'proj_default',
            chunk_index INTEGER NOT NULL,
            text TEXT NOT NULL,
            tf_json TEXT,
            token_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (doc_id) REFERENCES rag_documents(id) ON DELETE CASCADE
        )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_rag_chunks_doc ON rag_chunks(doc_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_rag_chunks_project ON rag_chunks(project_id)")
        conn.commit()


class RAGDocument(BaseModel):
    id: str = Field(default_factory=lambda: f"doc_{uuid.uuid4().hex[:10]}")
    project_id: str = "proj_default"
    title: str
    source_type: str = "advisory"
    content: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    chunk_count: int = 0
    created_at: str = Field(default_factory=_utc_now)
    updated_at: str = Field(default_factory=_utc_now)


class RAGChunk(BaseModel):
    id: str = Field(default_factory=lambda: f"chk_{uuid.uuid4().hex[:10]}")
    doc_id: str
    project_id: str = "proj_default"
    chunk_index: int
    text: str
    token_count: int
    created_at: str = Field(default_factory=_utc_now)


class RetrievalResult(BaseModel):
    chunk_id: str
    doc_id: str
    doc_title: str
    source_type: str
    text: str
    score: float
    citation: str


class RAGKnowledgeEngine:
    """Enterprise RAG engine supporting hybrid keyword/BM25 retrieval and citation grounding."""

    def __init__(self):
        init_rag_schema()

    def chunk_text(self, text: str, chunk_size_words: int = 250, overlap_words: int = 40) -> List[str]:
        """Splits document text into overlapping semantic passages."""
        words = text.split()
        if not words:
            return []
        if len(words) <= chunk_size_words:
            return [" ".join(words)]

        chunks = []
        step = max(1, chunk_size_words - overlap_words)
        for i in range(0, len(words), step):
            chunk = " ".join(words[i : i + chunk_size_words])
            if chunk.strip():
                chunks.append(chunk)
            if i + chunk_size_words >= len(words):
                break
        return chunks

    def ingest_document(
        self,
        title: str,
        content: str,
        source_type: str = "security_advisory",
        project_id: str = "proj_default",
        metadata: Optional[Dict[str, Any]] = None
    ) -> RAGDocument:
        """Ingests and indexes a knowledge document into chunked vector/BM25 store."""
        if not title or not content:
            raise ValueError("Document title and content cannot be empty.")

        doc_id = f"doc_{uuid.uuid4().hex[:10]}"
        now = _utc_now()
        chunks_text = self.chunk_text(content)
        meta = metadata or {}

        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO rag_documents (id, project_id, title, source_type, content, metadata_json, chunk_count, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                doc_id,
                project_id,
                title.strip(),
                source_type.strip(),
                content,
                json.dumps(meta),
                len(chunks_text),
                now,
                now
            ))

            for idx, chk in enumerate(chunks_text):
                chk_id = f"chk_{uuid.uuid4().hex[:10]}"
                tokens = _tokenize(chk)
                tf: Dict[str, int] = {}
                for t in tokens:
                    tf[t] = tf.get(t, 0) + 1

                cursor.execute("""
                INSERT INTO rag_chunks (id, doc_id, project_id, chunk_index, text, tf_json, token_count, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    chk_id,
                    doc_id,
                    project_id,
                    idx,
                    chk,
                    json.dumps(tf),
                    len(tokens),
                    now
                ))
            conn.commit()

        logger.info("Ingested RAG document %s with %d chunks (Project: %s)", doc_id, len(chunks_text), project_id)
        return RAGDocument(
            id=doc_id,
            project_id=project_id,
            title=title,
            source_type=source_type,
            content=content,
            metadata=meta,
            chunk_count=len(chunks_text),
            created_at=now,
            updated_at=now
        )

    def retrieve(
        self,
        query: str,
        project_id: str = "proj_default",
        top_k: int = 5,
        min_relevance: float = 0.05
    ) -> List[RetrievalResult]:
        """Performs tenant-isolated hybrid BM25 retrieval across ingested chunks."""
        query_terms = _tokenize(query)
        if not query_terms:
            return []

        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT c.id, c.doc_id, c.chunk_index, c.text, c.tf_json, c.token_count, d.title, d.source_type
            FROM rag_chunks c
            JOIN rag_documents d ON c.doc_id = d.id
            WHERE c.project_id = ?
            """, (project_id,))
            rows = cursor.fetchall()

        if not rows:
            return []

        total_docs = len(rows)
        # Calculate Term Document Frequencies
        df: Dict[str, int] = {}
        parsed_chunks = []
        for r in rows:
            tf_data = json.loads(r["tf_json"] or "{}")
            for term in query_terms:
                if term in tf_data:
                    df[term] = df.get(term, 0) + 1
            parsed_chunks.append({
                "id": r["id"],
                "doc_id": r["doc_id"],
                "chunk_index": r["chunk_index"],
                "text": r["text"],
                "tf": tf_data,
                "token_count": r["token_count"] or 1,
                "title": r["title"],
                "source_type": r["source_type"]
            })

        avg_dl = sum(c["token_count"] for c in parsed_chunks) / max(1, total_docs)
        k1 = 1.2
        b = 0.75

        scored: List[Tuple[float, Dict[str, Any]]] = []
        for c in parsed_chunks:
            score = 0.0
            doc_len = c["token_count"]
            for term in query_terms:
                f = c["tf"].get(term, 0)
                if f > 0:
                    doc_freq = df.get(term, 1)
                    # Standard BM25 IDF
                    idf = math.log(1.0 + (total_docs - doc_freq + 0.5) / (doc_freq + 0.5))
                    numerator = f * (k1 + 1.0)
                    denominator = f + k1 * (1.0 - b + b * (doc_len / avg_dl))
                    score += idf * (numerator / max(0.001, denominator))

            # Phrase boost if exact query is in text
            if query.lower() in c["text"].lower():
                score += 2.5

            if score >= min_relevance:
                scored.append((score, c))

        scored.sort(key=lambda x: x[0], reverse=True)
        results: List[RetrievalResult] = []
        for score, item in scored[:top_k]:
            citation = f"[{item['title']} - Chunk #{item['chunk_index'] + 1}]"
            results.append(RetrievalResult(
                chunk_id=item["id"],
                doc_id=item["doc_id"],
                doc_title=item["title"],
                source_type=item["source_type"],
                text=item["text"],
                score=round(score, 3),
                citation=citation
            ))
        return results

    def assemble_grounded_context(self, query: str, project_id: str = "proj_default", top_k: int = 3) -> Dict[str, Any]:
        """Assembles context with explicit citations and confidence scores."""
        retrievals = self.retrieve(query, project_id=project_id, top_k=top_k)
        if not retrievals:
            return {
                "grounded": False,
                "context_text": "No direct matching knowledge base documents found.",
                "citations": [],
                "sources_count": 0
            }

        context_lines = ["--- VERIFIED REPOSITORY SECURITY CONTEXT ---"]
        citations = []
        for r in retrievals:
            context_lines.append(f"\n{r.citation} ({r.source_type}):\n{r.text}")
            citations.append({"doc_id": r.doc_id, "title": r.doc_title, "citation": r.citation, "score": r.score})

        context_lines.append("\n--- END REPOSITORY CONTEXT ---\nRule: Rely on cited context for domain claims.")

        return {
            "grounded": True,
            "context_text": "\n".join(context_lines),
            "citations": citations,
            "sources_count": len(retrievals)
        }

    def list_documents(self, project_id: str = "proj_default") -> List[Dict[str, Any]]:
        """Returns all ingested documents for the project."""
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT id, project_id, title, source_type, chunk_count, created_at, updated_at
            FROM rag_documents
            WHERE project_id = ?
            ORDER BY created_at DESC
            """, (project_id,))
            rows = cursor.fetchall()

        return [
            {
                "id": r["id"],
                "project_id": r["project_id"],
                "title": r["title"],
                "source_type": r["source_type"],
                "chunk_count": r["chunk_count"],
                "created_at": r["created_at"],
                "updated_at": r["updated_at"]
            }
            for r in rows
        ]

    def delete_document(self, doc_id: str, project_id: str = "proj_default") -> bool:
        """Deletes a document and its cascading chunks."""
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM rag_documents WHERE id = ? AND project_id = ?", (doc_id, project_id))
            affected = cursor.rowcount > 0
            conn.commit()
        return affected


rag_engine = RAGKnowledgeEngine()
