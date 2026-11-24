"""Single-database PostgreSQL + pgvector RAG for MITRE ATT&CK defensive SOC playbooks.

Replaces ChromaDB with native PostgreSQL `pgvector` cosine similarity search using
Google Gemini `gemini-embedding-001` (768-dim) for zero extra infrastructure.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from google import genai
from google.genai import types
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.db.models import PlaybookChunk

logger = get_logger(__name__)

_MITRE_ID_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")


@dataclass(slots=True)
class PlaybookMatch:
    """Retrieved playbook step/section with exact policy citation metadata."""

    playbook_file: str
    section_title: str
    mitre_id: str
    content: str
    distance: float

    @property
    def citation(self) -> str:
        return f"{self.playbook_file} :: {self.section_title} ({self.mitre_id})"

    def to_dict(self) -> dict[str, object]:
        return {
            "playbook_file": self.playbook_file,
            "section_title": self.section_title,
            "mitre_id": self.mitre_id,
            "citation": self.citation,
            "distance": round(self.distance, 4),
        }


class PlaybookRAG:
    """Manages PostgreSQL pgvector indexing and retrieval of Markdown SOC playbooks."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._client = (
            genai.Client(api_key=self.settings.gemini_api_key)
            if self.settings.gemini_api_key
            else None
        )

    def _embed_texts(self, texts: list[str]) -> list[list[float]]:
        """Generate 768-dim embeddings via Gemini `gemini-embedding-001` with local fallback."""
        dim = self.settings.embedding_dimensions
        if not texts:
            return []

        if self._client is not None:
            try:
                response = self._client.models.embed_content(
                    model=self.settings.gemini_embedding_model,
                    contents=texts,
                    config=types.EmbedContentConfig(output_dimensionality=dim),
                )
                return [list(emb.values) for emb in response.embeddings]
            except Exception as exc:
                logger.warning("Gemini embedding call failed (%s); using local fallback.", exc)

        return [self._fallback_embed(t, dim=dim) for t in texts]

    @staticmethod
    def _fallback_embed(text: str, dim: int = 768) -> list[float]:
        """Deterministic trigram hash embedding for offline/unconfigured environments."""
        vec = [0.0] * dim
        normalized = text.lower()
        for idx in range(max(1, len(normalized) - 2)):
            gram = normalized[idx : idx + 3].encode("utf-8", errors="ignore")
            digest = hashlib.sha256(gram).digest()
            bucket = int.from_bytes(digest[:2], "big") % dim
            vec[bucket] += 1.0
        norm = sum(v * v for v in vec) ** 0.5 or 1.0
        return [v / norm for v in vec]

    def document_count(self, db: Session) -> int:
        """Return count of indexed playbook sections in PostgreSQL."""
        return int(db.scalar(select(func.count(PlaybookChunk.id))) or 0)

    def index_playbooks(self, db: Session, force_reindex: bool = False) -> int:
        """Ingest Markdown playbooks from `data/playbooks/` into PostgreSQL pgvector."""
        playbooks_dir = self.settings.playbooks_path
        if not playbooks_dir.exists():
            logger.warning("Playbooks directory does not exist: %s", playbooks_dir)
            return 0

        existing_count = self.document_count(db)
        if not force_reindex and existing_count > 0:
            logger.info("pgvector playbook_chunks already has %d indexed sections.", existing_count)
            return existing_count

        records: list[tuple[str, str, str, str, str]] = []
        for md_file in sorted(playbooks_dir.glob("*.md")):
            text = md_file.read_text(encoding="utf-8")
            sections = self._split_markdown_sections(md_file, text)
            for idx, (section_title, mitre_id, body) in enumerate(sections):
                chunk_id = f"{md_file.stem}__sec_{idx}"
                full_text = f"{section_title}\n\n{body}"
                records.append((chunk_id, md_file.name, section_title, mitre_id, full_text))

        if not records:
            return 0

        embeddings = self._embed_texts([rec[4] for rec in records])
        for (chunk_id, filename, section_title, mitre_id, full_text), vec in zip(
            records, embeddings, strict=False
        ):
            existing = db.get(PlaybookChunk, chunk_id)
            if existing is None:
                db.add(
                    PlaybookChunk(
                        id=chunk_id,
                        playbook_file=filename,
                        section_title=section_title,
                        mitre_id=mitre_id,
                        content=full_text,
                        embedding=vec,
                    )
                )
            else:
                existing.section_title = section_title
                existing.mitre_id = mitre_id
                existing.content = full_text
                existing.embedding = vec

        db.commit()
        logger.info("Indexed %d SOC playbook sections into PostgreSQL pgvector.", len(records))
        return len(records)

    def retrieve(self, db: Session, query: str, top_k: int = 3) -> list[PlaybookMatch]:
        """Retrieve top-k defensive playbook sections via pgvector cosine distance."""
        if self.document_count(db) == 0:
            self.index_playbooks(db)
        if self.document_count(db) == 0:
            return []

        query_vec = self._embed_texts([query])[0]
        distance_expr = PlaybookChunk.embedding.cosine_distance(query_vec).label("distance")
        stmt = (
            select(PlaybookChunk, distance_expr)
            .order_by(distance_expr)
            .limit(top_k)
        )
        rows = db.execute(stmt).all()
        return [
            PlaybookMatch(
                playbook_file=chunk.playbook_file,
                section_title=chunk.section_title,
                mitre_id=chunk.mitre_id,
                content=chunk.content,
                distance=float(dist),
            )
            for chunk, dist in rows
        ]

    @staticmethod
    def _split_markdown_sections(
        md_file: Path,
        content: str,
    ) -> list[tuple[str, str, str]]:
        """Split a Markdown playbook into (section_title, mitre_id, body) tuples."""
        file_mitre_match = _MITRE_ID_RE.search(md_file.name) or _MITRE_ID_RE.search(content)
        default_mitre = file_mitre_match.group(1) if file_mitre_match else "General"

        parts = re.split(r"(?m)^##\s+", content)
        sections: list[tuple[str, str, str]] = []
        for part in parts:
            stripped = part.strip()
            if not stripped:
                continue
            lines = stripped.splitlines()
            title = lines[0].lstrip("# ").strip()
            body = "\n".join(lines[1:]).strip()
            if not body:
                continue
            sec_mitre = _MITRE_ID_RE.search(stripped)
            mitre_id = sec_mitre.group(1) if sec_mitre else default_mitre
            sections.append((title, mitre_id, body))

        return sections or [(md_file.stem, default_mitre, content.strip())]


_rag_singleton: PlaybookRAG | None = None


def get_playbook_rag() -> PlaybookRAG:
    """Return a lazily initialized singleton PlaybookRAG instance."""
    global _rag_singleton
    if _rag_singleton is None:
        _rag_singleton = PlaybookRAG()
    return _rag_singleton
