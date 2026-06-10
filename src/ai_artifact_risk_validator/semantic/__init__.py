"""Semantic analysis engine for AI artifact risk detection.

Provides embedding-based similarity scoring, corpus management, and intent
classification to complement regex-based pattern detection. All components
gracefully degrade to no-ops when ML dependencies (sentence-transformers)
are not installed.
"""

from ai_artifact_risk_validator.semantic.batch_processor import BatchProcessor
from ai_artifact_risk_validator.semantic.cache import EmbeddingCache
from ai_artifact_risk_validator.semantic.chunker import chunk_text
from ai_artifact_risk_validator.semantic.corpus import CorpusManager
from ai_artifact_risk_validator.semantic.embeddings import EmbeddingEngine
from ai_artifact_risk_validator.semantic.intent_classifier import ContentIntent, IntentClassifier
from ai_artifact_risk_validator.semantic.similarity import SimilarityScorer

__all__ = [
    "BatchProcessor",
    "ContentIntent",
    "CorpusManager",
    "EmbeddingCache",
    "EmbeddingEngine",
    "IntentClassifier",
    "SimilarityScorer",
    "chunk_text",
]
