"""结构化经验层"""
from .schema import Category, KnowledgeRecord, SolutionStep, FailureReason, Source
from .knowledge_store import (
    KnowledgeStore,
    get_knowledge_store,
    KnowledgeStore as Store,
    simple_hash_embedding,
    cosine_similarity,
    KNOWLEDGE_BUCKET_MAIN,
    KNOWLEDGE_BUCKET_FORUM,
    KNOWLEDGE_BUCKET_EXTERNAL,
    DEFAULT_MIN_CONFIDENCE,
    DEFAULT_TOP_K,
    EMBEDDING_DIM,
)

__all__ = [
    # Schema
    "Category",
    "KnowledgeRecord",
    "SolutionStep",
    "FailureReason",
    "Source",
    # Store
    "KnowledgeStore",
    "get_knowledge_store",
    "Store",
    # Utilities
    "simple_hash_embedding",
    "cosine_similarity",
    # Constants
    "KNOWLEDGE_BUCKET_MAIN",
    "KNOWLEDGE_BUCKET_FORUM",
    "KNOWLEDGE_BUCKET_EXTERNAL",
    "DEFAULT_MIN_CONFIDENCE",
    "DEFAULT_TOP_K",
    "EMBEDDING_DIM",
]
