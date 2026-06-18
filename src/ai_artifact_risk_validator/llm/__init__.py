"""LLM meta-analyzer package for AI artifact risk analysis enrichment.

Provides LLM-assisted explanation and remediation enrichment for scan findings.
All LLM features are opt-in and gated by ``allow_llm_analysis=True`` in config.

Submodules:
  - provider.py: LLM provider abstraction (OpenAI, local)
  - meta_analyzer.py: Finding enrichment orchestration
  - budget.py: Token budget tracking

Usage:
    from ai_artifact_risk_validator.llm.meta_analyzer import LLMMetaAnalyzer

    analyzer = LLMMetaAnalyzer(config)
    enriched = analyzer.enrich(findings)
"""
