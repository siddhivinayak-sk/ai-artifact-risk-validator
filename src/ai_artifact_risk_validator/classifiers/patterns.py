"""Detection patterns for artifact type classification.

Defines pattern dictionaries and signal weights used by the ArtifactClassifier
to determine the type of AI artifacts from file extensions, path patterns,
content markers, and directory context signals.

Signal weights:
    - extension: 0.30 — file extension match
    - path: 0.35 — file path pattern match
    - content: 0.25 — content marker match
    - directory_context: 0.10 — surrounding directory context match
"""

from ai_artifact_risk_validator.models.enums import ArtifactType

# ---------------------------------------------------------------------------
# Signal weights for the weighted scoring algorithm
# ---------------------------------------------------------------------------

SIGNAL_WEIGHTS: dict[str, float] = {
    "extension": 0.30,
    "path": 0.35,
    "content": 0.25,
    "directory_context": 0.10,
}

# ---------------------------------------------------------------------------
# EXTENSION_PATTERNS
# Maps ArtifactType to file extension patterns (case-insensitive matching).
# Patterns may include compound extensions like ".prompt.md".
# ---------------------------------------------------------------------------

EXTENSION_PATTERNS: dict[ArtifactType, list[str]] = {
    ArtifactType.PROMPT: [
        ".prompt.md",
        ".prompt",
    ],
    ArtifactType.SKILL: [
        ".md",
    ],
    ArtifactType.AGENT: [
        ".md",
        ".yaml",
        ".yml",
        ".json",
    ],
    ArtifactType.SOP: [
        ".md",
        ".sop.md",
    ],
    ArtifactType.STEERING: [
        ".md",
    ],
    ArtifactType.MCP: [
        ".json",
        ".ts",
        ".py",
    ],
    ArtifactType.HOOK: [
        ".yaml",
        ".yml",
        ".json",
        ".md",
    ],
    ArtifactType.INSTRUCTION: [
        ".instructions.md",
        ".md",
    ],
    ArtifactType.PLUGIN: [
        ".json",
        ".ts",
        ".vsix",
    ],
    ArtifactType.MEMORY: [
        ".md",
        ".json",
        ".yaml",
        ".yml",
    ],
    ArtifactType.RAG: [
        ".md",
        ".json",
        ".yaml",
        ".yml",
    ],
    ArtifactType.EVAL_HARNESS: [
        ".yaml",
        ".yml",
        ".json",
    ],
    ArtifactType.ORCHESTRATION: [
        ".yaml",
        ".yml",
        ".json",
    ],
    ArtifactType.API_SCHEMA: [
        ".yaml",
        ".yml",
        ".json",
    ],
}

# ---------------------------------------------------------------------------
# PATH_PATTERNS
# Maps ArtifactType to path pattern regexes (matched against the full
# normalized file path using case-insensitive search).
# ---------------------------------------------------------------------------

PATH_PATTERNS: dict[ArtifactType, list[str]] = {
    ArtifactType.PROMPT: [
        r"prompts/",
        r"prompt-templates/",
    ],
    ArtifactType.SKILL: [
        r"skills/",
    ],
    ArtifactType.AGENT: [
        r"agents/",
    ],
    ArtifactType.SOP: [
        r"sops/",
        r"procedures/",
    ],
    ArtifactType.STEERING: [
        r"\.kiro/steering/",
    ],
    ArtifactType.MCP: [
        r"mcp-servers/",
        r"mcp/",
        r"/mcp\.json$",
        r"\.kiro/settings/mcp\.json$",
        r"mcp-server",
    ],
    ArtifactType.HOOK: [
        r"\.hooks/",
        r"\.kiro/hooks/",
    ],
    ArtifactType.INSTRUCTION: [
        r"(^|/)\.github/",
        r"(^|/)[^/]*instructions[^/]*$",
    ],
    ArtifactType.PLUGIN: [
        r"extensions/",
        r"plugins/",
    ],
    ArtifactType.MEMORY: [
        r"\.memory/",
    ],
    ArtifactType.RAG: [
        r"knowledge/",
        r"context/",
        r"rag/",
    ],
    ArtifactType.EVAL_HARNESS: [
        r"eval/",
        r"benchmark/",
        r"evaluations/",
    ],
    ArtifactType.ORCHESTRATION: [
        r"workflows/",
        r"pipelines/",
    ],
    ArtifactType.API_SCHEMA: [
        r"api/",
        r"schemas/",
    ],
}

# ---------------------------------------------------------------------------
# CONTENT_MARKERS
# Maps ArtifactType to content marker patterns (regexes matched against file
# content using case-insensitive multiline search).
# ---------------------------------------------------------------------------

CONTENT_MARKERS: dict[ArtifactType, list[str]] = {
    ArtifactType.PROMPT: [
        r"##\s*System\s*Prompt",
        r"\brole\s*:\s*(system|user|assistant)\b",
        r"\b(system|user|assistant)\s*:",
        r"<\|system\|>",
        r"\[INST\]",
    ],
    ArtifactType.SKILL: [
        r"\bSKILL\.md\b",
        r"\binvocation\s+criteria\b",
        r"^---\s*\n[\s\S]*?\bskill\b[\s\S]*?\n---",
    ],
    ArtifactType.AGENT: [
        r"\bAGENT\.md\b",
        r"\btool\s*declarations?\b",
        r"\bcapability\s*declarations?\b",
        r"\btools\s*:\s*\[",
    ],
    ArtifactType.SOP: [
        r"\bSOP\b",
        r"^\s*\d+\.\s+\w+",
        r"\bstep\s+\d+\b",
        r"\bprocedure\b",
    ],
    ArtifactType.STEERING: [
        r"\bpriority\s*:",
        r"\bscope\s*:",
        r"^---\s*\n[\s\S]*?\binclusion\s*:[\s\S]*?\n---",
    ],
    ArtifactType.MCP: [
        r"\bmcp\.json\b",
        r"\btool\s+definitions?\b",
        r"\btransport\s*:",
        r"\"transport\"\s*:",
        r"\"tools\"\s*:\s*\[",
        r"\"mcpServers\"\s*:",
        r"\"mcpServers\"\s*:\s*\{",
        r"\"command\"\s*:.*\"(npx|uvx|node|python|docker)\b",
        r"\"protocolVersion\"\s*:",
        r"\"serverInfo\"\s*:",
        r"\"inputSchema\"\s*:",
    ],
    ArtifactType.HOOK: [
        r"\bevent\s*:",
        r"\baction\s*:",
        r"\bhook\b",
        r"\beventType\s*:",
        r"\"eventType\"\s*:",
    ],
    ArtifactType.INSTRUCTION: [
        r"\bcopilot-instructions\.md\b",
        r"^---\s*\n[\s\S]*?\bapplyTo\s*:[\s\S]*?\n---",
    ],
    ArtifactType.PLUGIN: [
        r"\"contributes\"\s*:",
        r"\"activationEvents\"\s*:",
        r"\"engines\"\s*:\s*\{[\s\S]*?\"vscode\"",
    ],
    ArtifactType.MEMORY: [
        r"\bmemory\b.*\b(file|store|session)\b",
        r"\bsession\s*(storage|context)\b",
        r"\bcontext\s+storage\b",
    ],
    ArtifactType.RAG: [
        r"\bknowledge\s*base\b",
        r"\bembedding\s*(index|file)\b",
        r"\bvector\s*(store|index|db)\b",
        r"\bchunk(s|ing)?\b.*\b(size|overlap)\b",
    ],
    ArtifactType.EVAL_HARNESS: [
        r"\bbenchmark\b.*\bconfig\b",
        r"\bexpected\s*(output|result)s?\b",
        r"\bevaluation\s*metric",
        r"\btest\s*suite\b.*\bexpected\b",
    ],
    ArtifactType.ORCHESTRATION: [
        r"\bpipeline\s*:",
        r"\bworkflow\s*:",
        r"\bstage\s*:",
        r"\bstep\s*:.*\bdepends_on\b",
        r"\bDAG\b",
        r"\bdependencies\s*:",
    ],
    ArtifactType.API_SCHEMA: [
        r"\bopenapi\s*:",
        r"\"openapi\"\s*:",
        r"\b\$schema\b",
        r"\"\$schema\"\s*:",
        r"\bpaths\s*:[\s\S]*?\b(get|post|put|delete)\s*:",
    ],
}

# ---------------------------------------------------------------------------
# DIR_CONTEXT_PATTERNS
# Maps ArtifactType to directory context signals. These patterns describe
# conditions about the file's parent directory or sibling files that indicate
# a particular artifact type. Each entry is a regex matched against directory
# names or sibling filenames.
# ---------------------------------------------------------------------------

DIR_CONTEXT_PATTERNS: dict[ArtifactType, list[str]] = {
    ArtifactType.PROMPT: [
        r"^prompts$",
    ],
    ArtifactType.SKILL: [
        r"SKILL\.md$",
    ],
    ArtifactType.AGENT: [
        r"AGENT\.md$",
    ],
    ArtifactType.SOP: [
        r"^sops$",
        r"^procedures$",
    ],
    ArtifactType.STEERING: [
        r"\.kiro[/\\]steering",
    ],
    ArtifactType.MCP: [
        r"mcp\.json$",
    ],
    ArtifactType.HOOK: [
        r"\.hooks$",
        r"\.kiro[/\\]hooks",
    ],
    ArtifactType.INSTRUCTION: [
        r"instructions",
    ],
    ArtifactType.PLUGIN: [
        r"contributes",
    ],
    ArtifactType.MEMORY: [
        r"\.memory$",
    ],
    ArtifactType.RAG: [
        r"^knowledge$",
        r"^context$",
        r"^rag$",
    ],
    ArtifactType.EVAL_HARNESS: [
        r"^eval$",
        r"^benchmark$",
        r"^evaluations$",
    ],
    ArtifactType.ORCHESTRATION: [
        r"^workflows$",
        r"^pipelines$",
    ],
    ArtifactType.API_SCHEMA: [
        r"\bopenapi\b",
        r"\bswagger\b",
    ],
}
