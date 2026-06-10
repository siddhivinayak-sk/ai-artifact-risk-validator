# Scan Findings Triage Report — sbcp-mcp-builder

**Scan Date:** 2026-06-10  
**Scan Target:** `C:\sandeep\work\sbcp\sbcp-mcp-builder`  
**Validator Version:** 0.4.0  
**Gate Decision:** BLOCK (116 blocking findings)  
**Report:** `C:\sandeep\daily\report.html`

---

## Executive Summary

**116 blocking findings** were reported. After cross-referencing every High+ finding against the actual source files and the validator scanner logic, **all High and Critical findings are FALSE POSITIVES**. None represent genuine security risks in the scanned `sbcp-mcp-builder` repository.

The root causes fall into **3 systemic validator issues** and **1 whitelisting case**.

---

## Issue-by-Issue Analysis

### ISSUE GROUP 1: Presidio PERSON Entity → Critical Secret Finding (≈70 findings)

| Field | Details |
|---|---|
| **Risk IDs** | `SOP-S1`, `MCP-S3` |
| **Severity** | Critical (S9) — BLOCK |
| **Files** | `README.md`, `find_missing_docs.py` |
| **Scanner** | `SecretScan` → Presidio `PERSON` entity |
| **Evidence examples** | `Kafka`, `Gradle`, `Helm`, `ABAM`, `Docker`, `Thymeleaf`, `Claude Desktop`, `Liquibase`, `Trivy`, `Mockk`, `ROBIN`, `SBCP`, `Releasy`, `K6`, `Metabase`, `line.strip`, `JWE token` |

**Is it a real issue?** **NO.** These are technology/product names, framework names, and Python code fragments. Presidio's spaCy NER model misidentifies short capitalized words as person names — this is a [well-known limitation](https://github.com/microsoft/presidio/issues?q=false+positive+PERSON) of NER-based PII detection. Words like "Kafka" (the distributed streaming platform) or "Helm" (the K8s package manager) are detected as person names because they happen to resemble proper nouns.

**Verdict: FIX IN VALIDATOR** ✅

**Recommended fixes in `SecretScan` (`secret_scan.py` L725–756):**

1. Add `PERSON` to `_PRESIDIO_SKIP_ENTITIES` set — PERSON entities should NOT map to secret/credential risk IDs like `SOP-S1` or `MCP-S3`. A person name is not a "hardcoded API key."
2. If PERSON detection is still desired for PII tracking, map it only to PII-specific risk IDs (`P-S4`, `M-S3`) at WARN level, not BLOCK.
3. Add a minimum evidence length filter (e.g., skip entities < 4 characters) to avoid `K6` → `US_DRIVER_LICENSE` type false positives.
4. Add a technology-name allowlist for known product names common in technical documentation.

---

### ISSUE GROUP 2: `\bformat\b` Regex → Critical Destructive Operation (6 findings)

| Field | Details |
|---|---|
| **Risk ID** | `MCP-S10` |
| **Severity** | Critical (S9) — BLOCK |
| **Files** | `check_duplicate_files.py` (L14), `find_missing_docs.py` (L33), `find_pages_by_topic.py` (L21, L52) |
| **Scanner** | `PermAudit` |
| **Evidence** | `format` |

**Is it a real issue?** **NO.** The flagged lines are:

- `logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")` — Python logging configuration
- `# The file contains one path per line in the format:` — docstring comment
- `"""Build a GitLab raw file URL. Format: ...` — docstring

The regex `\b(?:format|mkfs|fdisk)\b` at `perm_audit.py` L434 matches the bare word `format` anywhere, which is one of the most common words in programming (string `.format()`, log `format=`, docstrings saying "format:"). `mkfs` and `fdisk` are correctly specific; `format` alone is far too broad.

**Verdict: FIX IN VALIDATOR** ✅

**Recommended fix in `PermAudit` (`perm_audit.py` L431–436):**

Replace the regex with context-aware patterns:

```python
# Instead of: r"(?i)\b(?:format|mkfs|fdisk)\b"
# Use:
r"(?i)(?:\bformat\s+[A-Z]:\b|\bformat\s+/dev/|\bmkfs(?:\.\w+)?\s|\bfdisk\s)"
```

This matches actual disk format commands like `format C:`, `format /dev/sda`, `mkfs.ext4`, `fdisk /dev/sdb` while ignoring Python's `format()`, `format=`, and the word "format" in documentation.

---

### ISSUE GROUP 3: Presidio EMAIL_ADDRESS → Critical Secret on CI Component Refs (2 findings)

| Field | Details |
|---|---|
| **Risk ID** | `P-S3` |
| **Severity** | Critical (S9) — BLOCK |
| **File** | `.gitlab-ci.yml` (L5, L8) |
| **Scanner** | `SecretScan` → Presidio `EMAIL_ADDRESS` |
| **Evidence** | `gitlab.sbs-software.com/ai-projects/74sw-catalog-components/...` |

**Is it a real issue?** **NO.** The evidence is a GitLab CI component reference using the `component:` keyword syntax, e.g.:

```yaml
- component: 'gitlab.sbs-software.com/ai-projects/74sw-catalog-components/validate@v0.0.1'
```

The `domain.com/path` structure triggers Presidio's email regex, but this is a CI component path, not an email address.

**Verdict: FIX IN VALIDATOR** ✅

**Recommended fix:** In `_scan_pii()`, add post-processing to filter Presidio `EMAIL_ADDRESS` results that match URL/path patterns (contain `/` after the domain). A simple check:

```python
if result.entity_type == "EMAIL_ADDRESS" and "/" in evidence:
    continue  # URL/path, not an email
```

---

### ISSUE GROUP 4: catalog-entry.yaml Contact Email → Critical Secret (1 finding)

| Field | Details |
|---|---|
| **Risk ID** | `P-S3` |
| **Severity** | Critical (S9) — BLOCK |
| **File** | `catalog-entry.yaml` (L6) |
| **Scanner** | `SecretScan` → PII: Email Address |
| **Evidence** | `jerome.vanderstichelen@sbs-software.com` |

**Is it a real issue?** **NO.** This IS a real email address, but it's in the `contact:` field of a catalog entry — this is **standard metadata** for Backstage-style service catalogs. The contact field is required/expected. Flagging it as "Hardcoded API Key" (P-S3) is semantically wrong — this is PII at most, not a credential.

**Verdict: WHITELIST in `.aav.yaml`** ✅ (also partial fix in validator — email in metadata `contact:` fields should be INFO, not BLOCK)

---

### ISSUE GROUP 5: URL References → "Destructive Operations in Orchestration" (2 findings)

| Field | Details |
|---|---|
| **Risk ID** | `OW-S2` |
| **Severity** | High (S8) — BLOCK |
| **File** | `catalog-entry.yaml` (L19, L22) |
| **Scanner** | `PermAudit` — Network pattern: "External URL access" |
| **Evidence** | `url: https://gitlab.sbs-software.com/...` |

**Is it a real issue?** **NO.** The `catalog-entry.yaml` file has `artifacts:` with `url:` fields pointing to GitLab repositories — these are documentation/metadata links, not "destructive operations." The network pattern `url:\s*https?://` in `perm_audit.py` L358–364 is too broad for `orchestration` type artifacts.

**Verdict: FIX IN VALIDATOR** ✅

**Recommended fix:** The network URL pattern should be context-aware — in orchestration/metadata files, a `url:` field referencing a git repository is informational metadata, not an outbound API call. Consider:

- Skip network findings when the URL points to known internal domains (e.g. same GitLab host)
- Lower severity for URL references in catalog/metadata YAML files
- Require action verbs (`curl`, `wget`, `fetch`, `requests`) for BLOCK-level network findings on orchestration artifacts

---

### ISSUE GROUP 6: Python Scripts Misclassified as MCP → Provenance Checks (6 findings)

| Field | Details |
|---|---|
| **Risk IDs** | `MCP-S4` (High S7), `MCP-S5` (High S7) |
| **Files** | `check_duplicate_files.py`, `find_missing_docs.py`, `find_pages_by_topic.py` |
| **Scanner** | `ProvenanceChk` |

**Is it a real issue?** **NO.** These are standalone Python utility scripts, not MCP server configurations. They were misclassified as `mcp` artifact type (likely because `mcp.json` exists in the same directory). Once misclassified, MCP-specific provenance checks (dependency verification, integrity hashes) apply to files where they make no sense.

**Verdict: FIX IN VALIDATOR** ✅ (classifier improvement)

**Recommended fix:** The artifact classifier should not classify `.py` files as `mcp` just because an `mcp.json` exists in the directory. MCP artifacts should be the `mcp.json` itself and files explicitly referenced by it.

---

### ISSUE GROUP 7: README Discussing GDPR → "PII Exposure Without Consent" (1 finding)

| Field | Details |
|---|---|
| **Risk ID** | `REG-4` |
| **Severity** | High (S8) — WARN |
| **File** | `README.md` (L91) |
| **Scanner** | `ComplianceAudit` |
| **Evidence** | `personal data` |

**Is it a real issue?** **NO.** Line 91 of `README.md` is in the ABAM documentation table: *"ABAM authorization functioning (access-profiles, permission-to-role mapping, RBAC...) and ABAM GDPR data registers (personal data categories, retention policies, data flows for compliance)."* This is **documentation about GDPR handling**, not actual PII processing.

**Verdict: WHITELIST in `.aav.yaml`** ✅ (the ComplianceAudit scanner can't distinguish "discussing PII handling" from "performing PII handling" — this is a known limitation per gap SEC-G3/QL-G5 in the validator's own `semantic-upgrade-analysis.md`)

---

## Summary Table

| # | Finding Group | Count | Severity | Real Issue? | Action | Where |
|---|---|---|---|---|---|---|
| 1 | Presidio PERSON → Secret/Credential | ~70 | Critical S9 | **No** | **Fix validator** | `SecretScan`: add PERSON to skip list |
| 2 | `\bformat\b` → Disk Format Command | 6 | Critical S9 | **No** | **Fix validator** | `PermAudit`: make regex context-aware |
| 3 | CI component path → Email Address | 2 | Critical S9 | **No** | **Fix validator** | `SecretScan`: filter EMAIL with `/` |
| 4 | Catalog contact email → API Key | 1 | Critical S9 | **No** | **Whitelist** | `.aav.yaml` for catalog-entry.yaml |
| 5 | Metadata URL → Destructive Op | 2 | High S8 | **No** | **Fix validator** | `PermAudit`: context-aware URL check |
| 6 | .py scripts misclassified as MCP | 6 | High S7 | **No** | **Fix validator** | Classifier: don't cascade `mcp` to .py |
| 7 | Documentation about PII → REG-4 | 1 | High S8 | **No** | **Whitelist** | `.aav.yaml` for README.md REG-4 |

---

## Priority for Validator Fixes

1. **P0 — Fix #1 (Presidio PERSON):** This alone produces ~70 of the 116 blocking findings. Add `"PERSON"` to `_PRESIDIO_SKIP_ENTITIES` in `secret_scan.py` L728.
2. **P0 — Fix #2 (format regex):** Change `\b(?:format|mkfs|fdisk)\b` to require disk-operation context in `perm_audit.py` L434.
3. **P1 — Fix #3 (EMAIL with paths):** Filter Presidio `EMAIL_ADDRESS` results containing `/` in the matched text.
4. **P1 — Fix #5 (URL in metadata):** Make network URL detection aware of artifact context.
5. **P2 — Fix #6 (Classifier):** Improve `.py` file classification when `mcp.json` is present.

---

## `.aav.yaml` Whitelist Entries Needed

For findings that can't be fixed via scanner logic improvements:

```yaml
suppressions:
  - rule_id: P-S3
    file: catalog-entry.yaml
    line: 6
    reason: "Contact email is required metadata in catalog entries"

  - rule_id: REG-4
    file: README.md
    reason: "README documents GDPR handling procedures, does not process PII"
```
