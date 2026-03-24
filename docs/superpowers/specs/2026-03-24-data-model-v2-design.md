# Security Patches Dataset v2.0 — Data Model Design

## Problem

The v1.0 dataset uses a single flat CSV with stringified dicts for nested data (files, comments, parents). This makes it hard to query file-level information, loses upstream data from OSV and NVD (affected packages, CVSS decomposition, reference tags), and forces researchers to re-parse or re-scrape for common analyses.

## Goals

Support four primary use cases with a single dataset:

1. **ML/classification** — commit message + diff → security/not-security
2. **Vulnerability research** — fix patterns, response times, CWE distributions
3. **Supply chain analysis** — mapping vulns to packages/ecosystems/versions
4. **General-purpose benchmark** — broad, well-structured, and complete

## Design: Normalized Relational Model

Six relational CSV tables plus one flat convenience view. All CSVs use `escapechar="\"`, `doublequote=False`, `quoting=QUOTE_NONNUMERIC`. All date/time fields use ISO 8601 format (`YYYY-MM-DDTHH:MM:SSZ`). All list-type fields use JSON arrays (`["a", "b"]`), never Python set literals.

Output directory: `dataset/v2/`

### Data Quality Filters

Before populating any table, filter out:
- OSV entries with a `withdrawn` field (retracted vulnerabilities)
- NVD entries with `vulnStatus == "Rejected"`

### Table 1: vulnerabilities.csv

One row per unique vulnerability. Root entity.

| Column | Type | Source | Notes |
|--------|------|--------|-------|
| `vuln_id` | str (PK) | OSV/NVD | Canonical ID (see dedup rules below) |
| `aliases` | str | OSV | JSON array: `["CVE-2024-1234", "GHSA-xxxx"]` |
| `summary` | str | OSV/NVD | Short description |
| `details` | str | OSV | Longer description (OSV only, NVD uses summary) |
| `cwe_ids` | str | Both | JSON array: `["CWE-79", "CWE-89"]` |
| `cvss_base_score` | float | Both | Best available (v3.1 > v3.0 > v2.0) |
| `cvss_severity` | str | Both | LOW/MEDIUM/HIGH/CRITICAL |
| `cvss_vector` | str | Both | Full CVSS vector string |
| `cvss_version` | str | Both | "3.1", "3.0", "2.0" |
| `published_date` | str | Both | ISO 8601 |
| `modified_date` | str | Both | ISO 8601 |
| `source_datasets` | str | Pipeline | JSON array: `["osv", "nvd"]` |

**Deduplication algorithm:**

1. Build a mapping of all aliases using a **union-find (disjoint set)** data structure: for each OSV entry, union all its aliases (CVE, GHSA, ecosystem ID) into the same equivalence class. This handles transitive chains (e.g., entry A has `[CVE-X, GHSA-Y]` and entry B has `[GHSA-Y, PYSEC-Z]` → all three merge).
2. For each NVD entry, look up its CVE ID in the alias mapping. If found, merge into the existing group; if not, create a new entry.
3. **Canonical `vuln_id`:** Use CVE ID when available (most common cross-source identifier). For OSV-only entries without a CVE alias, use the original OSV ID (e.g., GHSA-xxxx, PYSEC-xxxx).
4. **Field merge priority:** NVD for CVSS data (has full decomposition), OSV for summary/details/aliases (richer narrative). `cwe_ids` is the union from both sources.
5. `source_datasets` records which sources contributed: `["osv"]`, `["nvd"]`, or `["osv", "nvd"]`.

### Table 2: cvss.csv

Full CVSS decomposition. One row per vulnerability per CVSS version per assessor. Composite PK: (`vuln_id`, `cvss_version`, `source`).

| Column | Type | Source | Notes |
|--------|------|--------|-------|
| `vuln_id` | str (FK) | - | |
| `cvss_version` | str | Both | "2.0", "3.0", "3.1" |
| `source` | str | NVD | Assessor: `nvd@nist.gov`, CNA identifier, etc. `"osv"` for OSV-parsed entries |
| `vector_string` | str | Both | Full vector string |
| `base_score` | float | Both | |
| `base_severity` | str | Both | LOW/MEDIUM/HIGH/CRITICAL |
| `attack_vector` | str | Both | NETWORK/ADJACENT_NETWORK/LOCAL/PHYSICAL |
| `attack_complexity` | str | Both | LOW/HIGH (v3.x) or LOW/MEDIUM/HIGH (v2.0) |
| `privileges_required` | str | v3.x only | NONE/LOW/HIGH (null for v2.0 rows) |
| `user_interaction` | str | v3.x only | NONE/REQUIRED (null for v2.0 rows) |
| `scope` | str | v3.x only | UNCHANGED/CHANGED (null for v2.0 rows) |
| `authentication` | str | v2.0 only | NONE/SINGLE/MULTIPLE (null for v3.x rows) |
| `confidentiality_impact` | str | Both | NONE/LOW/HIGH (v3.x) or NONE/PARTIAL/COMPLETE (v2.0) |
| `integrity_impact` | str | Both | Same as above |
| `availability_impact` | str | Both | Same as above |
| `exploitability_score` | float | NVD | Sub-score (NVD only) |
| `impact_score` | float | NVD | Sub-score (NVD only) |

**CVSS version handling:**
- v3.x rows use `privileges_required`, `user_interaction`, `scope`; `authentication` is null.
- v2.0 rows use `authentication`; `privileges_required`, `user_interaction`, `scope` are null.
- Impact values are preserved as-is from each version (v2.0 uses NONE/PARTIAL/COMPLETE, v3.x uses NONE/LOW/HIGH).
- OSV entries with only a CVSS vector string: parse using the `cvss` PyPI library to extract individual components and compute the base score.
- NVD entries provide all fields natively.

### Table 3: commits.csv

One row per fix commit. Composite PK: (`commit_sha`, `vuln_id`) — a commit can fix multiple vulns, a vuln can have multiple commits.

| Column | Type | Source | Notes |
|--------|------|--------|-------|
| `commit_sha` | str | Processing | Full 40-char SHA |
| `vuln_id` | str (FK) | Processing | |
| `project` | str | Processing | `https://github.com/owner/repo` |
| `commit_url` | str | Processing | Full commit URL |
| `patch_type` | str | Processing | SINGLE/MULTI |
| `chain_length` | int | Processing | Number of commits in the fix chain |
| `chain_position` | int | GitHub API | Position in ordered chain (1-indexed) |
| `message` | str | GitHub API | Commit message |
| `author_name` | str | GitHub API | `commit.author.name` |
| `author_date` | str | GitHub API | ISO 8601, from `commit.author.date` |
| `committer_name` | str | GitHub API | `commit.committer.name` |
| `committer_date` | str | GitHub API | ISO 8601, from `commit.committer.date` |
| `is_merge` | bool | GitHub API | `len(commit.parents) > 1` |
| `is_signed` | bool | GitHub API | `commit.verification.verified` |
| `parents` | str | GitHub API | JSON array of parent SHAs |
| `additions` | int | GitHub API | `commit.stats.additions` |
| `deletions` | int | GitHub API | `commit.stats.deletions` |
| `files_changed` | int | GitHub API | `len(commit.files)` |
| `comments` | str | GitHub API | JSON array of comment objects, null if none |
| `dataset` | str | Pipeline | Which source this commit came from: osv, nvd, bigvul, etc. |

**Note on `dataset` vs `source_datasets`:** `dataset` records which source the commit URL was extracted from. `source_datasets` on vulnerabilities records which sources mention the vulnerability. These can differ — e.g., an NVD-sourced commit may belong to a vulnerability also in OSV.

### Table 4: files.csv

One row per changed file per commit. Composite PK: (`commit_sha`, `filename`).

| Column | Type | Source | Notes |
|--------|------|--------|-------|
| `commit_sha` | str (FK) | GitHub API | |
| `filename` | str | GitHub API | Full path: `src/auth/login.py` |
| `additions` | int | GitHub API | Lines added in this file |
| `deletions` | int | GitHub API | Lines deleted |
| `changes` | int | GitHub API | Total changes |
| `status` | str | GitHub API | modified/added/removed/renamed |
| `extension` | str | Derived | `.py`, `.js`, `.c`, etc. |
| `language` | str | Derived | Mapped using GitHub Linguist conventions |
| `is_test_file` | bool | Derived | Matches patterns: `test_*`, `*_test.*`, `*_spec.*`, `spec/`, `tests/`, `__tests__/`, `testing/` |
| `previous_filename` | str | GitHub API | Previous path when `status == "renamed"`, null otherwise |
| `patch` | str | GitHub API | Raw unified diff for this file |

### Table 5: affected_packages.csv

One row per affected package per version range. Extracted from OSV JSON. Composite PK: (`vuln_id`, `package_name`, `ecosystem`, `range_type`, `version_introduced`, `version_fixed`).

| Column | Type | Source | Notes |
|--------|------|--------|-------|
| `vuln_id` | str (FK) | OSV | |
| `package_name` | str | OSV | e.g., `django`, `lodash` |
| `ecosystem` | str | OSV | PyPI, npm, Go, Maven, etc. |
| `purl` | str | OSV | Package URL: `pkg:pypi/django` |
| `range_type` | str | OSV | ECOSYSTEM, SEMVER, or GIT |
| `version_introduced` | str | OSV | First affected version (from range events) |
| `version_fixed` | str | OSV | Version that fixes it (from range events) |
| `versions_affected` | str | OSV | JSON array when explicit version list is available |

**Range handling:** Each `affected[].ranges[]` entry produces a separate row. A single package can have multiple rows if it has multiple range types (e.g., ECOSYSTEM + GIT) or multiple introduced/fixed pairs within a range. When `version_introduced` or `version_fixed` is absent from the range events, use empty string `""` (not null) to ensure composite PK uniqueness.

NVD CPE configurations are out of scope for v2 (see Future Work).

### Table 6: references.csv

One row per reference URL per vulnerability. Composite PK: (`vuln_id`, `url`, `source`).

| Column | Type | Source | Notes |
|--------|------|--------|-------|
| `vuln_id` | str (FK) | Both | |
| `url` | str | Both | Full URL |
| `osv_ref_type` | str | OSV | Upstream classification: ADVISORY, FIX, REPORT, WEB, ARTICLE, PACKAGE |
| `source` | str | NVD | Reporter: `cve@mitre.org`, etc. (null for OSV-only refs) |
| `tags` | str | NVD | JSON array: `["Patch", "Vendor Advisory"]` (null when absent) |
| `ref_type` | str | Derived | `commit`, `issue`, `pull_request`, `advisory`, `other` — inferred from URL pattern |
| `host` | str | Derived | `github.com`, `gitlab.com`, etc. |

**NVD processing note:** `tools/nvd/process.py` must be extended to extract per-reference `source` and `tags` fields (currently only extracts URLs).

### Flat Convenience View: security_patches_v2.0.csv

Pre-joined for quick ML use. One row per (`vuln_id`, `commit_sha`):

| Column | Source Table |
|--------|-------------|
| `vuln_id` | vulnerabilities |
| `cwe_ids` | vulnerabilities |
| `cvss_base_score` | vulnerabilities |
| `cvss_severity` | vulnerabilities |
| `summary` | vulnerabilities |
| `published_date` | vulnerabilities |
| `project` | commits |
| `commit_sha` | commits |
| `message` | commits |
| `author_name` | commits |
| `author_date` | commits |
| `patch_type` | commits |
| `additions` | commits |
| `deletions` | commits |
| `files_changed` | commits |
| `primary_language` | Derived: language with most lines changed; ties broken alphabetically |
| `dataset` | commits |

## Data Flow

```
OSV JSON files ─┐
                 ├─► new build_tables.py ─► vulnerabilities, cvss, affected_packages, references
NVD JSON file  ─┘

Filtered commit CSVs ─► cli.py (process/merge) ─► commits (pre-metadata)

commits + GitHub API ─► github_data.py (extended) ─► commits (enriched), files

All tables ─► curate step ─► flat convenience view + deduplication
```

**Implementation changes required:**
- Migrate all `str(set(...))` serialization in `osv/process.py` and `nvd/process.py` to `json.dumps(sorted(list(...)))` for JSON array compliance
- New `scripts/build_tables.py` — reads raw OSV JSON + NVD JSON, outputs vulnerabilities, cvss, affected_packages, references tables
- Extend `tools/nvd/process.py` — extract per-reference `source` and `tags`
- Extend `scripts/github_data.py` — extract `committer_name`, `committer_date`, `is_signed`, `is_merge`; output files table separately
- New curate step — join tables into flat convenience view, compute `primary_language`
- Add `cvss` PyPI library — for parsing CVSS vector strings from OSV

## Key Decisions

1. **JSON arrays over stringified Python sets** — all list/set fields use `["a", "b"]` format, not `{'a', 'b'}`, for interoperability with other languages
2. **Diffs included in files table** — large but critical for ML; researchers can drop the column if unneeded
3. **OSV packages only, no NVD CPE** — OSV's package model is cleaner and more actionable
4. **CVSS parsed from vector strings** — OSV often only has the vector; parse with `cvss` library so all entries have decomposed fields
5. **CVSS v2.0 and v3.x coexist** — version-specific columns (`authentication` for v2.0, `privileges_required`/`user_interaction`/`scope` for v3.x) with nulls for inapplicable fields
6. **Filter withdrawn/rejected** — remove OSV `withdrawn` entries and NVD `Rejected` entries before processing
7. **Canonical vuln_id is CVE when available** — fall back to OSV ID (GHSA, PYSEC, etc.) for entries without a CVE alias
8. **Comments as JSON array** — `[{"author": "...", "date": "...", "body": "..."}]` instead of numbered-key dicts

## Future Work

- **Derived features (Approach C):** `time_to_fix`, `fix_complexity`, `has_test_changes`, `is_multi_language_fix`, `cwe_category` (top-25 mapping), negative samples
- **NVD CPE configurations table:** Map vulnerabilities to affected products/vendors/versions using NVD's CPE match data
