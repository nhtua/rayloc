# Technical Design: High-Precision Secret Detection Pipeline (`rayloc`)

This document specifies the detection engine architecture for `rayloc`. To achieve high recall with near-zero false positives at sub-millisecond speeds, `rayloc` uses a **4-Stage Hybrid Detection Pipeline**.

---

## 1. Detection Pipeline Overview

Every candidate line or byte stream passes through four evaluation gates in sequential order. A candidate must survive all four stages to be flagged as a secret.

```
       [ Input Stream (File / Git Diff Slice) ]
                         │
                         ▼
┌──────────────────────────────────────────────────┐
│ Stage 1: Fast Path & File Lexer                  │  <-- Binary check, path rules, line tokenization
└────────────────────────┬─────────────────────────┘
                         │ Line Tokens / String Literals
                         ▼
┌──────────────────────────────────────────────────┐
│ Stage 2: Structural Signature Matching           │  <-- Known regex sets (AWS, GitHub, JWT, Private Keys)
└────────────────────────┬─────────────────────────┘
                         │ Matched / Unmatched High-Entropy Candidates
                         ▼
┌──────────────────────────────────────────────────┐
│ Stage 3: Adaptive Shannon Entropy Engine         │  <-- Charset-aware entropy & identifier proximity
└────────────────────────┬─────────────────────────┘
                         │ High-Confidence Candidates
                         ▼
┌──────────────────────────────────────────────────┐
│ Stage 4: False Positive Exclusion Matrix         │  <-- Placeholder dictionaries, checksums, mock data
└────────────────────────┬─────────────────────────┘
                         │
                         ▼
              [ Verified Secret Match ]
```

---

## 2. Stage-by-Stage Specification

### Stage 1: Fast Path & File Lexer

* **Goal**: Reject unscanable targets immediately and extract raw string literals without allocating heap memory.
* **Mechanism**:
    1. **Binary & Lockfile Guard**: Inspect the first 1,024 bytes for null bytes (`0x00`) or non-UTF8 binary signatures. Skip automatically.
    2. **Path Filter**: Evaluate file path against `.raylocignore` and built-in noise rules (e.g., `*.lock`, `*.sum`, `node_modules/`).
    3. **Zero-Copy Tokenizer**: Scan byte slices (`&[u8]`) for quote boundaries (`"..."`, `'...'`, `` `...` ``) and continuous non-whitespace token slices.

### Stage 2: Structural Signature Engine (Known Secrets)

* **Goal**: Instant detection of structured secrets with high pattern uniqueness.
* **Mechanism**:
  * Utilizes a single, unified `regex::RegexSet` and `aho_corasick::AhoCorasick` pre-filter running in $O(N)$ single-pass time.
  * **Prefix / Format Anchors**:
    * **AWS Access Key ID**: `(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`
    * **GitHub Fine-Grained Token**: `github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}`
    * **Stripe Secret Key**: `sk_(?:live|test)_[0-9a-zA-Z]{24,99}`
    * **Slack Webhook**: `https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,12}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}`
    * **Private Keys**: `-----BEGIN [A-Z ]+ PRIVATE KEY-----`
    * **JWT Token**: `eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`
* *If a Structural Signature matches, bypass Stage 3 and proceed directly to Stage 4.*

### Stage 3: Adaptive Entropy & Proximity Engine (Generic Secrets)

* **Goal**: Detect unstructured secrets (passwords, raw secret keys, obscure tokens) assigned to generic variables.
* **Mechanism**:
    1. **Proximity Keyword Gate**: Candidate strings must appear within 30 characters of a suspect assignment target or key name matching:
        $$\text{Target} \in \{\text{secret, key, token, password, passwd, auth, api\_key, bearer, credential, private}\}$$
    2. **Charset-Adaptive Shannon Entropy**:
        Calculate standard Shannon entropy over string $S$ of length $n$:
        $$H(S) = -\sum_{i=1}^{k} P(x_i) \log_2 P(x_i)$$
        Where $P(x_i)$ is the frequency of byte $x_i$ in $S$.
    3. **Charset Normalization**: Adjust threshold dynamically based on the string's character set size ($\vert{}\Sigma\vert{}$):
        * **Base64** ($\vert{}\Sigma\vert{} = 64, H_{\text{max}} = 6.0$): Minimum threshold = **4.5 bits/char**
        * **Hexadecimal** ($\vert{}\Sigma\vert{} = 16, H_{\text{max}} = 4.0$): Minimum threshold = **3.0 bits/char**
        * **Alphanumeric** ($\vert{}\Sigma\vert{} = 62, H_{\text{max}} \approx 5.95$): Minimum threshold = **4.2 bits/char**

### Stage 4: False Positive Exclusion Matrix (De-Noising)

* **Goal**: Filter out false positives, mock data, and public hashes before emitting a finding.
* **Filters Applied**:
    1. **Placeholder Dictionary**: Reject matches matching known dummy strings (`EXAMPLE`, `REDACTED`, `12345678`, `xxxxxxxx`, `your_key_here`, `foo`, `bar`).
    2. **Homogeneity & Monotonicity Check**: Reject strings with low character variance (e.g., `aaaaaaaaaaaaaaaa` or `0123456789012345`).
    3. **Checksum / Structure Verification**:
        * **Base64 Padding Check**: Reject invalid Base64 strings missing required padding.
        * **UUID / Hash Exclusions**: Skip standard v4 UUIDs, MD5 (32 hex), SHA-1 (40 hex), and SHA-256 (64 hex) strings unless assigned directly to a high-risk token variable name.
    4. **Inline Directive Check**: Skip lines tagged with `// rayloc:ignore` or `# rayloc:ignore`.

---

## 3. Data Structures & Rust Implementation Strategy

```rust
/// Zero-allocation scan context holding line references
pub struct ScanTarget<'a> {
    pub file_path: &'a Path,
    pub line_number: usize,
    pub line_content: &'a [u8],
}

/// A validated finding with auto-redacted representation
pub struct SecretMatch {
    pub rule_id: &'static str,
    pub line_number: usize,
    pub start_col: usize,
    pub end_col: usize,
    pub entropy: f32,
    pub raw_snippet: RedactedString,
}

/// Custom wrapper ensuring raw secrets never leak to terminal or stdout
pub struct RedactedString(pub String);

impl std::fmt::Display for RedactedString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let len = self.0.len();
        if len <= 8 {
            write!(f, "********")
        } else {
            // Keep first 3 and last 3 characters visible for developer context
            write!(f, "{}...****...{}", &self.0[..3], &self.0[len - 3..])
        }
    }
}
```

---

## 4. Performance Requirements

* **Throughput**: Minimum **500 MB/s per CPU core** for directory scans.
* **Latency**: Under **5ms** total execution time for staged git diff scans under 1,000 lines.
* **Concurrency**: File-level concurrency orchestrated by `rayon` threadpool using lock-free thread-local counters.
