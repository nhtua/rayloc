# P4 context, suppression and JOSE contract

P4 adds no dependencies. A bounded Base64url decoder and a small protected-header
JSON parser use the standard library. The parser covers JSON objects, arrays,
strings/escapes/Unicode surrogate pairs, numbers and literals, rejects duplicate
object keys, and enforces explicit limits. Unknown members are parsed completely;
only top-level `alg` and `enc` receive security-field type checks. This is a small
specialized validator rather than a public general-purpose JSON API. Existing
YAML, regex and ignore dependencies and their lockfile remain unchanged. An actual
`cargo +1.85.0 test --locked --all` validates the new code on the stated MSRV.

## Supported lexical forms

Each physical line is independent. Supported forms are unquoted `.env`
assignments, YAML/JSON key-value pairs, ordinary code assignments with `=` or `:`,
and unquoted or quoted `Authorization: Bearer` header values. Single/double quotes
respect escaped quotes. Findings span the captured value, excluding its surrounding
quotes and the Bearer prefix. Case, snake names, camel names and acronym boundaries
normalize to words; matching strong field names requires a word boundary, so
`compassword` and `notapikey` are weak evidence.

Strong fields include `api_key`, `access_token`, `client_secret`, `credential(s)`,
`auth_token`, `secret_key`, `password`, `passwd`, and the AWS secret-key fields.
Prefixes such as `dbPassword` are supported. Bare `key`, `auth`, and `private` are
weak evidence. Concrete password assignments of at least eight source bytes are
reported without an entropy gate. AWS `aws_secret_access_key` and
`secret_access_key` assignments require exactly 40 alphanumeric/`+`/`/` bytes.
Provider rules describe matching format/context, not credential validity.

Generic strong-context values require at least 16 source bytes. Alphabet precedence
is hex, alphanumeric, Base64/Base64url, then other bytes. Defaults are 3.0, 4.2,
4.5, and the configured fallback respectively. Class overrides apply before the
length cap: 3.5 for 16–23 bytes, 4.0 for 24–31, and the selected class threshold
at 32 or more. Up to two trailing Base64 padding bytes are omitted from entropy
measurement. Explicit custom-rule entropy gates retain their independent values.
Standalone entropy is deferred, with no enabling option.

Supported reference prefixes are `$`, `{{`, `<`, `process.env`, `os.getenv`,
`os.environ`, `env(`, `getenv(`, `config.`, `settings.`, and `ENV[`. Bare code
function/index expressions and following `+`/`.` expressions are deferred. This
is a deliberately bounded lexer, not a language parser. Multiline literals,
template/heredoc syntax, arbitrary expressions, and language-aware escape decoding
are not supported. Values/entropy use source bytes. No context state can cross
files or noncontiguous diff additions.

## Scoped exclusions and counts

Exact, case-insensitive password placeholders: `changeme`, `your_password`,
`your-password`, `password_here`, `example_password`, `replace_me`. Exact generic
placeholders: `your_api_key_here`, `your-api-key-here`, `replace_with_your_key`,
`example_api_key`, `insert_token_here`. The published AWS secret-key example is an
exact case-sensitive exclusion under the AWS context only. Ordinary concrete
`password` literals, weak repeated passwords, and values containing `test`, `foo`
or `EXAMPLE` remain eligible. Explicit custom rules have no implicit placeholder
or generic homogeneity exclusions.

Generic candidates matching a homogeneous value or a contiguous known ascending
alphabet/hex sequence are filtered. These filters do not affect provider rules,
JOSE, or the strong password branch. Checksum exclusions require an identifier
word `checksum`, `digest`, `sha256`, `sha512`, `sha1`, or `md5`; hex-shaped
`api_key` values remain eligible. Checksum words never suppress the independent
concrete-password branch, including `checksum_password`. An enabled strong
candidate is bounded before checksum or any other exclusion. Disabled branches
skip candidate limits, entropy and their suppression filters; any enabled
applicable branch still enforces its limit, including on inline-ignored lines.
Whole-line provider rules still examine reference
and comment text, independently of generic context exclusions.

Exact trailing `# rayloc:ignore` and `// rayloc:ignore` comments outside supported
quoted strings suppress that physical line. URI `://` is not a comment start.
`--no-inline-ignores` disables this policy for CI; it does not change other
exclusions. Candidate/parser limits still fail suppressed lines rather than
hiding oversized input. Reports retain only numeric counts: `inline` counts
explicitly ignored physical lines; `placeholder`, `reference`, and
`generic-filter` count excluded strong-context candidates; `checksum` counts
recognized checksum assignments of at least 16 bytes. These are different units,
not a claim that every counted exclusion would otherwise have produced a finding.
All counters use checked accumulation, including the public detector helper.

## Structural JOSE and budgets

Three-segment compact JWS has a nonempty Base64url payload and a nonempty
signature unless `alg` is exactly `none`, which requires an empty signature.
Five-segment compact JWE requires nonempty IV/ciphertext/tag plus top-level string
`alg` and `enc`; `dir`/`ECDH-ES` require an empty encrypted-key segment and other
algorithms require a nonempty segment. Encoding is unpadded, URL-safe and canonical
(including zero unused tail bits). The protected header must decode to one UTF-8
JSON object with a nonempty string `alg`. Prefix `eyJ` is not required. Compact
JWE does not establish JWT plaintext. No signatures, expiration, revocation or
live activity are checked. Unencoded-payload JOSE extensions are deferred.

Dotted `ghs_APPID_JOSE` forms require a nonempty decimal application ID and valid
compact JOSE. Malformed dotted tokens cannot fall back to opaque `ghs_` matches. Numeric APPID
framing includes forbidden `=` padding so each complete malformed segment is
rejected rather than accepting an unpadded prefix.
Opaque legacy GitHub signatures retain their previous detection heuristics. The
complete provider token span is retained and fully masked. Old dotted synthetic
fixtures were replaced with structurally valid fixtures; malformed ones are
explicit negatives.

| Resource | Limit / behavior |
| --- | --- |
| Existing physical record / candidate | 1 MiB / 64 KiB; incomplete on excess |
| Encoded JOSE protected header | 8 KiB; incomplete on excess |
| JSON recursive value depth | 16 from root depth 0; incomplete on excess |
| JSON values, including root | 512; incomplete on excess |
| Per-line distinct emitted spans | 10,000; incomplete on excess |
| Globally retained findings | Existing 10,000; incomplete on excess |

Decoded header storage is at most 6 KiB. JSON node/key/string work is bounded by
that header plus depth/value caps; object duplicate checks are bounded by the
value count. Suffix segments receive canonical encoding checks without retaining
or decoding payload/ciphertext bytes. Each compact run is visited once. The
per-line span set retains numeric ranges only. Identical spans emit once, with
provider evidence before JOSE/context/custom evidence; distinct occurrences and
nonidentical overlapping spans survive. Existing source/location sorting remains
at the reader/report boundary. No retained finding, suppression or diagnostic
contains source bytes.
