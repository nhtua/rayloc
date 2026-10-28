# Stream redaction design

Date: 2026-10-28. Status: approved by the user for implementation. Based on
checkout `58d860b` and the user's accepted three-mode scope.

## Intent and accepted scope

Filter application logs and piped file contents through Rayloc, replacing detected
secrets while leaving other content intact. Rayloc's own messages must never be
mixed into either data channel. Keep shell routing flexible and keep the filter
small enough that running one instance per channel is practical.

The user selected:

1. Stdio mode: read stdin, redact text, write stdout. Shell redirection and process
   substitution can independently route the producer's stdout and stderr through
   two Rayloc instances.
2. Command mode: `--` introduces a program Rayloc launches, allowing it to filter
   that program's stdout and stderr independently.
3. `--stdout=false` and `--stderr=false` mean pass the corresponding channel through
   unchanged to its original destination. They never mean discard.
4. Reports belong in `/tmp/rayloc-report-<time>.txt`, not the data channels.
5. File mode: `rayloc redact path/to/file` reads the selected file through the same
   text filter as stdin and writes stdout. It does not modify the source file.

### Approved design decisions

- Name the command **`redact`**. Do not add `pipe` or `stream` aliases in v1.
- Channel flags apply only to command mode; stdin and files each supply one
  unlabelled input stream.
- Buffer physical lines up to 1 MiB and flush each completed line. Hold an
  unterminated line until EOF. Exceeding the limit stops processing safely.
- Use `[REDACTED]` without revealing a credential prefix.
- Include a process ID and collision suffix in the report filename, with mode
  `0600`; write aggregate metadata only, never source content or matched values.
- Retain Rayloc's 0/1/2 exit contract. A failed wrapped command maps to exit 2;
  its actual exit status is recorded in the report.
- Include full private-key block masking in this feature. Reusing the current
  marker-only detection would leave the key body visible.

## Constraints

- Rust edition 2024; minimum Rust version 1.85. Target Linux and macOS.
- Add no runtime dependencies or network calls.
- Compile policy regexes once per process and share immutable policy between channels.
- Never load an entire input into memory; memory must be independent of stream length.
- Reader buffer: 256 KiB per filtered channel. Maximum physical-line payload:
  1,048,576 bytes excluding LF, including a trailing CR when present.
- Preserve the existing 65,536-byte candidate limit and 10,000-match per-line limit.
- Require at least 97% production line and region coverage and 100% function coverage.
- Preserve existing scan, preview, accept, hook, Git diff, and reporting behavior.
- Never print detected secret bytes on an enabled channel or in Rayloc diagnostics.
  Explicitly disabled channels intentionally pass raw producer output unchanged.

The coverage target follows the stricter requirements in `AGENTS.md`. The current
`cargo coverage` alias enforces only 95% lines/regions and 98% functions; passing
that alias alone does not meet this feature's acceptance criteria. Do not lower
any thresholds or exclude production code to satisfy this change.

## Approaches and Unix behavior

**Selected: one text filter with stdin, file, or command input.** This reuses
ordinary shell composition, removes the need for `cat` when reading a file, and
adds one-process handling of two channels when convenient.

**Considered: always merge both producer channels into stdin.** Simple but loses
their origins. Support this as a shell choice, not an automatic operation.

**Considered: two input file descriptors or FIFO arguments to one Rayloc process.**
Preserves origins but adds a new input protocol and lifecycle surface. Defer it;
process substitution and command mode already cover the accepted workflows.

A pipe carries bytes with no channel labels. `app | rayloc redact` processes only
the app's stdout. `app 2>&1 | rayloc redact` processes their merged bytes and emits
everything on stdout. Bash process substitution keeps two independent paths:

```bash
app > >(rayloc redact) 2> >(rayloc redact >&2)
```

There are two Rayloc processes and two reports. Bash runs substitutions
asynchronously; that expression alone does not collect their exit statuses or
guarantee the shell waits for their completion. Documentation must explain this
and recommend command mode when callers need one completion/status boundary.
No mode promises relative interleaving between independent stdout/stderr streams;
each individual channel preserves its byte order.

Sources: [GNU Bash pipelines](https://www.gnu.org/software/bash/manual/html_node/Pipelines),
[process substitution](https://www.gnu.org/s/bash/manual/html_node/Process-Substitution.html),
and [redirections](https://www.gnu.org/s/bash/manual/html_node/Redirections.html).
The routing was also verified locally using two `sed` filters and separately
captured stdout/stderr.

## CLI contract

```text
rayloc redact [--config <file>]
rayloc redact [--config <file>] <file>
rayloc redact [--config <file>] [--stdout=true|false] [--stderr=true|false] -- <program> [arguments...]
rayloc redact --help
```

Examples:

```bash
cat application.log | rayloc redact
rayloc redact application.log > application.redacted.log
app 2>&1 | rayloc redact
app > >(rayloc redact) 2> >(rayloc redact >&2)
rayloc redact -- app argument
rayloc redact --stdout=false -- app argument
rayloc redact --stderr=false -- app argument
```

- Both channels default to enabled in command mode. Both may be disabled.
- Accept exactly `--stdout=true`, `--stdout=false`, `--stderr=true`, and
  `--stderr=false`; reject misspellings, duplicate flags and other boolean forms.
- Channel flags in stdio/file mode are errors, even if set to true. The filter cannot
  infer whether stdin originally came from a producer's stdout, stderr, or both.
- `--config <file>` uses the existing policy merge semantics. Duplicate/missing
  values are errors. A single positional path selects file mode; reject multiple
  paths, a path combined with a command delimiter, directories, and nonregular
  files. Accept OS-native paths, including spaces and non-UTF-8 names. Options
  may precede or follow the path; use `./-name` for a filename starting with `-`.
- File mode opens the file read-only and never consumes stdin or writes back to
  the file. Follow symlinks to regular files using normal file-read semantics;
  validate regular-file metadata before opening and again on the opened handle.
  Missing/unreadable/nonregular targets yield report-only errors and exit 2.
  Output goes to stdout; Rayloc's own stderr stays empty. Redirection onto the
  input path is shell truncation and is not supported as an in-place operation.
- The first `--` terminates Rayloc option parsing. All following OS-native
  arguments, including `--help` and another `--`, belong to the child. A missing
  program is an error. Execute directly, without interpolating a shell command.
- `--help`/`-h` alone after `redact` prints usage to stdout and exits 0; it reads
  no input, starts no child, and creates no report. Mixed help/options are errors.
- Do not support `--no-redact`, `preview`, `--silent`, Git scopes, thread-count
  flags, or automatic terminal reports within `redact`.

## Text transformation contract

### Record boundaries and exact output

Treat input as bytes, not a lossy UTF-8 string. A physical record ends at LF or
EOF. An LF preceded by CR has a CRLF terminator. Give the detector the record
content without the terminator, then write the original terminator unchanged.
A lone CR elsewhere, including at EOF, is content, not a record delimiter.

Preserve empty records, spaces, tabs, control bytes, invalid UTF-8, NUL bytes,
and the absence of a final newline. Do not apply the file scanner's binary-file
skip policy to streamed content. Output is identical to input except for the
union of detected sensitive byte spans. Do not escape, normalize, recolor,
reformat JSON, or add a BOM or newline.

For each record, collect spans before emitting any of that record. Validate
`0 <= start < end <= content.len()`, sort and merge overlapping or adjacent spans,
then replace each merged interval with the exact ASCII bytes `[REDACTED]`.
This prevents overlapping rules from leaking suffixes or duplicating content.
Only a fully successful detection pass may release a record.

Flush after each complete record and at EOF, rather than waiting for a large
output buffer to fill. Do not flush an unfinished record merely because a read
returned, a timer fired, or the producer paused. A secret may cross any read
boundary. Applications producing progress text without LF may see delayed output.

### Detection and policy

Reuse `Registry::detect_line` with text syntax, builtin/provider/JOSE/contextual
rules, configured custom captures, entropy gates and explicitly disabled rules.
Load policy from the existing current-directory/root discovery plus the explicit
overlay before consuming input or launching a child. Outside a repository, this
must work with no Git executable installed, using current-directory/default policy.
Do not load file/path exclusion policy: these streams have no trustworthy paths.

Set `registry.inline_ignores = false`: an input log line cannot opt out by
containing `rayloc:ignore`. File-specific accepted IDs do not suppress streams;
do not synthesize file fingerprints or invent stream accept IDs. Existing
placeholder/reference/checksum filtering remains part of the detector. Explicit
configuration can still disable rules, so the report must identify that policy
was applied without including policy paths or custom text.

Scope remains detection by supported rules, not identification of every possible
secret. Arbitrary multiline custom regexes, encoded secrets, terminal escape
normalization, and missing private-key opening markers are outside v1.

### Private-key blocks

The current provider rule recognizes `BEGIN ... PRIVATE KEY` markers only. In
`redact`, expand an enabled marker detection into a stateful sensitive interval
ending at its corresponding `END` marker. Cover all six labels currently in
`PRIVATE_KEY_MARKERS`; use one shared label definition rather than duplicated lists.

- On an opening marker, preserve the preceding nonsecret bytes, mask from the
  opening marker onward, and enter that key-label state.
- On each subsequent line, mask all non-terminator bytes until the matching end
  marker (inclusive), then resume normal detection on the suffix of that line.
- Matching begin/end on one line, multiple blocks on one line and empty body lines
  are supported. Never retain an entire block in memory.
- Emit one replacement per merged sensitive interval on each line, preserving LF
  and CRLF. Empty body lines retain their terminator with no invented content.
- If the closing marker is missing, mask through EOF; report an unterminated
  block and exit 2. A mismatched/nested marker never ends the current block.
- Run ordinary detection against the complete original record so custom anchors
  and context boundaries retain their meaning; union those spans with the PEM
  intervals. A record whose content is entirely covered by a PEM interval can
  skip ordinary detection. On partially covered records, any detector error still
  fails the whole record, including a limit triggered inside a PEM interval.
- If the marker rule is explicitly disabled, no block masking is applied. Public
  keys and certificates do not enter this state.

State is independent for every filtered channel and every process invocation.
File mode uses exactly the same bounded record/filter state as stdio; file size
does not change the filter algorithm or policy. Policy discovery remains based
on the invocation's working directory, not the selected file's parent directory,
so `rayloc redact file` and `cat file | rayloc redact` use identical policy.

### Limits and failures

Use bounded reads; do not call an unbounded `read_to_end`, `read_to_string`, or
`read_until` into an ever-growing vector. At most the configured record budget,
bounded detector scratch/span storage, and a fixed reader buffer are retained
per channel. Do not accumulate findings, records, or report rows for stream life.

An oversize record, detector/candidate/match limit, invalid span, counter overflow,
read failure, write failure (including broken pipe), or flush failure returns 2.
Withhold the failing record's buffered raw bytes; never fall back to raw forwarding.
Earlier safe output may already have been delivered. A partial write may deliver
a prefix of already transformed output; it must never expose an unredacted match.
Retry interrupted reads/writes using standard I/O semantics.

Retain the per-record 10,000-match limit; do not inherit the file collector's
10,000-finding cap across an unlimited stream. All lifetime counters are checked
`u64` counters. A channel may redact millions of records with bounded memory.

## Command mode and channel ownership

- Launch with inherited environment, working directory and stdin. Rayloc does not
  consume the child's stdin, rewrite arguments, or invoke a shell implicitly.
- For an enabled output channel, use a child pipe and a dedicated worker that
  runs the same filter as stdio mode, writing to the corresponding parent channel.
- For a disabled channel, use `Stdio::inherit()` directly. Do not buffer, scan,
  count its bytes, or copy it onto a different channel. Mark its report row as
  passthrough with unknown counts, never as clean/scanned.
- Read both enabled pipes concurrently, including when one is idle or produces
  more than the OS pipe capacity. One channel reaching EOF cannot cancel the other.
- The coordinator owns/reaps the child. It must observe worker failures while
  the child is still running. On filtering failure, kill and reap the immediate
  child, close pipe ownership, join workers, and finalize an incomplete report.
- On ordinary child exit, finish reading both pipes through EOF, flush workers,
  join them, and only then finalize the report and exit.
- Ordinary blocking Unix backpressure applies: a downstream reader that keeps a
  pipe open but stops consuming may block its worker indefinitely. Killing the
  producer cannot cancel that output write. Cleanup/join completion assumes the
  downstream writes can make progress; v1 does not add nonblocking output,
  cancellation of stalled writes or an output timeout. Test failure cleanup with
  failing/progressing sinks, not a promise to interrupt arbitrary blocked sinks.
- Do not hold a stdout/stderr lock on the coordinator thread while workers need
  those handles. The current `cli::run` holds stderr's lock during dispatch and
  must be adjusted specifically for the new command to prevent deadlock.

This is a text-processing wrapper, not a terminal emulator or process supervisor.
No PTY, process-group creation, arbitrary signal forwarding, daemon management,
or guarantees for descendants retaining pipes after the direct child exits.
Foreground Ctrl-C follows the shell's existing process-group behavior. An external
kill may leave an unfinished report. Never install handlers that print diagnostics.

## Reports and exit codes

### File lifecycle

For every data-processing invocation (including invalid redact arguments), create
one report before reading input or starting a child. Proposed filename:

```text
/tmp/rayloc-report-<unix-seconds>-<nanoseconds>-<pid>-<collision>.txt
```

Use `OpenOptions::create_new(true)` and Unix mode `0600`. Retry existing names
with a bounded collision counter (64 attempts); never truncate an existing file
or follow a pre-existing final-component symlink. Use `/tmp` deliberately rather
than letting an untrusted `TMPDIR` reroute reports. Private test helpers may inject
a directory and clock/ID values; there is no public report-path flag in v1.

Write and flush an initial header with report version, PID, start time, and
`status=running`. Append a final summary only after processing is done. A report
without a final summary is unfinished and must not be interpreted as success.
When creation/initial writing fails, consume no input/start no child; exit 2
silently. When later report writes fail, exit 2 silently; no fallback diagnostic
may contaminate stdout/stderr. No cleanup/rotation daemon; retain reports for users.

### Summary contents

Record mode (`stdio`, `file`, `command`, or `invalid` for rejected arguments),
start/end time and elapsed duration, the
applied-policy indicator, source identity (`stdin`, `file`, `stdout`, `stderr`),
processing/passthrough status, bytes
read/written, records processed, detector spans found, merged intervals redacted,
private-key blocks, incomplete blocks, final status and Rayloc exit code. Record
the child's numeric exit code or terminating signal when available, otherwise a
fixed not-started/unavailable category. On error, include only fixed categories.

Counts describe observed processing; do not claim complete input consumption on
failure. Redaction counts include private-key body intervals. Passthrough channels
have unknown content counts, not zero scanned bytes. Do not store individual
findings: aggregate statistics keep memory and report size bounded.

Never include original input, matched bytes (even partially masked), snippets,
program/argument text, paths, environment values, custom rule names, raw OS error
strings, or a child panic/error diagnostic in Rayloc-owned report text. Producer
diagnostics remain data and pass through the selected channel policy.

### Exit policy

| Condition, in priority order | Exit |
| --- | --- |
| Argument/configuration/report/I/O/limit/worker/spawn/wait failure, unfinished key block, or child exit unsuccessful/signalled | 2 |
| Processing completed, child succeeded if present, and an enabled channel redacted at least one interval | 1 |
| Processing completed, child succeeded if present, and no enabled channel redacted anything | 0 |

Thus command mode is a Rayloc operation with a 0/1/2 result, not transparent
forwarding of arbitrary child exit codes. Both channels disabled still produce
a report; a successful child yields 0 and the report does not claim secret-free
output. A child failure does not truncate otherwise readable output: drain and
filter it normally before returning 2. Explicit help is the documented exception
to silent data mode.

## Implementation boundaries

Use a new internal `src/redact/` module. Keep it separate from
`src/scanner/stream.rs`, which is the existing file scanner's physical-line
transaction engine, and from `src/rules/stream.rs`, which defines detector events.
Neither currently transforms a stream for output.

Suggested ownership:

| Module | Responsibility |
| --- | --- |
| `src/redact/mod.rs` | Fixed safe errors, checked stats, outcomes |
| `src/redact/filter.rs` | Bounded byte records, span union/replacement, streaming I/O |
| `src/redact/pem.rs` | Per-channel private-key block intervals and label state |
| `src/redact/report.rs` | Secure report creation and bounded summaries |
| `src/redact/command.rs` | Child capture, concurrent workers, completion and cleanup |
| `src/redact/cli.rs` | Strict arguments, policy setup, file input and report-only errors |

Register the private module in `src/lib.rs`. Keep `src/cli.rs` integration small
and preserve existing command behavior. Use standard-library byte/I/O/thread/process
types and existing `Registry`; no new regex compilations in record loops, no new
public library API just for this feature, and no raw-value match structs. Follow
the existing `#[path = "../../tests/unit/..."]` unit-test layout.

## Acceptance and verification

1. Clean stdin, including invalid UTF-8/NUL/CRLF/no-final-LF, round-trips exactly.
2. Secrets become `[REDACTED]`; surrounding bytes and terminators stay identical.
   Split every position of a representative token across reads and assert the
   same output as a single read. Overlapping/custom captures do not leak suffixes.
3. Completed records become visible before producer EOF; partial records stay
   withheld. Exactly 1 MiB payload works; 1 MiB + 1 fails without releasing it.
4. Inline-ignore text and accepted file IDs do not bypass redaction. Disabled
   policy rules and existing context filters behave as specified.
5. Private keys are masked through the matching closing marker; body bytes never
   appear in either stream/report. Missing/mismatched closers fail safely.
6. Concurrent stdout/stderr loads beyond pipe capacity complete with correct
   per-channel output. EOF, idle channels, disabled channels, native arguments,
   inherited stdin and child exit failures follow the command-mode contract.
7. A worker/report/I/O failure returns 2 without hangs or Rayloc-owned output;
   injected raw error strings and arguments appear nowhere in diagnostics.
8. Each invocation gets a distinct mode-0600 report. Collisions, symlinks, report
   directory failures and report finalization failures cannot clobber files or
   silently become success. An invalid invocation creates no child.
9. Two Bash substitutions preserve separate destinations and create two reports;
   merged input stays merged on stdout. Test shell completion explicitly.
10. A generated stream over 10 MiB with over 10,000 detections completes with
    bounded memory; do not allocate that input as a production-sized in-memory
    fixture. Existing file/diff/preview/hook tests remain green.
11. Explicit file input produces byte-identical output, exit status and content
    counts to piping that same file from the same directory/policy. Preserve the
    source file's contents and permissions. Cover large files, spaces/non-UTF-8
    paths, symlinks, missing/unreadable/nonregular files, input-mode conflicts,
    and unused stdin; reports must not reveal the selected path.

Run the mandatory project checks at implementation time:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
cargo bench
cargo coverage
cargo llvm-cov --locked --workspace --all-features --ignore-filename-regex '(^|/)(tests|benches)/' --fail-under-functions 100 --fail-under-lines 97 --fail-under-regions 97
```

Add paired release-build measurements for clean and secret-dense stdin streams,
two-channel command capture, completed-record latency and peak RSS. Compare the
same fixture sizes and policy with an immutable pre-change scanner baseline;
do not confuse scan-report throughput with redaction throughput. Record numbers
and limits honestly; no unsupported absolute throughput promise is added here.

## Non-goals

No release, deployment, or changing existing scan behavior is implied by this
design. No FIFO/extra-FD input
API, explicit channel labels embedded in data, general multiline custom matching,
PTY behavior, prefix previews, report content dumps, or automatic report deletion.

