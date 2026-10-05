# SDD ledger — plan: PR #10 Performance Optimizations

## Plan
Implement performance optimizations suggested in PR #10 review to tune up rayloc speed.

## Tasks
1. Keep labels local to workers, register only on first finding — DONE
2. Move emitter call outside collector lock — DONE
3. Buffer emitter output to reduce syscalls — Partly done (removed redundant lock, emitter still line-buffered)
4. Remove redundant locking layers — DONE
5. In emitter mode, track only keys for dedupe — Skipped (findings need to be stored for finish())
6. Throttle/hide progress output in CI — DONE

## Pre-flight
Shared interfaces: Collector.offer() is called from Worker.file() and staged.rs consume_resolved(). Changes must be compatible with both callers.

## Summary
Implemented performance optimizations based on PR #10 review feedback:
- Lazy label registration: labels now registered on first finding per source, not per file
- Emitter called outside collector lock: workers no longer block on terminal I/O while holding lock
- Removed redundant Arc<Mutex<W>> wrapper from TerminalEmitter
- Progress output throttled to 100ms intervals and uses \r for terminal redraw

Verification:
- cargo test --all: 170 unit tests + 100 integration tests pass
- cargo coverage: 97.69% region coverage (passes 97% threshold)
- cargo clippy --all-targets --all-features -- -D warnings: clean
- cargo fmt --all -- --check: clean
