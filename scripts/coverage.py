#!/usr/bin/env python3
"""Measure all production Rust functions/lines/regions using LLVM, no packages.

Run from any directory: python3 scripts/coverage.py
LLVM_COV and LLVM_PROFDATA can select installed compatible LLVM executables.
Test helpers, fixtures, and benchmark drivers are excluded, never production code.
"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

root = Path(__file__).resolve().parent.parent
target = root / "target" / "coverage"
profiles = target / "profiles"
profiles.mkdir(parents=True, exist_ok=True)
for previous in profiles.glob("*.profraw"):
    previous.unlink()

sysroot = Path(subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip())
llvm_tools = list((sysroot / "lib" / "rustlib").glob("*/bin"))
executables = {}
for tool, variable in [("llvm-cov", "LLVM_COV"), ("llvm-profdata", "LLVM_PROFDATA")]:
    candidates = [os.environ.get(variable)]
    candidates += [str(directory / tool) for directory in llvm_tools]
    candidates += [shutil.which(tool)]
    candidates += ["/opt/rocm/lib/llvm/bin/" + tool]
    found = next((candidate for candidate in candidates if candidate and Path(candidate).is_file()), None)
    if not found:
        sys.exit("LLVM tools unavailable; install llvm-tools-preview or set " + variable)
    executables[tool] = found

environment = dict(os.environ)
environment["CARGO_TARGET_DIR"] = str(target)
environment["RUSTFLAGS"] = environment.get("RUSTFLAGS", "") + " -C instrument-coverage -C link-dead-code"
environment["LLVM_PROFILE_FILE"] = str(profiles / "%m-%p.profraw")
build = subprocess.run(
    ["cargo", "test", "--all", "--all-features", "--no-run", "--message-format=json"],
    cwd=root, env=environment, check=True, stdout=subprocess.PIPE, text=True,
)
objects = set()
for line in build.stdout.splitlines():
    event = json.loads(line)
    if event.get("reason") == "compiler-artifact" and event.get("executable"):
        objects.add(event["executable"])
binary = target / "debug" / ("rayloc.exe" if os.name == "nt" else "rayloc")
if binary.is_file():
    objects.add(str(binary))
subprocess.run(["cargo", "test", "--all", "--all-features"], cwd=root, env=environment, check=True)
raw_profiles = sorted(profiles.glob("*.profraw"))
if not raw_profiles or not objects:
    sys.exit("No executable coverage data was produced")
profile = target / "merged.profdata"
subprocess.run(
    [executables["llvm-profdata"], "merge", "-sparse", *map(str, raw_profiles), "-o", str(profile)],
    check=True,
)
objects = sorted(objects)
# Enumerate every production source instead of filtering arbitrary directory
# names in absolute paths. Dependency/test/benchmark code cannot dilute the gate.
sources = sorted((root / "src").rglob("*.rs"))
arguments = [objects[0], *["-object=" + item for item in objects[1:]],
             "-instr-profile=" + str(profile), "--sources", *map(str, sources)]
report = subprocess.check_output([executables["llvm-cov"], "export", *arguments], text=True)
(target / "coverage.json").write_text(report)
subprocess.run([executables["llvm-cov"], "report", *arguments], check=True)
data = json.loads(report)["data"]
if len(data) != 1:
    sys.exit("Unexpected coverage export format")
totals = data[0]["totals"]
failed = False
for metric in ["functions", "lines", "regions"]:
    values = totals[metric]
    print(f"Production {metric}: {values['covered']}/{values['count']} ({values['percent']:.4f}%)", flush=True)
    if not values["count"] or values["percent"] <= 98:
        failed = True
if totals["functions"]["covered"] != totals["functions"]["count"]:
    failed = True
print("Coverage data: " + str(target / "coverage.json"), flush=True)
sys.exit(1 if failed else 0)
