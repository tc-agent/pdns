#!/usr/bin/env python3
# This file ships into oss-fuzz review-repo PRs via the fuzz-all composite
# action; oss-fuzz's `infra/presubmit.py` check_license greps every Python
# file under non-projects/ paths for the Apache 2.0 LICENSE-2.0 URL, so we
# carry the standard header here even though it's our own infra code.
# Copyright 2026 fuzz-for-me contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Run all libFuzzer harnesses for an oss-fuzz project concurrently.

Shared by CI workflows (oss_fuzz_verify.yml, upstream_verify.yml) and the agent
CLI. stdlib-only so it can run in a stock oss-fuzz CI environment without the
fuzz_for_me package installed.
"""

import argparse
import os
import shlex
import stat
import subprocess
import sys
from pathlib import Path

SKIP_SUFFIXES = (".options", ".dict", "_seed_corpus.zip")
SKIP_NAMES = {"llvm-symbolizer", "jazzer_agent_deploy.jar", "jazzer_driver"}


def discover_harnesses(out_dir):
  out = []
  for entry in sorted(out_dir.iterdir()):
    if not entry.is_file():
      continue
    if entry.name in SKIP_NAMES:
      continue
    if any(entry.name.endswith(s) for s in SKIP_SUFFIXES):
      continue
    if not (entry.stat().st_mode & stat.S_IXUSR):
      continue
    out.append(entry.name)
  return out


def build_cmd(args, harness, corpus_dir):
  # --out-dir is intentionally NOT passed to helper.py run_fuzzer: not all
  # versions of upstream helper.py accept it. The default location
  # (oss-fuzz/build/out/<project_basename>) is what build_fuzzers writes to.
  cmd = [sys.executable, str(args.helper_py), "run_fuzzer"]
  if args.external:
    cmd.append("--external")
  cmd += ["--corpus-dir", str(corpus_dir), args.project, harness]
  if args.max_total_time > 0:
    cmd += ["--", f"-max_total_time={args.max_total_time}"]
  return cmd


def main():
  ap = argparse.ArgumentParser()
  ap.add_argument("--helper-py", required=True, type=Path)
  ap.add_argument("--project",
                  required=True,
                  help="oss-fuzz project name, or path in --external mode")
  ap.add_argument("--out-dir",
                  required=True,
                  type=Path,
                  help="build/out/<project> — where the harness binaries are")
  ap.add_argument("--corpus-root", required=True, type=Path)
  ap.add_argument("--logs-dir", required=True, type=Path)
  ap.add_argument("--max-total-time",
                  type=int,
                  default=0,
                  help="seconds per harness; 0 = unbounded (use --detach)")
  ap.add_argument("--external",
                  action="store_true",
                  help="pass --external to helper.py")
  ap.add_argument("--detach",
                  action="store_true",
                  help="launch and exit immediately, printing PIDs")
  args = ap.parse_args()

  args.out_dir = args.out_dir.resolve()
  args.corpus_root = args.corpus_root.resolve()
  args.logs_dir = args.logs_dir.resolve()
  args.helper_py = args.helper_py.resolve()

  if not args.detach and args.max_total_time <= 0:
    ap.error("--max-total-time must be > 0 unless --detach is given")

  harnesses = discover_harnesses(args.out_dir)
  if not harnesses:
    print(f"::error::no harness binaries found in {args.out_dir}",
          file=sys.stderr)
    return 1

  args.corpus_root.mkdir(parents=True, exist_ok=True)
  args.logs_dir.mkdir(parents=True, exist_ok=True)

  print(
      f"Harnesses ({len(harnesses)}): {' '.join(harnesses)} — "
      f"max_total_time={args.max_total_time}s, detach={args.detach}",
      flush=True)

  procs = []
  for h in harnesses:
    corpus_dir = args.corpus_root / h
    corpus_dir.mkdir(parents=True, exist_ok=True)
    log_path = args.logs_dir / f"{h}.log"
    log_fp = open(log_path, "w")
    cmd = build_cmd(args, h, corpus_dir)
    proc = subprocess.Popen(cmd,
                            stdout=log_fp,
                            stderr=subprocess.STDOUT,
                            start_new_session=True)
    procs.append((h, proc, log_fp, log_path, corpus_dir))

  if args.detach:
    for h, proc, log_fp, log_path, _ in procs:
      log_fp.close()
      print(f"{h} pid={proc.pid} log={log_path}")
    return 0

  rc = 0
  timeout = args.max_total_time + 60
  for h, proc, log_fp, _, _ in procs:
    try:
      proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
      print(f"::warning::{h} exceeded timeout, killing", file=sys.stderr)
      proc.kill()
      proc.wait()
      rc = max(rc, 1)
    finally:
      log_fp.close()

  for h, proc, _, log_path, corpus_dir in procs:
    n_corpus = sum(
        1 for _ in corpus_dir.iterdir()) if corpus_dir.is_dir() else 0
    print(f"::group::{h}", flush=True)
    try:
      sys.stdout.write(log_path.read_text(errors="replace"))
    except OSError as e:
      print(f"(failed to read log: {e})")
    print(f"\nCorpus: {n_corpus} files (exit={proc.returncode})", flush=True)
    print("::endgroup::", flush=True)

  return rc


if __name__ == "__main__":
  sys.exit(main())
