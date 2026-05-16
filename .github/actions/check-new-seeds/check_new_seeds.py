# This file ships into oss-fuzz review-repo PRs via the check-new-seeds
# composite action; oss-fuzz's `infra/presubmit.py` check_license greps every
# Python file under non-projects/ paths for the Apache 2.0 LICENSE-2.0 URL,
# so we carry the standard header here even though it's our own infra code.
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
"""Verify newly-added fuzz seeds aren't redundant given the baseline corpus.

For each harness whose seed dir got new files in this PR, run libfuzzer's
`-merge=1` over (baseline + new) and check every new seed survived. A seed
is redundant if any of:
  - its content already exists in baseline (exact duplicate of preexisting),
  - its content matches another newly-added seed (dup within the PR),
  - libfuzzer's merge dropped it (covers no new edges beyond what's loaded).

Hard-fails (exit 1) with a per-seed reason and a copy-paste reproducer.

Inputs (env vars):
  PROJECT     project name (used for OUT_BASE/<project>/<harness>)
  BASE_SHA    git SHA to diff against (typically merge-base with main/master)
  OUT_BASE    dir containing built harness binaries
              (e.g. build/out for oss-fuzz, /tmp/oss-fuzz/build/out for upstream)
  SEEDS_DIR   workspace-relative seeds root, grouped by harness
              (e.g. projects/<name>/seeds for oss-fuzz, .github/fuzz/seeds for upstream)
  BASE_RUNNER (optional) override base-runner image, default
              gcr.io/oss-fuzz-base/base-runner
"""

import hashlib
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict

DEFAULT_BASE_RUNNER = "gcr.io/oss-fuzz-base/base-runner"


def file_sha(p: pathlib.Path) -> str:
  return hashlib.sha1(p.read_bytes()).hexdigest()


def hashes_in(d: pathlib.Path) -> set[str]:
  return {file_sha(p) for p in d.iterdir() if p.is_file()}


def added_paths(base_sha: str, prefix: str) -> list[str]:
  """Files added in commits between base_sha and HEAD, restricted to prefix/."""
  result = subprocess.run(
      [
          "git",
          "diff",
          "--name-only",
          "--diff-filter=A",
          f"{base_sha}...HEAD",
          "--",
          prefix,
      ],
      capture_output=True,
      text=True,
      check=True,
  )
  return [line for line in result.stdout.splitlines() if line]


def group_by_harness(paths: list[str], seeds_dir: str) -> dict[str, list[str]]:
  """Group seed paths by their harness subdir.

  e.g. projects/foo/seeds/parser/a.in -> {"parser": ["projects/foo/seeds/parser/a.in"]}
  """
  prefix = seeds_dir.rstrip("/") + "/"
  groups: dict[str, list[str]] = defaultdict(list)
  for p in paths:
    if not p.startswith(prefix):
      continue
    rest = p[len(prefix):]
    parts = rest.split("/", 1)
    if len(parts) != 2:  # seed file directly under seeds/, no harness subdir
      continue
    groups[parts[0]].append(p)
  return groups


def docker_merge(
    image: str,
    out_dir: pathlib.Path,
    harness: str,
    minimized: pathlib.Path,
    baseline: pathlib.Path,
    new: pathlib.Path,
) -> subprocess.CompletedProcess:
  """Run `<harness> -merge=1 /minimized /baseline /new` inside the base-runner."""
  cmd = [
      "docker",
      "run",
      "--rm",
      "--privileged",
      "-e",
      "FUZZING_ENGINE=libfuzzer",
      "-e",
      "SANITIZER=address",
      "-e",
      "ARCHITECTURE=x86_64",
      "-e",
      "OUT=/out",
      "-v",
      f"{out_dir.resolve()}:/out:ro",
      "-v",
      f"{baseline.resolve()}:/baseline:ro",
      "-v",
      f"{new.resolve()}:/new:ro",
      "-v",
      f"{minimized.resolve()}:/minimized",
      "--entrypoint",
      "/out/" + harness,
      image,
      "-merge=1",
      "/minimized",
      "/baseline",
      "/new",
  ]
  return subprocess.run(cmd, capture_output=True, text=True)


def check_harness(
    harness: str,
    out_dir: pathlib.Path,
    seeds_root: pathlib.Path,
    new_names: set[str],
    image: str,
    work_root: pathlib.Path,
) -> tuple[list[tuple[str, str]], str]:
  """Returns (redundant_seeds, debug_log).

  redundant_seeds: list of (filename, reason) for each redundant new seed.
  debug_log: stdout+stderr of the merge run (always returned for diagnostics).
  """
  harness_seeds = seeds_root / harness
  if not harness_seeds.is_dir():
    return [], f"{harness}: seeds dir {harness_seeds} missing — skipping"

  binary = out_dir / harness
  if not binary.is_file():
    return [], (
        f"{harness}: harness binary not built ({binary} missing) — skipping. "
        "If this is unexpected, check the build_fuzzers step.")

  work = work_root / harness
  baseline = work / "baseline"
  new = work / "new"
  minimized = work / "minimized"
  for d in (baseline, new, minimized):
    d.mkdir(parents=True, exist_ok=True)

  for f in harness_seeds.iterdir():
    if not f.is_file():
      continue
    dst = (new if f.name in new_names else baseline) / f.name
    shutil.copyfile(f, dst)

  baseline_hashes = hashes_in(baseline)

  proc = docker_merge(image, out_dir, harness, minimized, baseline, new)
  log = (
      f"$ {' '.join(['<harness>', '-merge=1', '/minimized', '/baseline', '/new'])}\n"
      f"--- exit {proc.returncode} ---\n"
      f"--- stdout ---\n{proc.stdout}\n"
      f"--- stderr ---\n{proc.stderr}")
  if proc.returncode != 0:
    return [(harness, f"libfuzzer merge failed (exit {proc.returncode})")], log

  minimized_hashes = hashes_in(minimized)

  redundant: list[tuple[str, str]] = []
  seen_in_new: set[str] = set()
  for src in sorted(new.iterdir()):
    h = file_sha(src)
    if h in baseline_hashes:
      redundant.append((src.name, "duplicate of an existing baseline seed"))
    elif h in seen_in_new:
      redundant.append((src.name, "duplicate of another newly-added seed"))
    elif h not in minimized_hashes:
      redundant.append(
          (src.name, "covers no new edges beyond baseline + earlier new seeds"))
    else:
      seen_in_new.add(h)

  return redundant, log


def _emit(line: str = ""):
  print(line, flush=True)


def report_failure(
    findings: list[tuple[str, list[tuple[str, str]], str]],
    seeds_dir: str,
    out_base: str,
    project: str,
):
  """Print a GH-Actions error block + per-harness fix instructions."""
  total = sum(len(rs) for _, rs, _ in findings)
  _emit(f"::error::{total} redundant new seed(s) — see details below.")
  _emit()
  _emit("=" * 70)
  _emit("Redundant new seeds detected")
  _emit("=" * 70)
  _emit()
  _emit("libfuzzer's -merge=1 keeps only inputs that add new code coverage. "
        "Each seed below either duplicated an existing seed or covered nothing "
        "new on top of the corpus loaded before it.")
  _emit()
  for harness, redundant, log in findings:
    _emit(f"### {harness}")
    for name, reason in redundant:
      _emit(f"  - {seeds_dir}/{harness}/{name}")
      _emit(f"    -> {reason}")
    _emit()
    _emit("  merge log (last 20 lines of stderr):")
    tail = "\n".join(log.splitlines()[-20:])
    for line in tail.splitlines():
      _emit(f"    | {line}")
    _emit()
  _emit("=" * 70)
  _emit("How to make CI go green")
  _emit("=" * 70)
  _emit()
  _emit("Pick one per redundant file:")
  _emit("  (a) Delete the file from the PR.")
  _emit("  (b) Replace its content with input that exercises a new code path")
  _emit("      (different parser branch, new field, edge value, etc.).")
  _emit()
  _emit("To reproduce locally on a built project:")
  _emit(f"  cd {out_base}/{project}")
  _emit("  mkdir -p baseline new minimized")
  _emit(
      "  # populate baseline/ with preexisting seeds, new/ with the added ones")
  _emit("  ./<harness> -merge=1 minimized/ baseline/ new/")
  _emit(
      "  # any seed in new/ whose content-hash is not in minimized/ is redundant."
  )


def main() -> int:
  project = os.environ["PROJECT"]
  base_sha = os.environ["BASE_SHA"]
  out_base = os.environ["OUT_BASE"]
  seeds_dir = os.environ["SEEDS_DIR"]
  image = os.environ.get("BASE_RUNNER", DEFAULT_BASE_RUNNER)

  added = added_paths(base_sha, seeds_dir)
  if not added:
    _emit(f"No new seed files under {seeds_dir} in this PR — skipping check.")
    return 0

  groups = group_by_harness(added, seeds_dir)
  if not groups:
    _emit(f"Seeds added under {seeds_dir} but none in a per-harness subdir — "
          "skipping. (Expected layout: <seeds_dir>/<harness>/<file>.)")
    return 0

  out_dir = pathlib.Path(out_base) / project
  seeds_root = pathlib.Path(seeds_dir)

  findings: list[tuple[str, list[tuple[str, str]], str]] = []
  with tempfile.TemporaryDirectory() as tmp:
    tmp_root = pathlib.Path(tmp)
    for harness, paths in sorted(groups.items()):
      new_names = {pathlib.Path(p).name for p in paths}
      _emit(f"::group::Verify new seeds: {harness} ({len(new_names)} new)")
      redundant, log = check_harness(harness, out_dir, seeds_root, new_names,
                                     image, tmp_root)
      if redundant:
        findings.append((harness, redundant, log))
        _emit(f"  -> {len(redundant)} redundant")
      else:
        _emit("  -> all new seeds non-redundant")
      _emit("::endgroup::")

  if findings:
    report_failure(findings, seeds_dir, out_base, project)
    return 1

  _emit("All new seeds are non-redundant.")
  return 0


if __name__ == "__main__":
  sys.exit(main())
