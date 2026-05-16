# This file ships into oss-fuzz review-repo PRs via the post-fuzz-report
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
"""Render before/after coverage comparison as a sticky PR comment body.

Reads artifacts downloaded by the calling workflow:
  stats/baseline/meta.json, project.summary.json, corpus.json, harness/*.summary.json
  stats/current/ ... (same layout)

Writes the markdown body to stdout.
"""

import datetime
import json
import os
import pathlib
import sys

try:
  # In-tree (tests, host package).
  from fuzz_for_me.ci import cov
except ImportError:  # pragma: no cover - only the shipped bare-CI layout
  # Shipped standalone next to this file in the composite action; exercised
  # end-to-end by TestShippedStandalone via a subprocess.
  import cov  # ty: ignore[unresolved-import]

MARKER = "<!-- fuzz-coverage-report -->"

# Δ is computed on covered counts (not percent points) so the same metric is
# meaningful when the denominator changes — e.g. when new code lands the
# instrumented line count grows, so comparing raw percentages understates real
# coverage gains. "new" / "deleted" cover the divide-by-zero edges.
FOOTER_DELTA_NOTE = (
    "<sub>Δ = (after − before) / before, to accommodate that denominators "
    'may change. "new" when before is 0; "deleted" when after is 0.</sub>')
FOOTER_GENERIC = FOOTER_DELTA_NOTE
FOOTER_UPSTREAM = ("<sub>Same harness config applied to both sides "
                   "(baseline = base source + PR harness).</sub>\n" +
                   FOOTER_DELTA_NOTE)


def _load_json(path: pathlib.Path):
  if not path.exists():
    return None
  try:
    return json.loads(path.read_text())
  except json.JSONDecodeError:
    return None


def _load_variant(base: pathlib.Path) -> dict:
  harness: dict = {}
  hd = base / "harness"
  if hd.is_dir():
    for f in sorted(hd.glob("*.summary.json")):
      data = _load_json(f)
      if data is not None:
        harness[f.name.removesuffix(".summary.json")] = data
  return {
      "meta": _load_json(base / "meta.json"),
      "project": _load_json(base / "project.summary.json"),
      "harness": harness,
      "reachability": _load_json(base / "reachability.json"),
  }


def _totals(summary):
  """Harness-excluded coverage totals from an llvm-cov ``summary.json``."""
  return cov.coverage_totals(summary)


def _reach_totals(functions):
  """Harness-excluded static reachability from the introspector per-function
  list (``all-fuzz-introspector-functions.json``, carried by the
  reachability.json artifact). ``None`` when no data is available."""
  return cov.reach_totals(functions)


def _fmt_cov(tot, key):
  if not tot:
    return "0%"
  cov, n, pct = tot[key]
  return f"{pct:.1f}% ({cov}/{n})"


def _fmt_delta(b, a, key, c_has=True):
  if not b and not a:
    return "—"
  if not a:
    # Baseline has data, current doesn't.
    return "**removed**" if c_has else "**build failed**"
  cov_a = a[key][0]
  cov_b = b[key][0] if b else 0
  if cov_b == 0 and cov_a == 0:
    return "—"
  if cov_b == 0:
    return "**new**"
  if cov_a == 0:
    return "**deleted**"
  d = (cov_a - cov_b) / cov_b * 100
  sign = "+" if d >= 0 else ""
  return f"**{sign}{d:.1f}%**"


def _fmt_reach_cell(reach, variant_has, run_url):
  """Format a reachability value cell.

  ``FAIL`` (linked to the workflow run) when the variant ran but introspector
  produced no summary; ``0%`` when the variant didn't run at all (matching
  the coverage-row convention).
  """
  if reach:
    return _fmt_cov(reach, "reach")
  if variant_has:
    return f"[FAIL]({run_url})"
  return "0%"


def _fmt_reach_delta(br, cr):
  """Delta for the reachability row. Like ``_fmt_delta`` but treats a missing
  variant as a build failure (``continue-on-error: true``) rather than a
  removed metric — there is no "remove static reachability" intent."""
  if not br and not cr:
    return "—"
  if not br:
    d = cr["reach"][2]
    return f"**+{d:.1f}%**"
  if not cr:
    return "**build failed**"
  d = cr["reach"][2] - br["reach"][2]
  sign = "+" if d >= 0 else ""
  return f"**{sign}{d:.1f}%**"


def render(
    stats_root: pathlib.Path,
    run_url: str,
    fuzz_seconds: str,
    now_utc: str,
    footer: str,
) -> str:
  b = _load_variant(stats_root / "baseline")
  c = _load_variant(stats_root / "current")

  b_meta = b["meta"] or {}
  c_meta = c["meta"] or {}
  b_sha_full = b_meta.get("sha") or ""
  c_sha_full = c_meta.get("sha") or ""
  b_sha = b_sha_full[:7] if b_sha_full else "unknown"
  c_sha = c_sha_full[:7] if c_sha_full else "unknown"
  project = c_meta.get("project") or b_meta.get("project") or "?"
  b_has = bool(b_meta.get("has_project"))
  c_has = bool(c_meta.get("has_project"))

  out = [MARKER, "", "## Fuzzing Coverage Report", ""]

  tested = f"**Tested:** project `{project}` · base `{b_sha}`"
  if not b_has:
    tested += (
        " _(no baseline — project not present at base or baseline build failed)_"
    )
  tested += f" → head `{c_sha}`"
  if not c_has:
    tested += " _(current measurement failed)_"
  tested += (f" · {fuzz_seconds}s total fuzz budget"
             f" · updated {now_utc}"
             f" · [workflow run]({run_url})")
  out += [tested, ""]

  bt = _totals(b["project"])
  ct = _totals(c["project"])
  br = _reach_totals(b["reachability"])
  cr = _reach_totals(c["reachability"])
  if b_has or c_has or bt or ct or br or cr:
    out += [
        "| Metric | Before | After | Delta |",
        "|---|---|---|---|",
        f"| Static reachability | {_fmt_reach_cell(br, b_has, run_url)} | "
        f"{_fmt_reach_cell(cr, c_has, run_url)} | "
        f"{_fmt_reach_delta(br, cr)} |",
    ]
    if bt or ct:
      out += [
          f"| Line coverage | {_fmt_cov(bt, 'lines')} | {_fmt_cov(ct, 'lines')} | {_fmt_delta(bt, ct, 'lines', c_has)} |",
          f"| Branch coverage | {_fmt_cov(bt, 'branches')} | {_fmt_cov(ct, 'branches')} | {_fmt_delta(bt, ct, 'branches', c_has)} |",
          f"| Function coverage | {_fmt_cov(bt, 'functions')} | {_fmt_cov(ct, 'functions')} | {_fmt_delta(bt, ct, 'functions', c_has)} |",
      ]
    out.append("")

  all_h = sorted(set(b["harness"].keys()) | set(c["harness"].keys()))
  if all_h:
    out += [
        "### Per-harness",
        "",
        "| Harness | Lines before | Lines after | Δ |",
        "|---|---|---|---|",
    ]
    for h in all_h:
      bh = _totals(b["harness"].get(h))
      ch = _totals(c["harness"].get(h))
      out.append(
          f"| `{h}` | {_fmt_cov(bh, 'lines')} | {_fmt_cov(ch, 'lines')} | "
          f"{_fmt_delta(bh, ch, 'lines', c_has)} |")
    out.append("")

  if not (b_has or c_has or bt or ct or all_h or br or cr):
    out += [
        "_No coverage data collected. Check the workflow run for build errors._",
        "",
    ]

  out.append(footer)
  return "\n".join(out)


def main():
  stats_root = pathlib.Path(os.environ.get("STATS_ROOT", "stats"))
  run_url = os.environ["RUN_URL"]
  fuzz_seconds = os.environ.get("FUZZ_SECONDS", "300")
  footer_kind = os.environ.get("FOOTER", "generic")
  now_utc = datetime.datetime.now(
      datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
  footer = FOOTER_UPSTREAM if footer_kind == "upstream" else FOOTER_GENERIC
  sys.stdout.write(render(stats_root, run_url, fuzz_seconds, now_utc, footer))
  sys.stdout.write("\n")


if __name__ == "__main__":
  main()
