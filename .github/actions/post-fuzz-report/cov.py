# This file ships into oss-fuzz review-repo PRs via the post-fuzz-report
# composite action (next to render_comment.py); oss-fuzz's
# `infra/presubmit.py` check_license greps every Python file under
# non-projects/ paths for the Apache 2.0 LICENSE-2.0 URL, so we carry the
# standard header here even though it's our own infra code.
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
"""Single source of truth for "project coverage".

Project coverage = the aggregate over in-scope source files, *excluding* the
fuzz harnesses. Harness bodies run on every input, so they're ~100% covered by
construction; counting them inflates the headline and is pure noise. llvm-cov's
precomputed ``data[0]["totals"]`` and Fuzz Introspector's
``MergedProjectProfile.stats`` are both harness-inclusive, so the headline must
be re-derived from the per-file / per-function lists instead of trusting those
free aggregates.

stdlib-only and dependency-free: this module ships standalone next to
``render_comment.py`` into bare CI, and is also imported in-tree by
``manager.py``.
"""

HARNESS_PREFIX = "/src/harnesses/"

_METRICS = ("lines", "branches", "functions")


def _triple(covered, count):
  return (covered, count, (100.0 * covered / count) if count else 0.0)


def coverage_totals(summary):
  """Harness-excluded totals from an llvm-cov export ``summary.json``.

    Sums the per-file ``summary`` blocks (``data[0]["files"]``) for files not
    under ``HARNESS_PREFIX``. Returns ``{metric: (covered, count, pct)}`` for
    lines/branches/functions, or ``None`` when no usable data is present.
    """
  if not summary:
    return None
  try:
    files = summary["data"][0]["files"]
  except (KeyError, IndexError, TypeError):
    return None
  acc = {m: [0, 0] for m in _METRICS}
  for f in files:
    if f["filename"].startswith(HARNESS_PREFIX):
      continue
    s = f["summary"]
    for m in _METRICS:
      sm = s.get(m)
      if sm:
        acc[m][0] += sm["covered"]
        acc[m][1] += sm["count"]
  return {m: _triple(*acc[m]) for m in _METRICS}


def reach_totals(functions):
  """Harness-excluded static reachability from Fuzz Introspector.

    ``functions`` is the parsed ``all-fuzz-introspector-functions.json`` list
    (``summary.json`` itself carries only the harness-inclusive scalar). Counts
    entries whose ``Functions filename`` is not under ``HARNESS_PREFIX``; an
    entry is "reached" when ``Combined reached by Fuzzers`` is non-empty.
    Returns ``{"reach": (reached, total, pct)}`` or ``None``.
    """
  if not functions:
    return None
  reached = total = 0
  for fn in functions:
    if fn["Functions filename"].startswith(HARNESS_PREFIX):
      continue
    total += 1
    if fn["Combined reached by Fuzzers"]:
      reached += 1
  return {"reach": _triple(reached, total)}
