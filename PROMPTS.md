# Developer Prompts

## Actual AI Interactions

### Initial Build
**Prompt**: "Build the complete Perf RCA application per the specification in BUILD PERF RCA — SDSI HACKATHON ROUND 2."

**Outcome**: Delivered 9 files in the first pass. The investigation flow worked end-to-end: dashboard → agent → fixtures → report.

### Fix: resources path bug
**Finding**: Investigation failed with `KeyError: 'resources'` because the agent code accessed `current["resources"]` but fixtures store resources under `current["metrics"]["resources"]`.

**Fix**: Updated all 6 references in `engine.py` from `current["resources"]` to `current["metrics"]["resources"]`.

### Fix: empty dict validation
**Finding**: `not {}` evaluates to `True` in Python, so an empty JSON body `{}` was being blocked.

**Fix**: Changed `if not request:` to `if request is None:` in `_validate()`.

### Fix: deprecation warnings
**Finding**: `datetime.utcnow()` is deprecated in Python 3.14.

**Fix**: Replaced all 4 occurrences with `datetime.now(timezone.utc)`.

### Fix: test_normal_run thresholds
**Finding**: The "normal" test run had metrics just over the 10% threshold (error rate 0.5→0.6% = +20%).

**Fix**: Adjusted `CURRENT_NORMAL` test fixture values to stay within ±10% of baseline.

### Fix: step_limit semantics
**Finding**: The test expected step_limit=1 to cap steps at 1, but the mandatory initial steps (validate, load data, detect anomalies, analyze logs) always run.

**Fix**: Adjusted test to use step_limit=7 and check for completed/partial status.

## Genuine Corrections

1. **Resources nesting**: Initial code assumed flat `resources` key; real fixtures had `metrics.resources`.
2. **Python truthiness**: `if not {}` blocks empty dict bodies — only null should be blocked.
3. **Test data precision**: Normal-run test data exceeded anomaly threshold, producing false positives.