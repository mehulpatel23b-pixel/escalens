# Contributing

The value of `escalens` is its rule catalog. Contributions are welcome, especially new escalation primitives.

## Adding a rule

1. Open `src/escalens/rules.py`.
2. Append a `Rule` to `CATALOG`. Every rule needs:
   - a unique `id` (`ESC-` for escalation chains, `BRD-` for breadth, `ADM-` for effective admin)
   - a `title` that names the permission and the outcome
   - `severity` in `critical | high | medium | low`
   - `requires`: a tuple of AND-ed clauses, each clause a tuple of OR-ed action patterns
   - `impact`: what an attacker gains, in plain language
   - `remediation`: the specific control that removes the risk
   - `category` and, where it applies, `mitre`
   - `reference` to public research or AWS documentation
   - `needs_broad_resource=True` if the rule should only fire on `Resource: "*"` grants
3. Add a test in `tests/test_engine.py` proving it fires on the required combination and does **not** fire when only one clause is present.
4. Run `python -m unittest discover -s tests -t .`

The suite includes `test_every_rule_is_reachable`, which fails if a rule can never be matched. That guard exists to keep the catalog from drifting into decoration.

## Rules we will not merge

- Anything requiring a live API call, credentials, or network access.
- Anything that performs exploitation rather than detection.
- Rules with no remediation. A finding a reader cannot act on is noise.
- Rules keyed to one organization's naming. Use permission combinations, not role names.

## Code style

Standard library only. No new dependencies: the zero-dependency property is the point. Python 3.9+ compatible, `from __future__ import annotations`, type hints on public functions, docstrings that explain *why*.
