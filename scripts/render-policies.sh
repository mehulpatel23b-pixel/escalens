#!/usr/bin/env bash
# Render the IAM policies touched by the current diff into one JSON file for escalens.
# Usage: ./scripts/render-policies.sh [base-ref]   (default: origin/main)
set -euo pipefail

BASE="${1:-origin/main}"

mapfile -t files < <(git diff --name-only "$BASE"...HEAD -- '*.json' | grep -E '(policy|iam|role)' || true)

if [ ${#files[@]} -eq 0 ]; then
  echo "no IAM policy files changed since $BASE" >&2
  exit 0
fi

echo "{" > /tmp/escalens-bundle.json
first=1
for f in "${files[@]}"; do
  [ -f "$f" ] || continue
  if [ $first -eq 0 ]; then echo "," >> /tmp/escalens-bundle.json; fi
  first=0
  printf '"%s": %s' "$f" "$(cat "$f")" >> /tmp/escalens-bundle.json
done
echo "}" >> /tmp/escalens-bundle.json

# escalens reads one policy per file; a directory of copies is the simplest bundle.
tmpdir="$(mktemp -d)"
for f in "${files[@]}"; do
  [ -f "$f" ] || continue
  cp "$f" "$tmpdir/$(echo "$f" | tr '/' '_')"
done
echo "$tmpdir"
