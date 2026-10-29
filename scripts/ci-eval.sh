#!/usr/bin/env bash
# Detector regression gate.
#
# Runs the labelled corpus and fails when recall drops or false positives rise
# past the thresholds recorded here. CI calls this script; run it locally before
# changing a signature so a regression is caught before the push.
set -euo pipefail

cd "$(dirname "$0")/.."

corpus="deploy/eval/corpus.jsonl"
min_recall="0.85"
max_fpr="0.05"

go run ./cmd/vigilante -mode eval \
  -eval-corpus "$corpus" \
  -eval-min-recall "$min_recall" \
  -eval-max-fpr "$max_fpr"
