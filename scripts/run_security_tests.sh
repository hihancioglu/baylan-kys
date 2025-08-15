#!/bin/bash
# Run security scanners and generate reports.
set -e

# Bandit: Python static analysis
if command -v bandit >/dev/null 2>&1; then
  bandit -r portal -f json -o bandit-report.json
else
  echo "bandit not installed" >&2
fi

# OWASP ZAP baseline scan
if command -v zap-baseline.py >/dev/null 2>&1; then
  zap-baseline.py -t http://localhost:8090 -r zap-report.html || true
else
  echo "OWASP ZAP baseline not installed" >&2
fi

# Lighthouse audit
if command -v lighthouse >/dev/null 2>&1; then
  lighthouse http://localhost:8090 --output html --output-path lighthouse-report.html || true
else
  echo "Lighthouse not installed" >&2
fi
