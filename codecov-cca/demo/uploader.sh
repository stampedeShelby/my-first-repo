#!/usr/bin/env bash
# Simplified stand-in for the Codecov Bash Uploader (legitimate version).
# It collects a coverage report and "uploads" it using CODECOV_TOKEN.
echo "Codecov uploader v1.4.0"
echo "Found coverage report: coverage.xml"
if [ -n "$CODECOV_TOKEN" ]; then
  echo "Uploading coverage for commit ${GITHUB_SHA:-local} ... done"
else
  echo "No CODECOV_TOKEN set, skipping upload"
fi
