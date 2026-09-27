#!/usr/bin/env bash
# Two-pass build of the final report: find chapter pages, then fill the contents page numbers.
# Needs LibreOffice (soffice; override with $SOFFICE) and pdftotext.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="$HERE/../../final"
NAME=INS_CCA_Report_Codecov_Supply_Chain
python3 "$HERE/build_final_report.py" >/dev/null
TMP="$(mktemp -d)"
cp "$OUTDIR/$NAME.docx" "$TMP/r.docx"
(cd "$TMP" && ${SOFFICE:-soffice} --headless --convert-to pdf r.docx >/dev/null 2>&1)
PAGES=$(python3 - "$TMP/r.pdf" <<'PY'
import re, subprocess, sys
pages = subprocess.run(["pdftotext", "-layout", sys.argv[1], "-"], capture_output=True, text=True).stdout.split("\f")
first = next(i for i, p in enumerate(pages) if re.search(r"CHAPTER 1\s*\n", p))
found = {}
for i, p in enumerate(pages):
    m = re.search(r"CHAPTER (\d+)\s*\n", p)
    if m:
        found.setdefault(int(m.group(1)), i - first + 1)
print(",".join(str(found[k]) for k in range(1, 11)))
PY
)
echo "chapter pages: $PAGES"
python3 "$HERE/build_final_report.py" --pages "$PAGES"
cp "$OUTDIR/$NAME.docx" "$TMP/final.docx"
(cd "$TMP" && ${SOFFICE:-soffice} --headless --convert-to pdf final.docx >/dev/null 2>&1)
cp "$TMP/final.pdf" "$OUTDIR/$NAME.pdf"
echo "wrote $OUTDIR/$NAME.pdf"
