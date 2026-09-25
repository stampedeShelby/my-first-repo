#!/usr/bin/env bash
# Build the report twice: first to find chapter pages, then with page numbers in the contents list.
# Requires LibreOffice (soffice) and poppler-utils (pdftotext).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="$HERE/.."
python3 "$HERE/build_report.py" >/dev/null
TMP="$(mktemp -d)"
cp "$OUTDIR/INS_CCA_Report_Codecov_Supply_Chain.docx" "$TMP/r.docx"
(cd "$TMP" && ${SOFFICE:-soffice} --headless --convert-to pdf r.docx >/dev/null 2>&1)
PAGES=$(python3 - "$TMP/r.pdf" <<'PY'
import re, subprocess, sys
txt = subprocess.run(["pdftotext", "-layout", sys.argv[1], "-"], capture_output=True, text=True).stdout
pages = txt.split("\f")
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
python3 "$HERE/build_report.py" --pages "$PAGES"
(cd "$TMP" && cp "$OUTDIR/INS_CCA_Report_Codecov_Supply_Chain.docx" final.docx && ${SOFFICE:-soffice} --headless --convert-to pdf final.docx >/dev/null 2>&1)
cp "$TMP/final.pdf" "$OUTDIR/INS_CCA_Report_Codecov_Supply_Chain.pdf"
echo "wrote $OUTDIR/INS_CCA_Report_Codecov_Supply_Chain.pdf"
