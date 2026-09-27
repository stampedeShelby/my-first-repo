# INS (BCS701) CCA deliverables

## Final submission: `final/`

These describe **the team's submitted implementation** (`secure-supply-chain.zip`: `vendor/`, `verifier/`,
`ci/`, `audit/`, `dashboard/app.py`, `demo.py`, `tests/test_supply_chain.py`).

| File | What it is |
|---|---|
| `final/INS_CCA_Report_Codecov_Supply_Chain.docx` / `.pdf` | Report on the BMSIT format: cover, evaluation sheet, numbered contents, 10 chapters |
| `final/INS_CCA_Presentation_Codecov_Supply_Chain.pptx` | 17 slides on the BCS701 format, with speaker notes |
| `final/figures/` | Diagrams drawn from the submitted code, plus the dashboard screenshot |
| `final/revoked_key_test_fix.patch` | Fix: Scenario 3A in `attack_simulation/revoked_key_test.py` overwrote the genuine `uploader.sh.manifest.json` |

Rebuild: `python3 tools/final/make_figures.py && tools/final/make_final_report.sh && python3 tools/final/build_final_slides.py`

---

## Earlier draft (prototype built in this repository)

**Case study:** Codecov Bash Uploader supply-chain attack (2021)
**Title:** *Cryptographically Verified Software Supply Chain for Preventing
Codecov-Style Supply-Chain Attacks*
**Deadline:** 28-09-2026. Submit the PDF report and the PPT.

| File | What it is |
|---|---|
| `INS_CCA_Report_Codecov_Supply_Chain.docx` | The report, built on the institute's report format (cover, evaluation sheet, contents with page numbers, and 10 chapters) |
| `INS_CCA_Report_Codecov_Supply_Chain.pdf` | PDF export of the report, for submission |
| `INS_CCA_Presentation_Codecov_Supply_Chain.pptx` | 16-slide deck on the BCS701 PPT format, with speaker notes on every slide for a 5 to 7 minute talk |
| `templates/` | The original formats supplied with the assignment |
| `tools/` | Scripts that regenerate the report and deck from the prototype's results |

## Before you submit

1. **Report cover and evaluation sheet:** type the team members' names and
   USNs into the empty NAME/USN table rows. Then export to PDF again from Word
   (File → Save As → PDF). The contents page numbers stay the same.
2. **Slide 1:** replace `Name 1 (USN)  Name 2 (USN)  Name 3 (USN)` with your
   names and USNs, and delete the grey helper line below them.
3. Rehearse with the speaker notes (View → Notes). Slide 11 is the live demo:
   run `python demo.py` inside `secure-supply-chain/`.

## Regenerating

```bash
cd secure-supply-chain && python -m tests.generate_test_report && python docs/results/make_charts.py
cd ../deliverables/tools
./make_report.sh           # two passes: fills the contents page numbers, then writes the .docx and .pdf
python build_slides.py     # rebuilds the .pptx
```

This needs `python-docx`, `python-pptx`, LibreOffice (`soffice`) and
`pdftotext` (poppler).
