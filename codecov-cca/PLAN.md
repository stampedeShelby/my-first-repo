# CCA Plan: Codecov 2021 → SignGate

**Deadline:** 28-09-2026 · **Submit:** PDF report + PPT · **Marks:** 20

## The story in one line
> An attacker modified a trusted CI tool (Codecov Bash Uploader) using a leaked key. SignGate makes
> CI verify the tool cryptographically *before* running it, and run it with only the secrets it needs.

## How each deliverable maps to the rubric

| Rubric (marks) | Where it is covered | Report section | Slides |
|---|---|---|---|
| Problem Understanding & Requirements (3) | Incident context, CIA violated, V1–V6, objectives, FR/SR | 1, 3, 4 | 3–7 |
| **Design & Implementation (9)** | Architecture, crypto table, manifest, key hierarchy + lifecycle, transparency log, 6-check gate, working Python code | 5 | 8–12 |
| Security Analysis & Testing (2) | Original attack vector, STRIDE, attacker-capability table, 7 attack scenarios, assume-breach, timing | 6, 7 | 13–15 |
| Innovation & Relevance (2) | Standard fix vs SignGate, SLSA / NIST SSDF / EO 14028, cost, feasibility | 8 | 16 |
| Documentation & Presentation (4) | College templates, 8 figures, 12 tables, 19 IEEE refs, speaker notes | all | all |

## Files
- `docs/INS_CCA_Report_Codecov_SignGate.docx` / `.pdf`: report on the college template (cover, evaluation sheet, contents with page numbers)
- `docs/INS_CCA_Slides_Codecov_SignGate.pptx`: 19 slides on the BCS701 template, **speaker notes on every slide**
- `signgate/`, `demo/`, `tests/`: the working prototype (show it live if asked)
- `docs/src/`: scripts that rebuild figures, report and slides from the templates

## What YOU still need to do
1. **Names & USNs**: fill the NAME/USN table on the report cover page, and replace
   `<Student Name 1> – <USN>` on slide 1.
2. Check your case study is not taken by another team (first-come rule).
3. Read the report once and change a few sentences into your own words (plagiarism checks apply).
4. Rehearse with the speaker notes. Run the demo once on your laptop:
   `pip install cryptography && python demo/attack_demo.py`
5. Export the final PDF from Word after your edits (File → Save As → PDF).

## 6-minute talk split (from speaker notes)
| Time | Slides | Who (suggested) |
|---|---|---|
| 0:00–1:30 | 1–5 Title, abstract, incident, problem | Member 1 |
| 1:30–2:15 | 6–8 Objectives, requirements, methodology | Member 1 |
| 2:15–4:30 | 9–12 Architecture, crypto, keys, implementation | Member 2 |
| 4:30–5:45 | 13–16 Security analysis, results, demo, innovation | Member 3 |
| 5:45–6:30 | 17–19 Conclusion, references, Q&A | Member 3 |

## Likely viva questions (short answers)
- **Why not just publish a SHA-256?** Whoever can change the file can change the hash. A signature needs the private key.
- **Why Ed25519 over RSA?** ~128-bit security, 64-byte signatures, fast, deterministic (no nonce bugs).
- **What if the release key is stolen?** Unlogged release → rejected (check 6). Logged → monitor alerts → root-signed CRL → rejected (check 2).
- **What if the root key is stolen?** It is offline in an HSM with a two-person rule. Rotating it means customers update the pinned key (rare).
- **What doesn't it stop?** A compromised build server signing malware (SolarWinds-style). The log makes it visible; SLSA provenance is future work.
- **Which CIA property?** Integrity and authentication failed first. Confidentiality was lost as a consequence.
