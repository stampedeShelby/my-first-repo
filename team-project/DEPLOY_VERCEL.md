# Deploying the dashboard to Vercel

The deployable part of this project is the Flask dashboard (`dashboard/app.py`). On Vercel it runs as a
Python serverless function (`api/index.py`). It shows the audit log and the key revocation list, and its
**Verify Legitimate Artifact** button runs the real verifier (`verifier/verify.py`) against
`artifacts/uploader.sh` on every click.

The command-line tools (`demo.py`, `tests/`, `attack_simulation/`, `ci/security_gate.py`) are not
websites. Run them locally as before.

## Option A: import from GitHub (no command line)

1. Go to vercel.com, sign in with GitHub, choose **Add New… → Project**, and import `stampedeShelby/my-first-repo`.
2. Set **Root Directory** to `team-project`, and leave Framework Preset as **Other**.
3. Click **Deploy**. Vercel builds from the repository's production branch (`main` by default), so this
   folder must be on `main` first. Either merge the branch that contains it, or change
   *Settings → Git → Production Branch* to that branch.

## Option B: Vercel CLI from your laptop

```bash
git clone -b claude/lucid-cannon-t65pq3 https://github.com/stampedeShelby/my-first-repo
cd my-first-repo/team-project
npx vercel          # log in, accept the defaults -> preview URL
npx vercel --prod   # production URL
```

## What was changed for Vercel

| File | Why |
|---|---|
| `api/index.py` | Vercel entry point. Copies the audit DB to `/tmp` (the only writable path) and exposes the Flask `app` |
| `audit/audit_logger.py` | `DEFAULT_DB_PATH` honours the `AUDIT_DB_PATH` environment variable; local behaviour is unchanged |
| `vercel.json` | Routes every URL to the Flask function; static output is limited to `public/` |
| `.vercelignore`, `.gitignore` | Private keys (`*_priv.pem`), caches and backups are never uploaded or committed |

**Private keys are not in this folder.** The dashboard only needs public keys and the revocation list.
To run `demo.py` or the tests locally, use your original project folder, or generate keys with
`python vendor/key_manager.py` (the test suite creates any missing keys itself).

Events logged by the live Verify button live in `/tmp` on that function instance, so they reset when
Vercel starts a new one. The bundled history from the team's runs is always shown.
