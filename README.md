# otto-release-signer

Signs Otto releases for Performance Architects' clients (Otto roadmap item 45). Nothing else lives here: no Otto code, no client data.

**Why a separate public repository.** Each client release is signed only after the release approver approves the signing job in the GitHub app. That needs an environment with a required reviewer, which GitHub's Team plan offers on public repositories only. The private key is the secret `OTTO_RELEASE_SIGNING_KEY` of the environment `release-signer`: its only required reviewer is the approver, administrators cannot bypass it, and only `main` may use it. Secrets of a public repository never reach forks or pull requests.

**What is signed.** `sign.py` builds the statement from three checked fields (version, commit, date) with `release_sig.statement`, the exact text Otto and every client account verify; anything else is refused. The run's name shows the version and commit, so the approval screen does too. The signature is public data: it goes to the job summary and an artifact, and from there into Otto's release channel record, which checks it again (against Otto's `releases/allowed_signers`, and that the release tag points at the signed commit) before writing it.

**Files.** `sign.py` (the signer), `release_sig.py` (a copy of Otto's `scripts/release_sig.py`), `allowed_signers` (the public key), `.github/workflows/sign.yml` (the approval-gated job), `tests/`.

**Sign a release** (Otto's `scripts/release_sign.py --step request` does this and hands the signature to the channel):

```
gh workflow run sign.yml --repo Performance-Architects-Inc/otto-release-signer --ref main -f version=1.2.3 -f commit=<40-char> -f date=YYYY-MM-DD
```

then approve the run in the GitHub app.
