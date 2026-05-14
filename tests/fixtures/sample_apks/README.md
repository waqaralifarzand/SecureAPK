# Sample APKs

This directory is the drop zone for **real APK fixtures** used in
manual smoke tests and (optionally) parser-integration tests.
**Binary APKs are not committed** — fetch them yourself.

## Recommended downloads

| APK | Purpose | Source |
|---|---|---|
| `diva-beta.apk` | Damn Insecure & Vulnerable App — covers most static-analysis findings. | https://github.com/payatu/diva-android |
| `insecureshop.apk` | InsecureShop — wider coverage including IPC and WebView issues. | https://github.com/hax0rgb/InsecureShop |
| `androgoat.apk` | AndroGoat — alternative vulnerable testbed. | https://github.com/satishpatnayak/AndroGoat |

## Where to put them

After downloading or building, drop the APK file directly into this
directory:

```
tests/fixtures/sample_apks/diva-beta.apk
```

The unit tests in `tests/test_manifest_analyzer.py` will pick them up
automatically when present and `pytest.skip` cleanly when absent.

## Manual smoke test

```bash
python app.py                       # in one shell
# in another, open http://127.0.0.1:5000 and upload e.g. diva-beta.apk
```

You should see in the Manifest tab:

- package name, app name, version, target/min SDK populated
- permissions list with danger badges
- exported components table with unprotected components flagged
- insecure flag values (debuggable, cleartext, backup, NSC)
- manifest findings with severity badges

## Important

**Do NOT commit APK binaries.** They are intentionally vulnerable and
some hosting platforms (and `git`) flag binary blobs in the repo as
problematic. Always re-download fresh from the upstream source.
