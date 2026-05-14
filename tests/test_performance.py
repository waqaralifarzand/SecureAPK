"""Phase 9 - performance benchmark.

PHASES.md acceptance criterion: a small APK completes Phases 2 + 3 (the
expensive static-analysis phases) within 60 seconds. If this fails on a
slow machine, we want the failure message to include the actual wall
time so the cause is actionable instead of mysterious.
"""
from __future__ import annotations

import time
import zipfile

from modules import manifest_analyzer, source_analyzer


MAX_SECONDS = 60.0


def test_phases_2_and_3_complete_within_60_seconds(tmp_path):
    apk = tmp_path / "bench.apk"
    # A modest synthetic APK: manifest stub + a classes.dex with enough
    # printable strings to exercise the regex catalog under the
    # dex_strings fallback (jadx isn't required to hit the time budget).
    payload = b""
    for i in range(2000):
        payload += (
            f"com.example.app{i}\x00"
            f"android.permission.READ_SMS\x00"
            f"AIzaSyB-{i:040d}\x00"
            "MessageDigest.getInstance(\"MD5\")\x00"
            "Log.d(\"auth\", \"password=hunter2\")\x00"
        ).encode("ascii")
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("AndroidManifest.xml", b"stub")
        z.writestr("classes.dex", payload)

    started = time.perf_counter()
    manifest = manifest_analyzer.analyze(str(apk))
    source = source_analyzer.analyze(str(apk))
    elapsed = time.perf_counter() - started

    # Print actual timing so a failure is actionable.
    print(f"\nBenchmark: Phase 2 + Phase 3 elapsed = {elapsed:.2f}s "
          f"(budget {MAX_SECONDS}s, payload ~{len(payload) // 1024} KiB)")

    assert elapsed < MAX_SECONDS, (
        f"Phase 2 + Phase 3 took {elapsed:.2f}s, exceeding the "
        f"{MAX_SECONDS}s budget. Investigate before tagging a release."
    )
    # And the phases actually produced something - guards against a
    # silent regression that "passes" by doing no work.
    assert manifest["parser_used"] in ("pyaxmlparser", "aapt", "dex_strings")
    assert source["decompiler_used"] in ("jadx", "dex_strings")
