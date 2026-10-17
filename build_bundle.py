"""Assemble portable runtime sources without historical folders or path rewriting."""
import hashlib
import json
from pathlib import Path

from portable_support import COMPATIBLE_LAYOUT_SHA256, LAYOUT_PROFILES, SUPPORTED_BUILDS

ROOT = Path(__file__).resolve().parent
SCRIPT_NAMES = (
    "capture_registration_state.py", "capture_ui_frontier.py",
    "chessshark_ui_helper_nofallback.py", "guard_late_failure.py",
    "guard_main_pointer.py", "inspect_live_objects.py",
    "launch_chessshark_with_scan_fix.py", "native_message_probe.py",
    "repair_scan_parameters.py", "run_external_hwtrace.py",
    "set_startup_gate.py", "watch_main_destructor.py",
)
SHARED_NAMES = ("portable_support.py", "pe_compatibility.py", "version_profiles.py")


def main():
    available = {path.name for path in (ROOT / "scripts").glob("*.py")}
    if available != set(SCRIPT_NAMES):
        raise RuntimeError("Runtime source list differs from the expected twelve scripts")
    destination = ROOT / "bundle" / "scripts"
    expected = set(SCRIPT_NAMES + SHARED_NAMES)
    if destination.exists() and any(path.name not in expected for path in destination.glob("*.py")):
        raise RuntimeError("Generated bundle contains unexpected scripts; inspect the bundle directory")
    sources = [ROOT / "scripts" / name for name in SCRIPT_NAMES]
    sources += [ROOT / name for name in SHARED_NAMES]
    contents = {}
    for source in sources:
        raw = source.read_bytes()
        compile(raw.decode("utf-8-sig"), source.name, "exec")
        contents[source.name] = raw
    destination.mkdir(parents=True, exist_ok=True)
    manifest = {
        "source": "scripts/ plus shared portable modules",
        "files": {},
        "compatible_code_layout_sha256": COMPATIBLE_LAYOUT_SHA256,
        "layout_profiles": LAYOUT_PROFILES,
        "supported_target_sha256": list(SUPPORTED_BUILDS),
        "compatibility_rule": "Known file or same non-resource section bytes and critical PE layout; retain runtime checks.",
    }
    for name, raw in sorted(contents.items()):
        (destination / name).write_bytes(raw)
        manifest["files"][name] = hashlib.sha256(raw).hexdigest()
    (ROOT / "bundle" / "bundle_manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"bundle": "bundle", "files": len(manifest["files"])}))


if __name__ == "__main__":
    main()
