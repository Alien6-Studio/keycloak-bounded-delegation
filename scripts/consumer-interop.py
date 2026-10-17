"""Run optional consumer interoperability using the exact pinned Hanko harness."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "github.com/Alien6-Studio/hankoshell-operator/internal/controller"


def identity(directory):
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=directory, text=True, timeout=10).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=directory, text=True, timeout=10).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", revision) or dirty:
        raise ValueError("Qualification requires clean committed source checkouts")
    return revision


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keycloak-version", required=True)
    parser.add_argument("--harness", type=Path, required=True)
    args = parser.parse_args()
    contract = json.loads((ROOT / "compatibility.json").read_text())
    if args.keycloak_version not in contract["keycloak"]:
        raise ValueError("Unqualified Keycloak version")
    expected = contract["integrations"]["hanko"]
    source, revision = identity(ROOT), identity(args.harness)
    if revision != expected["revision"]:
        raise ValueError("Use the exact reviewed qualification harness")
    target = ROOT / "target" / args.keycloak_version
    # Remove stale reports and classes before building this exact clean revision.
    if target.exists():
        shutil.rmtree(target)
    repository = os.environ.get("MAVEN_REPO_LOCAL", str(ROOT / ".tools/maven"))
    subprocess.run([str(ROOT / "mvnw"), "-B", "-ntp", "-Dkeycloak.version=" + args.keycloak_version,
                    "-Dmaven.repo.local=" + repository, "verify"], cwd=ROOT, timeout=600, check=True)
    java = []
    for path in sorted((target / "surefire-reports").glob("TEST-*.xml")):
        suite = ET.parse(path).getroot()
        if suite.tag != "testsuite" or any(int(suite.get(key, "0")) for key in ("failures", "errors", "skipped")):
            raise ValueError("Java qualification requires all tests to pass without skips")
        java += [case.get("classname", "") + "/" + case.get("name", "") for case in suite.findall("testcase")]
    if len(java) < 15 or len(java) != len(set(java)):
        raise ValueError("Missing or duplicate Java test evidence")
    jar = target / ("bounded-delegation-keycloak-" + args.keycloak_version + ".jar")
    if not jar.is_file() or not 0 < jar.stat().st_size < 5 * 1024 * 1024:
        raise ValueError("Missing matching SDK artifact")
    digest = hashlib.sha256(jar.read_bytes()).hexdigest()
    output = target / "interop"
    output.mkdir()
    env = {**os.environ, "KEYCLOAK_VERSION": args.keycloak_version, "KEYCLOAK_EXTENSION_JAR": str(jar)}
    with (output / "go.jsonl").open("w") as stream:
        process = subprocess.run(["go", "test", "-json", "-tags=keycloak_integration,keycloak_extension_integration", "-race", "-count=1",
            "-timeout=8m", "-run=^" + expected["root"] + "$", "./internal/controller"], cwd=args.harness, env=env, stdout=stream, timeout=600, check=False)
    log = output / "go.jsonl"
    if log.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("Interoperability report exceeds its size budget")
    rows = [json.loads(line) for line in log.read_text().splitlines()]
    outcomes = [row for row in rows if row.get("Action") in ("pass", "fail", "skip") and row.get("Test")]
    names = [row["Test"] for row in outcomes]
    packages = [row for row in rows if row.get("Action") in ("pass", "fail", "skip") and not row.get("Test")]
    unchanged = (identity(ROOT) == source and identity(args.harness) == revision
                 and hashlib.sha256(jar.read_bytes()).hexdigest() == digest)
    complete = (process.returncode == 0 and unchanged and len(names) == len(set(names))
                and sorted(names) == expected["tests"]
                and all(row["Action"] == "pass" and row.get("Package") == PACKAGE for row in outcomes)
                and len(packages) == 1 and packages[0]["Action"] == "pass" and packages[0].get("Package") == PACKAGE)
    (output / "results.json").write_text(json.dumps({"schema": 1, "complete": complete,
        "extension_revision": source, "worktree_dirty": False, "source_unchanged": unchanged,
        "harness_revision": revision, "keycloak": args.keycloak_version, "jar_sha256": digest,
        "java_tests": java, "tests": [{"name": row["Test"], "result": row["Action"]} for row in outcomes]}, indent=2) + "\n")
    print("Native interoperability: " + ("PASS" if complete else "FAIL") + " (" + str(len(outcomes)) + " tests)")
    return 0 if complete else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.SubprocessError, ET.ParseError) as error:
        print("Qualification failed: " + type(error).__name__, file=sys.stderr)
        raise SystemExit(1) from error
