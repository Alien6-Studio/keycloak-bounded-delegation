"""Qualify the extension with the official Keycloak framework, independently of consumers."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def identity():
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, timeout=10).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True, timeout=10).strip())
    return revision, dirty


def outcomes(directory):
    cases = []
    for path in sorted(directory.glob("TEST-*.xml")):
        if path.stat().st_size > 32 * 1024 * 1024:
            raise ValueError("Test report exceeds its size budget")
        data = path.read_text()
        if "<!DOCTYPE" in data.upper() or "<!ENTITY" in data.upper():
            raise ValueError("Unsupported report declaration")
        suite = ET.fromstring(data)
        if suite.tag != "testsuite" or any(int(suite.get(k, "0")) for k in ("failures", "errors", "skipped")):
            raise ValueError("All required tests must pass without skips")
        for case in suite.findall("testcase"):
            if any(case.find(k) is not None for k in ("failure", "error", "skipped")):
                raise ValueError("Failed or skipped required test")
            name = case.get("classname", "") + "/" + case.get("name", "")
            if not name.startswith("io.alien6.keycloak.delegation.") or not case.get("name"):
                raise ValueError("Unexpected test identity")
            cases.append(name)
    if not cases or len(cases) != len(set(cases)):
        raise ValueError("Missing or duplicate test inventory")
    return sorted(cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keycloak-version", required=True)
    parser.add_argument("--release-assets", action="store_true")
    parser.add_argument("--allow-dirty", action="store_true", help="local iteration only; output cannot be released")
    args = parser.parse_args()
    contract = json.loads((ROOT / "compatibility.json").read_text())
    if args.keycloak_version not in contract["keycloak"]:
        raise ValueError("Unqualified SDK")
    source = identity()
    if source[1] and not args.allow_dirty:
        raise ValueError("Commit source before qualification, or explicitly use --allow-dirty locally")
    target = ROOT / "target" / args.keycloak_version
    report = target / "qualification/results.json"
    report.unlink(missing_ok=True)
    profiles = "native-tests,release" if args.release_assets else "native-tests"
    repository = os.environ.get("MAVEN_REPO_LOCAL", str(ROOT / ".tools/maven"))
    env = {**os.environ, "MAVEN_USER_HOME": os.environ.get("MAVEN_USER_HOME", str(ROOT / ".tools/maven-user"))}
    result = subprocess.run([str(ROOT / "mvnw"), "-B", "-ntp", "-Dkeycloak.version=" + args.keycloak_version,
        "-Dmaven.repo.local=" + repository, "-P" + profiles, "clean", "verify"], cwd=ROOT, env=env, timeout=900, check=False)
    if result.returncode:
        return result.returncode
    unit = outcomes(target / "surefire-reports")
    native = outcomes(target / "failsafe-reports")
    expected = [contract["native"]["test_class"] + "/" + name for name in contract["native"]["tests"]]
    if len(unit) < contract["native"]["minimum_unit_tests"] or native != expected or identity() != source:
        raise ValueError("Test inventory drift or source changed during qualification")
    jar = target / ("bounded-delegation-keycloak-" + args.keycloak_version + ".jar")
    if not jar.is_file() or not 0 < jar.stat().st_size <= 5 * 1024 * 1024:
        raise ValueError("Missing or oversized provider JAR")
    report.parent.mkdir(exist_ok=True)
    report.write_text(json.dumps({"schema": 1, "complete": True, "revision": source[0], "worktree_dirty": source[1],
        "keycloak": args.keycloak_version, "contract": contract["contract"], "java_release": contract["java"],
        "jar_sha256": hashlib.sha256(jar.read_bytes()).hexdigest(), "unit_tests": unit, "native_tests": native}, indent=2) + "\n")
    print("PASS: " + str(len(unit)) + " unit / " + str(len(native)) + " native tests; SDK " + args.keycloak_version)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, ET.ParseError, subprocess.SubprocessError) as error:
        print("Qualification failed: " + str(error), file=sys.stderr)
        raise SystemExit(1) from error
