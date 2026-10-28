"""Prepare and verify release assets; remote publication remains a separate draft-only workflow step."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
SHA = re.compile(r"[0-9a-f]{40}")
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*)?")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def document(path):
    require(path.is_file() and path.stat().st_size <= 8 * 1024 * 1024, "Missing or oversized release document")
    return json.loads(path.read_text())


def digest(path):
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= 32 * 1024 * 1024, "Invalid asset")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pom_version():
    return ET.parse(ROOT / "pom.xml").getroot().findtext("{http://maven.apache.org/POM/4.0.0}version")


def github(repository, path):
    endpoint = "repos/" + repository + ("/" + path if path else "")
    result = subprocess.run(["gh", "api", "--method", "GET", endpoint],
                            capture_output=True, timeout=30, check=True)
    require(len(result.stdout) <= 8 * 1024 * 1024, "GitHub metadata exceeds its size budget")
    return json.loads(result.stdout)


def verify_tag(repository, tag, api=None):
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is not None, "Invalid repository")
    require(isinstance(tag, str) and tag.startswith("v") and VERSION.fullmatch(tag[1:]) is not None, "Invalid release tag")
    version = tag[1:]
    require("-" in version and "SNAPSHOT" not in version.upper(), "Only explicit experimental prereleases are currently eligible")
    api = api or (lambda path: github(repository, path))
    info = api("")
    require(info.get("full_name") == repository and info.get("default_branch") == "main", "Release repository/default branch mismatch")
    require(api("branches/main").get("protected") is True, "Main must remain protected")
    ref = api("git/ref/tags/" + tag)
    obj = ref.get("object", {})
    require(ref.get("ref") == "refs/tags/" + tag and obj.get("type") == "tag" and SHA.fullmatch(obj.get("sha", "")), "A signed annotated tag is required")
    annotation = api("git/tags/" + obj["sha"])
    verification = annotation.get("verification", {})
    target = annotation.get("object", {})
    require(annotation.get("tag") == tag and annotation.get("sha") == obj["sha"]
            and verification.get("verified") is True and verification.get("reason") == "valid"
            and target.get("type") == "commit" and SHA.fullmatch(target.get("sha", "")), "Tag signature or target is not GitHub Verified")
    revision = target["sha"]
    commit = api("commits/" + revision)
    signed = commit.get("commit", {}).get("verification", {})
    require(commit.get("sha") == revision and signed.get("verified") is True and signed.get("reason") == "valid", "Source commit must be GitHub Verified")
    compare = api("compare/" + revision + "...main")
    require(compare.get("status") in ("ahead", "identical") and compare.get("merge_base_commit", {}).get("sha") == revision,
            "Release source is not on protected main")
    return {"tag": tag, "version": version, "revision": revision}


def validate_jar(path, version, compiled=None, sdk=None):
    with ZipFile(path) as jar:
        names = set(jar.namelist())
        require(len(names) == len(jar.namelist()), "Ambiguous duplicate JAR entries")
        require({"META-INF/LICENSE", "META-INF/NOTICE", "bounded-delegation.properties",
                 "META-INF/services/org.keycloak.protocol.oidc.TokenExchangeProviderFactory",
                 "META-INF/services/org.keycloak.services.resource.RealmResourceProviderFactory",
                 "META-INF/services/org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory",
                 "META-INF/services/org.keycloak.services.ui.extend.UiPageProviderFactory",
                 "META-INF/services/org.keycloak.services.ui.extend.UiTabProviderFactory"} <= names, "Provider metadata or license missing")
        lines = jar.read("bounded-delegation.properties").decode().strip().splitlines()
        pairs = [line.split("=", 1) for line in lines]
        require(len(pairs) == 2 and all(len(pair) == 2 for pair in pairs), "Packaged extension metadata mismatch")
        metadata = dict(pairs)
        require(set(metadata) == {"version", "keycloakVersion"} and metadata["version"] == version
                and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", metadata["keycloakVersion"])
                and (sdk is None or metadata["keycloakVersion"] == sdk), "Packaged extension version or SDK mismatch")
        classes = [name for name in names if name.endswith(".class")]
        require(classes and all(name.startswith("io/alien6/keycloak/delegation/") for name in classes), "Unexpected shaded runtime/test dependency")
        for name in classes:
            value = jar.read(name)
            require(value[:4] == b"\xca\xfe\xba\xbe" and int.from_bytes(value[6:8], "big") == 65, "Provider must target Java 21")
        if compiled is not None:
            require(compiled.is_dir(), "Tested compiled provider is missing")
            tested = {p.relative_to(compiled).as_posix(): p for p in compiled.rglob("*") if p.is_file()}
            require(set(classes) == {name for name in tested if name.endswith(".class")}, "Packaged classes differ from the tested provider")
            require(all(name in names and jar.read(name) == source.read_bytes() for name, source in tested.items()),
                    "Packaged provider bytes differ from the official-framework test inputs")


def validate_cluster(cluster, sdk, revision, jar_sha256, contract, images, dry_run=False):
    require(cluster.get("schema") == 1 and cluster.get("complete") is True and cluster.get("revision") == revision
            and cluster.get("keycloak") == sdk and cluster.get("state_store") == contract["state_store"]
            and cluster.get("jar_sha256") == jar_sha256
            and cluster.get("cluster_tests") == [contract["test_class"] + "/" + name for name in contract["tests"]]
            and cluster.get("images") == {"keycloak": images["keycloak"][sdk], "postgres": images["postgres"]}
            and cluster.get("measurements", {}).get("complete") is True,
            "Missing or foreign multi-node database-state qualification")
    require(dry_run or cluster.get("worktree_dirty") is False, "Cluster qualification must bind clean source")


def validate_lifecycle(proof, sdk, revision, jar_sha256, contract, baseline, images, dry_run=False):
    require(proof.get("schema") == 1 and proof.get("complete") is True and proof.get("revision") == revision
            and proof.get("keycloak") == sdk and proof.get("jar_sha256") == jar_sha256
            and proof.get("images") == {"keycloak": images["keycloak"][sdk], "postgres": images["postgres"]}
            and set(proof.get("checks", {})) == set(contract["checks"])
            and all(value is True for value in proof["checks"].values())
            and {key: proof.get("baseline", {}).get(key) for key in baseline} == baseline
            and re.fullmatch(r"[0-9a-f]{64}", proof.get("baseline", {}).get("jar_sha256", "")),
            "Missing or foreign provider lifecycle qualification")
    require(dry_run or proof.get("worktree_dirty") is False, "Lifecycle qualification must bind clean source")


def package(sdk, output, dry_run=False):
    contract = document(ROOT / "compatibility.json")
    require(sdk in contract["keycloak"], "Unqualified SDK")
    version = pom_version()
    require(VERSION.fullmatch(version) is not None, "Invalid project version")
    require(dry_run or "-" in version and "SNAPSHOT" not in version.upper(), "Production packaging requires a prerelease version")
    target = ROOT / "target" / sdk
    report = document(target / "qualification/results.json")
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip())
    expected = [contract["native"]["test_class"] + "/" + name for name in contract["native"]["tests"]]
    require(report.get("complete") is True and report.get("revision") == revision and report.get("keycloak") == sdk
            and report.get("contract") == contract["contract"] and report.get("java_release") == 21
            and report.get("native_tests") == expected and len(report.get("unit_tests", [])) >= contract["native"]["minimum_unit_tests"], "Incomplete or foreign qualification")
    require(dry_run or not dirty and report.get("worktree_dirty") is False, "Release assets require clean qualified source")
    stem = "bounded-delegation-keycloak-" + sdk
    binary = target / (stem + ".jar")
    require(digest(binary) == report.get("jar_sha256"), "Provider changed after qualification")
    cluster = document(target / "qualification/cluster.json")
    images = document(ROOT / contract["cluster"]["images"])
    validate_cluster(cluster, sdk, revision, digest(binary), contract["cluster"], images, dry_run)
    lifecycle = document(target / "qualification/lifecycle.json")
    baseline = document(ROOT / contract["lifecycle"]["baseline"])
    validate_lifecycle(lifecycle, sdk, revision, digest(binary), contract["lifecycle"], baseline, images, dry_run)
    validate_jar(binary, version, target / "classes", sdk)
    sbom = document(target / "sbom.json")
    require(sbom.get("bomFormat") == "CycloneDX" and sbom.get("metadata", {}).get("component", {}).get("version") == version,
            "Missing or foreign SBOM")
    require(any(item.get("group") == "org.keycloak" and item.get("name") == "keycloak-services" and item.get("version") == sdk
                for item in sbom.get("components", [])), "SBOM must inventory the matching provided Keycloak SDK")
    assets = {"bounded-delegation-" + version + "-keycloak-" + sdk + suffix: source for suffix, source in (
        (".jar", binary), ("-sources.jar", target / (stem + "-sources.jar")),
        ("-javadoc.jar", target / (stem + "-javadoc.jar")), ("-sbom.json", target / "sbom.json"),
        ("-qualification.json", target / "qualification/results.json"),
        ("-cluster-qualification.json", target / "qualification/cluster.json"),
        ("-lifecycle-qualification.json", target / "qualification/lifecycle.json"))}
    require(not output.exists() or not any(output.iterdir()), "Use an empty staging directory; assets are never overwritten")
    output.mkdir(parents=True, exist_ok=True)
    files = {}
    for name, source in assets.items():
        value = digest(source)
        shutil.copyfile(source, output / name)
        files[name] = value
    manifest = {"schema": 1, "version": version, "revision": revision, "keycloak": sdk,
                "releasable": not dry_run, "worktree_dirty": dirty or report.get("worktree_dirty") is not False, "files": files}
    (output / ("release-" + sdk + ".json")).write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def assemble(incoming, output, dry_run=False):
    contract = document(ROOT / "compatibility.json")
    expected = {"release-" + sdk + ".json" for sdk in contract["keycloak"]}
    require({p.name for p in incoming.glob("release-*.json")} == expected, "Release SDK matrix is incomplete or contains foreign cells")
    version = pom_version()
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    require(not output.exists() or not any(output.iterdir()), "Use an empty bundle directory")
    accepted = set(expected)
    for sdk in contract["keycloak"]:
        record = document(incoming / ("release-" + sdk + ".json"))
        require(record.get("schema") == 1 and record.get("version") == version and record.get("revision") == revision
                and record.get("keycloak") == sdk and (dry_run or record.get("releasable") is True and record.get("worktree_dirty") is False), "Foreign or non-releasable SDK cell")
        names = {"bounded-delegation-" + version + "-keycloak-" + sdk + suffix
                 for suffix in (".jar", "-sources.jar", "-javadoc.jar", "-sbom.json", "-qualification.json", "-cluster-qualification.json", "-lifecycle-qualification.json")}
        require(isinstance(record.get("files"), dict) and set(record["files"]) == names, "Unexpected release asset inventory")
        for name, value in record["files"].items():
            require(re.fullmatch(r"[0-9a-f]{64}", value) is not None and digest(incoming / name) == value, "Release asset checksum mismatch")
        accepted.update(names)
    require({p.name for p in incoming.iterdir()} == accepted, "Unexpected files in incoming release artifacts")
    output.mkdir(parents=True, exist_ok=True)
    for name in sorted(accepted):
        shutil.copyfile(incoming / name, output / name)
    for name in ("LICENSE", "NOTICE"):
        shutil.copyfile(ROOT / name, output / name)
    notes = "\n".join([
        "# Keycloak Bounded Delegation " + version, "",
        "Experimental software-v1 prerelease. Independently maintained; upstream integration is proposed, not accepted.", "",
        "Source: `" + revision + "`. Qualified SDKs: " + ", ".join(contract["keycloak"]) + ".", "",
        "Assets include the SDK-specific provider, sources, Javadoc, CycloneDX inventory and native qualification evidence.",
        "Provided Keycloak dependencies are inventoried but not shaded into the provider.", "",
        "Two-node replay and coordinated provider replacement are qualified only for the recorded database-backed topology and exact SDKs.",
        "Mixed-version rolling upgrades, sustained production load, human delegation and cache-only recovery remain unqualified.",
        "Offline JWT revocation is bounded by expiry. Withdraw grants and wait their maximum lifetime before removing enforcement.", "",
        "Verify SHA256SUMS and `gh attestation verify ASSET --repo Alien6-Studio/keycloak-bounded-delegation` before installation.",
        "Copy only the provider JAR matching your Keycloak SDK into providers/ and rebuild the server.", "",
        "See installation, security and roadmap documents in the source archive for activation, limitations and rollback.", "",
    ])
    (output / "RELEASE_NOTES.md").write_text(notes)
    archive = output / ("keycloak-bounded-delegation-" + version + "-source.tar.gz")
    subprocess.run(["git", "archive", "--format=tar.gz", "--prefix=keycloak-bounded-delegation-" + version + "/", "--output=" + str(archive.resolve()), revision], cwd=ROOT, check=True)
    sums = "".join(digest(path) + "  " + path.name + "\n" for path in sorted(output.iterdir()))
    (output / "SHA256SUMS").write_text(sums)
    return {"version": version, "revision": revision, "keycloak": contract["keycloak"], "releasable": not dry_run}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    tag = commands.add_parser("verify-tag")
    tag.add_argument("--repository", required=True)
    tag.add_argument("--tag", required=True)
    cell = commands.add_parser("package")
    cell.add_argument("--keycloak-version", required=True)
    cell.add_argument("--output", type=Path, required=True)
    cell.add_argument("--dry-run", action="store_true")
    bundle = commands.add_parser("assemble")
    bundle.add_argument("--incoming", type=Path, required=True)
    bundle.add_argument("--output", type=Path, required=True)
    bundle.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.command == "verify-tag":
        result = verify_tag(args.repository, args.tag)
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip()
        require(head == result["revision"] and not dirty and pom_version() == result["version"], "Checkout/POM differs from verified release tag")
    elif args.command == "package":
        result = package(args.keycloak_version, args.output.resolve(), args.dry_run)
    else:
        result = assemble(args.incoming.resolve(), args.output.resolve(), args.dry_run)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, ET.ParseError, subprocess.SubprocessError) as error:
        print("Release validation failed: " + str(error), file=sys.stderr)
        raise SystemExit(1) from error
