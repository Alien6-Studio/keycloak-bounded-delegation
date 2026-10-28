"""Check the extension's SDK, test, wrapper and workflow contracts for drift."""
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

import yaml

ROOT = Path(__file__).resolve().parents[1]


def check(root=ROOT):
    contract = json.loads((root / "compatibility.json").read_text())
    versions = contract["keycloak"]
    if (contract["schema"] != 1 or contract["java"] != 21 or contract["state"] != "experimental"
            or not versions or len(versions) != len(set(versions))
            or any(not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) for version in versions)):
        raise ValueError("Invalid experimental qualification window")
    pom = ET.parse(root / "pom.xml").getroot()
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    default = pom.findtext("m:properties/m:keycloak.version", namespaces=ns)
    if default not in versions:
        raise ValueError("Default Maven SDK is not qualified")
    task_source = (root / "src/main/java/io/alien6/keycloak/delegation/TaskContext.java").read_text()
    task_sdks = re.search(r'Set.of\(([^)]*)\).contains\(Version.VERSION\)', task_source)
    if task_sdks is None or sorted(re.findall(r'"([0-9.]+)"', task_sdks[1])) != sorted(versions):
        raise ValueError("Task capability SDK window differs from native qualification")
    make_default = re.search(r"(?m)^KEYCLOAK_VERSION \?= (\S+)$", (root / "Makefile").read_text())
    if make_default is None or make_default[1] != default:
        raise ValueError("Make and Maven must use the same qualified default SDK")
    if pom.findtext("m:properties/m:maven.compiler.release", namespaces=ns) != str(contract["java"]):
        raise ValueError("Java release differs from qualification")
    test = root / "src/it/java" / (contract["native"]["test_class"].replace(".", "/") + ".java")
    names = sorted(re.findall(r"@Test\s+void\s+(\w+)\(", test.read_text()))
    if not names or names != contract["native"]["tests"] or len(names) != len(set(names)):
        raise ValueError("Native test inventory drift")
    cluster = contract["cluster"]
    cluster_source = root / "src/cluster/java" / (cluster["test_class"].replace(".", "/") + ".java")
    cluster_tests = sorted(re.findall(r"@Test\s+@Order\(\d+\)\s+void\s+(\w+)\(", cluster_source.read_text()))
    images = json.loads((root / cluster["images"]).read_text())
    if (cluster.get("required_for_release") is not True or cluster.get("state_store") != "database" or cluster.get("feature") != "stateless"
            or not cluster_tests or cluster_tests != cluster["tests"] or len(cluster_tests) != len(set(cluster_tests))
            or images.get("schema") != 1 or set(images.get("keycloak", {})) != set(versions)
            or any(not re.fullmatch(r"quay\.io/keycloak/keycloak:" + re.escape(version) + r"@sha256:[0-9a-f]{64}", image)
                   for version, image in images["keycloak"].items())
            or not re.fullmatch(r"docker\.io/library/postgres:[0-9.]+@sha256:[0-9a-f]{64}", images.get("postgres", ""))):
        raise ValueError("Native database/cluster qualification inventory drift")
    for filename in ("ci.yml", "release.yml"):
        workflow = yaml.safe_load((root / ".github/workflows" / filename).read_text())
        if workflow["jobs"]["qualify"]["strategy"]["matrix"]["keycloak"] != versions:
            raise ValueError("SDK matrix drift in " + filename)
    consumer_versions = contract["integrations"]["hanko"]["keycloak"]
    consumer_workflow = yaml.safe_load((root / ".github/workflows/consumer-interop.yml").read_text())
    if (not consumer_versions or len(set(consumer_versions)) != len(consumer_versions)
            or not set(consumer_versions) <= set(versions)
            or consumer_workflow["jobs"]["hanko"]["strategy"]["matrix"]["keycloak"] != consumer_versions):
        raise ValueError("Consumer SDK matrix differs from its own pinned fixtures")
    environment = json.loads((root / ".github/release-environment.json").read_text())
    release = yaml.safe_load((root / ".github/workflows/release.yml").read_text())
    if (environment != {"name": "release", "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
                        "allowed_refs": [{"name": "main", "type": "branch"}], "required_reviewers": []}
            or release["jobs"]["draft"]["environment"] != environment["name"]
            or release["jobs"]["eligibility"]["steps"][0]["with"]["ref"] != "${{ github.workflow_sha }}"
            or release["jobs"]["draft"]["permissions"] != {"contents": "write", "id-token": "write", "attestations": "write"}):
        raise ValueError("Release environment/publisher authority drift")
    properties = dict(line.split("=", 1) for line in (root / ".mvn/wrapper/maven-wrapper.properties").read_text().splitlines() if "=" in line)
    if (not re.fullmatch(r"https://repo\.maven\.apache\.org/maven2/org/apache/maven/apache-maven/([0-9.]+)/apache-maven-\1-bin\.zip", properties.get("distributionUrl", ""))
            or not re.fullmatch(r"[0-9a-f]{64}", properties.get("distributionSha256Sum", ""))):
        raise ValueError("Maven wrapper must pin its official distribution and SHA256")
    for path in (root / ".github/workflows").glob("*.yml"):
        for action in re.findall(r"uses:\s*([^\s#]+)", path.read_text()):
            if not re.fullmatch(r"[A-Za-z0-9_./-]+@[0-9a-f]{40}", action):
                raise ValueError("Action must use an immutable SHA: " + action)
    upstream = json.loads((root / "upstream.json").read_text())
    if upstream["repository"] != "keycloak/keycloak" or not re.fullmatch(r"[0-9a-f]{40}", upstream["revision"]):
        raise ValueError("Upstream source review needs an immutable official revision")


if __name__ == "__main__":
    try:
        check()
        print("SDK, native tests, wrapper and workflow contracts match")
    except (ValueError, KeyError, OSError, ET.ParseError, yaml.YAMLError) as error:
        print("Project contract failed: " + str(error), file=sys.stderr)
        raise SystemExit(1) from error
