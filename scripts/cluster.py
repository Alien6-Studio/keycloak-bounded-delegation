"""Own an isolated two-node PostgreSQL/embedded-cache Keycloak qualification lab.

Only random, labelled containers created by this process are modified. No bearer
or credential is placed in public reports, subprocess arguments or node logs.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
from urllib.request import urlopen
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def free_port():
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        return server.getsockname()[1]


def write_private(path, content):
    """Create a lab-only plaintext input privately, including under a permissive umask.

    These generated credentials must be read by the owned Docker/Java processes.
    They are never public evidence, image inputs or reusable deployment secrets.
    Exclusive creation refuses existing files and symlinks before any write.
    """
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(content)


def cache_configuration(source):
    if len(source) > 1024 * 1024 or b"<!DOCTYPE" in source.upper() or b"<!ENTITY" in source.upper():
        raise ValueError("Unexpected native cache configuration")
    root = ET.fromstring(source)
    namespace = root.tag.split("}")[0] + "}"
    container = root.find(namespace + "cache-container")
    if container is None:
        raise ValueError("Native cache container absent")
    existing = [node for node in container if node.get("name") == "actionTokens"]
    for node in existing:
        container.remove(node)
    cache = ET.SubElement(container, namespace + "distributed-cache", {"name": "actionTokens", "owners": "2", "mode": "SYNC"})
    encoding = ET.SubElement(cache, namespace + "encoding")
    for kind in ("key", "value"):
        ET.SubElement(encoding, namespace + kind, {"media-type": "application/x-protostream"})
    ET.SubElement(cache, namespace + "expiration", {"max-idle": "-1"})
    ET.SubElement(cache, namespace + "partition-handling", {"when-split": "DENY_READ_WRITES", "merge-policy": "NONE"})
    ET.register_namespace("", namespace[1:-1])
    return ET.tostring(root, encoding="unicode", xml_declaration=True)


class Lab:
    def __init__(self, directory, version, jar, pins, state_store="database"):
        self.directory, self.version, self.jar, self.pins = directory, version, jar, pins
        self.directory.chmod(0o700)
        # The container UID needs TLS access; it never receives the private
        # parent containing environment files or the Java driver's credentials.
        self.runtime_directory = self.directory / "runtime"
        self.runtime_directory.mkdir(mode=0o755)
        self.name = "bounded-lab-" + secrets.token_hex(8)
        self.containers = []
        self.network = None
        self.cache_network = None
        self.image = None
        self.state_store = state_store
        self.password = secrets.token_hex(32)
        self.ports = [free_port(), free_port()]
        self.issuer = "https://localhost:" + str(self.ports[0])

    def docker(self, *args, timeout=180):
        result = subprocess.run(["docker", *map(str, args)], capture_output=True, text=True, timeout=timeout, check=False)
        if result.returncode:
            # Docker errors can echo environment/arguments. Keep private output
            # available to the local process only, never the qualification log.
            operation = args[0] + ("/" + args[1] if args[0] == "network" and len(args) > 1 else "")
            raise ValueError("Isolated cluster Docker operation failed: " + operation)
        return (result.stdout + (result.stderr if args[0] == "logs" else "")).strip()

    def runtime_snapshot(self):
        """Bounded hardware allocation and point-in-time memory, never host names."""
        runtime = json.loads(self.docker("info", "--format", '{"cpus":{{.NCPU}},"architecture":{{json .Architecture}},"server_version":{{json .ServerVersion}}}'))
        if (type(runtime.get("cpus")) is not int or not 1 <= runtime["cpus"] <= 65536
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", runtime.get("architecture", ""))
                or not isinstance(runtime.get("server_version"), str) or len(runtime["server_version"]) > 64):
            raise ValueError("Unexpected Docker runtime metadata")
        nodes = []
        for node in self.nodes:
            data = json.loads(self.docker("stats", "--no-stream", "--format", "{{json .}}", node))
            match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)\s*(B|KiB|MiB|GiB|TiB|kB|MB|GB)", data["MemUsage"].split("/")[0].strip())
            if match is None:
                raise ValueError("Unexpected container memory sample")
            factors = {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3, "TiB": 1024**4, "kB": 1000, "MB": 1000**2, "GB": 1000**3}
            cpu = float(data["CPUPerc"].removesuffix("%"))
            memory = int(float(match[1]) * factors[match[2]])
            if not 0 <= cpu <= 6553600 or not 0 < memory <= 1073741824:
                raise ValueError("Container runtime sample outside its bounds")
            nodes.append({"memory_usage_bytes": memory, "cpu_percent": cpu})
        return {"runtime": runtime, "nodes": nodes, "sampling": "Docker point-in-time after tests; not peak memory", "time": datetime.now(timezone.utc).isoformat()}

    def container(self, suffix, *args):
        identifier = self.docker("create", "--name", self.name + "-" + suffix, "--label", "bounded.lab=" + self.name, *args)
        if not re.fullmatch(r"[0-9a-f]{64}", identifier):
            raise ValueError("Created container identity unavailable")
        self.containers.append(identifier)
        return identifier

    def certificates(self):
        key, certificate = self.runtime_directory / "tls.key", self.runtime_directory / "tls.crt"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-keyout", str(key), "-out", str(certificate), "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], capture_output=True, check=True, timeout=30)
        # Only the owned containers can traverse this mount. Other host users
        # cannot traverse its 0700 parent. Everything is removed on lab exit.
        key.chmod(0o644)
        return ssl.create_default_context(cafile=str(certificate))

    def start(self):
        context = self.certificates()
        self.network = self.docker("network", "create", "--label", "bounded.lab=" + self.name, self.name)
        cache_name = self.name + "-cache"
        self.cache_network = self.docker("network", "create", "--label", "bounded.lab=" + self.name, cache_name)
        cache_metadata = json.loads(self.docker("network", "inspect", self.cache_network))[0]
        subnet = ipaddress.ip_network(cache_metadata["IPAM"]["Config"][0]["Subnet"])
        # Let Docker allocate a free range, then declare that same owned range
        # explicitly. Linux engines require a user-configured subnet for --ip.
        self.docker("network", "rm", self.cache_network)
        self.cache_network = None
        self.cache_network = self.docker("network", "create", "--internal", "--label", "bounded.lab=" + self.name,
                                         "--subnet", str(subnet), cache_name)
        cache_addresses = [str(subnet.network_address + index) for index in (10, 11)]
        database_env = self.directory / "postgres.env"
        write_private(database_env, "POSTGRES_DB=keycloak\nPOSTGRES_USER=keycloak\nPOSTGRES_PASSWORD=" + self.password + "\n")
        database = self.container("db", "--network", self.name, "--network-alias", "database", "--env-file", database_env, self.pins["postgres"])
        self.docker("start", database)
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            ready = subprocess.run(["docker", "exec", database, "pg_isready", "-U", "keycloak"], capture_output=True, timeout=10, check=False)
            if ready.returncode == 0:
                break
            time.sleep(1)
        else:
            raise ValueError("Isolated PostgreSQL did not become ready")
        template = self.container("template", self.pins["keycloak"][self.version])
        source = self.directory / "cache-native.xml"
        self.docker("cp", template + ":/opt/keycloak/conf/cache-ispn.xml", source)
        configured = cache_configuration(source.read_bytes()) if self.state_store == "cache" else source.read_text()
        cache_xml = ET.fromstring(configured)
        namespace = cache_xml.tag.split("}")[0] + "}"
        transport = cache_xml.find(namespace + "cache-container/" + namespace + "transport")
        if transport is None:
            raise ValueError("Native JGroups transport configuration absent")
        transport.set("cluster", self.name)
        ET.register_namespace("", namespace[1:-1])
        configured = ET.tostring(cache_xml, encoding="unicode", xml_declaration=True)
        (self.directory / "cache-lab.xml").write_text(configured)
        shutil.copyfile(self.jar, self.directory / "bounded-delegation.jar")
        (self.directory / "Dockerfile").write_text("FROM " + self.pins["keycloak"][self.version] + "\n"
            "COPY --chown=keycloak:keycloak bounded-delegation.jar /opt/keycloak/providers/\n"
            "COPY --chown=keycloak:keycloak cache-lab.xml /opt/keycloak/conf/\n"
            "RUN /opt/keycloak/bin/kc.sh build --db=postgres --health-enabled=true --metrics-enabled=true"
            + (" --features=stateless" if self.state_store == "database" else "") + "\n")
        (self.directory / ".dockerignore").write_text("*\n!Dockerfile\n!bounded-delegation.jar\n!cache-lab.xml\n")
        self.image = self.name + ":candidate"
        self.docker("build", "--network=none", "--tag", self.image, self.directory, timeout=300)
        self.cache_addresses = cache_addresses
        nodes = self.start_nodes(self.image, context)
        configuration = {"schema": 1, "issuer": self.issuer, "endpoints": ["https://localhost:" + str(port) for port in self.ports],
            "adminUser": "cluster-admin", "adminPassword": self.password, "network": cache_name, "cacheAddresses": cache_addresses, "nodes": nodes,
            "label": self.name, "ca": str(self.runtime_directory / "tls.crt"), "keycloak": self.version, "stateStore": self.state_store}
        path = self.directory / "private-cluster.json"
        write_private(path, json.dumps(configuration))
        return path

    def start_nodes(self, image, context):
        nodes = []
        for index, port in enumerate(self.ports):
            # Lifecycle replacement creates a fresh immutable input rather than
            # reopening or replacing a file used by an earlier process.
            node_env = self.directory / ("node" + str(index) + "-" + secrets.token_hex(8) + ".env")
            write_private(node_env, "KC_DB_PASSWORD=" + self.password + "\nKC_BOOTSTRAP_ADMIN_PASSWORD=" + self.password + "\n"
                          "JAVA_OPTS_APPEND=-Djgroups.bind.address=" + self.cache_addresses[index] + "\n")
            node = self.container("node" + str(index), "--network", self.name, "--hostname", self.name + "-node" + str(index),
                "--memory", "1g", "--cpus", "2",
                "--env-file", node_env, "--publish", f"127.0.0.1:{port}:8443", "--volume", str(self.runtime_directory) + ":/fixture:ro",
                image, "start", "--optimized",
                "--db-url=jdbc:postgresql://database/keycloak", "--db-username=keycloak",
                "--bootstrap-admin-username=cluster-admin", "--hostname=" + self.issuer, "--http-enabled=false",
                "--https-certificate-file=/fixture/tls.crt", "--https-certificate-key-file=/fixture/tls.key",
                "--cache=ispn", "--cache-stack=jdbc-ping", "--cache-config-file=cache-lab.xml",
                *( ["--cache-embedded-cluster-name=" + self.name] if tuple(map(int, self.version.split("."))) >= (26, 8, 0) else [] ),
                "--log-level=info,org.keycloak.connections.infinispan.DefaultInfinispanConnectionProviderFactory:debug")
            self.docker("network", "connect", "--ip", self.cache_addresses[index], self.cache_network, node)
            self.docker("start", node)
            nodes.append(node)
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                if self.docker("inspect", "--format", "{{.State.Running}}", node) != "true":
                    raise ValueError("Isolated Keycloak process exited before HTTPS readiness")
                try:
                    with urlopen(f"https://localhost:{port}/realms/master/.well-known/openid-configuration", context=context, timeout=2) as response:
                        if response.status == 200:
                            break
                except (OSError, ValueError):
                    pass
                time.sleep(1)
            else:
                raise ValueError("Isolated HTTPS Keycloak node did not become ready")
        self.await_cluster(nodes)
        self.nodes = nodes
        return nodes

    def replace_nodes(self, image, context):
        # Stop both processes before replacing either binary. This qualifies a
        # coordinated restart, not a mixed-version rolling upgrade.
        for node in self.nodes:
            self.docker("stop", "--time", "10", node)
        for node in self.nodes:
            self.docker("rm", "--volumes", node)
        return self.start_nodes(image, context)

    def await_cluster(self, nodes):
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            views = [self.docker("logs", node) for node in nodes]
            if all(re.search(r"ISPN000094:.*\(2\)", view) for view in views):
                return
            time.sleep(1)
        raise ValueError("Two independent Keycloak nodes did not prove shared cache membership")

    def cleanup(self):
        for identifier in reversed(self.containers):
            subprocess.run(["docker", "rm", "--volumes", "--force", identifier], capture_output=True, timeout=30, check=False)
        if self.cache_network:
            subprocess.run(["docker", "network", "rm", self.cache_network], capture_output=True, timeout=30, check=False)
        if self.network:
            subprocess.run(["docker", "network", "rm", self.network], capture_output=True, timeout=30, check=False)
        if self.image:
            subprocess.run(["docker", "image", "rm", self.image], capture_output=True, timeout=30, check=False)

    def private_diagnostics(self):
        directory = ROOT / ".tools/cluster-private" / self.name
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        for index, identifier in enumerate(self.containers):
            try:
                logs = self.docker("logs", "--tail", "1000", identifier, timeout=10)
                (directory / (str(index) + ".log")).write_text(logs.replace(self.password, "[credential withheld]"))
            except (ValueError, subprocess.SubprocessError):
                pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keycloak-version", required=True)
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("--state-store", choices=("database", "cache"), default="database")
    args = parser.parse_args()
    compatibility = json.loads((ROOT / "compatibility.json").read_text())
    pins = json.loads((ROOT / "cluster-images.json").read_text())
    if set(pins["keycloak"]) != set(compatibility["keycloak"]) or args.keycloak_version not in pins["keycloak"]:
        raise ValueError("Cluster image pins differ from the native SDK matrix")
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip())
    if dirty and not args.allow_dirty:
        raise ValueError("Commit cluster source or use --allow-dirty for nonpublishable iteration")
    target = ROOT / "target" / args.keycloak_version
    jar = target / ("bounded-delegation-keycloak-" + args.keycloak_version + ".jar")
    if not jar.is_file():
        raise ValueError("Build the exact SDK JAR before cluster qualification")
    report = target / ("qualification/cluster.json" if args.state_store == "database" else "qualification/cluster-cache.json")
    report.unlink(missing_ok=True)
    initial_jar = digest(jar)
    with tempfile.TemporaryDirectory(prefix="bounded-cluster-") as temporary:
        lab = Lab(Path(temporary), args.keycloak_version, jar, pins, args.state_store)
        try:
            config = lab.start()
            env = {**os.environ, "BOUNDED_CLUSTER_CONFIG": str(config),
                "MAVEN_USER_HOME": os.environ.get("MAVEN_USER_HOME", str(ROOT / ".tools/maven-user"))}
            repository = os.environ.get("MAVEN_REPO_LOCAL", str(ROOT / ".tools/maven"))
            subprocess.run([str(ROOT / "mvnw"), "-B", "-ntp", "-Dmaven.repo.local=" + repository,
                "-Dkeycloak.version=" + args.keycloak_version, "-Pcluster-tests", "verify"], cwd=ROOT, env=env, check=True, timeout=900)
            spec = importlib.util.spec_from_file_location("native_qualification", ROOT / "scripts/qualify.py")
            native = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(native)
            cases = native.outcomes(target / "cluster-failsafe-reports")
            expected = [compatibility["cluster"]["test_class"] + "/" + name for name in compatibility["cluster"]["tests"]]
            if cases != expected or digest(jar) != initial_jar:
                raise ValueError("Cluster test inventory or tested provider bytes changed")
            measurements = json.loads((target / "qualification/cluster-measurements.json").read_text())
            if measurements.get("complete") is not True:
                raise ValueError("Cluster failure matrix incomplete")
            report.parent.mkdir(exist_ok=True)
            report.write_text(json.dumps({"schema": 1, "complete": True, "revision": source, "worktree_dirty": dirty,
                "keycloak": args.keycloak_version, "jar_sha256": initial_jar, "cluster_tests": cases,
                "images": {"keycloak": pins["keycloak"][args.keycloak_version], "postgres": pins["postgres"]},
                "runtime_limits": {"keycloak_nodes": 2, "cpus_per_node": 2, "memory_bytes_per_node": 1073741824},
                "runtime_snapshot": lab.runtime_snapshot(),
                "state_store": args.state_store,
                "topology": "two Keycloak JVMs; shared PostgreSQL; independent HTTPS/database and JGroups networks",
                "completed_at": datetime.now(timezone.utc).isoformat(), "measurements": measurements}, indent=2) + "\n")
        except Exception:
            lab.private_diagnostics()
            raise
        finally:
            lab.cleanup()


if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        raise SystemExit("Cluster qualification failed: " + str(error)) from None
    except (OSError, subprocess.SubprocessError) as error:
        raise SystemExit("Cluster qualification failed: " + type(error).__name__) from None
