"""Qualify coordinated provider upgrade, guarded rollback, removal and reinstall.

The actual published rc.2 JAR is checksum-verified for each SDK. Only the lab's two labelled
nodes are replaced; their PostgreSQL database, native identities and journals
remain. Tokens/credentials and OpenSSL inputs stay in the private lab directory.
"""
import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import tempfile
import time
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from cluster import Lab, ROOT, digest

ATTRIBUTE = "oauth.bounded-delegation.v1"
ACCESS = "urn:ietf:params:oauth:token-type:access_token"
CHECKS = (
    "baseline_signed_software_exchange", "upgrade_preserves_native_identities_and_journal",
    "upgrade_preserves_spent_actor", "upgrade_accepts_fresh_software_evidence",
    "task_option_is_not_implicitly_enabled", "task_opt_in_issues_signed_binding",
    "task_online_check_allows_current_operation", "task_cancellation_refuses_online_use",
    "withdrawn_task_grant_refuses_new_issuance", "rollback_preserves_native_identities_and_journal",
    "rollback_preserves_spent_actor", "rollback_accepts_fresh_software_evidence",
    "removal_preparation_refuses_new_issuance", "removed_provider_is_absent",
    "removal_preserves_native_identities_and_journal", "removed_provider_cannot_issue_delegation",
    "removal_preserves_native_client_credentials", "reinstall_retains_explicit_exchange_disable",
    "reinstall_preserves_spent_actor", "explicit_reactivation_accepts_fresh_software_evidence",
)


def require(value, reason):
    if not value:
        raise ValueError(reason)


def baseline_source(pin, sdk):
    require(pin.get("schema") == 1 and pin.get("repository") == "Alien6-Studio/keycloak-bounded-delegation"
            and re.fullmatch(r"[0-9a-f]{40}", pin.get("revision", ""))
            and pin.get("tag") == "v0.1.0-rc.2"
            and re.fullmatch(r"[0-9a-f]{64}", pin.get("published_jars", {}).get(sdk, "")),
            "Invalid published lifecycle baseline pin")
    directory = ROOT / ".tools/cache/lifecycle-releases" / pin["revision"]
    directory.mkdir(parents=True, exist_ok=True)
    name = "bounded-delegation-0.1.0-rc.2-keycloak-" + sdk + ".jar"
    jar = directory / name
    if not jar.exists():
        url = "https://github.com/" + pin["repository"] + "/releases/download/" + pin["tag"] + "/" + name
        with tempfile.TemporaryDirectory(prefix="fetch-", dir=directory) as temporary:
            staged = Path(temporary) / name
            with urlopen(url, timeout=90) as response:
                content = response.read(5 * 1024 * 1024 + 1)
            require(0 < len(content) <= 5 * 1024 * 1024, "Published baseline JAR exceeds its budget")
            staged.write_bytes(content)
            require(digest(staged) == pin["published_jars"][sdk], "Published lifecycle baseline checksum mismatch")
            staged.rename(jar)
    require(not jar.is_symlink() and digest(jar) == pin["published_jars"][sdk],
            "Lifecycle baseline differs from its published rc.2 JAR")
    return jar


def decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def der(tag, content):
    size = len(content)
    length = bytes([size]) if size < 128 else bytes([128 + (size.bit_length() + 7) // 8]) + size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([tag]) + length + content


def rsa_integer(value):
    raw = decode(value).lstrip(b"\x00")
    require(bool(raw), "Invalid native signing key")
    return der(2, (b"\x00" if raw[0] & 128 else b"") + raw)


class Lifecycle:
    def __init__(self, lab, context):
        self.lab, self.context = lab, context
        self.realm = "lifecycle-" + lab.name
        self.base = "/admin/realms/" + self.realm
        self.issuer = lab.issuer + "/realms/" + self.realm
        self.secret = lab.password
        self.clients, self.users, self.keys, self.checks, self.timings = {}, {}, {}, {}, {}
        self.admin, self.admin_at = "", 0

    def request(self, method, path, body=None, form=None, bearer=None, expected=(200,), node=0):
        data, headers = None, {}
        if body is not None:
            data, headers["Content-Type"] = json.dumps(body).encode(), "application/json"
        if form is not None:
            data, headers["Content-Type"] = urlencode(form).encode(), "application/x-www-form-urlencoded"
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        try:
            with urlopen(Request("https://localhost:" + str(self.lab.ports[node]) + path,
                                 data=data, headers=headers, method=method), context=self.context, timeout=20) as response:
                status, raw = response.status, response.read(65537)
        except HTTPError as error:
            status, raw = error.code, error.read(65537)
        require(status in expected and len(raw) <= 65536, "Lifecycle HTTP boundary refused: " + method + " " + str(status))
        return status, json.loads(raw) if raw and raw.lstrip().startswith((b"{", b"[")) else {}

    def api(self, method, path, body=None):
        if time.monotonic() - self.admin_at > 25:
            self.admin = self.request("POST", "/realms/master/protocol/openid-connect/token", form={
                "grant_type": "password", "client_id": "admin-cli", "username": "cluster-admin", "password": self.secret})[1]["access_token"]
            self.admin_at = time.monotonic()
        return self.request(method, path, body=body, bearer=self.admin, expected=(200, 201, 204))[1]

    def record(self, name, valid):
        require(name in CHECKS and name not in self.checks and valid, "Lifecycle invariant failed: " + name)
        self.checks[name] = True
        print("Native lifecycle: " + name + " passed", flush=True)

    def raw(self, result):
        require(result[0] == 200 and bool(result[1].get("access_token")), "Native lifecycle token unavailable")
        return result[1]["access_token"]

    def access(self, client):
        return self.raw(self.request("POST", "/realms/" + self.realm + "/protocol/openid-connect/token", form={
            "grant_type": "client_credentials", "client_id": client, "client_secret": self.secret}))

    def input(self, client):
        return self.raw(self.request("POST", "/realms/" + self.realm + "/protocol/openid-connect/token", bearer=self.access(client), form={
            "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket", "audience": "invoice-api", "permission": "invoice#read"}))

    def exchange(self, actor, subject, approval=None, accepted=True):
        form = {"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "client_id": "actor", "client_secret": self.secret,
                "actor_token": actor, "actor_token_type": ACCESS, "subject_token": subject, "subject_token_type": ACCESS, "audience": "invoice-api"}
        if approval is not None:
            form["task_context"] = approval
        result = self.request("POST", "/realms/" + self.realm + "/protocol/openid-connect/token", form=form,
                              expected=(200,) if accepted else (400, 401, 403))
        if not accepted:
            require(not result[1].get("access_token"), "Refused lifecycle exchange returned a token")
            return True
        return self.verify(self.raw(result), actor, subject)

    def verify(self, token, actor=None, subject=None):
        require(len(token) <= 65536 and token.count(".") == 2, "Malformed signed lifecycle output")
        header, payload, signature = token.split(".")
        metadata = json.loads(decode(header))
        require(metadata.get("alg") == "RS256" and metadata.get("kid") in self.keys, "Unqualified native signer")
        private = self.lab.directory / "signature-check"
        private.mkdir(exist_ok=True, mode=0o700)
        key, sig, message = private / "key.pem", private / "signature", private / "message"
        key.write_bytes(self.keys[metadata["kid"]]); sig.write_bytes(decode(signature)); message.write_bytes((header + "." + payload).encode())
        for path in (key, sig, message):
            path.chmod(0o600)
        result = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(key), "-signature", str(sig), str(message)], capture_output=True, timeout=10)
        require(result.returncode == 0, "Native lifecycle signature verification failed")
        claims = json.loads(decode(payload))
        require(claims.get("iss") == self.issuer and claims.get("exp", 0) > time.time(), "Native lifecycle issuer/expiry refused")
        if actor is not None:
            inputs = [self.verify(value) for value in (actor, subject)]
            audience = claims.get("aud")
            require(audience == "invoice-api" or audience == ["invoice-api"], "Lifecycle audience widened")
            permissions = claims.get("authorization", {}).get("permissions", [])
            require(len(permissions) == 1 and permissions[0].get("rsid") == self.resource and permissions[0].get("scopes") == ["read"]
                    and not claims.get("realm_access", {}).get("roles")
                    and not any(value.get("roles") for value in claims.get("resource_access", {}).values())
                    and not claims.get("scope"), "Lifecycle authority widened")
            require(claims.get("azp") == "actor" and claims.get("sub") == self.users["subject"]
                    and claims.get("act", {}).get("sub") == self.users["actor"] and claims["act"].get("client_id") == "actor"
                    and claims["exp"] <= min(value["exp"] for value in inputs) and claims["exp"] <= time.time() + 90,
                    "Lifecycle identity or lifetime widened")
        return claims

    def binding(self, client):
        return {"id": self.clients[client], "attribute": "bounded.lifecycle.identity", "value": client}

    def save(self, document):
        client = self.api("GET", self.base + "/clients/" + self.clients["invoice-api"])
        client["attributes"][ATTRIBUTE] = json.dumps(document, separators=(",", ":"))
        self.api("PUT", self.base + "/clients/" + self.clients["invoice-api"], client)

    def preserved(self):
        for name, identifier in self.clients.items():
            values = self.api("GET", self.base + "/clients?" + urlencode({"clientId": name}))
            require(len(values) == 1 and values[0]["id"] == identifier, "Lifecycle replaced a native identity")
        current = self.api("GET", self.base + "/clients/" + self.clients["invoice-api"])
        return current["attributes"][ATTRIBUTE] == json.dumps(self.document, separators=(",", ":"))

    def setup(self):
        self.api("POST", "/admin/realms", {"realm": self.realm, "enabled": True, "accessTokenLifespan": 900,
            "attributes": {"oauth.bounded-delegation.profile": "software-v1"}})
        for name in ("actor", "subject", "invoice-api", "task-authority"):
            self.api("POST", self.base + "/clients", {"clientId": name, "enabled": True, "protocol": "openid-connect",
                "publicClient": False, "fullScopeAllowed": False, "serviceAccountsEnabled": True, "secret": self.secret,
                "authorizationServicesEnabled": name == "invoice-api", "attributes": {"bounded.lifecycle.identity": name,
                    "standard.token.exchange.enabled": "true", "oauth.bounded-delegation.actor.v1": "lifecycle-bound"}})
            self.clients[name] = self.api("GET", self.base + "/clients?clientId=" + name)[0]["id"]
            self.users[name] = self.api("GET", self.base + "/clients/" + self.clients[name] + "/service-account-user")["id"]
        base = self.base + "/clients/" + self.clients["invoice-api"] + "/authz/resource-server"
        for route in ("permission", "resource", "policy"):
            for item in self.api("GET", base + "/" + route):
                self.api("DELETE", base + "/" + route + "/" + item["_id" if route == "resource" else "id"])
        self.api("POST", base + "/scope", {"name": "read"})
        scopes = self.api("GET", base + "/scope")
        self.api("POST", base + "/resource", {"name": "invoice", "type": "invoice", "ownerManagedAccess": False, "scopes": scopes})
        self.resource = self.api("GET", base + "/resource")[0]["_id"]
        self.api("POST", base + "/policy/client", {"name": "software", "type": "client", "logic": "POSITIVE", "decisionStrategy": "AFFIRMATIVE",
            "clients": [self.clients["actor"], self.clients["subject"]]})
        policy = self.api("GET", base + "/policy")[0]["id"]
        self.api("POST", base + "/permission/scope", {"name": "invoice", "type": "scope", "logic": "POSITIVE", "decisionStrategy": "AFFIRMATIVE",
            "resources": [self.resource], "scopes": [item["id"] for item in scopes], "policies": [policy]})
        self.document = {"version": 1, "phase": "Committed", "ownerUID": "lifecycle-owner", "revision": "lifecycle-revision",
            "realmID": self.api("GET", self.base)["id"], "audience": self.binding("invoice-api"), "retiredActors": [],
            "grants": [{"name": "read", "actor": self.binding("actor"), "subject": self.binding("subject"),
                "authority": {"scopes": [], "realmRoles": [], "clientRoles": {}, "permissions": {self.resource: ["read"]}},
                "conditions": [{"kind": "client", "id": self.clients[name], "attribute": "bounded.lifecycle.identity", "value": name}
                               for name in ("actor", "subject")], "maxDepth": 1, "maxTTLSeconds": 90}]}
        self.save(self.document)
        jwks = self.request("GET", "/realms/" + self.realm + "/protocol/openid-connect/certs")[1]
        for key in jwks["keys"]:
            if key.get("kty") == "RSA" and key.get("use") == "sig":
                result = subprocess.run(["openssl", "rsa", "-RSAPublicKey_in", "-inform", "DER", "-pubout"],
                    input=der(48, rsa_integer(key["n"]) + rsa_integer(key["e"])), capture_output=True, timeout=10)
                require(result.returncode == 0, "Native RSA key conversion failed")
                self.keys[key["kid"]] = result.stdout
        require(bool(self.keys), "Native signing keys absent")

    def fresh(self):
        return self.exchange(self.input("actor"), self.input("subject"))

    def task_round_trip(self):
        realm = self.api("GET", self.base)
        realm["attributes"].update({"oauth.bounded-delegation.task.profile": "task-bound-software",
            "oauth.bounded-delegation.task.issuer": json.dumps(self.binding("task-authority"))})
        self.api("PUT", self.base, realm)
        for name in ("task-authority", "invoice-api"):
            self.api("POST", self.base + "/clients/" + self.clients[name] + "/protocol-mappers/models", {
                "name": "task-endpoint", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
                "config": {"included.custom.audience": "bounded-delegation-task-context", "access.token.claim": "true"}})
        document = {**self.document, "version": 2, "profile": "task-bound-software"}
        self.save(document)
        path = "/realms/" + self.realm + "/bounded-delegation/task-context"
        actor, subject = self.input("actor"), self.input("subject")
        registration = {"audience": self.clients["invoice-api"], "grant": "read", "actorJti": self.verify(actor)["jti"],
            "subjectJti": self.verify(subject)["jti"], "actorSubject": self.users["actor"], "subjectSubject": self.users["subject"],
            "permissions": {self.resource: ["read"]}, "parametersHash": "a" * 64, "ttlSeconds": 8}
        created = self.request("POST", path + "/contexts", body=registration, bearer=self.access("task-authority"), expected=(201,))[1]
        output = self.exchange(actor, subject, created["approval"])
        self.record("task_opt_in_issues_signed_binding", output.get("urn:alien6:bounded-delegation:task", {}).get("reference") == created["reference"])
        query = {"reference": created["reference"], "tokenId": output["jti"], "parametersHash": "a" * 64, "resource": self.resource, "scope": "read"}
        recipient = self.access("invoice-api")
        self.record("task_online_check_allows_current_operation", self.request("POST", path + "/check", body=query, bearer=recipient)[1].get("active") is True)
        self.request("DELETE", path + "/contexts/" + created["reference"], bearer=self.access("task-authority"))
        self.record("task_cancellation_refuses_online_use", self.request("POST", path + "/check", body=query, bearer=recipient, expected=(403,), node=1)[0] == 403)
        self.save({**document, "phase": "Prepared"})
        self.record("withdrawn_task_grant_refuses_new_issuance", self.exchange(self.input("actor"), self.input("subject"), accepted=False))
        time.sleep(max(0, created["expiresAt"] - time.time()) + 1)
        realm = self.api("GET", self.base)
        realm["attributes"].pop("oauth.bounded-delegation.task.profile")
        realm["attributes"].pop("oauth.bounded-delegation.task.issuer")
        self.api("PUT", self.base, realm)
        self.save(self.document)

    def replace(self, image, phase):
        began = time.monotonic()
        self.lab.replace_nodes(image, self.context)
        self.admin_at = 0
        self.timings[phase + "_restart_ms"] = round((time.monotonic() - began) * 1000, 3)

    def replay(self):
        # A refusal must not be confounded with expired input.
        self.verify(self.spent_actor); self.verify(self.spent_subject)
        return self.exchange(self.spent_actor, self.spent_subject, accepted=False)

    def qualify(self, candidate, absent):
        self.setup()
        self.spent_actor, self.spent_subject = self.input("actor"), self.input("subject")
        self.record("baseline_signed_software_exchange", bool(self.exchange(self.spent_actor, self.spent_subject)))
        baseline_image = self.lab.image
        self.replace(candidate, "upgrade")
        self.record("upgrade_preserves_native_identities_and_journal", self.preserved())
        self.record("upgrade_preserves_spent_actor", self.replay())
        self.record("upgrade_accepts_fresh_software_evidence", bool(self.fresh()))
        path = "/realms/" + self.realm + "/bounded-delegation/task-context"
        self.record("task_option_is_not_implicitly_enabled", self.request("GET", path)[1].get("enabled") is False)
        self.task_round_trip()
        self.replace(baseline_image, "rollback")
        self.record("rollback_preserves_native_identities_and_journal", self.preserved())
        self.record("rollback_preserves_spent_actor", self.replay())
        self.record("rollback_accepts_fresh_software_evidence", bool(self.fresh()))
        self.document = {**self.document, "phase": "Prepared"}
        self.save(self.document)
        actor = self.api("GET", self.base + "/clients/" + self.clients["actor"])
        actor["attributes"]["standard.token.exchange.enabled"] = "false"
        self.api("PUT", self.base + "/clients/" + self.clients["actor"], actor)
        self.record("removal_preparation_refuses_new_issuance", self.exchange(self.input("actor"), self.input("subject"), accepted=False))
        self.replace(absent, "removal")
        self.record("removed_provider_is_absent", self.request("GET", "/realms/" + self.realm + "/bounded-delegation", expected=(404,))[0] == 404)
        self.record("removal_preserves_native_identities_and_journal", self.preserved())
        self.record("removed_provider_cannot_issue_delegation", self.exchange(self.input("actor"), self.input("subject"), accepted=False))
        self.record("removal_preserves_native_client_credentials", self.verify(self.access("subject"))["sub"] == self.users["subject"])
        self.replace(candidate, "reinstall")
        self.record("reinstall_retains_explicit_exchange_disable", self.exchange(self.input("actor"), self.input("subject"), accepted=False))
        actor = self.api("GET", self.base + "/clients/" + self.clients["actor"])
        actor["attributes"]["standard.token.exchange.enabled"] = "true"
        self.api("PUT", self.base + "/clients/" + self.clients["actor"], actor)
        self.document = {**self.document, "phase": "Committed"}
        self.save(self.document)
        self.record("reinstall_preserves_spent_actor", self.replay())
        self.record("explicit_reactivation_accepts_fresh_software_evidence", bool(self.fresh()))


def build_image(lab, jar, suffix):
    directory = lab.directory / suffix
    directory.mkdir()
    shutil.copyfile(lab.directory / "cache-lab.xml", directory / "cache-lab.xml")
    provider = ""
    if jar is not None:
        shutil.copyfile(jar, directory / "bounded-delegation.jar")
        provider = "COPY --chown=keycloak:keycloak bounded-delegation.jar /opt/keycloak/providers/\n"
    (directory / "Dockerfile").write_text("FROM " + lab.pins["keycloak"][lab.version] + "\n" + provider
        + "COPY --chown=keycloak:keycloak cache-lab.xml /opt/keycloak/conf/\n"
        + "RUN /opt/keycloak/bin/kc.sh build --db=postgres --health-enabled=true --metrics-enabled=true --features=stateless\n")
    image = lab.name + ":" + suffix
    lab.docker("build", "--network=none", "--tag", image, directory, timeout=300)
    return image


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keycloak-version", required=True)
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()
    compatibility = json.loads((ROOT / "compatibility.json").read_text())
    pins = json.loads((ROOT / compatibility["cluster"]["images"]).read_text())
    pin = json.loads((ROOT / "lifecycle-baseline.json").read_text())
    require(args.keycloak_version in compatibility["keycloak"], "Unqualified lifecycle SDK")
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip())
    require(not dirty or args.allow_dirty, "Commit lifecycle source or explicitly allow a nonpublishable local run")
    target = ROOT / "target" / args.keycloak_version
    report = target / "qualification/lifecycle.json"
    report.unlink(missing_ok=True)
    candidate = target / ("bounded-delegation-keycloak-" + args.keycloak_version + ".jar")
    candidate_hash = digest(candidate)
    baseline = baseline_source(pin, args.keycloak_version)
    baseline_hash = digest(baseline)
    with tempfile.TemporaryDirectory(prefix="bounded-lifecycle-") as temporary:
        lab = Lab(Path(temporary), args.keycloak_version, baseline, pins)
        images = []
        try:
            lab.start()
            context = ssl.create_default_context(cafile=str(lab.runtime_directory / "tls.crt"))
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            for jar, suffix in ((candidate, "upgraded"), (None, "absent")):
                images.append(build_image(lab, jar, suffix))
            fixture = Lifecycle(lab, context)
            fixture.qualify(*images)
            final_revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
            final_dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip())
            require(set(fixture.checks) == set(CHECKS) and digest(candidate) == candidate_hash and digest(baseline) == baseline_hash
                    and (final_revision, final_dirty) == (revision, dirty), "Lifecycle evidence incomplete or source/provider changed")
            report.parent.mkdir(exist_ok=True)
            report.write_text(json.dumps({"schema": 1, "complete": True, "revision": revision, "worktree_dirty": dirty,
                "keycloak": args.keycloak_version, "jar_sha256": candidate_hash, "baseline": {**pin, "jar_sha256": baseline_hash},
                "images": {"keycloak": pins["keycloak"][args.keycloak_version], "postgres": pins["postgres"]},
                "checks": fixture.checks, "measurements": fixture.timings, "completed_at": datetime.now(timezone.utc).isoformat(),
                "limits": ["coordinated two-node restart; no mixed-version rolling upgrade", "one published rc.2 baseline per matching SDK",
                           "task grants cancelled/withdrawn and expired before rollback", "provider removal requires explicit native exchange disable",
                           "offline JWTs retain their residual lifetime; business transactions are outside the issuer"]}, indent=2) + "\n")
        except Exception:
            lab.private_diagnostics()
            raise
        finally:
            lab.cleanup()
            for image in images:
                subprocess.run(["docker", "image", "rm", image], capture_output=True, timeout=30, check=False)


if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        raise SystemExit("Lifecycle qualification failed: " + str(error)) from None
    except (OSError, KeyError, subprocess.SubprocessError) as error:
        raise SystemExit("Lifecycle qualification failed: " + type(error).__name__) from None
