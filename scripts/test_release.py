import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile

import release

spec = importlib.util.spec_from_file_location("qualification", Path(__file__).with_name("qualify.py"))
qualification = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qualification)


class ReleaseTests(unittest.TestCase):
    def metadata(self):
        revision, annotation = "a" * 40, "b" * 40
        return {
            "": {"full_name": "example/extension", "default_branch": "main"},
            "branches/main": {"protected": True},
            "git/ref/tags/v0.1.0-rc.1": {"ref": "refs/tags/v0.1.0-rc.1", "object": {"type": "tag", "sha": annotation}},
            "git/tags/" + annotation: {"tag": "v0.1.0-rc.1", "sha": annotation, "verification": {"verified": True, "reason": "valid"}, "object": {"type": "commit", "sha": revision}},
            "commits/" + revision: {"sha": revision, "commit": {"verification": {"verified": True, "reason": "valid"}}},
            "compare/" + revision + "...main": {"status": "identical", "merge_base_commit": {"sha": revision}},
        }

    def test_only_verified_annotated_prerelease_on_protected_main_is_eligible(self):
        docs = self.metadata()
        self.assertEqual(release.verify_tag("example/extension", "v0.1.0-rc.1", docs.__getitem__)["revision"], "a" * 40)
        mutations = [
            ("branches/main", lambda d: d.update(protected=False)),
            ("git/ref/tags/v0.1.0-rc.1", lambda d: d["object"].update(type="commit")),
            ("git/tags/" + "b" * 40, lambda d: d["verification"].update(verified=False)),
            ("git/tags/" + "b" * 40, lambda d: d["object"].update(type="tag")),
            ("commits/" + "a" * 40, lambda d: d["commit"]["verification"].update(reason="unverified_email")),
            ("compare/" + "a" * 40 + "...main", lambda d: d.update(status="diverged")),
            ("compare/" + "a" * 40 + "...main", lambda d: d["merge_base_commit"].update(sha="c" * 40)),
        ]
        for path, mutate in mutations:
            changed = copy.deepcopy(docs)
            mutate(changed[path])
            with self.subTest(path=path), self.assertRaises(ValueError):
                release.verify_tag("example/extension", "v0.1.0-rc.1", changed.__getitem__)

    def test_stable_snapshot_and_malformed_tags_fail_before_network(self):
        for tag in ("v0.1.0", "v0.1.0-SNAPSHOT", "main", "v01.0.0-rc.1", "v0.1.0-rc.1\n", "v0.1.0-rc.1;echo bad"):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release.verify_tag("example/extension", tag, lambda path: self.fail("unexpected network"))

    def test_provider_rejects_missing_metadata_wrong_version_or_shaded_classes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "provider.jar"
            entries = {"META-INF/LICENSE": "license", "META-INF/NOTICE": "notice", "bounded-delegation.properties": "version=0.1.0-rc.1\n",
                       "META-INF/services/org.keycloak.protocol.oidc.TokenExchangeProviderFactory": "provider",
                       "META-INF/services/org.keycloak.services.resource.RealmResourceProviderFactory": "discovery",
                       "io/alien6/keycloak/delegation/Provider.class": b"\xca\xfe\xba\xbe\x00\x00\x00A"}
            for change in ({}, {"bounded-delegation.properties": "version=foreign"}, {"org/keycloak/Shaded.class": b"\xca\xfe\xba\xbe\x00\x00\x00A"},
                           {"io/alien6/keycloak/delegation/Provider.class": b"\xca\xfe\xba\xbe\x00\x00\x00B"}):
                with ZipFile(path, "w") as jar:
                    for name, value in {**entries, **change}.items():
                        jar.writestr(name, value)
                if not change:
                    release.validate_jar(path, "0.1.0-rc.1")
                    compiled = Path(temporary) / "classes"
                    for name, value in entries.items():
                        target = compiled / name
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(value.encode() if isinstance(value, str) else value)
                    release.validate_jar(path, "0.1.0-rc.1", compiled)
                    (compiled / "io/alien6/keycloak/delegation/Provider.class").write_bytes(b"changed after functional tests")
                    with self.assertRaisesRegex(ValueError, "bytes differ"):
                        release.validate_jar(path, "0.1.0-rc.1", compiled)
                else:
                    with self.assertRaises(ValueError):
                        release.validate_jar(path, "0.1.0-rc.1")

    def test_bundle_refuses_missing_foreign_dirty_or_tampered_cells(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "compatibility.json").write_text(json.dumps({"keycloak": ["26.8.0"]}))
            incoming = root / "incoming"
            incoming.mkdir()
            files = {}
            for suffix in (".jar", "-sources.jar", "-javadoc.jar", "-sbom.json", "-qualification.json"):
                name = "bounded-delegation-0.1.0-rc.1-keycloak-26.8.0" + suffix
                (incoming / name).write_bytes(b"synthetic asset")
                files[name] = hashlib.sha256(b"synthetic asset").hexdigest()
            valid = {"schema": 1, "version": "0.1.0-rc.1", "revision": "a" * 40, "keycloak": "26.8.0", "releasable": True, "worktree_dirty": False, "files": files}
            with patch.object(release, "ROOT", root), patch.object(release, "pom_version", return_value="0.1.0-rc.1"), \
                    patch.object(release.subprocess, "check_output", return_value="a" * 40):
                for change in ({"revision": "b" * 40}, {"version": "0.1.0-rc.2"}, {"keycloak": "99.0.0"}, {"releasable": False}, {"worktree_dirty": True}, {"files": {}}):
                    (incoming / "release-26.8.0.json").write_text(json.dumps({**valid, **change}))
                    with self.subTest(change=change), self.assertRaises(ValueError):
                        release.assemble(incoming, root / "out")
                (incoming / "release-26.8.0.json").write_text(json.dumps(valid))
                first = next(iter(files))
                (incoming / first).write_bytes(b"tampered")
                with self.assertRaisesRegex(ValueError, "checksum"):
                    release.assemble(incoming, root / "out")

    def test_skips_failures_duplicates_and_empty_reports_cannot_qualify(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for case in ("", '<testcase classname="io.alien6.keycloak.delegation.T" name="one"><skipped/></testcase>',
                         '<testcase classname="io.alien6.keycloak.delegation.T" name="one"><failure/></testcase>',
                         '<testcase classname="io.alien6.keycloak.delegation.T" name="one"/>' * 2):
                (root / "TEST-suite.xml").write_text('<testsuite failures="0" errors="0" skipped="0">' + case + '</testsuite>')
                with self.subTest(case=case), self.assertRaises(ValueError):
                    qualification.outcomes(root)


if __name__ == "__main__":
    unittest.main()
