import importlib.util
from pathlib import Path
import re
import shutil
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("project", Path(__file__).with_name("check-project.py"))
project = importlib.util.module_from_spec(spec)
spec.loader.exec_module(project)


class ProjectContractTests(unittest.TestCase):
    def test_current_project_contract(self):
        project.check()

    def test_unqualified_default_sdk_cannot_hide_behind_matrix_overrides(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("compatibility.json", "pom.xml"):
                shutil.copyfile(project.ROOT / name, root / name)
            path = root / "pom.xml"
            original = path.read_text()
            path.write_text(re.sub(r"<keycloak.version>[^<]+</keycloak.version>", "<keycloak.version>99.0.0</keycloak.version>", original))
            with self.assertRaisesRegex(ValueError, "not qualified"):
                project.check(root)


if __name__ == "__main__":
    unittest.main()
