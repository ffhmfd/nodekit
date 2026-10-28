import importlib.util
import pathlib
import subprocess
import tempfile
import unittest


class ExportTests(unittest.TestCase):
    def test_snapshot_excludes_private_and_untracked_files(self):
        spec = importlib.util.spec_from_file_location("export_public", pathlib.Path(__file__).with_name("export-public.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "repo"
            root.mkdir()
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            for name in ["go.mod", "internal/demo.go", "docs/validation/private.md", "secret.key", "internal/token.json", "README.md"]:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            (root / "internal/untracked.go").write_text("private", encoding="utf-8")
            dest = pathlib.Path(tmp) / "public"
            module.export(root, dest)
            files = {p.relative_to(dest).as_posix() for p in dest.rglob("*") if p.is_file()}
            self.assertEqual(files, {"go.mod", "internal/demo.go", "README.md"})
            with self.assertRaises(FileExistsError):
                module.export(root, dest)


if __name__ == "__main__":
    unittest.main()
