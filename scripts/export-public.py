"""Export tracked public source only, without operational docs or git history."""
import argparse
import pathlib
import shutil
import subprocess


TOP = {"README.md", "LICENSE", "THIRD_PARTY_NOTICES.md", "go.mod", "go.sum", "install.sh", ".gitignore"}
SCRIPTS = {"build.sh", "package.sh", "verify-units.sh", "remote.ps1", "cross-test.ps1", "export-public.py", "test-export-public.py"}


def allowed(path):
    name = path.as_posix()
    if name in TOP:
        return True
    if path.parts[0] in {"cmd", "internal", "tests"}:
        return path.suffix == ".go"
    if path.parts[0] == "packaging":
        return path.suffix in {".go", ".service"}
    if len(path.parts) == 2 and path.parts[0] == "scripts":
        return path.name in SCRIPTS
    return name == ".github/workflows/release.yml"


def export(root, dest):
    root, dest = pathlib.Path(root).resolve(), pathlib.Path(dest).resolve()
    if dest.exists():
        raise FileExistsError(dest)
    names = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z"]).decode().split("\0")
    selected = []
    for name in filter(None, names):
        relative = pathlib.PurePosixPath(name)
        if not allowed(relative):
            continue
        source = root / relative
        if source.is_symlink() or not source.resolve().is_relative_to(root):
            raise ValueError(f"Refusing public symlink: {name}")
        selected.append((source, relative))
    dest.mkdir(parents=True)
    for source, relative in selected:
        target = dest / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(0o755 if target.suffix == ".sh" else 0o644)
    return len(selected)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=pathlib.Path)
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    print(f"Exported {export(args.root, args.destination)} public files to {args.destination}")
