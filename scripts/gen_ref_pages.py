"""Generate the code reference pages."""

import shutil
from pathlib import Path

import mkdocs_gen_files


root = Path(__file__).parent.parent
src_dir = root / "aia_chaser"
reference_dir = root / "docs" / "reference"

# shutil.rmtree(reference_dir, ignore_errors=True)

nav = mkdocs_gen_files.Nav()

for path in sorted(src_dir.rglob("*.py")):
    module_path = path.relative_to(root).with_suffix("")
    doc_path = path.relative_to(root).with_suffix(".md")
    full_doc_path = reference_dir / doc_path

    parts = tuple(module_path.parts)

    if parts[-1] == "__init__":
        print(parts)
        parts = parts[:-1]
    elif parts[-1] == "__main__":
        continue

    nav[parts] = doc_path.as_posix()

    with mkdocs_gen_files.open(full_doc_path, "w") as fd:
        identifier = ".".join(parts)
        print("::: " + identifier, file=fd)

    mkdocs_gen_files.set_edit_path(full_doc_path, path.relative_to(root))

with mkdocs_gen_files.open(reference_dir / "summary.md", "w") as nav_file:
    nav_file.writelines(nav.build_literate_nav())
