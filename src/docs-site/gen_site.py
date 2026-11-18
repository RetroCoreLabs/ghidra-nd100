#!/usr/bin/env python3
"""Build the source tree of the ghidra-nd100 documentation site.

Run from the repository root:

    python src/docs-site/gen_site.py <out folder>
    mkdocs build --strict -f <out folder>/mkdocs.yml -d <site folder>

The site is MkDocs + Material, "shape B" of the RetroCore Labs DOCS-SITE standard: this script
wipes <out folder> and writes docs/ plus a child mkdocs.yml that INHERITs the committed
src/docs-site/mkdocs.yml (theme and extensions) and adds the generated nav. Nothing generated is
committed. MkDocs was chosen over DocFX because the documentation is guides and Java loaders and
analyzers; the only C# in the repository is the internal code generator, whose API nobody uses.

What goes on the site (only files git tracks; checked with git ls-files):
  - README.md as the home page, the guides in src/docs/, CONTRIBUTING and SECURITY;
  - one reference page per Java class of the plugin, made from the class comment in the
    template source (src/NDGen.Generators.Ghidra/Ghidra/ND-100/..., the source of truth), with
    the name Ghidra shows, "uses" / "used by" links and the source in a fold-out.
What stays off, on purpose:
  - src/PLAN.md (a plan of open work, not documentation; it is linked on GitHub instead);
  - the generated ND-100/ tree and the generator's internal template READMEs;
  - nd100-definitions (another repository).
A relative link to a file that is not a page becomes a link to that file on GitHub.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys

REPO_URL = "https://github.com/RetroCoreLabs/ghidra-nd100"
JAVA_DIR = "src/NDGen.Generators.Ghidra/Ghidra/ND-100/src/main/java/nd/bpun"

# repository path -> site path, for the hand-written pages
PAGES = [
    ("README.md", "index.md", "Home"),
    ("src/docs/SCREENSHOTS.md", "guides/screenshots.md", "Screenshots"),
    ("src/docs/HOW-THE-SPEC-IS-BUILT.md", "guides/how-the-spec-is-built.md", "How the spec is built"),
    ("src/docs/HANDOFF-BRF-LOADER.md", "guides/brf-loader.md", "BRF loader"),
    ("src/docs/HANDOFF-REGISTER-JUMPS.md", "guides/register-jumps.md", "Jumps through a register"),
    (".github/CONTRIBUTING.md", "contributing.md", "Contributing"),
    (".github/SECURITY.md", "security.md", "Security"),
]
SHOTS = "src/assets/screenshots"    # taken by hand; see src/docs/SCREENSHOTS.md
ASSETS = ["src/assets/ghidra-nd100.svg", "src/assets/ghidra-nd100.ico", "src/assets/ghidra-nd100.png",
          "src/docs-site/extra.css"]

# The label may hold one level of brackets: a badge is an image link inside a link.
LINK = re.compile(r"(!?)\[((?:[^\[\]]|\[[^\]]*\])*)\]\(([^)\s]+)\)")


def tracked() -> set[str]:
    out = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True).stdout
    return set(out.splitlines())


def rewrite_links(text: str, src: str, dst: str, page_of: dict[str, str]) -> str:
    """Point each relative link at the site page for that file, or at the file on GitHub."""
    src_dir = os.path.dirname(src)
    dst_dir = os.path.dirname(dst)

    def fix(m: re.Match) -> str:
        bang, label, target = m.groups()
        if re.match(r"^[a-z]+:", target) or target.startswith("#"):
            return m.group(0)
        path, _, anchor = target.partition("#")
        full = os.path.normpath(os.path.join(src_dir, path)).replace("\\", "/")
        if full.startswith("../"):
            # README's "../../releases": a GitHub page of this repository
            rest = full.lstrip("./").split("/", 1)[-1] if "/" in full else full.lstrip("./")
            return f"{bang}[{label}]({REPO_URL}/{rest}{'#' + anchor if anchor else ''})"
        if bang and full.startswith(SHOTS + "/") and full not in page_of:
            # a screenshot on the plan that has not been taken yet (src/docs/SCREENSHOTS.md)
            return f"*Not captured yet: `{full}`.*"
        if full in page_of:
            rel = os.path.relpath(page_of[full], dst_dir or ".").replace("\\", "/")
            return f"{bang}[{label}]({rel}{'#' + anchor if anchor else ''})"
        kind = "tree" if os.path.isdir(full) else "blob"
        return f"{bang}[{label}]({REPO_URL}/{kind}/main/{full}{'#' + anchor if anchor else ''})"

    return LINK.sub(fix, text)


# ------------------------------------------------------------------ Java class pages

def class_comment(src: str) -> str:
    """The Javadoc block right before the class declaration, as Markdown."""
    m = re.search(r"/\*\*(.*?)\*/\s*(?:@\w+(?:\([^)]*\))?\s*)*(?:public\s+)?(?:final\s+)?class\s",
                  src, re.S)
    if not m:
        return ""
    lines = []
    for ln in m.group(1).splitlines():
        ln = re.sub(r"^\s*\* ?", "", ln)
        lines.append(ln.rstrip())
    text = "\n".join(lines).strip("\n")
    text = re.sub(r"\{@code\s+([^}]*)\}", r"`\1`", text)
    text = re.sub(r"\{@link(?:plain)?\s+([^}]*)\}", r"`\1`", text)
    text = re.sub(r"</?p>", "\n", text)
    text = text.replace("<pre>", "\n```\n").replace("</pre>", "\n```\n")
    # Javadoc lists are written as "  - item" with continuation lines indented under the text.
    # Markdown reads four leading spaces as code, so drop the indentation of plain prose lines
    # and keep list items flat.
    out = []
    in_code = False
    for ln in text.splitlines():
        if ln.strip().startswith("```"):
            in_code = not in_code
            out.append(ln.strip())
            continue
        if in_code:
            out.append(ln)
            continue
        # Javadoc prose writes "<control byte>" and "<checksum>" as text; in Markdown they would
        # be read as HTML tags and vanish. Escape them outside `code`.
        ln = re.sub(r"(`[^`]*`)|<", lambda m: m.group(1) or "&lt;", ln)
        s = ln.strip()
        if re.match(r"^[-*] ", s):
            # Markdown starts a list only after a blank line; Javadoc puts the first item
            # straight under its introducing sentence.
            if out and out[-1].strip() and not re.match(r"^[-*] ", out[-1].strip()):
                out.append("")
            out.append(s)
        elif s and out and re.match(r"^[-*] ", out[-1].strip()) and ln.startswith(" "):
            out[-1] = out[-1] + " " + s           # continuation of a list item
        else:
            out.append(s)
    return re.sub(r"\n{3,}", "\n\n", "\n".join(out)).strip()


def first_sentence(md: str) -> str:
    para = md.split("\n\n", 1)[0].replace("\n", " ")
    m = re.match(r"(.+?[.!?])(\s|$)", para)
    return (m.group(1) if m else para)[:220]


def java_pages(files: list[str]) -> tuple[list[tuple[str, str]], dict[str, str]]:
    names = [os.path.splitext(os.path.basename(f))[0] for f in files]
    srcs = {n: open(f, encoding="utf-8").read() for n, f in zip(names, files)}
    uses = {n: sorted(o for o in names if o != n and re.search(r"\b" + o + r"\b", srcs[n]))
            for n in names}
    used_by = {n: sorted(o for o in names if n in uses[o]) for n in names}
    groups: dict[str, list[tuple[str, str]]] = {"Loaders": [], "Analyzers": [], "Helpers": []}
    pages = {}
    for n, f in zip(names, files):
        src = srcs[n]
        comment = class_comment(src)
        if re.search(r"class\s+\w+\s+extends\s+\w*Loader\b", src):
            group = "Loaders"
        elif re.search(r"class\s+\w+\s+extends\s+\w*Analyzer\b", src):
            group = "Analyzers"
        else:
            group = "Helpers"
        shown = re.search(r'static final String \w*NAME\s*=\s*"([^"]+)"', src)
        groups[group].append((n, first_sentence(comment) if comment else ""))
        body = [f"<!-- generated by src/docs-site/gen_site.py from {f}; edit the class comment there -->",
                f"# {n}", ""]
        facts = [f"**Kind:** {group[:-1].lower()}"]
        if shown:
            facts.append(f"**Name in Ghidra:** {shown.group(1)}")
        facts.append(f"**Source:** [{os.path.basename(f)}]({REPO_URL}/blob/main/{f}) "
                     f"({src.count(chr(10))} lines)")
        body += ["  \n".join(facts), ""]
        if comment:
            body += [comment, ""]
        if uses[n]:
            body += ["**Uses:** " + ", ".join(f"[{o}]({o}.md)" for o in uses[n]), ""]
        if used_by[n]:
            body += ["**Used by:** " + ", ".join(f"[{o}]({o}.md)" for o in used_by[n]), ""]
        code = "\n".join("    " + ln for ln in src.splitlines())
        body += [f'??? abstract "The source of {os.path.basename(f)}"', "", "    ```java", code, "    ```", ""]
        pages[n] = "\n".join(body)
    index = ["<!-- generated by src/docs-site/gen_site.py -->",
             "# Plugin reference", "",
             "One page per Java class of the plugin, made from the class comment in the source. "
             "Loaders read a file into Ghidra; analyzers run during auto-analysis; helpers are "
             "used by both.", ""]
    nav = []
    for g, items in groups.items():
        if not items:
            continue
        index += [f"## {g}", "", "| Class | What it does |", "|---|---|"]
        for n, s in sorted(items):
            index.append(f"| [{n}]({n}.md) | {s.replace('|', '/')} |")
        index.append("")
        nav.append((g, sorted(n for n, _ in items)))
    pages["index"] = "\n".join(index)
    return nav, pages


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    out = os.path.abspath(sys.argv[1])
    if os.path.exists(os.path.join(out, "mkdocs.yml")) or not os.path.exists(out):
        shutil.rmtree(out, ignore_errors=True)
    elif os.listdir(out):
        print(f"refusing to wipe {out}: it is not a folder this script made", file=sys.stderr)
        return 1
    docs = os.path.join(out, "docs")
    os.makedirs(docs)
    have = tracked()

    page_of = {}
    for src, dst, _ in PAGES:
        if src in have:
            page_of[src] = dst
        else:
            print(f"skipped {src}: not tracked by git", file=sys.stderr)
    for f in sorted(have):
        if f.startswith(SHOTS + "/"):
            page_of[f] = "assets/screenshots/" + os.path.basename(f)
            os.makedirs(os.path.join(docs, "assets", "screenshots"), exist_ok=True)
            shutil.copy(f, os.path.join(docs, page_of[f]))
    for src, dst in page_of.items():
        if not src.endswith(".md"):
            continue
        text = open(src, encoding="utf-8").read()
        text = rewrite_links(text, src, dst, page_of)
        os.makedirs(os.path.join(docs, os.path.dirname(dst)), exist_ok=True)
        open(os.path.join(docs, dst), "w", encoding="utf-8").write(text)
    for a in ASSETS:
        os.makedirs(os.path.join(docs, "assets"), exist_ok=True)
        shutil.copy(a, os.path.join(docs, "assets", os.path.basename(a)))

    files = sorted(f for f in have if f.startswith(JAVA_DIR + "/") and f.endswith(".java"))
    nav_groups, pages = java_pages(files)
    os.makedirs(os.path.join(docs, "reference"))
    for n, text in pages.items():
        open(os.path.join(docs, "reference", n + ".md"), "w", encoding="utf-8").write(text)

    # the instruction set, one page per instruction, from the nd100-definitions submodule
    sys.dont_write_bytecode = True          # no __pycache__ beside the source
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import gen_isa
    isa_pages, isa_nav = gen_isa.build()
    for path, text in isa_pages.items():
        os.makedirs(os.path.join(docs, os.path.dirname(path)), exist_ok=True)
        open(os.path.join(docs, path), "w", encoding="utf-8").write(text)

    titles = {dst: t for src, dst, t in PAGES if src in page_of}
    # INHERIT takes the base file by its full path: the output folder is usually outside the
    # checkout (the runner's temp folder, or another drive), where a relative path can not reach.
    base = os.path.abspath("src/docs-site/mkdocs.yml").replace("\\", "/")
    y = ["# generated by src/docs-site/gen_site.py", f"INHERIT: {base}",
         "docs_dir: docs", "nav:", "  - Home: index.md"]
    y.append("  - Guides:")
    for dst, t in titles.items():
        if dst.startswith("guides/"):
            y.append(f"    - {t}: {dst}")
    y.append("  - Instruction set:")
    for t, v in isa_nav:
        if isinstance(v, str):
            y.append(f"    - {t}: {v}")
        else:
            y.append(f'    - "{t}":')
            for n, path in v:
                y.append(f'      - "{n}": {path}')
    y.append("  - Plugin reference:")
    y.append("    - Overview: reference/index.md")
    for g, names in nav_groups:
        y.append(f"    - {g}:")
        for n in names:
            y.append(f"      - {n}: reference/{n}.md")
    for dst in ("contributing.md", "security.md"):
        if dst in titles:
            y.append(f"  - {titles[dst]}: {dst}")
    open(os.path.join(out, "mkdocs.yml"), "w", encoding="utf-8").write("\n".join(y) + "\n")
    print(f"wrote {len(page_of)} pages, {len(pages)} reference pages, {len(isa_pages)} instruction-set pages to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
