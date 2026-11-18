"""The instruction-set pages of the documentation site, made from the nd100-definitions YAML.

Called by gen_site.py. Reads the submodule as checked out (nd100-definitions/specs): one page
per instruction file in specs/instructions/, an overview by category, the addressing modes
(specs/operand_types/addressing_modes.yaml) and the status register bits (specs/cpu.yaml).
Every sentence on these pages comes from those files; nothing is written here by hand except
the headings and the "how to read this page" text. A field that a file does not have is left
out of its page, never filled with a placeholder. To improve a page, improve the YAML in the
nd100-definitions repository.

The source links point at the exact nd100-definitions commit this repository pins.
"""
from __future__ import annotations

import glob
import html
import os
import re
import subprocess
import textwrap

import yaml

SPECS = "nd100-definitions/specs"
DEFS_URL = "https://github.com/RetroCoreLabs/nd100-definitions"


def _pinned_commit() -> str:
    try:
        return subprocess.run(["git", "-C", "nd100-definitions", "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "main"


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def text_md(t: str | None) -> str:
    """YAML prose to Markdown. Indented runs and <ascii-table> blocks become code blocks, so
    formulas and drawn tables keep their columns."""
    if not t:
        return ""
    t = textwrap.dedent(str(t)).strip("\n")
    t = re.sub(r"[ \t]*<ascii-table>\n(.*?)\n[ \t]*</ascii-table>",
               lambda m: "\n```text\n" + textwrap.dedent(m.group(1)) + "\n```\n", t, flags=re.S)
    out: list[str] = []
    in_fence = False
    in_indent = False
    for ln in t.splitlines():
        if ln.startswith("```"):
            in_fence = not in_fence
            out.append(ln)
            continue
        if in_fence:
            out.append(ln)
            continue
        indented = ln.startswith("    ") or ln.startswith("\t")
        if indented and not in_indent:
            # start an indented run as a fenced block: an indented block right under a
            # paragraph line would otherwise be read as more paragraph
            out += ["", "```text"]
            in_indent = True
        elif not indented and in_indent and ln.strip():
            out += ["```", ""]
            in_indent = False
        if in_indent:
            out.append(ln[4:] if ln.startswith("    ") else ln.lstrip("\t"))
        else:
            # the definitions are written line by line (a formula on its own line, then the
            # sentence); keep each line break instead of running the lines together
            if ln.strip() and out and out[-1].strip() and not out[-1].startswith("```")                     and not re.match(r"\s*([-*]|\d+\.) ", ln):
                out[-1] = out[-1] + "  "
            out.append(ln.rstrip())
    if in_indent:
        while out and not out[-1].strip():
            out.pop()
        out.append("```")
    s = "\n".join(out)
    # "<dr>" in prose would be read as an HTML tag; escape it outside code
    parts = re.split(r"(```.*?```|`[^`]*`)", s, flags=re.S)
    for i in range(0, len(parts), 2):
        parts[i] = parts[i].replace("<", "&lt;")
    return re.sub(r"\n{3,}", "\n\n", "".join(parts)).strip()


def bits_of(spec: str) -> tuple[int, int]:
    a, _, b = str(spec).partition("-")
    hi, lo = int(a), int(b or a)
    return max(hi, lo), min(hi, lo)


def mask_of(m: str | None) -> int:
    return int(str(m).replace("_", ""), 2) if m else 0


def encoding_html(opcode: int, mask: int, operands: list[dict]) -> str:
    """A 16-cell drawing of the instruction word: fixed bits as 0/1, fields named."""
    owner: dict[int, str] = {}
    for op in operands or []:
        if "bits" not in op:
            continue
        hi, lo = bits_of(op["bits"])
        for b in range(lo, hi + 1):
            owner[b] = op.get("name", "")
    head = "".join(f'<th>{b}</th>' for b in range(15, -1, -1))
    cells = []
    b = 15
    while b >= 0:
        if mask >> b & 1:
            cells.append(f'<td class="isa-fixed">{opcode >> b & 1}</td>')
            b -= 1
            continue
        name = owner.get(b, "")
        n = 1
        while b - n >= 0 and not (mask >> (b - n) & 1) and owner.get(b - n, "") == name:
            n += 1
        label = html.escape(name.replace("_", " ")) if name else ""
        cls = "isa-field" if name else "isa-free"
        cells.append(f'<td class="{cls}" colspan="{n}">{label}</td>')
        b -= n
    return ('<div class="isa-enc"><table class="isa-word">\n<thead><tr>' + head + '</tr></thead>\n<tbody><tr>'
            + "".join(cells) + "</tr></tbody>\n</table></div>")


def w_disp(w: dict, X: int, I: int, B: int, regs: dict) -> int:
    """The displacement of a worked example: the number in its instruction line.

    Read from the LDA line of the example's code (the operand field holds exactly one
    number, the displacement), so the drawing uses what the listing shows.
    """
    for line in w["code"].splitlines():
        if "LDA" in line:
            op = line.split("LDA", 1)[1].split("%", 1)[0]
            m = re.search(r"-?\d+", op)
            if m:
                return int(m.group(0), 8)
    raise SystemExit(f"worked example {w['title']!r}: no LDA line with a displacement")


def mode_svg(v: dict, w: dict) -> str:
    """One drawing of how an addressing mode forms its effective address, with worked numbers.

    The steps come only from the mode's X, I and B bits in nd100-definitions
    (operand_types/addressing_modes.yaml): B picks the B register as base; with neither B nor
    I set and X set, X itself is the base ((X) + disp); otherwise P is the base. I reads the
    word at that address and uses it as the address; X is then added last.
    The numbers are the worked example (one of the mode's worked_examples) in the same file: a practical case with the
    register and memory contents it reads. The address is recomputed here from those
    contents, and a mismatch with the file's effective_address_value stops the build.
    Colours come from classes in extra.css (light and dark).
    """
    f = {}
    for d in v.get("fields") or []:
        f.update(d)
    X, I, B = int(f.get("X", 0)), int(f.get("I", 0)), int(f.get("B", 0))
    ex = {k: int(x, 8) for k, x in w["registers"].items()}
    mem = {int(k, 8): int(x, 8) for k, x in w["memory"].items()}
    if B:
        base, base_sub = "B", "B register"
    elif X and not I:
        base, base_sub = "X", "X register"
    else:
        base, base_sub = "P", "P register = address of this instruction"
    o = lambda n: f"{n & 0xFFFF:06o}"
    disp = w_disp(w, X, I, B, ex)
    a1 = (ex[base] + disp) & 0xFFFF
    ds = f"{disp:o}" if disp >= 0 else f"-{-disp:o}"   # octal, as written in the code
    e = html.escape
    W, x0, cw = 760, 40, 42                       # 16 cells of 42 px from x=40
    out = []

    def box(x, y, w, h, cls, title, sub=""):
        out.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6" class="{cls}"/>')
        ty = y + (h / 2 + 5 if not sub else h / 2 - 3)
        out.append(f'<text x="{x + w / 2}" y="{ty}" class="am-t">{e(title)}</text>')
        if sub:
            out.append(f'<text x="{x + w / 2}" y="{y + h / 2 + 14}" class="am-s">{e(sub)}</text>')

    def wire(x1, y1, x2, y2, label="", dashed=False):
        cls = "am-w am-dash" if dashed else "am-w"
        out.append(f'<path d="M{x1} {y1} L{x2} {y2}" class="{cls}" marker-end="url(#am-arrow)"/>')
        if label:
            out.append(f'<text x="{(x1 + x2) / 2 + 10}" y="{(y1 + y2) / 2 + 5}" class="am-v">{e(label)}</text>')

    def adder(cx, cy):
        out.append(f'<circle cx="{cx}" cy="{cy}" r="17" class="am-add"/>')
        out.append(f'<text x="{cx}" y="{cy + 6}" class="am-t am-plus">+</text>')

    # the instruction word: bit numbers, then opcode | X | I | B | disp
    for b in range(16):
        out.append(f'<text x="{x0 + (15 - b) * cw + cw / 2}" y="22" class="am-s">{b}</text>')
    box(x0, 30, 5 * cw, 40, "am-word", "opcode")
    for i, (name, val) in enumerate((("X", X), ("I", I), ("B", B))):
        cls = "am-word am-on" if val else "am-word"
        box(x0 + (5 + i) * cw, 30, cw, 40, cls, f"{name}={val}")
    box(x0 + 8 * cw, 30, 8 * cw, 40, "am-word", f"disp = {ds}", f"binary {disp & 0xFF:08b} = {disp & 0xFF:03o} octal, signed")

    # base register and displacement, added
    bx, dx, bw = 50, x0 + 8 * cw + 4 * cw - 110, 220
    box(bx, 110, bw, 50, "am-reg", f"{base} = {o(ex[base])}", base_sub)
    box(dx, 110, bw, 50, "am-disp", f"disp = {ds}", "from the instruction word")
    wire(x0 + 7 * cw + cw / 2, 70, bx + bw - 30, 110, "", dashed=True)   # the mode bits pick the base
    wire(dx + bw / 2, 70, dx + bw / 2, 110, "", dashed=True)
    cx, cy = W / 2, 205
    adder(cx, cy)
    wire(bx + bw / 2, 160, cx - 15, cy - 8)
    wire(dx + bw / 2, 160, cx + 15, cy - 8)
    y = cy + 17
    addr, steps = a1, [f"{o(ex[base])} {'-' if disp < 0 else '+'} {abs(disp):o} = {o(a1)}"]
    if I:
        ptr = mem[a1]
        box(cx - 170, y + 44, 340, 54, "am-mem", f"memory[{o(a1)}] = {o(ptr)}",
            "this word is the indirect address")
        wire(cx, y, cx, y + 44, o(a1))
        y += 98
        steps.append(f"memory[{o(a1)}] = {o(ptr)}")
        addr = ptr
    if X and base != "X":                         # X as the base is added already
        ay = y + 54
        adder(cx, ay)
        wire(cx, y, cx, ay - 17, o(addr))
        box(dx + 40, ay - 25, bw - 40, 50, "am-reg", f"X = {o(ex['X'])}", "X register")
        wire(dx + 40, ay, cx + 17, ay)
        steps.append(f"{o(addr)} + {o(ex['X'])} = {o(addr + ex['X'])}")
        addr = (addr + ex["X"]) & 0xFFFF
        y = ay + 17
    box(cx - 190, y + 44, 380, 54, "am-ea", f"effective address = {o(addr)}",
        v.get("effective_address", ""))
    wire(cx, y, cx, y + 44, o(addr))
    y += 98
    if o(addr) != w["effective_address_value"]:
        raise SystemExit(f"{v['name']}: worked example gives {o(addr)}, file says "
                         f"{w['effective_address_value']}")
    val = mem[addr]
    box(cx - 190, y + 44, 380, 54, "am-mem", f"memory[{o(addr)}] = {o(val)}",
        w["result"])
    wire(cx, y, cx, y + 44, "")
    y += 98
    out.append(f'<text x="{W / 2}" y="{y + 30}" class="am-s">Worked example, all numbers octal: '
               f'{e("; ".join(steps))}</text>')
    H = y + 46
    return (f'<svg class="am-svg" viewBox="0 0 {W} {H}" role="img" '
            f'aria-label="{e(v.get("mode", ""))}: effective address {e(v.get("effective_address", ""))}">'
            '<defs><marker id="am-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
            'markerHeight="7" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" class="am-head"/>'
            '</marker></defs>' + "".join(out) + "</svg>")


def build(have_specs: bool = True) -> tuple[dict[str, str], list[tuple[str, str]]]:
    """Return ({site path: markdown}, nav entries [(title, site path)])."""
    if not os.path.isdir(os.path.join(SPECS, "instructions")):
        raise SystemExit("nd100-definitions is not checked out: git submodule update --init")
    commit = _pinned_commit()
    cpu = yaml.safe_load(open(os.path.join(SPECS, "cpu.yaml"), encoding="utf-8"))
    meta = cpu.get("metadata", cpu)
    classes = {c["name"]: c for c in meta.get("instruction_classes", [])}
    sts = next((r for r in meta.get("registers", []) if r.get("name") == "STS"), {})
    flags = {f["name"]: f for f in sts.get("bits", [])}
    # manual titles and privilege wording: cpu.yaml; groups, their order, sources and text:
    # categories.yaml. The same data the Ghidra plugin's PDF manual is made from.
    manuals = {m["id"]: m["title"] for m in meta.get("manuals", [])}
    priv_text = {p["name"]: p["description"] for p in meta.get("privilege_levels", [])}
    catdefs = yaml.safe_load(open(os.path.join(SPECS, "categories.yaml"), encoding="utf-8"))["categories"]
    cat_order = [c["name"] for c in catdefs]

    def ref_md(r: dict) -> str:
        t = manuals.get(r["manual"])
        out = f"{t} ({r['manual']})" if t else r["manual"]
        if r.get("page"):
            out += f", page {r['page']}"
        elif r.get("pages"):
            out += (", pages " if "-" in str(r["pages"]) else ", page ") + str(r["pages"])
        if r.get("section"):
            out += f", section {r['section']}"
        return out

    insns = []
    for f in sorted(glob.glob(os.path.join(SPECS, "instructions", "*.yaml"))):
        if os.path.basename(f).startswith("_"):
            continue
        d = yaml.safe_load(open(f, encoding="utf-8"))["instruction"]
        d["_file"] = os.path.relpath(f, "nd100-definitions").replace("\\", "/")
        insns.append(d)

    pages: dict[str, str] = {}
    by_cat: dict[str, list[dict]] = {}
    for d in insns:
        cat = str(d.get("category") or "Other").strip().replace("_", " ")
        by_cat.setdefault(cat, []).append(d)
    used = {}
    for d in insns:
        s = slug(str(d["name"]))
        if s in used:
            s = s + "-" + slug(os.path.splitext(os.path.basename(d["_file"]))[0])
        used[s] = d
        d["_slug"] = s

    for d in insns:
        name = str(d["name"])
        desc = text_md(d.get("description"))
        summary, _, rest = desc.partition("\n\n")
        summary = summary.replace("\n", " ").strip()
        cls = classes.get(d.get("instruction_class") or "")
        operands = d.get("operands") or (cls or {}).get("operands") or []
        mask = mask_of(d.get("mask") or (cls or {}).get("mask"))
        try:
            opcode = int(str(d["opcode"]), 8)
        except ValueError:
            opcode = 0
        cat = str(d.get("category") or "Other").strip().replace("_", " ")
        # front matter: rank instruction pages first in the site search, so "SAT" finds SAT on top
        L = ["---", "search:", "  boost: 3", "---",
             f"<!-- generated by src/docs-site/gen_isa.py from nd100-definitions/{d['_file']} -->",
             f"# {name}", ""]
        if summary:
            L += [f"**{summary}**", ""]
        rows = [("Opcode", f"`{d['opcode']}` (octal)")]
        if mask:
            rows.append(("Fixed bits (mask)", f"`{mask:016b}`"))
        if d.get("format"):
            rows.append(("Assembler format", "`" + str(d["format"]).strip() + "`"))
        rows.append(("Category", f"[{cat}](index.md#{slug(cat)})"))
        if cls:
            rows.append(("Instruction class", str(cls["name"]).replace("_", " ")))
        if d.get("privilege"):
            p = str(d["privilege"]).strip().lower()
            rows.append(("Privilege", f"{p}: {priv_text[p]}" if p in priv_text else p))
        for r in d.get("manual_refs") or []:
            rows.append(("Manual", ref_md(r)))
        if d.get("flags_affected"):
            fl = []
            for x in d["flags_affected"]:
                x = str(x)
                fd = flags.get(x)
                # only a real STS bit gets a link; S, for one, is the sign of a result, not a bit
                fl.append(f"[{x}](status-flags.md#{slug(x)}) ({fd['description']})" if fd else x)
            rows.append(("Status flags changed", ", ".join(fl)))
        if d.get("inline_words"):
            rows.append(("Data words after it", str(d["inline_words"])))
        if d.get("isalias"):
            rows.append(("Alias", "yes"))
        L += ["| Property | Value |", "|---|---|"] + [f"| {a} | {b} |" for a, b in rows] + [""]

        L += ["## Encoding", "", encoding_html(opcode, mask, operands), ""]
        if d.get("bit_format"):
            L += ["```text", textwrap.dedent(str(d["bit_format"])).strip("\n"), "```", ""]
        if operands:
            L += ["| Field | Bits | Meaning |", "|---|---|---|"]
            for op in operands:
                L.append(f"| {op.get('name', '')} | {op.get('bits', '')} | "
                         f"{text_md(op.get('description')).replace(chr(10), ' ').replace('|', '&#124;')} |")
            L.append("")
            for op in operands:
                if op.get("enum"):
                    L += [f"Values of **{op.get('name')}** (octal):", "",
                          "| Value | Name | Meaning |", "|---|---|---|"]
                    for e in op["enum"]:
                        L.append(f"| {e.get('value', '')} | {e.get('name', '')} | "
                                 f"{text_md(e.get('description')).replace(chr(10), ' ').replace('|', '&#124;')} |")
                    L.append("")
                elif op.get("type") in ("addressing_mode", "addressing_modes"):
                    L += [f"The **{op.get('name')}** field is one of the "
                          f"[addressing modes](addressing-modes.md).", ""]
        if rest.strip():
            L += ["## What it does", "", rest.strip(), ""]
        for key, title in (("detailed_description", "In detail"),
                           ("extended_description", "More"), ("before_use", "Before use")):
            if d.get(key):
                L += [f"## {title}", "", text_md(d[key]), ""]
        if d.get("examples"):
            L += ["## Examples", ""]
            for ex in d["examples"]:
                if isinstance(ex, dict):
                    if ex.get("description"):
                        L += [text_md(ex["description"]), ""]
                    if ex.get("code"):
                        L += ["```text", str(ex["code"]).rstrip(), "```", ""]
                else:
                    L += ["```text", str(ex).rstrip(), "```", ""]
        if d.get("exits"):
            L += ["## Where execution continues", "",
                  "| Continues at | When | Condition |", "|---|---|---|"]
            for x in d["exits"]:
                at = (f"the next word" if x.get("offset") == 1 else
                      f"{x['offset']} words on" if "offset" in x else str(x.get("target", "")).replace("_", " "))
                L.append(f"| {at} | {x.get('when', '')} | {text_md(x.get('condition')).replace(chr(10), ' ').replace('|', '&#124;')} |")
            L.append("")
            if d.get("exits_source"):
                L += [f"Source of this: {html.escape(str(d['exits_source']))}.", ""]
        L += [f"*Defined in [{d['_file']}]({DEFS_URL}/blob/{commit}/{d['_file']}) "
              f"in the nd100-definitions repository.*", ""]
        pages[f"isa/{d['_slug']}.md"] = "\n".join(L)

    # overview
    O = ["<!-- generated by src/docs-site/gen_isa.py -->", "# The ND-100 instruction set", "",
         f"All {len(insns)} instructions defined in the "
         f"[nd100-definitions]({DEFS_URL}) repository, by category. The same definitions build "
         "the Ghidra plugin's disassembler, so what is written here is what the plugin decodes.",
         "", "Numbers are **octal**, as in every Norsk Data manual. Each page draws the 16-bit "
         "instruction word: a 0 or 1 is a fixed bit, a named box is a field that the "
         "assembler fills in.", "",
         "See also: [addressing modes](addressing-modes.md) · [status flags](status-flags.md)", "",
         # filter box, driven by isa-filter.js; the site's search box also finds every page
         '<input id="isa-filter" class="isa-filter" type="search" placeholder="Filter instructions: name, opcode or word" '
         'aria-label="Filter instructions"><span id="isa-filter-count" class="isa-filter-count"></span>', ""]
    for cat in cat_order:
        if cat not in by_cat:
            continue
        cd = next(c for c in catdefs if c["name"] == cat)
        O += [f"## {cat} {{#{slug(cat)}}}", ""]
        if cd.get("description"):
            O += ["??? note \"About this group\"", ""] + [("    " + l).rstrip() for l in text_md(cd["description"]).splitlines()] + [""]
        O += ["| Instruction | Opcode | What it does |", "|---|---|---|"]
        for d in sorted(by_cat[cat], key=lambda x: str(x["name"])):
            # the first line of the description is its short form, as in the PDF manual's index
            first = str(d.get("description") or "").strip().splitlines()[0].strip().replace("|", "&#124;").replace("<", "&lt;")
            priv = " *(privileged)*" if str(d.get("privilege", "")).lower().startswith("priv") else ""
            O.append(f"| [{d['name']}]({d['_slug']}.md) | `{d['opcode']}` | {first}{priv} |")
        O.append("")
    pages["isa/index.md"] = "\n".join(O)

    am = yaml.safe_load(open(os.path.join(SPECS, "operand_types", "addressing_modes.yaml"), encoding="utf-8"))
    A = ["<!-- generated by src/docs-site/gen_isa.py -->", "# Addressing modes", "",
         text_md(am.get("description")), "",
         "Memory transfer instructions carry three mode bits (X, I, B) and an 8-bit signed "
         "displacement. The mode decides how the effective address is formed.", "",
         "| Bits X I B | Mode | Assembler form | Example | Effective address |", "|---|---|---|---|---|"]
    for v in am.get("values", []):
        A.append(f"| `{v.get('bit_pattern', '')}` | [{v.get('mode', '')}](#{slug(str(v.get('name', '')))}) | "
                 f"`{v.get('format', '')}` | `{v.get('example', '')}` | `{v.get('effective_address', '')}` |")
    A += ["", "## How each mode forms the address", "",
          "Each mode is shown with a practical example: a few lines of code, the register "
          "and memory contents, and a drawing that follows those numbers step by step to the "
          "address and the value an LDA gets. All numbers are octal, as on the machine.", ""]
    for v in am.get("values", []):
        A += [f"### {v.get('mode', '')} {{#{slug(str(v.get('name', '')))}}}", "",
              f"Bits X I B = `{v.get('bit_pattern', '')}` · form `{v.get('format', '')}` · "
              f"example `{v.get('example', '')}`", ""]
        for w in v["worked_examples"]:
            d = w_disp(w, 0, 0, 0, {})
            sign = "positive" if d >= 0 else "negative"
            A += [f"**Example, {sign} displacement: {w['title']}.** {' '.join(str(w['story']).split())}", "",
                  "```", str(w["code"]).rstrip(), "```", "",
                  "*In the drawing every number is octal; the bit row is binary.*", "",
                  '<div class="am-fig">' + mode_svg(v, w) + "</div>", "",
                  f"Result: **{w['result']}**", ""]
    pages["isa/addressing-modes.md"] = "\n".join(A) + "\n"

    S = ["<!-- generated by src/docs-site/gen_isa.py -->", "# Status flags", "",
         "The bits of the status register STS, from `specs/cpu.yaml`. Instruction pages link "
         "here for the flags they change.", "",
         "| Bit | Name | Meaning |", "|---|---|---|"]
    for fbit in sorted(sts.get("bits", []), key=lambda x: x.get("position", 0)):
        pos = fbit.get("position", "")
        size = fbit.get("size", 1)
        where = f"{pos}" if size == 1 else f"{pos}-{pos + size - 1}"
        S.append(f"| {where} | <span id=\"{slug(fbit['name'])}\"></span>{fbit['name']} | {fbit.get('description', '')} |")
    pages["isa/status-flags.md"] = "\n".join(S) + "\n"

    nav = [("Overview", "isa/index.md"), ("Addressing modes", "isa/addressing-modes.md"),
           ("Status flags", "isa/status-flags.md")]
    cats = []
    for cat in [c for c in cat_order if c in by_cat]:
        cats.append((cat, [(str(d["name"]), f"isa/{d['_slug']}.md")
                           for d in sorted(by_cat[cat], key=lambda x: str(x["name"]))]))
    return pages, nav + cats
