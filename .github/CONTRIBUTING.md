# Contributing to ghidra-nd100

Thanks for looking. This file says how to get a build running, where a change has to be made so
it survives the next build, and what will get a change sent back.

---

## Getting a build

The tools and the two environment variables are listed in the README under
[Prerequisites](../README.md#prerequisites) and
[Environment variables](../README.md#environment-variables): .NET 10, a Java 25 JDK, Ghidra 12.2,
`GHIDRA_INSTALL_DIR` and `JAVA_HOME`.

```bat
git clone https://github.com/RetroCoreLabs/ghidra-nd100.git
cd ghidra-nd100
git submodule update --init --recursive
build.bat
```

`build.bat` runs the C# generator, which writes the Ghidra extension project into `ND-100/`, then
runs Gradle; the extension zip lands in `ND-100\dist\`. `make help` lists the same steps one at a
time. Ghidra reads an extension only when it starts: after installing a new build, restart Ghidra
and import the test file again.

## Change the source, not the generated copy

`ND-100/` is **generated**. The generator overwrites it on every build.

| What you want to change | Where the change goes |
|---|---|
| An instruction: its bits, its text, what it does | the YAML in the `nd100-definitions` submodule (its own repository) |
| How the Sleigh files are written | the C# generator under `src/` |
| A loader, analyzer or other Java class | the template under `src/NDGen.Generators.Ghidra/Ghidra/ND-100/`; copy it to the same place under `ND-100/` if you build with Gradle only |

## What the code is expected to look like

 - **Run the machine's algorithm, not a shortcut to the same answer.** A loader or analyzer that
   reproduces what the real ND software does is the goal. When the real behaviour is not known,
   leave the case logged and open (see `src/PLAN.md`) rather than guessing a plausible result.
 - **Every rule about a file format or an instruction carries its source** - the manual and
   section (ND-60.066.04 section 2.5, ND-06.014.2A page 158), or the measurement that settled it.
 - **Keep the comments, and add more.** A comment that records a manual reference, a measurement,
   or the reason a thing is NOT done the obvious way is the most valuable line in the file. Never
   delete one because a style guide prefers less; replace one only when it has become wrong.
 - **C#: no LINQ, and avoid `foreach`.** Index-based `for` loops.
 - **Plain words** in code, comments, commit messages and documentation alike.

## Testing a change

There is no unit-test project in this repository yet (the instruction definitions have their own
tests in `nd100-definitions`). A change is tested by building, installing, and importing real
files, ideally headless so the result can be read and repeated:

```bat
%GHIDRA_INSTALL_DIR%\support\analyzeHeadless.bat <scratch folder>\proj t -import <file> -noanalysis -overwrite
```

Use a scratch project, never one you keep work in, and read the log for errors and warnings.

## Documentation changes

```bat
python src\eng\check-docs.py .
```

It must exit 0. It fails on a relative link that does not resolve, a relative link that escapes
the repository root, a machine-specific absolute path, and a malformed Mermaid diagram.

> [!WARNING]
> **Never put an absolute path in anything committed here.** A drive letter or a home directory is
> correct on exactly one machine, and this repository is public. A path inside the repository goes
> repo-relative; a sibling repository is named, not located; anything outside is described. A
> variable such as `%USERPROFILE%` or `~` is fine.

## The documentation site

https://retrocorelabs.github.io/ghidra-nd100/ is built from this repository by
`.github/workflows/docs.yml` on every push to `main`. The guides are the Markdown files in
`src/docs/`; the plugin reference pages are made from the class comments of the Java files, so a
better class comment is a better page. The instruction-set pages (one per instruction) are made from the
YAML in the `nd100-definitions` submodule by `src/docs-site/gen_isa.py`, so the submodule must be
checked out, and a better instruction page is a better YAML file in that repository. To build it locally, from the repository root:

```bat
pip install -r src\docs-site
equirements.txt
python src\docs-site\gen_site.py %TEMP%\ghidra-nd100-sitesrc
mkdocs build --strict -f %TEMP%\ghidra-nd100-sitesrc\mkdocs.yml -d %TEMP%\ghidra-nd100-site
```

The generator only takes files git tracks, so `git add` a new page first. Screenshots go in
`src/assets/screenshots/` under the names listed in `src/docs/SCREENSHOTS.md`.

## Submitting a change

 1. Branch off `main`. Do not commit to `main` directly.
 2. One logical change per commit. A commit message says **what changed and why**, in plain
    words. If you measured something - files imported, functions found, fix-ups that land on a
    loaded word - put the number in the message.
 3. Say in the pull request which files you imported and what you checked. "It builds" on its own
    is not useful.
 4. If something is still broken or unfinished, say so plainly. A known gap that is written down
    is fine. One that is hidden is not.

## Licence

By contributing you agree your work is licensed under the MIT licence in [LICENSE](../LICENSE).
