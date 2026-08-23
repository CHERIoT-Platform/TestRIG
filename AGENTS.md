# TestRIG Development Instructions

These instructions are mandatory for all work started from this TestRIG project. Follow them for TestRIG itself and for the CHERIoT Sail and Sail RISC-V repositories used by this flow.

## Authoritative repositories and branches

Use only these repositories and branches unless the user explicitly specifies a different source or says not to use the repository:

| Component | Authoritative repository | Required branch |
| --- | --- | --- |
| TestRIG | `https://github.com/CHERIoT-Platform/TestRIG.git` | `dii-read-from-file` |
| CHERIoT Sail | `https://github.com/CHERIoT-Platform/cheriot-sail.git` | `dii-read-from-file` |
| Sail RISC-V used by CHERIoT Sail | `https://github.com/CHERIoT-Platform/sail-riscv.git` | `cheriot-dii-read-from-file` |

The primary project root is the TestRIG repository containing this file. Resolve the actual paths of CHERIoT Sail and its nested Sail RISC-V checkout from the current TestRIG checkout and its submodule metadata; do not guess paths from memory.

## Mandatory start-of-task procedure

Before analyzing, editing, or generating code:

1. Use repository source as the authority. Do not reconstruct current source files from memory, prior chat output, cached snippets, or an older downloaded copy.
2. Unless the user explicitly says not to pull or not to use the repository, ensure that the complete TestRIG repository and all required submodules are present in the local workspace.
3. If TestRIG is absent, clone the required branch with its submodules:

   ```bash
   git clone --branch dii-read-from-file --recurse-submodules \
     https://github.com/CHERIoT-Platform/TestRIG.git TestRIG
   ```

4. If a checkout already exists, inspect it before changing anything:

   ```bash
   git -C <repo> remote -v
   git -C <repo> status --short --branch
   git -C <repo> branch --show-current
   ```

5. Verify that each `origin` URL identifies the authoritative repository above. Verify the required branch explicitly; do not assume that the displayed directory name proves the repository or branch is correct.
6. Preserve all existing user changes. Never discard, overwrite, reset, clean, or silently stash a dirty working tree. If existing changes prevent a safe update, create a separate fresh clone or worktree for the task, or stop and explain the conflict.
7. For a safe existing checkout, update without rewriting history:

   ```bash
   git -C <repo> fetch --prune origin <required-branch>
   git -C <repo> switch <required-branch>
   git -C <repo> pull --ff-only origin <required-branch>
   ```

   If the branch does not exist locally, create it to track `origin/<required-branch>`. Never use force-pull, `git reset --hard`, or another destructive shortcut.
8. From the updated TestRIG root, synchronize and populate submodules:

   ```bash
   git submodule sync --recursive
   git submodule update --init --recursive
   ```

9. After submodule initialization, explicitly put CHERIoT Sail on `dii-read-from-file` and its Sail RISC-V checkout on `cheriot-dii-read-from-file`, then fetch and fast-forward each one safely. Do not leave either repository at an unrelated detached commit when the task requires current branch source.
10. Before editing, record the resolved path, origin URL, branch, and starting commit of every repository that will be used.
11. Read the actual relevant source files, callers, wrappers, build files, and tests from the synchronized checkout. When changing an interface or command-line option, search all downstream callers and wrapper scripts.

If repository or network access is unavailable, do not pretend that cached source is current. Report the blocker and ask whether the user wants work based on the available snapshot.

## Workspace and dependency setup

Install and use the tools needed to compile and execute the affected flow. The user's request authorizes task-relevant downloads and installations inside the local workspace or the project-provided containers.

1. Inspect the current branch's `README`, `Makefile`, Dockerfiles, Compose files, setup scripts, lockfiles, and CI configuration before choosing tool versions or commands.
2. Prefer the environment already defined by TestRIG, including its Docker Compose services and Dockerfiles. Reuse valid images and caches when possible; rebuild an image when its definition or required contents changed.
3. If a required tool is missing, install it in a project-local environment, a dedicated tool directory, a Python virtual environment, an opam switch, or the appropriate TestRIG container. Avoid unrelated machine-wide changes.
4. Install required tools such as GHC/Cabal, opam/Sail, Verilator, Python packages, Docker images, and other dependencies when they are necessary to build or run the affected code. Do not skip verification merely because a tool is initially missing.
5. Use versions required by the checked-out repository. Do not arbitrarily upgrade a compiler, dependency, lockfile, submodule, or container base image.
6. Verify every installed tool before relying on it. Use an appropriate version or smoke check, for example:

   ```bash
   ghc --version
   cabal --version
   opam --version
   sail --version
   verilator --version
   docker --version
   docker compose version
   python3 --version
   ```

7. For Python packages, verify the exact interpreter that will run the flow can import the package. For containerized tools, verify them inside the same service/container that will run the test.
8. Keep a record of installations and verified versions for the final report.

If installation requires permission or access that is unavailable, report the exact blocker. Do not mark the work verified and do not produce a completed downloadable code artifact.

## Implementation rules

1. Make the smallest practical change that satisfies the request.
2. Preserve unrelated behavior and user changes.
3. Follow existing repository conventions and reuse existing helpers instead of introducing duplicate modules or unnecessary files.
4. For command-line changes, keep spelling and propagation consistent across Python scripts, shell wrappers, Docker commands, and help text. Exercise the exact spelling requested by the user.
5. Base explanations and modifications on inspected source. Clearly label any inference that cannot be confirmed from code or execution.
6. Do not modify generated output after it has been tested. If code changes after a successful test, rerun the applicable verification.

## Mandatory compile-and-run verification

Before presenting any modified code as complete or creating a downloadable code file:

1. Determine the repository's actual build and test commands from the synchronized source. Do not invent commands from memory.
2. Run syntax or static checks appropriate to every modified file.
3. Compile or build every affected compiled component.
4. Run the smallest relevant end-to-end TestRIG flow that exercises the change, not only a parser or import check.
5. If the user provided a failing or requested command, run that exact command or a locally equivalent command with the same options.
6. Check both the process exit status and the expected output. A zero exit status alone is insufficient when an expected ELF, DII trace, RVFI trace, comparison result, or other artifact is missing.
7. When a change crosses wrappers or phases, verify the option and value reach every affected phase. For new CLI options, run `--help` and invoke each new option at least once.
8. If a test fails, diagnose the failure, fix it, and rerun all affected checks. Do not hide, downgrade, or summarize a failure as success.
9. Review the final diff for regressions, accidental generated files, hard-coded local paths, and unrelated changes.

Apply at least these language-specific checks when relevant, plus the repository's own tests:

- Python: `python3 -m py_compile <files>`, `--help` for CLI scripts, and a representative execution.
- Shell: `bash -n <files>`, `shellcheck` when available, and a representative execution.
- Haskell: build the affected QuickCheck/TestRIG component with the repository's Cabal or Stack command and run the relevant generator or test.
- Sail, C, or C++: rebuild the affected Sail model or executable and run a representative simulation.
- Verilator/SystemVerilog: rebuild the affected simulator and execute a representative trace.
- Docker Compose: run `docker compose config`, build the required service when needed, and execute the appropriate quick or full TestRIG service/flow.

Do not claim that code was compiled, run, or tested unless those commands were actually executed in the current task. If complete verification is blocked, state exactly what passed, what did not run, and why. Do not create a completed downloadable code file unless the user explicitly asks for an unverified draft after seeing the limitation.

## Downloadable-file rules

Create downloadable files only after the mandatory verification succeeds.

1. Generate a unique, descriptive filename using this pattern:

   ```text
   <original-stem>_<YYYYMMDD_HHMMSS>_<short-change-description>.<extension>
   ```

   Use local time in `America/Los_Angeles`. If the name already exists, append `_02`, `_03`, and so on. Never overwrite or ambiguously reuse an earlier download name.
2. Produce the download by copying the exact tested file; do not retype or regenerate its contents after testing.
3. Compare the tested source and downloadable copy byte-for-byte with `cmp`, or record and compare SHA-256 hashes.
4. If packaging multiple files, include only the required files, give the archive a unique timestamped name, and verify the archive can be listed and extracted.
5. If the downloadable copy differs from the tested source, discard it, recreate it from the tested source, and repeat the comparison.

## Required final report

Every completed code handoff must state:

- Repository path, origin, branch, and commit used for each affected repository.
- Files changed.
- Tools or containers installed or rebuilt, with verified versions where relevant.
- Exact build and test commands executed and whether each passed.
- Any limitations or checks that could not be completed.
- The unique downloadable filename and its SHA-256 checksum.

Lead with the result. Never say the work is complete, verified, or ready to download when a mandatory check failed or did not run.
