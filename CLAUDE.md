# TULPAR: working rules for Claude Code

TULPAR is an ns-3 simulation of a distributed UAV-USV collective. Read this file before every task.

## Sources of truth

- **Requirements:** `docs/rsd/TULPAR_RSD.md`. It is a living document: the copy on `main` is the only valid RSD, and earlier states in the git history or copies kept elsewhere (such as RSD v1.1 files) are not sources. Requirement identifiers (`RSD-XXX-NNa`) are stable and never renumbered. Where an architecture document differs from the RSD, the RSD governs.
- **Work items:** Jira project `TULPAR` on `dasdas.atlassian.net`, through the Atlassian connector. Every code change belongs to one Jira issue.
- **Backlog map:** `docs/backlog/TULPAR_Jira_Backlog.json` lists the issues of the initial import with their Jira key (`TULPAR-n`), RSD identifier, planned gate and acceptance criterion. Jira governs assignees, owner labels, status and dates; the owner labels in this file may be out of date.

## Changing the RSD

- Do not edit `docs/rsd/` unless the user asks for that change. When a requirement looks wrong, outdated or ambiguous, tell the user and propose the correction with the RSD text quoted.
- An RSD change is its own pull request, separate from code, and its commits start with the key of the issue where the problem was found. Özgür Can Güngör approves it, together with the owner of every module it affects. It is valid as soon as it is merged.
- Correct text that is wrong, outdated or ambiguous. Never rewrite a requirement because the implementation cannot meet it: keep the requirement and record the gap in Section 6.3 (Known limitations), or move it explicitly to Section 6.6 (Optional items and future work).
- Identifiers are never renumbered or reused. A new obligation gets a new identifier and a new Jira issue; a removed requirement is marked withdrawn.
- When the text of an atomic requirement changes, update the quoted requirement and acceptance criterion in its Jira issue. A requirement verified before the change is verified again against the new text.
- A copy of the RSD sent outside the repository is identified by a git tag on its commit (`rsd-v1.1`, `rsd-v1.2`, ...).
- Departing from an architecture document where the RSD is silent is not an RSD change: record it with its reason in the design document (for example `docs/design/encodings.md`, Section 9).

## Repository layout

| Path | Content |
|---|---|
| `module/` | The ns-3 module `tulpar`; `scripts/bootstrap.sh` links it to `external/ns-3/contrib/tulpar` |
| `module/agent/<m>/` | Agent modules `com`, `del`, `cry`, `evs`, `obs`, `sec`, `mis`, `lsc` (one static target each) and `root` (wiring) |
| `module/common/` | Shared types and the write-only event sink |
| `module/sim/` | Simulation harness M-SIM: scenario controller, ground-truth store, event log |
| `third_party/botan-3.13.0/` | Vendored Botan 3.13.0 amalgamation; regenerate with its `generate.sh`, never edit by hand |
| `tools/check_static.py` | Static checks; rules in `tools/deps_rules.json` |
| `scripts/` | `bootstrap.sh`, `build.sh`, `g0_checks.sh` |

## Ownership

Every folder has one owner, following the Jira assignments. Work only on issues assigned to the current user, and change files only in that user's folders.

| Path | Owner |
|---|---|
| `module/agent/com/`, `module/agent/del/` | Cemre Karabulut |
| `module/agent/cry/`, `module/agent/evs/` | Özgür Can Güngör |
| `module/agent/obs/`, `module/agent/sec/` | Berkan Mursal |
| `module/agent/mis/` | Berra Senem Mıynat |
| `module/agent/lsc/`, `module/sim/`, `module/examples/` | Çağlar Mesci |
| `module/common/`, `module/agent/root/`, `module/CMakeLists.txt`, `.clang-format`, `docker/`, `.github/`, `tools/`, `scripts/`, `module/test/tulpar-g0-test-suite.cc` | Çağlar Mesci (shared) |
| `module/test/tulpar-<module>-test-suite.cc` | Owner of the module |
| `docs/rsd/`, `docs/backlog/`, `docs/g0/`, `CLAUDE.md`, `README.md`, `third_party/` | Özgür Can Güngör |
| `docs/design/` | Özgür Can Güngör (shared); the owners of TULPAR-480 to TULPAR-484 add their message formats |
| `.github/CODEOWNERS`, `.github/workflows/pr-title.yml`, `tools/deps_rules.json` | Özgür Can Güngör |

- If a change is needed outside the current user's folders, stop and tell the user; the owner makes the change or approves it.
- In a shared file, add only the current user's own part: the sources of their own target, their own test, their own static check or the wiring of their own module. Changing the shared structure needs the file owner.
- An interface change (RSD Table 4.25, a type in `module/common/`, a message format) is one pull request, approved by the owners of the producing and the consuming modules; the affected stubs change in the same pull request.
- Relaxing a rule in `tools/deps_rules.json` is an RSD change (see Changing the RSD).
- Approvals: none when a pull request touches only the author's folders; the owner for another person's folder or a shared file; both module owners for an interface; Özgür Can Güngör for `docs/rsd/`, `CLAUDE.md`, `docs/design/` and `tools/deps_rules.json`.
- GitHub enforces these approvals: `.github/CODEOWNERS` mirrors this table, so a pull request asks the owners for review and cannot be merged before they approve. Change the table and `CODEOWNERS` in the same pull request.
- Never push to `main`, merge a pull request or disable a CI check.

## Commands

```bash
scripts/bootstrap.sh           # clone ns-3.49, link the module, configure
scripts/build.sh               # build tulpar, tulpar-g0 and the test runner
scripts/g0_checks.sh           # gate G0 checks; evidence in out/g0/
python3 tools/check_static.py  # static dependency and wall-clock checks
cd external/ns-3 && ./test.py --no-build -s tulpar-g0
```

## Jira workflow

1. **Pick work.** Use the issue the user names; if it is assigned to someone else, say so and stop until it is reassigned. Otherwise:
   `project = TULPAR AND assignee = currentUser() AND labels = agent-claude AND statusCategory != Done ORDER BY fixVersion ASC, rank ASC`
2. **Before coding.** Read the issue and the RSD text of every requirement it names (search the RSD for the identifier). Move the issue to In Progress.
3. **Branch and commits.** Branch `TULPAR-<n>-<short-name>`; every commit message starts with the issue key, then an imperative summary (`TULPAR-123: Add beacon jitter`).
4. **Tests.** Each acceptance criterion becomes an automated check whose name contains the requirement identifier (for example the test case `RSD-SIM-01d same seed gives identical event logs`). Static (S) criteria go into `tools/check_static.py`; run-based criteria go into the ns-3 test suite or `scripts/`.
5. **Pull request.** Open a pull request to `main` whose title starts with the issue key, and request review from every owner whose approval the Ownership section requires. The user merges it. `main` is merged by squash, so the title becomes the commit on `main`; the `pr-title` check rejects a title that does not start with the issue key.
6. **Done.** An issue is done only when its acceptance check passes in CI. Comment on the issue with the commit hash, the check name and, for run-based checks, the run id and seed; then move it to Done. For criteria marked Simulation (M), the implementation issue closes when its deterministic checks pass; the statistical verdict is recorded on the experiment issue (E1-E15).
7. **Blocked or unclear.** Comment on the issue, state what is missing and stop. Do not invent a requirement, a threshold or a value. If the cause is an error in the RSD, propose the correction (see Changing the RSD). Work found during a task becomes a new issue linked to it.

## Jira writing rules

- Comments are written in formal Turkish and record only work that was done: what changed, the commit, the check name and, for run-based checks, the run id and seed. Do not write notes about removed settings, reversed decisions or corrections; to correct a comment, edit it.
- Discussions, questions and small notes stay out of Jira. The only other comment is the one that records why work is blocked.
- Issue descriptions are in Turkish. Requirement statements, acceptance criteria and any other text quoted from the RSD or the architecture stay in English, word for word. Issue summaries are not translated. In Turkish text, write İHA and İDA.
- Never change the status, labels, assignee or dates of an issue assigned to someone else.
- A new issue gets labels chosen for that issue, never copied from another: `owner-<owner>` and the assignee name the owner of the area, not the creator; then `gate-g<n>`, `area-<area>` and, where needed, `method-<m>`. Link it to the issue it came from, put it under its epic and give it start and due dates in its gate month.

## Evidence rules (from the RSD)

- Never mark a requirement verified without a run id, seed and commit. Never put a number into a results table that no run produced; placeholders stay visible.
- SIMDIS output is display only and never verification evidence. Mockups carry a watermark and live apart from run outputs.
- Thresholds of a statistical experiment are registered before its test runs; calibration runs are kept apart from test runs.

## Code rules (from the RSD)

- Agent modules are separate static targets. A module includes only its own headers, `common/` and M-CRY (I6); data between modules flows through the interfaces of RSD Table 4.25, wired in `agent/root`. The LSC includes and links nothing but `common/` (MD19). Security never reaches mission (MD5).
- No agent file includes the harness or the ground-truth store (RSD-SIM-02a, MD9); agents get only their identity, the write-only event sink and their stream number.
- Agent code reads no wall clock and uses no unseeded random source. Every random variable gets an explicit stream number from the harness; the run seed and run number select the MRG32k3a substreams (RSD-SIM-01a, RSD-SIM-01c).
- Event log lines are deterministic: integer nanoseconds, fields in fixed order, no pointers, no floating-point formatting.
- Toolchain: ns-3.49 module in C++23 under GPL-2.0-only, built with CMake and Ninja on Ubuntu 24.04 with GCC 13 (`docker/Dockerfile`). From Phase 1, cryptography goes through Botan 3.13.0: ML-KEM-1024, ML-DSA-87 in deterministic mode, AES-256-GCM with rule-based IVs, SHA-384, HMAC-SHA-384 and HKDF-SHA-384 (RSD-CRY-01). The viewer uses SIMDIS SDK 1.25; state machines are model-checked with UPPAAL 5.0.0.
- Processing delays are scheduled in simulation time from the micro-benchmark table, never measured during a run.
- Follow the ns-3 coding style (`.clang-format`, Doxygen with `@` tags, ASCII only in comments).
- Do not use the term "post-quantum" in code comments, documents or reports.
