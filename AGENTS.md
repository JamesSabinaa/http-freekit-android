# Agent instructions

## Scope

Read README.md, docs/implementation-plan.md, docs/architecture.md, docs/protocol.md, docs/security.md, and your work package before editing. This is initially a planning repository; do not claim app functionality exists until implemented and verified.

Use tasks/README.md to claim work and record its owner, branch, status, dependencies, and evidence. Work in a separate Git worktree and branch per agent. Do not edit another agent's worktree, stage their changes, reset shared work, or force push. A task claim is a coordination record, not a distributed lock: the coordinating human or agent must assign unique packages before starting concurrent work.

## Shared contracts

docs/protocol.md is the canonical cross-repository contract. It is a draft until package A records protocol v1 as frozen. Agents may build mocks against the draft, but production wire integration must wait for that gate. The foundation owner coordinates changes to shared contracts; communicate dependent changes before landing them. Version incompatible changes explicitly. Desktop work belongs in ../http-freekit under that repository's instructions; commit it separately and record both commit IDs in handoff notes.

Never disable certificate checks globally, expose the desktop management API for mobile access, embed shared passwords or signing keys, log pairing secrets or traffic by default, or copy upstream code without establishing its licence and attribution requirements. Do not infer authorization to publish, provision paid infrastructure, or upload signing material from these planning documents.

## Completion

Creating a Git commit is part of completing an implementation task unless the user says otherwise. Run relevant tests and checks first; inspect git status and git diff before staging. Stage only task files. Use a concise imperative commit message. Do not bypass failing checks or hooks; report the exact blocker. Include commit IDs, validation evidence, remaining limitations, and any changed contracts in your handoff.

Documentation changes require checking local links, consistency, and git diff --check. Implementation changes require the meaningful checks defined in docs/validation.md. Do not report emulator or physical-device checks as passing when the environment cannot run them.

## Build outputs

Put deliverable APKs, archives, checksums, and associated metadata directly in dist/ with stable filenames. Overwrite artifacts with the same names. Standard Android and Gradle working directories may remain. Do not commit build outputs, local SDK paths, credentials, or signing keys.
