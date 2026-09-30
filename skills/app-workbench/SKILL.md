---
name: app-workbench
description: Investigate registered Apps, websites and shared backends, recommend a concrete iteration, and coordinate an approved plan through implementation, independent review, testing and delivery. Use for requests such as 看看 AI Pet Studio 最近的情况, 规划 CalorieSnapshot 下一版, 按这份计划执行 or 查看版本进度 in the user's AppWorkbench. Do not use for unrelated one-off coding tasks.
---

# AppWorkbench

Use the current Codex conversation as coordinator. Announce this skill on first use. Code root is `${APP_WORKBENCH_CODE:-$HOME/AppWorkbench}`, with executable `bin/wb`; private registry, credentials and SQLite state live at `${APP_WORKBENCH_HOME:-$HOME/.config/app-workbench}`. Read the code root's `docs/workflow.md` and product repository instructions before a workflow; use `bin/wb --help` for current command arguments. Keep runtime evidence outside Git. Read `docs/acceptance.md` for candidate release and human acceptance.

## Route the conversation

- “看看…最近情况 / 规划下一版”: resolve the product via `product list/show`, inspect its repositories and capabilities, collect relevant sources, inspect instrumentation and compare actual behavior with product goals. Browse primary market/platform sources when needed, recording source links and query time. Missing data remains unknown; no revenue access is not zero revenue. Separate versions, currencies, populations and event definitions; low samples permit descriptive findings and measurement proposals, not causal claims.
- Recommend one useful version using `templates/analysis.md` and `templates/plan.md`: evidence, scope, tests, acceptance, delivery order, expected effect and a small number of alternatives. Register the exact plan with `iteration create`; show the saved revision before asking for confirmation. Investigation and framework authorization do not approve a product iteration.
- “按这份计划执行”: establish which saved revision the human actually approved; use `iteration approve` with the genuine instruction and actor. If the reference is ambiguous, ask which revision. Do not manufacture human messages, approvals or acceptance. Continue implementation within approved scope; changed scope requires a revised plan and fresh confirmation.
- “查看进度 / 继续”: query persistent iteration status first. Resume from its real evidence and remaining dependencies, not chat memory. An uncertain external action requires authenticated remote reconciliation before retry.
- “验收反馈”: preserve the user's actual evidence. In-scope defects stay with the iteration; new features become next-plan proposals. Human evidence must correspond to the tested version/build.

## Implement and deliver

At most three agents including coordinator, inheriting the current conversation model and reasoning. Delegate only worthwhile independent work; assign exclusive files, prohibit children from delegating, and avoid simultaneous publishers. Inspect legacy CalorieSnapshot execution ownership before claiming product development/release; preserve its scripts and ledger. Do not create schedules, select paid model APIs or change prices, rights, brand or legal terms.

Bind every repository candidate to its actual commit and identity using `candidate set`. Use templates as authoring aids, then check actual CLI schema. The final candidate needs a fresh reviewer who did not implement it; supply raw candidate, approved scope and evidence, not an expected verdict. Record actual author/reviewer identities and commits. Candidate/configuration changes invalidate dependent gates. Run relevant checks through `check`; mock transport tests do not prove production, purchase or human acceptance.

Use `deliver` only after engine gates pass. Multi-repository delivery starts with a backward-compatible backend and satisfied dependencies, then Web/iOS. Persist external intent before action; confirm real remote identity/results. A timeout is uncertain, not permission for another upload/deploy. Cloud actions need configured rollback and post-deploy smoke evidence. Reports show each target's actual partial state.

For iOS, validate archive, distribution signing, artifact and TestFlight remote processing separately. Publish test instructions with remaining human checks. Real installation, core paths, purchase, restore and existing rights come from the user; automatic tests cannot attest them. Formal preparation ends at 待你提审. Never invoke App Store submission or release.

## Close the loop

Show what changed, what was reused, evidence, unresolved items and next human action. Measure effects only after actual release, with the right versions/dates. Read-only dashboard/export must omit secrets and private raw provider responses. Credential updates use the external credential maintenance tool, never product source. New-machine setup requires real platform/session/signing revalidation; restored metadata is not a successful deployment.
