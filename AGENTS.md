# AppWorkbench

Read docs/architecture.md before changing workflow behavior. User-confirmed product plans authorize only their own scope. Framework implementation is not approval to modify or publish a product version.

Keep credentials, product registry, business reports and runtime data outside Git, under APP_WORKBENCH_HOME (default ~/.config/app-workbench). Never print raw keys, tokens, signed JWTs or service-account contents. Return sanitized JSON errors. No paid model API, autonomous schedules, App Store submission/release, price/rights/legal changes.

Use the current Codex conversation for orchestration. Inherit its model and reasoning setting. When independent work merits delegation, use at most two children (three agents including coordinator); children must not delegate. Assign file ownership. Review the exact final candidate independently.

Use Python standard library for the core, existing cryptography runtime for authenticated migration and platform signing. Reuse existing CalorieSnapshot scripts via its adapter. Test changed behavior with focused unittest tests; do not repeatedly run full suites. Treat mocks as transport/control tests, never as real deployment or human acceptance.

Only release helper actions that passed plan, identity, commit, review, test, dependency, lock and deduplication checks. Persist external intent before dispatch; interrupted actions become uncertain and must be reconciled remotely before a retry. Only authenticated remote evidence may reconcile an external action.
