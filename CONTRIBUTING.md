# Contributing to PromptShield

Thanks for considering a contribution! PromptShield stays intentionally small and dependency-free, so contributions are especially valuable when they're precise.

## Reporting a bypass or false positive

Open an issue with:
- The exact input text that was misclassified
- What you expected (`safe: true`/`false`) vs what you got
- Why you believe it's a bypass or a false positive

## Adding or tuning a detection rule

1. Add or edit an entry in the `RULES` array in `lib/promptShield.js`.
2. Mirror the same change in `demo/index.html`'s inlined `RULES` array (kept in sync manually since the demo has zero build step).
3. Add a test in `test/promptShield.test.js` that:
   - Confirms the rule fires on a true-positive example.
   - Confirms a nearby, legitimate phrase does **not** fire (to guard against over-broad regex).
4. Run `npm test` and make sure everything passes.
5. Open a PR describing the pattern you're targeting and why the weight you chose makes sense relative to existing rules.

## Code style

- Plain Node.js, no external dependencies in `lib/` or `bin/`.
- Prefer explicit, readable regex over cleverness — these patterns get read and audited by security-conscious users.
- Keep the CLI's exit codes stable: `0` = safe, `1` = flagged, `2` = usage/runtime error.

## Reporting issues

Open a GitHub Issue with a clear description and, if relevant, the exact input that triggered the problem.
