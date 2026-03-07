# OpenAI OAuth via Codex CLI Token Reuse Plan

## Objective
When `openai-codex` (OpenAI OAuth mode) is selected in Nullclaw, reuse the existing Codex CLI token from `~/.codex/auth.json` instead of requiring a separate OAuth re-login flow.

## Current State (as of 2026-03-07)
- `src/providers/openai_codex.zig` already attempts:
  - `~/.nullclaw/auth.json` via `auth.loadCredential("openai-codex")`
  - fallback import from `~/.codex/auth.json` via `tryLoadCodexCliToken(...)`
- `nullclaw auth login openai-codex --import-codex` already exists in `src/main.zig`.
- API-key checks already exempt `openai-codex` provider in `src/main.zig`.
- Gaps likely remain in onboarding UX and explicit “OAuth mode selected” flow consistency.

## Scope
- Tighten and standardize Codex token reuse behavior.
- Make onboarding/selection flow explicitly support this auth mode.
- Improve reliability and diagnostics without reengineering OAuth.

## Non-Goals
- No full OAuth Authorization Code + PKCE browser implementation.
- No dependency on new external libraries.
- No broad auth subsystem redesign.

## Implementation Plan

### Phase 1: Define Source-of-Truth and Resolution Order
1. Keep this token resolution order for `openai-codex`:
   1. `~/.nullclaw/auth.json` (managed by Nullclaw, refreshed tokens)
   2. `~/.codex/auth.json` (Codex CLI fallback import-on-read)
2. Document this order in code comments and user-facing help.
3. Ensure no token values are logged (length/status only).

### Phase 2: Harden Codex Token Reader (`tryLoadCodexCliToken`)
1. Validate expected shape:
   - `auth_mode == "chatgpt"` (or allow missing for forward compatibility with warning path)
   - `tokens.access_token` required
   - `tokens.refresh_token` optional
   - `tokens.account_id` optional
2. Keep strict null-on-error behavior for malformed files.
3. Add tests for:
   - valid token object
   - missing/empty `access_token`
   - expired JWT `exp`
   - non-chatgpt `auth_mode`
   - malformed JSON

### Phase 3: Make “OAuth Mode Selected” UX Explicit
1. Add `openai-codex` to onboarding provider choices (`src/onboard.zig`) with clear label:
   - “OpenAI Codex (ChatGPT OAuth via Codex CLI token)”
2. Ensure onboarding does not ask for API key for this provider.
3. If `openai-codex` is selected and no local Nullclaw credential exists:
   - auto-attempt read from `~/.codex/auth.json`
   - on failure, print direct actionable guidance:
     - `codex login`
     - or `nullclaw auth login openai-codex --import-codex`
4. Keep existing device-code auth command available as explicit fallback.

### Phase 4: Refresh and Persistence Behavior
1. Continue refreshing with refresh token via existing `auth.refreshAccessToken(...)`.
2. Persist refreshed tokens to `~/.nullclaw/auth.json` only.
3. Do not mutate `~/.codex/auth.json` (treat as external source).
4. Add tests that verify refresh path does not require Codex file once Nullclaw store exists.

### Phase 5: CLI/Docs Polish
1. Update `auth` help text and provider descriptions to emphasize token reuse path first.
2. Update README sections for `openai-codex` setup:
   - fastest path: `codex login` then select/use `openai-codex`
   - optional explicit import command
3. Add troubleshooting section for common failure cases:
   - missing `~/.codex/auth.json`
   - expired token without refresh token
   - unsupported account entitlement

### Phase 6: Validation
1. Run focused tests:
   - `zig test src/providers/openai_codex.zig`
   - `zig test src/main.zig` (or command parsing/auth tests if split)
   - `zig test src/onboard.zig`
2. Run full suite:
   - `zig build test --summary all`
3. Optionally build release target:
   - `zig build -Doptimize=ReleaseSmall`

## Concerns / Risks
1. Policy risk: whether long-term third-party reuse of Codex CLI-issued tokens is acceptable per OpenAI terms.
2. File-format drift risk: `~/.codex/auth.json` may change shape over time.
3. Entitlement ambiguity: token may be valid but model access may still be denied.
4. Security risk: accidental token leakage in logs/errors if debug output expands.
5. UX ambiguity: users may confuse `openai` (API key billing) vs `openai-codex` (subscription OAuth token).

## Questions To Confirm Before Implementation
1. Should we require `auth_mode == "chatgpt"` strictly, or allow unknown modes as long as tokens parse?
2. When both stores exist, do you want Nullclaw credentials to always win (current recommendation), or always prefer live Codex file?
3. Should onboarding auto-select `openai-codex/gpt-5.3-codex` as the default model for this provider?
4. If Codex token exists but is expired and has no refresh token, should onboarding fail hard or allow setup with warning?
5. Do you want `openai-codex` surfaced as a first-class recommended provider in onboarding, or advanced/optional?

## Proposed Default Decisions (unless you override)
1. Accept unknown `auth_mode` but require `tokens.access_token`.
2. Prefer `~/.nullclaw/auth.json` over `~/.codex/auth.json`.
3. Default model for this provider: `gpt-5.3-codex` (configurable by user).
4. Fail with clear remediation when no valid token is available.
5. Show `openai-codex` in onboarding provider list with explanatory label.
