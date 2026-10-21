# Saber StableSwap — Security Review

**Scope:** `saber-hq/stable-swap` mirror @ `39d5d4e` (v1.8.2) + deployed ELF
`onchain/program.so` (SHA256 `383F720F…B4504`, 609,792 bytes) for program
`SSwpkEEcbUqx4vtoEByFjSkhKdCT862DNVb52nZg1UZ` on mainnet-beta.
**Method:** full first-hand read of the fund-flow processor (`processor/swap.rs`,
`admin.rs`, `checks.rs`, `token.rs`), the curve/fee math (`stable-swap-math`),
prior-audit digest, dependency source retrieval from crates.io, and BPF
disassembly of the deployed binary. No test suite was executed (see
"Verification" below) and no live or testnet interaction took place.

## Bottom line

**The `token_program_id` lead resolves to SOUND — it is not a finding.** Saber
dropped the `token_program_id` field that `spl-token-swap` carries, but it did
*not* drop the check. Every CPI Saber issues is built through
`spl_token::instruction::{transfer,mint_to,burn}`, and in spl-token 3.x each of
those builders calls `check_program_account()` as its **first statement**,
returning `ProgramError::IncorrectProgramId` when the supplied program id is not
`TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`. The guard fails *before* the
`Instruction` is constructed, so `invoke`/`invoke_signed` is never reached and
the swap-authority PDA signature is never handed to an attacker program. I
confirmed this in the dependency source, in the repo's own tests, and in the
deployed binary's instruction stream. No other novel, exploitable, in-scope
defect surfaced in the fund-flow code.

## Known-issue map (do NOT re-report)

The only prior audit is **Bramah Systems, May 2021** (`audit/bramah-systems.pdf`),
a *two-business-day* review of commit `d811ec1`. It reports **no security
findings** — only general/specific recommendations:

| Item | Type | Status |
|---|---|---|
| "Usage of Structs suggested" | style | general rec |
| "Deprecated function usage via `create_account`" | style | general rec |
| "Usage of `unwrap` presents concern" | style | general rec |
| "Usage of magic numbers referenced in source code" | style | specific rec |
| "TODO Item remains in source" | style | specific rec |
| "Typographic errors in code comments" | style | specific rec |

Treat the "audited" signal as **weak**: shallow, 2 days, and against a commit
~3 years older than the reviewed HEAD. Researcher saturation (Saber is a
long-lived, high-TVL Solana AMM) is the real reason the surface is hard, not
this report.

## Strongest lead — token program not stored in `SwapInfo` → RESOLVED SOUND

### The hypothesis

`SwapInfo` (`stable-swap-client/src/state.rs:14-55`, `LEN = 395`) has no
`token_program_id` field, unlike `spl-token-swap`, which Saber forked from and
which stores it and checks `*token_program_info.key == token_swap.token_program_id`.
`processor/swap.rs` takes `token_program_info` straight from
`next_account_info()` (`:116, :303, :440, :589, :702`) and passes it into
`token::transfer_as_swap` / `transfer_as_user` / `mint_to` / `burn` with no
explicit comparison anywhere in the Saber tree (`grep spl_token::id` hits only
test code). If unvalidated, the exploit would be devastating: a swap with a
malicious "token program" would no-op the user's inbound transfer, then receive
the swap-authority PDA **as a signer** on the outbound `invoke_signed`
(`token.rs:72-77`) and re-CPI the real spl-token to drain the reserve —
because Solana propagates signer privileges down the CPI chain.

### Why it does not hold

The check exists one layer down, in the instruction builders:

```rust
// spl-token 3.3.0, src/lib.rs:30-38
solana_program::declare_id!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");

pub fn check_program_account(spl_token_program_id: &Pubkey) -> ProgramResult {
    if spl_token_program_id != &id() {
        return Err(ProgramError::IncorrectProgramId);
    }
    Ok(())
}
```

`check_program_account(token_program_id)?` is the first line of all 21 builders
in `src/instruction.rs`, including the three Saber uses — `transfer` (:898),
`mint_to` (:1019), `burn` (:1049). Saber routes **every** CPI through them and
constructs no raw `Instruction` anywhere:

| `processor/token.rs` | builder | covers |
|---|---|---|
| `burn` :15 | `spl_token::instruction::burn` | withdraw, withdraw_one |
| `mint_to` :39 | `spl_token::instruction::mint_to` | initialize, deposit |
| `transfer_as_swap` :64 | `spl_token::instruction::transfer` | swap out, admin fee, withdraw out |
| `transfer_as_user` :88 | `spl_token::instruction::transfer` | swap in, deposit in |

Because the `?` propagates before `Instruction` construction, the attacker's
program is never invoked and the PDA signature is never granted.

### Verification — three independent confirmations

1. **Dependency source.** `Cargo.lock` pins `spl-token 3.3.0`
   (`checksum 0cc67166…c4fb`). Fetched the crate from crates.io and read it: the
   guard is present and called by every builder, as above.

2. **Repo tests (read, not executed).** The suite already covers exactly this
   attack, for all four fund-moving instructions, each asserting
   `Err(ProgramError::IncorrectProgramId)`: `swap.rs:1617` (deposit), `:2150`
   (withdraw), `:2529` (swap), `:3167` (withdraw_one) — each passes a
   `pubkey_rand()` as the token program, routed through `Processor::process`.
   I did **not** get these to execute: the pinned `solana-program`/`solana-sdk`
   1.9.x tree pulls `wasm-bindgen` 0.2.82, which rustc 1.97 refuses to compile
   (`older versions of the wasm-bindgen crate are incompatible`). Bumping it to
   0.2.92 unblocks compilation, but the debug build of the solana tree did not
   finish within the time I was willing to spend, and I reverted the lockfile
   rather than leave an unrelated dependency change in the tree. Confirmations
   1 and 3 do not depend on this, and (3) is the stronger evidence anyway —
   it is the shipped binary, not the source.

3. **Deployed binary.** The guard is compiled into the live program, not just
   the source:
   - The 32-byte spl-token program id appears **exactly once** in the ELF, at
     file offset `208908` → `.rodata` vaddr `0x3300c`. (Saber's own non-test
     code never references `spl_token::id()`, so this constant can only come
     from `check_program_account`.)
   - Scanning `.text` for `lddw` instructions loading that address yields
     **exactly 3 sites** — `0x13578`, `0x13d50`, `0x14528` — matching the three
     distinct builders Saber compiles.
   - Disassembling `0x13578` shows the guard verbatim:
     ```
     0x013578  lddw  r2, 0x3300c      ; &spl_token::ID
     0x013588  mov   r3, 32           ; len
     0x013590  call  sol_memcmp_
     0x0135a8  jne   r0, 0, +34       ; mismatch -> error path
     ```

**Verdict: not a finding.** Saber could safely drop the field precisely because
the dependency enforces it. (`spl-token-swap` kept it for historical reasons —
it was written against spl-token 2.x, before `check_program_account` existed.)
A side effect worth noting: hardcoding legacy spl-token means Token-2022 pools
are impossible, which *protects* this code from the transfer-fee/transfer-hook
class — `process_swap` credits `amount_in` to reserves without re-reading the
balance (`swap.rs:380-389`), which would be unsafe under a fee-on-transfer mint.

## Verified sound

Account substitution is the dominant bug class for a native Solana AMM. Saber
pins every consequential account against `SwapInfo`:

- **Swap authority** — `check_swap_authority` (`checks.rs:90`) recomputes
  `create_program_address([swap_info.key, nonce], program_id)` (`utils.rs:10`)
  and compares. Called on all four paths (`swap.rs:330, 446, 592, 712`). This is
  the load-bearing invariant: the PDA is bound to `swap_info.key`, so a forged
  state account yields a different authority with no power over real reserves.
- **Reserves** — `check_reserves_match` (`checks.rs:17`) on deposit
  (`checks.rs:45`) and withdraw (`checks.rs:75`); `swap` pins both legs via
  `check_swap_token_destination_accounts` (`checks.rs:107`) after matching
  `swap_source_info` to token A or B, falling through to `IncorrectSwapAccount`
  (`swap.rs:337-353`); `withdraw_one` pins the base/quote pair explicitly
  (`swap.rs:718-749`).
- **Admin fee destinations** — pinned to `token.admin_fees` on swap
  (`checks.rs:116`), withdraw (`checks.rs:80`), withdraw_one (`swap.rs:725, 738`).
- **Pool mint** — pinned to `token_swap.pool_mint` on deposit (`swap.rs:456`),
  withdraw (`swap.rs:611`), withdraw_one (`swap.rs:752`).
- **Self-deal blocked** — the user's source account is explicitly rejected if it
  is either reserve, on swap (`swap.rs:314-328`) and deposit (`checks.rs:50`).
- **Degenerate account aliasing** — `swap_source != swap_destination`
  (`swap.rs:305`) and `base != quote` (`swap.rs:713`).
- **Mint consistency on unpinned accounts** — the user's `destination_info` is
  deliberately free, and spl-token itself rejects a cross-mint transfer or a
  burn whose source mint ≠ the passed mint, so no additional check is needed.
- **`initialize` hardening** — reserves owned by the authority, LP destination
  *not* owned by it (`swap.rs:137-156`), `RepeatedMint`, `EmptySupply`, no
  delegate, no close authority, LP mint authority = swap authority, no freeze
  authority, zero LP supply, matching decimals (`swap.rs:158-211`).
- **Length-checked state decode** — `Pack::unpack_unchecked` rejects any account
  whose data length ≠ 395 before `array_ref!` can panic.
- **Arithmetic** — the math crate is uniformly `checked_*` over `U192`/`u128`
  and fails closed to `CalculationFailure`; the dual-path `mul_div` /
  `mul_div_imbalanced` (`math.rs:13, :27`) are arithmetically equivalent to
  their u128 branches and catch the single overflow case with `checked_mul`.
  `normalized_trade_fee` matches Curve's `fee * N / (4*(N-1))` exactly.

## Residual observations (real in code, **not** payable — do not submit)

1. **No explicit `swap_info.owner == program_id` check** on any path
   (`swap.rs:309, 442, 591, 708`; `admin.rs:33`). Normally a serious Solana
   bug. It is **neutralized** here because the swap authority is derived from
   `swap_info.key`: a forged state account produces a PDA with no authority over
   real reserves or the real LP mint, so every CPI fails. On the admin path, the
   trailing `SwapInfo::pack` into a non-owned account trips the runtime's
   `ExternalAccountDataModified`. Worth adding as defense-in-depth; **not**
   exploitable, so not a submission.

2. **`Fees` are unvalidated** at `initialize` (taken verbatim from instruction
   data, `swap.rs:97`) and at `set_new_fees` (`admin.rs:256`) — no
   `numerator <= denominator`, no non-zero denominator. A denominator of 0 or a
   numerator exceeding it makes withdrawals revert (`pool_converter.rs:28`),
   freezing LP funds. Reachable only by the pool admin → **trusted role, OOS**
   on essentially every program. For `initialize` it is the pool creator's own
   pool, so integrators — not the protocol — bear the risk.

3. **Newton iterations have no convergence assertion.** `compute_d`
   (`curve.rs:201`) and `compute_y_raw` (`curve.rs:292`) loop `0..256` and use
   the last iterate unconditionally if it has not converged, where Curve's Vyper
   raises. 256 iterations is far beyond the ~4–8 needed, and I found no input
   that exits the loop unconverged. Theoretical; inherited from `spl-token-swap`,
   so a duplicate even if demonstrated.

4. **A fully-drained pool is bricked.** With both reserves at 0,
   `compute_d` divides by `amount_*_times_coins == 0` → `None`, and
   `compute_mint_amount_for_deposit` divides by `d_0 == 0`. Requires every LP to
   exit first and loses no funds — a liveness quirk, not a vuln.

5. **`process_withdraw` does not check `is_paused`** while swap, deposit and
   withdraw_one do (`swap.rs:310, 443, 709`). This is **intentional** and matches
   Curve: pausing must not trap LPs, so balanced withdrawal stays open as the
   emergency exit. Not a bug.

## Deployed-vs-repo drift

None found on the security-relevant surface. All 19 account-pinning guard
strings from `checks.rs`/`swap.rs` are present in the deployed ELF (reserves A/B,
`Incorrect destination, expected`, admin fee + admin fee dest, swap authority,
admin signer, both source-cannot-be-reserve messages, pool mint, mint A/B, both
withdraw_one reserve/admin-fee pairs, LP mint authority, token A/B authority,
initial LP destination authority), plus the three `check_program_account` sites
above. The deployed program is functionally equivalent to repo HEAD on
fund-flow logic.

## Honest conclusion

**No novel, exploitable, in-scope finding.** The specific hypothesis that
motivated this pass — a missing token-program check implied by the absent
`SwapInfo.token_program_id` field — is a *false positive produced by comparing
against `spl-token-swap`'s shape rather than its behavior*. The check moved into
the dependency; it did not disappear. I verified that three ways, including in
the live binary, rather than inferring it from the source.

The account-pinning model is thorough and the arithmetic fails closed. The one
structural gap (no owner check on the state account) is genuinely neutralized by
PDA-to-`swap_info.key` binding, and the remaining observations are admin-trusted,
theoretical, or by-design. Nothing here is worth a submission; filing any of
items 1–5 would burn credibility on a known/OOS/non-exploitable report.

Methodological note for next time: **when a fork drops a field its upstream
checks, verify the dependency's instruction builders before writing an exploit
path.** `spl-token` 3.x self-validates on all 21 builders, which silently
discharges a whole family of "missing program id check" hypotheses against any
program that constructs its CPIs through them — and conversely, any program that
hand-rolls an `Instruction { program_id, .. }` does *not* get that protection and
remains worth checking.

No live testing was performed; all verification was static plus local
disassembly of an already-fetched binary.
