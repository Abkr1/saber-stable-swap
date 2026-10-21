# On-chain deployment — SSwpkEEcbUqx4vtoEByFjSkhKdCT862DNVb52nZg1UZ

This repo mirrors upstream [`saber-hq/stable-swap`](https://github.com/saber-hq/stable-swap)
at commit `39d5d4e` (HEAD at mirror time), which declares this exact program ID
in `stable-swap-program/program/src/lib.rs`, `stable-swap-anchor`,
`stable-swap-client` and `Anchor.toml`.

## Mainnet program (confirmed via RPC, slot ~459801526)

- **Program ID:** `SSwpkEEcbUqx4vtoEByFjSkhKdCT862DNVb52nZg1UZ`
  ([explorer](https://explorer.solana.com/address/SSwpkEEcbUqx4vtoEByFjSkhKdCT862DNVb52nZg1UZ),
  [Solscan](https://solscan.io/account/SSwpkEEcbUqx4vtoEByFjSkhKdCT862DNVb52nZg1UZ))
- **Program account:** executable, owner `BPFLoaderUpgradeab1e11111111111111111111111`
- **ProgramData account:** `54aePuBcYcf8G3CDrWWd2MEiw6Q7UGy2kjgQBDhqoMdt`
  (609,837 bytes incl. 45-byte header)
- **Deployed ELF:** 609,792 bytes, `onchain/program.so`
  (`SHA256: 383F720F2E0D47CE616DFDA2F9F263CCD83FC6D38A2629B472DCBFAD9DFB4504`)
- **Upgrade authority:** `EVmbDJCTGeExFGUKxmZwrfnzw4zpf7SPhPgfiLDJkUEV`
  (program is upgradeable)
- **Last deploy slot (programdata):** `11,278,087`
- **Anchor IDL:** none on-chain (native program, no IDL account) —
  instruction interface lives in `stable-swap-program/program/src/`.

## Reproducing `onchain/program.so`

```shell
# programdata account -> strip 45-byte upgradeable-loader header -> ELF
solana account 54aePuBcYcf8G3CDrWWd2MEiw6Q7UGy2kjgQBDhqoMdt \
  --output-file programdata.bin
# bytes [45:] are the BPF shared object
```

Binary fetched 2026-10-21 via `getAccountInfo` on mainnet-beta.
No source verification claim is made here beyond the program-ID match above;
for a byte-exact check, rebuild with the repo's pinned toolchain
(Anchor 0.24.2, Solana 1.11.10 per `Anchor.toml`) and compare hashes.
