# token-safety-check

Plain-English scam check for **Solana** and **EVM** tokens (Ethereum, Base, BNB Chain). One command, zero dependencies, read-only: it never asks for a key and cannot move funds.

```
$ node cli.mjs DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263
Bonk (Bonk) on solana: DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263
Verdict: OK (score 100/100). No major red flags found.

  ✓ Mint authority: Mint authority revoked: supply is fixed.  [GoPlus]
  ✓ Freeze authority: No freeze authority.  [GoPlus]
  ✓ Liquidity: $213.0K in the pool.  [DexScreener]
  ✓ Sells happening: 9005 buys / 7779 sells in 24h.  [DexScreener]
```

## What it checks

| Chain | Checks |
|---|---|
| Solana | mint/freeze authority, Token-2022 permanent delegate, transfer hooks and fees, default-frozen accounts, top-10 holder concentration (via RPC, pool excluded) |
| EVM | real buy+sell simulation (honeypot.is), buy/sell tax, owner/renounce status, hidden owner, reclaimable ownership, upgradeable proxy (EIP-1967 slot), LP lock %, holder concentration, creator bag |
| EVM source | pulls verified source from Sourcify and scans it: uncapped owner tax setters, owner balance edits, fake `renounceOwnership`, hidden admins in `onlyOwner`, blacklists, trading toggles, `selfdestruct`, `delegatecall` |
| Market | liquidity depth, liquidity/market-cap ratio, buys-with-zero-sells (honeypot tell), wash-trading volume, token age |

Every finding cites its source and explains *why* it matters.

## Usage

```
node cli.mjs <solana-mint>
node cli.mjs base:0x...        # ethereum | bsc | base
node cli.mjs <ref> --json      # full report as JSON
```

Exit code `1` when the verdict is `danger`, so it drops into scripts and CI.
Set `SOLANA_RPC` (and `ETH_RPC`/`BASE_RPC`/`BSC_RPC`) to your own endpoints; the public Solana RPC rate-limits holder lookups.

As a library:

```js
import { checkToken } from './safety.mjs';
import { deps } from './cli.mjs';
const report = await checkToken('base:0x...', deps, { minLiquidityUsd: 10000, maxTaxPct: 10, maxTop10Pct: 50 });
```

## Tests

`npm test` runs the source-scanner tests (node:test, no dependencies).

## Limits

This rules out *known* scam patterns. It is not an audit and not financial advice. Data comes from free public APIs (GoPlus, honeypot.is, Sourcify, DexScreener); when one is down, the affected checks show `?`.

## Hire me

I build Solana/EVM tooling, Telegram/Discord bots, wallet monitors and test suites. Open an issue or see the profile for contact. Paid in USDC (Solana or Base).
