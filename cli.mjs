#!/usr/bin/env node
// token-safety-check CLI: plain-English scam check for a Solana or EVM token. Read-only, no keys, no deps.
// Usage: node cli.mjs <mint>            (Solana)
//        node cli.mjs base:0xabc...      (ethereum | bsc | base | robinhood | monad)
//        add --json for machine-readable output
import { checkToken } from './safety.mjs';

const SOL_RPC = process.env.SOLANA_RPC || 'https://api.mainnet-beta.solana.com';
const EVM_RPC = {
  ethereum: process.env.ETH_RPC || 'https://ethereum-rpc.publicnode.com',
  bsc: process.env.BSC_RPC || 'https://bsc-rpc.publicnode.com',
  base: process.env.BASE_RPC || 'https://base-rpc.publicnode.com',
};
const DEX_CHAIN = { solana: 'solana', ethereum: 'ethereum', bsc: 'bsc', base: 'base', robinhood: 'robinhood', monad: 'monad' };

async function rpc(url, method, params) {
  const r = await fetch(url, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }), signal: AbortSignal.timeout(20000),
  });
  const j = await r.json();
  if (j.error) throw new Error(j.error.message || 'RPC error');
  return j.result;
}

export const deps = {
  solRpc: (method, params) => rpc(SOL_RPC, method, params),
  evmRpc: (chain, method, params) => {
    if (!EVM_RPC[chain]) throw new Error(`no RPC configured for ${chain}`);
    return rpc(EVM_RPC[chain], method, params);
  },
  // Map<address, { pair }> using the deepest DexScreener pair for each token
  async dexLookup(addresses, chain) {
    const out = new Map();
    const r = await fetch(`https://api.dexscreener.com/tokens/v1/${DEX_CHAIN[chain]}/${addresses.join(',')}`, { signal: AbortSignal.timeout(20000) });
    if (!r.ok) return out;
    const pairs = await r.json();
    for (const a of addresses) {
      const mine = (pairs || []).filter((p) => p.baseToken?.address?.toLowerCase() === a.toLowerCase());
      mine.sort((x, y) => (Number(y.liquidity?.usd) || 0) - (Number(x.liquidity?.usd) || 0));
      if (mine[0]) out.set(a, { pair: mine[0] });
    }
    return out;
  },
};

const ICON = { fail: '✗', warn: '!', pass: '✓', info: 'i', unknown: '?' };

export function render(rep) {
  const lines = [];
  lines.push(`${rep.name || '(unnamed)'} ${rep.symbol ? `(${rep.symbol})` : ''} on ${rep.chain}: ${rep.address}`);
  lines.push(`Verdict: ${rep.verdict.toUpperCase()}${rep.score != null ? ` (score ${rep.score}/100)` : ''}. ${rep.summary}`);
  lines.push('');
  for (const c of rep.checks) lines.push(`  ${ICON[c.status] || '-'} ${c.label}: ${c.detail}${c.source ? `  [${c.source}]` : ''}`);
  for (const f of rep.code?.findings || []) lines.push(`    code ${f.level}: ${f.file}:${f.line}  ${f.code}`);
  lines.push('', `Sources: ${[...new Set(rep.sources)].join(', ') || 'none'}. Not financial advice; this only rules out known scam patterns.`);
  return lines.join('\n');
}

const isMain = process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/').split('/').pop());
if (isMain) {
  const args = process.argv.slice(2);
  const ref = args.find((a) => !a.startsWith('--'));
  if (!ref) { console.error('usage: node cli.mjs <solana-mint | chain:0xaddress> [--json]'); process.exit(2); }
  const opts = { minLiquidityUsd: 10000, maxTaxPct: 10, maxTop10Pct: 50 };
  try {
    const rep = await checkToken(ref, deps, opts);
    console.log(args.includes('--json') ? JSON.stringify(rep, null, 2) : render(rep));
    process.exit(rep.verdict === 'danger' ? 1 : 0);
  } catch (e) { console.error('error:', e.message); process.exit(3); }
}
