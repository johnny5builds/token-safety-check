// token-safety-check: token safety checker.
// Combines free sources into one plain-English report:
//   GoPlus Security (EVM + Solana contract/holder analysis), honeypot.is (buy/sell simulation on
//   Ethereum, BNB Chain, Base), Sourcify (verified source code, which we scan for scam patterns),
//   on-chain RPC reads (owner, proxy slot, Solana top holders) and DexScreener (liquidity, volume).
// Nothing here can move money. It only reads public data.

export const CHAIN_IDS = { ethereum: '1', bsc: '56', base: '8453', robinhood: '4663', monad: '143' };
const HONEYPOT_IS = new Set(['1', '56', '8453']);
const DEAD = new Set(['0x0000000000000000000000000000000000000000', '0x000000000000000000000000000000000000dead', '0xdead000000000000000042069420694206942069']);
const EIP1967_IMPL = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';

const num = (x) => (x === undefined || x === null || x === '' ? null : Number(x));
const pct = (f) => `${(f * 100).toFixed(f < 0.01 ? 2 : 1)}%`;
const usd = (n) => (n >= 1e6 ? `$${(n / 1e6).toFixed(2)}M` : n >= 1e3 ? `$${(n / 1e3).toFixed(1)}K` : `$${Math.round(n)}`);
const short = (a) => (a ? `${a.slice(0, 6)}…${a.slice(-4)}` : '');

// ---------------------------------------------------------------- rate-limited fetch for GoPlus
let goplusChain = Promise.resolve();
function goplusGet(url) {
  const run = goplusChain.then(async () => {
    const r = await fetch(url, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(20000) });
    const j = await r.json().catch(() => null);
    await new Promise((res) => setTimeout(res, 1200)); // keep well under the free-tier limit
    if (!r.ok || !j || (j.code !== 1 && j.code !== 2)) throw new Error(`GoPlus: ${j?.message || 'HTTP ' + r.status}`);
    return j;
  });
  goplusChain = run.catch(() => {});
  return run;
}
async function getJson(url, ms = 20000) {
  const r = await fetch(url, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(ms) });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

// ---------------------------------------------------------------- source code scanner
// Patterns that show up in scam tokens. Each finding links the exact line so you can read it.
const CODE_RULES = [
  { id: 'fee_setter', level: 'warn', re: /function\s+\w*(set|update|change)\w*(fee|tax)\w*\s*\(/i,
    why: 'The owner can change buy/sell taxes after you buy. Scams raise the sell tax to 99% to trap holders. Check whether the code caps the fee (e.g. require(fee <= 10)).' },
  { id: 'blacklist', level: 'warn', re: /function\s+\w*(blacklist|blocklist|addbot|setbot|antibot|isbot|bots)\w*\s*\(/i,
    why: 'The owner can block specific wallets from selling. A classic honeypot trick: everyone who buys gets blacklisted.' },
  { id: 'trading_toggle', level: 'warn', re: /function\s+(enable|open|start|set|toggle)\w*(trading|swap)\w*\s*\(/i,
    why: 'Trading can be switched on or off by the owner. If it can be switched off again, sells can be frozen.' },
  { id: 'max_limits', level: 'warn', re: /function\s+\w*(setmax|updatemax|setmaxtx|setmaxwallet|setmaxtransaction|removelimits)\w*\s*\(/i,
    why: 'The owner can change the maximum transaction/wallet size. Setting it near zero stops everyone else from selling.' },
  { id: 'cooldown', level: 'warn', re: /cooldown/i,
    why: 'A trading cooldown limits how often you can sell. Owners can lengthen it to stop exits.' },
  { id: 'tx_origin', level: 'warn', re: /tx\.origin/,
    why: 'tx.origin checks are used by anti-bot code and by scams to block sells that go through routers.' },
  { id: 'delegatecall', level: 'warn', re: /\.delegatecall\s*\(/,
    why: 'delegatecall runs someone else\'s code with this contract\'s storage. It can be used to rewrite balances.' },
  { id: 'selfdestruct', level: 'fail', re: /\bselfdestruct\s*\(/,
    why: 'The contract can destroy itself.' },
  { id: 'assembly', level: 'info', re: /\bassembly\s*\{/,
    why: 'Inline assembly is hard to read. Legitimate libraries use it, but in a meme token it can hide logic.' },
  { id: 'fee_exclusion', level: 'info', re: /function\s+\w*(exclude|include)\w*(from|in)\w*(fee|reward|limit)\w*\s*\(/i,
    why: 'Some wallets can be exempt from fees and limits. Usually the team\'s own wallets.' },
];
// Function-level checks: owner-only functions that touch balances or supply.
const BODY_RULES = [
  { id: 'owner_balance_edit', level: 'fail', re: /_balances\s*\[[^\]]+\]\s*(=|\+=|-=)/,
    why: 'An owner-only function edits balances directly. The owner can zero out your tokens or print their own.' },
  { id: 'owner_mint', level: 'warn', re: /(_mint\s*\(|_totalSupply\s*(\+=|=))/,
    why: 'The owner can mint new tokens, diluting everyone. Safe only if ownership is renounced.' },
];
const OWNER_MOD = /\b(onlyOwner|onlyRole|authorized|onlyAdmin|onlyDev|onlyOperator|isOwner|require\s*\(\s*(msg\.sender|_msgSender\(\))\s*==\s*(owner|_owner|dev|admin))/;

export function scanSource(files) {
  const findings = [];
  for (const [path, content] of Object.entries(files)) {
    if (/(^|\/)(@openzeppelin|openzeppelin-contracts|lib\/|node_modules|@uniswap|solmate|solady)/i.test(path)) continue; // audited libraries
    const lines = content.split(/\r?\n/);
    lines.forEach((line, i) => {
      const code = line.replace(/\/\/.*$/, '');
      if (/^\s*function[^{]*;\s*$/.test(code)) return; // interface declaration, not real code
      for (const r of CODE_RULES) if (r.re.test(code)) findings.push({ rule: r.id, level: r.level, why: r.why, file: path, line: i + 1, code: line.trim().slice(0, 180) });
    });
    // owner modifier that lets more than one address through = hidden admin
    const modRe = /modifier\s+(onlyOwner|onlyAdmin|onlyDev|authorized)\s*\([^)]*\)\s*\{([\s\S]*?)\n\s*\}/g;
    let mm;
    while ((mm = modRe.exec(content))) {
      if (/\|\||isAuthorized\[|_authorized\[|admins\[/.test(mm[2])) {
        findings.push({ rule: 'hidden_admin', level: 'fail', why: 'The owner check lets a second address through. Ownership can be "renounced" while that hidden admin keeps full control.', file: path, line: content.slice(0, mm.index).split(/\r?\n/).length, code: mm[0].split(/\r?\n/).slice(0, 2).join(' ').trim().slice(0, 180) });
      }
    }
    // owner-only functions that edit balances / supply
    const fnRe = /function\s+(\w+)\s*\([^)]*\)([^{;]*)\{/g;
    let m;
    while ((m = fnRe.exec(content))) {
      const name = m[1];
      if (/^(constructor|_\w+|transfer|transferFrom|approve)$/.test(name)) continue;
      let depth = 1, i = fnRe.lastIndex;
      while (i < content.length && depth > 0) { if (content[i] === '{') depth++; else if (content[i] === '}') depth--; i++; }
      const body = content.slice(fnRe.lastIndex, i);
      const header = m[2] + body.slice(0, 200);
      if (!OWNER_MOD.test(header)) continue;
      const line = content.slice(0, m.index).split(/\r?\n/).length;
      if (/(set|update|change)\w*(fee|tax)/i.test(name) && !/require\s*\([^;]*(<=|<)\s*\d|if\s*\([^)]*>\s*\d+[^)]*\)\s*revert/.test(body)) {
        findings.push({ rule: 'uncapped_tax', level: 'fail', why: 'The owner can set the tax to any value with no upper limit, up to 100% of every sell.', file: path, line, code: `function ${name}(…) ${m[2].trim()}`.slice(0, 180) });
      }
      for (const r of BODY_RULES) if (r.re.test(body)) findings.push({ rule: r.id, level: r.level, why: r.why, file: path, line, code: `function ${name}(…) ${m[2].trim()}`.slice(0, 180) });
      if (name === 'renounceOwnership' && !/_transferOwnership|_setOwner|owner\s*=\s*address\(0\)|_owner\s*=\s*address\(0\)/.test(body)) {
        findings.push({ rule: 'fake_renounce', level: 'fail', why: 'renounceOwnership() is overridden and does not actually give up ownership. The token can say "renounced" while the owner keeps control.', file: path, line, code: `function renounceOwnership(…) ${m[2].trim()}`.slice(0, 180) });
      }
    }
  }
  // de-duplicate (same rule + line)
  const seen = new Set();
  return findings.filter((f) => { const k = `${f.rule}:${f.file}:${f.line}`; if (seen.has(k)) return false; seen.add(k); return true; }).slice(0, 60);
}

// ---------------------------------------------------------------- report builder
function makeReport(base) {
  const checks = [];
  const add = (id, label, status, detail, why = '', source = '') => checks.push({ id, label, status, detail, why, source });
  return { ...base, checks, add };
}
function finish(rep) {
  const fails = rep.checks.filter((c) => c.status === 'fail').length;
  const warns = rep.checks.filter((c) => c.status === 'warn').length;
  const known = rep.checks.filter((c) => c.status !== 'info' && c.status !== 'unknown').length;
  let score = 100 - fails * 35 - warns * 10;
  score = Math.max(0, Math.min(100, score));
  rep.verdict = fails ? 'danger' : known < 3 ? 'unknown' : warns >= 3 || score < 65 ? 'caution' : warns ? 'caution' : 'ok';
  if (!fails && warns <= 1 && known >= 3) rep.verdict = 'ok';
  rep.score = rep.verdict === 'unknown' ? null : score;
  rep.summary = {
    danger: `${fails} serious problem${fails === 1 ? '' : 's'} found. Avoid this token.`,
    caution: `${warns} warning${warns === 1 ? '' : 's'}. Possible, but understand the risks first.`,
    ok: 'No major red flags found. Still a risky asset: this only rules out known scam patterns.',
    unknown: 'Not enough data to judge yet (very new or unindexed token).',
  }[rep.verdict];
  rep.checkedAt = Date.now();
  delete rep.add;
  // order: fails, warns, passes, info
  const order = { fail: 0, warn: 1, pass: 2, unknown: 3, info: 4 };
  rep.checks.sort((a, b) => order[a.status] - order[b.status]);
  return rep;
}

// ---------------------------------------------------------------- market checks (both chains)
const ageDays = (pair) => (pair?.pairCreatedAt ? (Date.now() - pair.pairCreatedAt) / 86400000 : 0);
const isMature = (pair) => {
  const ageD = pair?.pairCreatedAt ? (Date.now() - pair.pairCreatedAt) / 86400000 : 0;
  return ageD > 30 && (Number(pair?.liquidity?.usd) || 0) > 100000;
};
function marketChecks(rep, pair, opts) {
  if (!pair) { rep.add('market', 'Market data', 'unknown', 'No DEX pair found on DexScreener yet.', 'Brand-new or untraded tokens have no price history to judge.', 'DexScreener'); return; }
  const liq = Number(pair.liquidity?.usd) || 0;
  const mcap = Number(pair.marketCap || pair.fdv) || 0;
  const vol = Number(pair.volume?.h24) || 0;
  const buys = pair.txns?.h24?.buys || 0, sells = pair.txns?.h24?.sells || 0;
  const ageH = pair.pairCreatedAt ? (Date.now() - pair.pairCreatedAt) / 3600000 : null;
  rep.market = { liquidityUsd: liq, mcapUsd: mcap, volume24h: vol, buys24h: buys, sells24h: sells, ageHours: ageH, dex: pair.dexId, pair: pair.pairAddress };
  const onCurve = ['pumpfun', 'fourmeme', 'moonshot', 'launchlab', 'boop'].includes(pair.dexId) || (pair.liquidity == null && /meme|pump|launch/i.test(pair.dexId || ''));
  if (onCurve) rep.add('liquidity', 'Liquidity', 'info', `Still on the ${pair.dexId === 'fourmeme' ? 'four.meme' : pair.dexId === 'pumpfun' ? 'pump.fun' : 'launchpad'} bonding curve. The curve contract holds the liquidity, so it cannot be pulled, but the creator and early wallets can still dump.`, 'On launchpad curves the classic "remove liquidity" rug is impossible before graduation.', 'DexScreener');
  else if (liq < 1000) rep.add('liquidity', 'Liquidity', 'fail', `Only ${usd(liq)} in the pool.`, 'With this little liquidity even a small sell crashes the price; you may not be able to exit.', 'DexScreener');
  else if (liq < opts.minLiquidityUsd) rep.add('liquidity', 'Liquidity', 'warn', `${usd(liq)} in the pool (your minimum is ${usd(opts.minLiquidityUsd)}).`, 'Thin pools mean big price impact when you sell.', 'DexScreener');
  else rep.add('liquidity', 'Liquidity', 'pass', `${usd(liq)} in the pool.`, '', 'DexScreener');
  if (!onCurve && mcap > 0 && liq >= 1000) {
    const ratio = liq / mcap;
    rep.add('liq_ratio', 'Liquidity vs market cap', ratio < 0.02 ? (isMature(pair) ? 'info' : 'warn') : 'pass', `Liquidity is ${pct(ratio)} of the ${usd(mcap)} market cap.`, 'Below about 2%, the market cap is mostly on paper: holders could not sell anywhere near that value.', 'DexScreener');
  }
  if (buys >= 20 && sells === 0) rep.add('no_sells', 'Sells happening', 'fail', `${buys} buys and zero sells in 24h.`, 'Lots of buyers and nobody selling is the textbook sign of a honeypot: people can buy but not sell.', 'DexScreener');
  else if (buys + sells > 0) rep.add('no_sells', 'Sells happening', 'pass', `${buys} buys / ${sells} sells in 24h.`, '', 'DexScreener');
  if (liq >= 1000 && vol / liq > (ageH != null && ageH < 24 ? 25 : 40) && !onCurve) rep.add('wash', 'Volume vs liquidity', 'warn', `24h volume is ${Math.round(vol / liq)}x the pool size.`, 'Volume far above liquidity often means bots trading with themselves (wash trading) to look popular.', 'DexScreener');
  if (ageH != null) rep.add('age', 'Token age', ageH < 1 ? 'warn' : 'info', ageH < 1 ? `${Math.round(ageH * 60)} minutes old.` : ageH < 48 ? `${ageH.toFixed(1)} hours old.` : `${Math.round(ageH / 24)} days old.`, 'Most rugs happen in the first hours.', 'DexScreener');
}

// ---------------------------------------------------------------- EVM
async function checkEvm(chain, address, deps, opts) {
  const cid = CHAIN_IDS[chain];
  const rep = makeReport({ chain, address, kind: 'evm', sources: [] });
  const [gp, hp, src, dex] = await Promise.allSettled([
    goplusGet(`https://api.gopluslabs.io/api/v1/token_security/${cid}?contract_addresses=${address}`),
    HONEYPOT_IS.has(cid) ? getJson(`https://api.honeypot.is/v2/IsHoneypot?address=${address}&chainID=${cid}`) : Promise.resolve(null),
    getJson(`https://sourcify.dev/server/v2/contract/${cid}/${address}?fields=sources`).catch((e) => (String(e.message).includes('404') ? { notVerified: true } : Promise.reject(e))),
    deps.dexLookup([address], chain),
  ]);
  const g = gp.status === 'fulfilled' ? gp.value.result?.[address.toLowerCase()] || null : null;
  const pair = dex.status === 'fulfilled' ? dex.value.get(address)?.pair || null : null;
  rep.name = g?.token_name || pair?.baseToken?.name || '';
  rep.symbol = g?.token_symbol || pair?.baseToken?.symbol || '';
  if (g) rep.sources.push('GoPlus');
  if (gp.status === 'rejected') rep.add('goplus', 'Security scan', 'unknown', `GoPlus did not answer (${gp.reason.message}).`, '', 'GoPlus');

  // --- honeypot / taxes
  const sim = hp.status === 'fulfilled' ? hp.value : null;
  if (sim?.honeypotResult) {
    rep.sources.push('honeypot.is');
    if (sim.honeypotResult.isHoneypot) rep.add('honeypot', 'Can you sell it?', 'fail', `Simulated sell FAILED${sim.honeypotResult.honeypotReason ? `: ${sim.honeypotResult.honeypotReason}` : ''}.`, 'A honeypot lets you buy but blocks or eats your sell. Your money would be stuck.', 'honeypot.is (real buy+sell simulation)');
    else rep.add('honeypot', 'Can you sell it?', 'pass', `Simulated buy and sell both worked (buy tax ${(sim.simulationResult?.buyTax ?? 0).toFixed(1)}%, sell tax ${(sim.simulationResult?.sellTax ?? 0).toFixed(1)}%).`, '', 'honeypot.is (real buy+sell simulation)');
  } else if (g) {
    if (g.is_honeypot === '1' || g.cannot_sell_all === '1') rep.add('honeypot', 'Can you sell it?', 'fail', g.is_honeypot === '1' ? 'GoPlus flags this as a honeypot.' : 'Holders cannot sell their whole balance.', 'A honeypot lets you buy but blocks or eats your sell.', 'GoPlus');
    else if (g.is_honeypot === '0') rep.add('honeypot', 'Can you sell it?', 'pass', 'GoPlus found no honeypot behaviour.', 'No sell simulation is available on this chain, so this relies on GoPlus\' analysis.', 'GoPlus');
  }
  if (sim && !sim.honeypotResult && /BUY_FAIL/i.test(String(sim.simulationError || ''))) rep.add('buy_sim', 'Can you buy it?', 'warn', 'A simulated buy failed. Trading may not be open yet, or buyers are being blocked.', '', 'honeypot.is');
  const flags = new Set((sim?.summary?.flags || []).map((f) => f.flag || f));
  if (flags.has('high_fail_rate')) rep.add('hp_fail_rate', 'Real holders failing to sell', 'fail', 'Many existing holders cannot sell.', 'honeypot.is checked real holder wallets and a large share of their sells fail.', 'honeypot.is holder analysis');
  if (flags.has('high_siphon_rate')) rep.add('hp_siphon', 'Tokens disappearing', 'fail', 'Tokens are being taken from holders without their consent.', 'A "siphon": the contract moves tokens out of your wallet.', 'honeypot.is holder analysis');
  if (sim?.contractCode && sim.contractCode.rootOpenSource && sim.contractCode.openSource === false) rep.add('hidden_contract', 'Hidden contract in sells', 'fail', 'The token is verified, but it calls an unverified contract when you trade.', 'The scam logic lives in a second contract nobody can read.', 'honeypot.is');
  if (g?.is_airdrop_scam === '1') rep.add('airdrop_scam', 'Airdrop scam', 'fail', 'This is a known airdrop scam token.', 'Free tokens that appear in your wallet are bait. Interacting with them is how you get drained.', 'GoPlus');
  if (g?.fake_token?.value === 1 || g?.fake_token?.value === '1') rep.add('fake_token', 'Fake token', 'fail', `Impersonates a real token${g.fake_token.true_token_address ? ` (real one: ${short(g.fake_token.true_token_address)})` : ''}.`, 'Same name and symbol as a real coin, different contract. Always identify tokens by address.', 'GoPlus');
  if (g?.cannot_buy === '1') rep.add('cannot_buy', 'Can you buy it?', 'fail', 'Buying is blocked.', '', 'GoPlus');
  const buyTax = sim?.simulationResult?.buyTax != null ? sim.simulationResult.buyTax / 100 : num(g?.buy_tax);
  const sellTax = sim?.simulationResult?.sellTax != null ? sim.simulationResult.sellTax / 100 : num(g?.sell_tax);
  if (buyTax != null || sellTax != null) {
    const worst = Math.max(buyTax || 0, sellTax || 0);
    rep.add('tax', 'Buy / sell tax', worst >= 0.3 ? 'fail' : worst > opts.maxTaxPct / 100 ? 'warn' : 'pass', `Buy ${pct(buyTax || 0)}, sell ${pct(sellTax || 0)}.`, 'Taxes are taken from every trade. Above ~10% you start most trades deep in the red.', sim ? 'honeypot.is' : 'GoPlus');
  }

  // --- ownership & privileges
  const owner = (g?.owner_address || '').toLowerCase();
  const ownerActive = owner && !DEAD.has(owner);
  let onchainOwner = null;
  try {
    const r = await deps.evmRpc(chain, 'eth_call', [{ to: address, data: '0x8da5cb5b' }, 'latest']); // owner()
    if (r && r !== '0x' && r.length >= 66) onchainOwner = '0x' + r.slice(-40);
  } catch { /* no owner() function */ }
  const ownerAddr = owner || onchainOwner || '';
  const active = ownerActive || (onchainOwner && !DEAD.has(onchainOwner));
  rep.owner = ownerAddr || null;
  rep.add('owner', 'Owner', active ? 'warn' : 'pass', active ? `Owned by ${short(ownerAddr)}. Owner-only functions are still live.` : 'No active owner (renounced or none).', 'An active owner can use any admin function in the contract. Renounced = nobody can change the rules any more.', 'GoPlus + on-chain owner()');
  if (g?.hidden_owner === '1') rep.add('hidden_owner', 'Hidden owner', 'fail', 'The contract has a hidden owner that can still control it.', 'A common trick: "renounce" ownership publicly while a second, hidden admin keeps control.', 'GoPlus');
  if (g?.can_take_back_ownership === '1') rep.add('take_back', 'Can reclaim ownership', 'fail', 'Ownership can be taken back after renouncing.', 'Fake renounce: the owner gives up control, then quietly takes it back.', 'GoPlus');
  if (g?.owner_change_balance === '1') rep.add('owner_balance', 'Owner can change balances', 'fail', 'The owner can edit holders\' balances.', 'They can wipe your balance or print tokens for themselves.', 'GoPlus');
  if (g?.selfdestruct === '1') rep.add('selfdestruct', 'Self-destruct', 'fail', 'The contract can be destroyed.', '', 'GoPlus');
  if (g?.honeypot_with_same_creator === '1') rep.add('serial', 'Creator history', 'fail', 'The same creator has deployed honeypots before.', 'Serial scammers reuse wallets.', 'GoPlus');
  if (g?.is_mintable === '1') rep.add('mint', 'Mintable', active ? 'warn' : 'info', active ? 'New tokens can be minted, and there is an active owner.' : 'Has a mint function, but no active owner to use it.', 'Minting dilutes holders. A rug variant: mint billions and dump them into the pool.', 'GoPlus');
  if (g?.is_blacklisted === '1') rep.add('blacklist', 'Blacklist', active ? 'warn' : 'info', 'The contract can block wallets from trading.', 'Used against bots, and by scammers against buyers.', 'GoPlus');
  if (g?.slippage_modifiable === '1' || g?.personal_slippage_modifiable === '1') rep.add('tax_modifiable', 'Tax can be changed', active ? 'fail' : 'warn', g?.personal_slippage_modifiable === '1' ? 'Tax can be set per wallet (one wallet can be charged 100%).' : 'The owner can change buy/sell tax.', 'A low tax today can become 99% tomorrow.', 'GoPlus');
  if (g?.transfer_pausable === '1') rep.add('pausable', 'Transfers can be paused', active ? 'warn' : 'info', 'Trading can be frozen.', 'Paused = nobody can sell.', 'GoPlus');
  if (g?.trading_cooldown === '1') rep.add('cooldown', 'Trading cooldown', 'warn', 'Wallets must wait between trades.', '', 'GoPlus');
  if (g?.external_call === '1') rep.add('external_call', 'External calls', 'warn', 'Transfers call another contract.', 'Behaviour can depend on code you cannot see here.', 'GoPlus');
  if (g?.anti_whale_modifiable === '1') rep.add('anti_whale', 'Max-tx limit changeable', active ? 'warn' : 'info', 'The owner can change the maximum trade size.', 'Set near zero, it blocks sells.', 'GoPlus');

  // --- code: verified source + proxy
  let proxyImpl = null;
  try {
    const slot = await deps.evmRpc(chain, 'eth_getStorageAt', [address, EIP1967_IMPL, 'latest']);
    if (slot && /[1-9a-f]/i.test(slot.slice(26))) proxyImpl = '0x' + slot.slice(-40);
  } catch { /* ignore */ }
  if (proxyImpl || g?.is_proxy === '1') rep.add('proxy', 'Upgradeable (proxy)', 'warn', proxyImpl ? `Proxy pointing at ${short(proxyImpl)}.` : 'GoPlus detected a proxy.', 'The code behind the token can be swapped for different code at any time, including malicious code.', 'on-chain EIP-1967 slot');
  const s = src.status === 'fulfilled' ? src.value : null;
  if (s?.sources) {
    rep.sources.push('Sourcify');
    const files = Object.fromEntries(Object.entries(s.sources).map(([p, v]) => [p, v.content || '']));
    rep.code = { verified: true, files: Object.keys(files).length, mainFiles: Object.keys(files).filter((p) => !/(openzeppelin|lib\/|@)/i.test(p)).slice(0, 8), findings: scanSource(files) };
    rep.add('verified', 'Source code', 'pass', `Verified on Sourcify (${rep.code.files} files).`, 'Anyone can read exactly what the contract does.', 'Sourcify');
    const f = rep.code.findings;
    const fails = f.filter((x) => x.level === 'fail').length, warns = f.filter((x) => x.level === 'warn').length;
    if (fails) rep.add('code_scan', 'Code red flags', 'fail', `${fails} dangerous pattern${fails === 1 ? '' : 's'} in the code (see below).`, '', 'code scan');
    else if (warns) rep.add('code_scan', 'Code red flags', active ? 'warn' : 'info', `${warns} owner-controlled feature${warns === 1 ? '' : 's'} in the code${active ? '' : ' (owner renounced, so they are locked)'}.`, '', 'code scan');
    else rep.add('code_scan', 'Code red flags', 'pass', 'No known scam patterns in the token code.', '', 'code scan');
  } else if (g?.is_open_source === '1') {
    rep.add('verified', 'Source code', 'pass', 'Verified on the block explorer (not on Sourcify, so not scanned here).', '', 'GoPlus');
  } else if (g?.is_open_source === '0' || s?.notVerified) {
    rep.add('verified', 'Source code', g?.is_open_source === '0' ? 'fail' : 'warn', 'Source code is NOT published.', 'Unverified code means nobody can check what it does. Legit projects verify; scams often do not.', g?.is_open_source === '0' ? 'GoPlus' : 'Sourcify');
  }

  // --- holders & liquidity locks
  if (g?.holders?.length) {
    const pools = new Set((g.dex || []).flatMap((d) => [d.pair, d.pool_manager]).filter(Boolean).map((x) => x.toLowerCase()));
    if (pair?.pairAddress) pools.add(pair.pairAddress.toLowerCase());
    const real = g.holders.filter((h) => !pools.has(h.address.toLowerCase()) && !DEAD.has(h.address.toLowerCase()) && h.is_locked !== 1 && !/lock|pool|pair|burn|null/i.test(h.tag || ''));
    const top10 = real.slice(0, 10).reduce((a, h) => a + (Number(h.percent) || 0), 0);
    rep.holders = { count: num(g.holder_count), top10, top: real.slice(0, 5).map((h) => ({ address: h.address, pct: Number(h.percent), contract: !!h.is_contract, tag: h.tag || '' })) };
    rep.add('holders', 'Top 10 holders', top10 > 0.8 ? 'fail' : top10 > opts.maxTop10Pct / 100 ? 'warn' : 'pass', `Top 10 wallets (excluding pools and locks) hold ${pct(top10)} · ${g.holder_count} holders.`, 'If a few wallets own most of the supply, they can crash the price whenever they sell.', 'GoPlus');
  }
  const creatorPct = num(g?.creator_percent);
  if (creatorPct != null) rep.add('creator', 'Creator holdings', creatorPct > 0.3 ? 'fail' : creatorPct > 0.1 ? 'warn' : 'pass', `Creator wallet holds ${pct(creatorPct)}.`, 'A creator sitting on a big bag can dump on buyers (a "soft rug").', 'GoPlus');
  const v2 = (g?.dex || []).some((d) => /v2/i.test(d.liquidity_type || d.name || ''));
  if (g?.lp_holders?.length && !v2) {
    rep.add('lp_lock', 'Liquidity locked/burned', 'info', 'Liquidity sits in Uniswap V3/V4-style positions (NFTs), which cannot be checked for locks the simple way.', 'Concentrated-liquidity positions can still be withdrawn by whoever owns them. Watch the liquidity number for sudden drops.', 'GoPlus');
  } else if (g?.lp_holders?.length) {
    const lockedPct = g.lp_holders.reduce((a, h) => a + ((h.is_locked === 1 || DEAD.has(String(h.address).toLowerCase())) ? Number(h.percent) || 0 : 0), 0);
    rep.lp = { lockedPct, holders: num(g.lp_holder_count) };
    rep.add('lp_lock', 'Liquidity locked/burned', lockedPct >= 0.9 ? 'pass' : isMature(pair) ? 'info' : lockedPct >= 0.5 || ageDays(pair) > 7 ? 'warn' : 'fail', `${pct(lockedPct)} of the pool's liquidity tokens are locked or burned.`, 'Unlocked liquidity can be withdrawn by its owner at any moment: the classic rug pull.', 'GoPlus');
  }
  marketChecks(rep, pair, opts);
  return finish(rep);
}

// ---------------------------------------------------------------- Solana
async function checkSolana(mint, deps, opts) {
  const rep = makeReport({ chain: 'solana', address: mint, kind: 'spl', sources: [] });
  const [gp, dex] = await Promise.allSettled([
    goplusGet(`https://api.gopluslabs.io/api/v1/solana/token_security?contract_addresses=${mint}`),
    deps.dexLookup([mint], 'solana'),
  ]);
  const g = gp.status === 'fulfilled' ? gp.value.result?.[mint] || null : null;
  const pair = dex.status === 'fulfilled' ? dex.value.get(mint)?.pair || null : null;
  rep.name = g?.metadata?.name || pair?.baseToken?.name || '';
  rep.symbol = g?.metadata?.symbol || pair?.baseToken?.symbol || '';
  if (g) rep.sources.push('GoPlus');
  else rep.add('goplus', 'Security scan', 'unknown', gp.status === 'rejected' ? `GoPlus did not answer (${gp.reason.message}).` : 'GoPlus has no data yet.', '', 'GoPlus');
  const on = (x) => x && String(x.status) === '1';
  if (g) {
    const trusted = g.trusted_token === 1 || g.trusted_token === '1';
    rep.add('mint_auth', 'Mint authority', on(g.mintable) ? (trusted ? 'info' : 'fail') : 'pass', on(g.mintable) ? 'Someone can still mint new tokens.' : 'Mint authority revoked: supply is fixed.', 'If the mint authority is live, the creator can print unlimited tokens and dump them.', 'GoPlus');
    rep.add('freeze_auth', 'Freeze authority', on(g.freezable) ? (trusted ? 'info' : 'fail') : 'pass', on(g.freezable) ? 'Someone can freeze your token account.' : 'No freeze authority.', 'A frozen account cannot sell: a Solana-style honeypot.', 'GoPlus');
    if (on(g.balance_mutable_authority)) rep.add('perm_delegate', 'Permanent delegate', 'fail', 'An authority can move or burn tokens from any wallet.', 'Token-2022 "permanent delegate": they can take your tokens without asking.', 'GoPlus');
    if (Array.isArray(g.transfer_hook) && g.transfer_hook.length) rep.add('transfer_hook', 'Transfer hook', 'fail', 'Every transfer runs extra custom code.', 'A transfer hook can block sells or charge hidden fees.', 'GoPlus');
    if (g.transfer_fee && Object.keys(g.transfer_fee).length) rep.add('transfer_fee', 'Transfer fee', 'warn', `Transfer fee: ${JSON.stringify(g.transfer_fee).slice(0, 80)}.`, 'Token-2022 fee on every transfer, possibly changeable.', 'GoPlus');
    if (String(g.non_transferable) === '1') rep.add('non_transferable', 'Non-transferable', 'fail', 'Tokens cannot be transferred.', '', 'GoPlus');
    if (String(g.default_account_state) === '2') rep.add('default_frozen', 'Accounts start frozen', 'fail', 'New holders are frozen by default.', '', 'GoPlus');
    if (on(g.closable)) rep.add('closable', 'Closable mint', 'warn', 'The mint account can be closed.', '', 'GoPlus');
    if (on(g.metadata_mutable)) rep.add('metadata', 'Metadata changeable', 'info', 'Name/image can still be changed.', 'Used in "rebrand" scams, mostly harmless.', 'GoPlus');
  }
  // top holders via RPC, excluding pools and the pump.fun bonding curve
  try {
    let largest;
    for (let i = 0; i < 3 && !largest; i++) {
      try { largest = await deps.solRpc('getTokenLargestAccounts', [mint, { commitment: 'confirmed' }]); }
      catch (e) { if (i === 2) throw e; await new Promise((r) => setTimeout(r, 2500 * (i + 1))); }
    }
    const supplyR = await deps.solRpc('getTokenSupply', [mint]);
    const supply = Number(supplyR?.value?.uiAmountString || 0);
    const accs = (largest?.value || []).slice(0, 20);
    const info = accs.length ? await deps.solRpc('getMultipleAccounts', [accs.map((a) => a.address), { encoding: 'jsonParsed' }]) : { value: [] };
    const exclude = new Set([deps.curveOf?.(mint), pair?.pairAddress].filter(Boolean));
    const rows = accs.map((a, i) => ({ owner: info.value[i]?.data?.parsed?.info?.owner || a.address, amount: Number(a.uiAmountString || 0) }));
    // pool vaults are owned by program-derived accounts; drop the biggest one if it looks like the pool/curve
    const real = rows.filter((r) => !exclude.has(r.owner));
    if (real.length && rows.length && real.length === rows.length && pair) real.shift(); // largest account is almost always the pool vault
    const top10 = supply ? real.slice(0, 10).reduce((a, r) => a + r.amount, 0) / supply : null;
    if (top10 != null) {
      rep.holders = { top10, top: real.slice(0, 5).map((r) => ({ address: r.owner, pct: supply ? r.amount / supply : null })) };
      rep.add('holders', 'Top 10 holders', top10 > 0.8 ? 'fail' : top10 > opts.maxTop10Pct / 100 ? 'warn' : 'pass', `Top 10 wallets (excluding the pool) hold ${pct(top10)}.`, 'A few wallets holding most of the supply (often the dev\'s "bundled" sniper wallets) can dump at any time.', 'Solana RPC');
    }
  } catch (e) { rep.add('holders', 'Top 10 holders', 'unknown', `Could not read holders (${e.message}).`, '', 'Solana RPC'); }
  marketChecks(rep, pair, opts);
  return finish(rep);
}

// ---------------------------------------------------------------- public API (with cache)
const cache = new Map();
const inflight = new Map();
export async function checkToken(ref, deps, opts) {
  const chain = String(ref).includes(':') ? String(ref).split(':')[0] : 'solana';
  const address = String(ref).includes(':') ? String(ref).split(':')[1] : String(ref);
  const key = `${chain}:${address.toLowerCase()}`;
  const hit = cache.get(key);
  const ttl = hit?.verdict === 'unknown' ? 2 * 60000 : 10 * 60000;
  if (hit && Date.now() - hit.checkedAt < ttl) return hit;
  if (inflight.has(key)) return inflight.get(key);
  const p = (async () => {
    let rep;
    if (chain === 'solana') rep = await checkSolana(address, deps, opts);
    else if (CHAIN_IDS[chain]) rep = await checkEvm(chain, address.toLowerCase(), deps, opts);
    else throw new Error(`Unsupported chain: ${chain}`);
    rep.ref = ref;
    cache.set(key, rep);
    if (cache.size > 500) cache.delete(cache.keys().next().value);
    return rep;
  })().finally(() => inflight.delete(key));
  inflight.set(key, p);
  return p;
}
export const cachedVerdict = (ref) => {
  const chain = String(ref).includes(':') ? String(ref).split(':')[0] : 'solana';
  const address = String(ref).includes(':') ? String(ref).split(':')[1] : String(ref);
  return cache.get(`${chain}:${address.toLowerCase()}`) || null;
};
