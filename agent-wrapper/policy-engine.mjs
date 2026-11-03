/**
 * AgentFence policy engine — pure-JS mirror of the on-chain contract logic.
 * Used by the agent wrapper so a prompt-injected agent cannot bypass checks
 * even before a transaction is signed. The real enforcement still lives on-chain.
 */

export const Verdict = { Allow: 'Allow', Warn: 'Warn', Block: 'Block' };

const DAY_MS = 24 * 60 * 60 * 1000;

export function createPurse({
  owner = 'owner.testnet',
  perTxLimit = 0.1e24,
  dailyLimit = 0.5e24,
  balance = 5e24,
} = {}) {
  return {
    owner,
    policy: { perTxLimit, dailyLimit, paused: false },
    daySpend: { day: dayKey(Date.now()), spent: 0 },
    allowlist: new Set(),
    blocklist: new Set(),
    risk: new Map(),
    reports: [],
    payments: [],
    agents: new Set(),
    balance,
  };
}

function dayKey(ts) {
  return Math.floor(ts / DAY_MS);
}

function looksImplicit(id) {
  return typeof id === 'string' && id.length === 64 && /^[0-9a-f]+$/i.test(id);
}

export function authorizeAgent(purse, agent) {
  purse.agents.add(agent);
}

export function allow(purse, account) {
  purse.blocklist.delete(account);
  purse.allowlist.add(account);
  purse.risk.set(account, 0);
}

export function block(purse, account) {
  purse.allowlist.delete(account);
  purse.blocklist.add(account);
  purse.risk.set(account, 100);
}

export function report(purse, reporter, target, reason, evidenceHash) {
  if (!purse.agents.has(reporter) && reporter !== purse.owner) {
    throw new Error('agent or owner only');
  }
  purse.reports.push({ reporter, target, reason, evidenceHash, ts: Date.now() });
  const prev = purse.risk.get(target) || 0;
  purse.risk.set(target, Math.min(100, prev + 25));
}

export function evaluateReceiver(purse, receiver) {
  const reasons = [];
  let score = purse.risk.get(receiver) || 0;

  if (purse.blocklist.has(receiver)) {
    reasons.push('receiver is on the shared blocklist');
    return { verdict: Verdict.Block, reasons, riskScore: Math.max(score, 100) };
  }
  if (purse.allowlist.has(receiver)) {
    reasons.push('receiver is on the owner allowlist');
    return { verdict: Verdict.Allow, reasons, riskScore: 0 };
  }
  if (looksImplicit(receiver)) {
    reasons.push('receiver is an implicit account (no human-readable name)');
    score += 20;
  }
  const prior = purse.payments.filter((p) => p.to === receiver).length;
  if (prior === 0) {
    reasons.push('no prior successful payments from this purse to receiver');
    score += 15;
  } else {
    reasons.push(`${prior} prior successful payment(s) to receiver`);
  }
  const reports = purse.reports.filter((r) => r.target === receiver).length;
  if (reports > 0) {
    reasons.push(`${reports} community report(s) against receiver`);
    score += 25 * Math.min(3, reports);
  }
  let verdict = Verdict.Allow;
  if (score >= 80) verdict = Verdict.Block;
  else if (score >= 35) verdict = Verdict.Warn;
  if (!reasons.length) reasons.push('no negative signals');
  return { verdict, reasons, riskScore: score };
}

/**
 * Agent wrapper: refuses to sign on Block; asks human on Warn; signs on Allow.
 * This is the pre-chain guard. The contract re-checks on-chain.
 */
export function agentPay(purse, { agent, receiver, amount, memo, forceWarn = false, humanApproveWarn = false }) {
  if (purse.policy.paused) throw new Error('purse is paused');
  if (!purse.agents.has(agent) && agent !== purse.owner) throw new Error('agent or owner only');
  if (!(amount > 0)) throw new Error('amount must be > 0');
  if (amount > purse.policy.perTxLimit) {
    return { ok: false, stage: 'wrapper', error: 'exceeds per_tx_limit', signed: false };
  }
  const today = dayKey(Date.now());
  if (purse.daySpend.day !== today) {
    purse.daySpend = { day: today, spent: 0 };
  }
  if (purse.daySpend.spent + amount > purse.policy.dailyLimit) {
    return { ok: false, stage: 'wrapper', error: 'exceeds daily_limit', signed: false };
  }
  if (amount > purse.balance) {
    return { ok: false, stage: 'wrapper', error: 'insufficient purse balance', signed: false };
  }

  const evaluation = evaluateReceiver(purse, receiver);

  if (evaluation.verdict === Verdict.Block) {
    return {
      ok: false,
      stage: 'wrapper',
      signed: false,
      evaluation,
      error: `BLOCKED: risk=${evaluation.riskScore} reasons=${evaluation.reasons.join('; ')}`,
    };
  }
  if (evaluation.verdict === Verdict.Warn && !forceWarn && !humanApproveWarn) {
    return {
      ok: false,
      stage: 'wrapper',
      signed: false,
      needsHuman: true,
      evaluation,
      error: `WARN: human approval required. risk=${evaluation.riskScore} reasons=${evaluation.reasons.join('; ')}`,
    };
  }

  // Would sign a function-call tx to AgentFence.pay here (FC key only).
  purse.balance -= amount;
  purse.daySpend.spent += amount;
  purse.payments.push({ to: receiver, amount, memo, ts: Date.now(), agent });
  return {
    ok: true,
    stage: 'on-chain-pay',
    signed: true,
    evaluation,
    tx: {
      receiverId: 'agent-fence.testnet',
      method: 'pay',
      args: { receiver, amount: String(amount), memo, force_warn: !!(forceWarn || humanApproveWarn) },
      keyType: 'FunctionCall',
      keyScope: {
        receiverId: 'agent-fence.testnet',
        methods: ['pay', 'evaluate_receiver', 'report_receiver', 'get_policy', 'get_day_spend', 'get_balance'],
        note: 'Cannot Transfer NEAR, AddKey, or call any other contract',
      },
    },
  };
}
