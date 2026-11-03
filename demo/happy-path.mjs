#!/usr/bin/env node
import {
  createPurse, authorizeAgent, allow, agentPay, report, evaluateReceiver,
} from '../agent-wrapper/policy-engine.mjs';

const YOCTO = 1e24;
const purse = createPurse({ balance: 2 * YOCTO, perTxLimit: 0.1 * YOCTO, dailyLimit: 0.5 * YOCTO });
const agent = 'hire-bot.testnet';
authorizeAgent(purse, agent);
allow(purse, 'compute-seller.testnet');

console.log('=== AgentFence happy path ===');
let r = agentPay(purse, {
  agent,
  receiver: 'compute-seller.testnet',
  amount: 0.08 * YOCTO,
  memo: 'GPU hour',
});
console.log(JSON.stringify(r, (_, v) => (typeof v === 'number' && v > 1e12 ? String(v) : v), 2));

console.log('\n=== Over daily limit ===');
r = agentPay(purse, {
  agent,
  receiver: 'compute-seller.testnet',
  amount: 0.1 * YOCTO,
  memo: 'more compute',
});
// spend until daily limit trips
for (let i = 0; i < 5; i++) {
  r = agentPay(purse, {
    agent,
    receiver: 'compute-seller.testnet',
    amount: 0.1 * YOCTO,
    memo: `batch-${i}`,
  });
}
console.log(r);

console.log('\n=== Community report escalates unknown → Warn/Block ===');
const shady = 'shady.testnet';
report(purse, agent, shady, 'asked for seed phrase', 'sha256:deadbeef');
report(purse, agent, shady, 'replay of known scam domain', 'sha256:cafebabe');
report(purse, agent, shady, 'matches shared sink cluster', 'sha256:00ff00');
console.log(evaluateReceiver(purse, shady));
