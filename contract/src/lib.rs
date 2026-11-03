//! AgentFence — on-chain spending policy + counterparty guard for AI agents on NEAR.
//!
//! The human owner deposits NEAR into this contract. The agent receives only a
//! function-call access key scoped to this contract (never a full-access key).
//! Every spend goes through `pay`, which enforces per-tx / daily limits, an
//! allow/block list, and a shared reputation score.

use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LookupMap, UnorderedMap, Vector};
use near_sdk::json_types::U128;
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{
    env, near, require, AccountId, Allowance, NearToken, PanicOnDefault, Promise, PublicKey,
};

const DAY_NS: u64 = 24 * 60 * 60 * 1_000_000_000;
const MAX_REPORT_REASON: usize = 280;

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub enum Verdict {
    Allow,
    Warn,
    Block,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub struct Evaluation {
    pub verdict: Verdict,
    pub reasons: Vec<String>,
    pub risk_score: u32,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub struct Policy {
    pub per_tx_limit: u128,
    pub daily_limit: u128,
    pub paused: bool,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub struct DaySpend {
    pub day: u64,
    pub spent: u128,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub struct PaymentRecord {
    pub to: AccountId,
    pub amount: u128,
    pub memo: String,
    pub ts: u64,
    pub agent: AccountId,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub struct Report {
    pub reporter: AccountId,
    pub target: AccountId,
    pub reason: String,
    pub evidence_hash: String,
    pub ts: u64,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct AgentFence {
    pub owner: AccountId,
    pub policy: Policy,
    pub day_spend: DaySpend,
    pub allowlist: UnorderedMap<AccountId, bool>,
    pub blocklist: UnorderedMap<AccountId, bool>,
    pub risk: LookupMap<AccountId, u32>,
    pub reports: Vector<Report>,
    pub payments: Vector<PaymentRecord>,
    pub authorized_agents: UnorderedMap<AccountId, bool>,
}

#[near]
impl AgentFence {
    #[init]
    pub fn new(per_tx_limit: U128, daily_limit: U128) -> Self {
        require!(!env::state_exists(), "Already initialized");
        require!(per_tx_limit.0 > 0, "per_tx_limit must be > 0");
        require!(daily_limit.0 >= per_tx_limit.0, "daily_limit must be >= per_tx_limit");
        Self {
            owner: env::predecessor_account_id(),
            policy: Policy {
                per_tx_limit: per_tx_limit.0,
                daily_limit: daily_limit.0,
                paused: false,
            },
            day_spend: DaySpend {
                day: current_day(),
                spent: 0,
            },
            allowlist: UnorderedMap::new(b"a"),
            blocklist: UnorderedMap::new(b"b"),
            risk: LookupMap::new(b"r"),
            reports: Vector::new(b"p"),
            payments: Vector::new(b"y"),
            authorized_agents: UnorderedMap::new(b"g"),
        }
    }

    pub fn set_policy(&mut self, per_tx_limit: U128, daily_limit: U128) {
        self.assert_owner();
        require!(per_tx_limit.0 > 0, "per_tx_limit must be > 0");
        require!(daily_limit.0 >= per_tx_limit.0, "daily_limit must be >= per_tx_limit");
        self.policy.per_tx_limit = per_tx_limit.0;
        self.policy.daily_limit = daily_limit.0;
    }

    pub fn pause(&mut self) {
        self.assert_owner();
        self.policy.paused = true;
    }

    pub fn unpause(&mut self) {
        self.assert_owner();
        self.policy.paused = false;
    }

    pub fn authorize_agent(&mut self, agent: AccountId) {
        self.assert_owner();
        self.authorized_agents.insert(&agent, &true);
    }

    pub fn revoke_agent(&mut self, agent: AccountId) {
        self.assert_owner();
        self.authorized_agents.remove(&agent);
    }

    pub fn allow(&mut self, account: AccountId) {
        self.assert_owner();
        self.blocklist.remove(&account);
        self.allowlist.insert(&account, &true);
        self.risk.insert(&account, &0);
    }

    pub fn block(&mut self, account: AccountId) {
        self.assert_owner();
        self.allowlist.remove(&account);
        self.blocklist.insert(&account, &true);
        self.risk.insert(&account, &100);
    }

    pub fn unblock(&mut self, account: AccountId) {
        self.assert_owner();
        self.blocklist.remove(&account);
    }

    #[payable]
    pub fn deposit(&mut self) {
        require!(
            env::attached_deposit() > NearToken::from_yoctonear(0),
            "Attach NEAR"
        );
    }

    pub fn withdraw(&mut self, amount: U128) -> Promise {
        self.assert_owner();
        require!(
            env::account_balance() >= NearToken::from_yoctonear(amount.0),
            "Insufficient balance"
        );
        Promise::new(self.owner.clone()).transfer(NearToken::from_yoctonear(amount.0))
    }

    /// Add a function-call key on this contract account, scoped to agent methods.
    /// Agents never receive a full-access key.
    pub fn add_agent_function_call_key(
        &mut self,
        public_key: PublicKey,
        allowance_yocto: U128,
        agent: AccountId,
    ) -> Promise {
        self.assert_owner();
        self.authorized_agents.insert(&agent, &true);
        let methods =
            "pay,evaluate_receiver,report_receiver,get_policy,get_day_spend,get_balance";
        let allowance = Allowance::limited(NearToken::from_yoctonear(allowance_yocto.0))
            .unwrap_or(Allowance::unlimited());
        Promise::new(env::current_account_id()).add_access_key_allowance(
            public_key,
            allowance,
            env::current_account_id(),
            methods.to_string(),
        )
    }

    pub fn delete_key(&mut self, public_key: PublicKey) -> Promise {
        self.assert_owner();
        Promise::new(env::current_account_id()).delete_key(public_key)
    }

    /// Counterparty check. Returns Allow / Warn / Block + reasons + risk score.
    pub fn evaluate_receiver(&self, receiver: AccountId) -> Evaluation {
        let mut reasons = Vec::new();
        let mut score: u32 = self.risk.get(&receiver).unwrap_or(0);

        if self.blocklist.get(&receiver).unwrap_or(false) {
            reasons.push("receiver is on the shared blocklist".to_string());
            score = score.max(100);
            return Evaluation {
                verdict: Verdict::Block,
                reasons,
                risk_score: score,
            };
        }

        if self.allowlist.get(&receiver).unwrap_or(false) {
            reasons.push("receiver is on the owner allowlist".to_string());
            return Evaluation {
                verdict: Verdict::Allow,
                reasons,
                risk_score: 0,
            };
        }

        if looks_like_implicit(&receiver) {
            reasons.push("receiver is an implicit account (no human-readable name)".to_string());
            score = score.saturating_add(20);
        }

        let prior = self.count_prior_payments(&receiver);
        if prior == 0 {
            reasons.push("no prior successful payments from this purse to receiver".to_string());
            score = score.saturating_add(15);
        } else {
            reasons.push(format!("{prior} prior successful payment(s) to receiver"));
        }

        let reports = self.count_reports(&receiver);
        if reports > 0 {
            reasons.push(format!("{reports} community report(s) against receiver"));
            score = score.saturating_add(25 * reports.min(3));
        }

        let verdict = if score >= 80 {
            Verdict::Block
        } else if score >= 35 {
            Verdict::Warn
        } else {
            Verdict::Allow
        };
        if reasons.is_empty() {
            reasons.push("no negative signals".to_string());
        }
        Evaluation {
            verdict,
            reasons,
            risk_score: score,
        }
    }

    /// Community report. Store a content hash, never raw PII.
    pub fn report_receiver(&mut self, target: AccountId, reason: String, evidence_hash: String) {
        self.assert_agent_or_owner();
        require!(!reason.is_empty() && reason.len() <= MAX_REPORT_REASON, "bad reason");
        require!(
            !evidence_hash.is_empty() && evidence_hash.len() <= 128,
            "bad evidence_hash"
        );
        let reporter = env::predecessor_account_id();
        self.reports.push(&Report {
            reporter,
            target: target.clone(),
            reason,
            evidence_hash,
            ts: env::block_timestamp(),
        });
        let prev = self.risk.get(&target).unwrap_or(0);
        self.risk.insert(&target, &prev.saturating_add(25).min(100));
    }

    /// Only path an agent uses to move money. Block refuses. Warn refuses unless
    /// `force_warn` (human override).
    pub fn pay(
        &mut self,
        receiver: AccountId,
        amount: U128,
        memo: String,
        force_warn: bool,
    ) -> Promise {
        require!(!self.policy.paused, "purse is paused");
        self.assert_agent_or_owner();
        require!(!memo.is_empty() && memo.len() <= 120, "bad memo");
        require!(amount.0 > 0, "amount must be > 0");
        require!(amount.0 <= self.policy.per_tx_limit, "exceeds per_tx_limit");

        self.refresh_day();
        require!(
            self.day_spend.spent.saturating_add(amount.0) <= self.policy.daily_limit,
            "exceeds daily_limit"
        );
        require!(
            env::account_balance() >= NearToken::from_yoctonear(amount.0),
            "insufficient purse balance"
        );

        let eval = self.evaluate_receiver(receiver.clone());
        match eval.verdict {
            Verdict::Block => env::panic_str(&format!(
                "BLOCKED: risk={} reasons={}",
                eval.risk_score,
                eval.reasons.join("; ")
            )),
            Verdict::Warn if !force_warn => env::panic_str(&format!(
                "WARN: human approval required. risk={} reasons={}",
                eval.risk_score,
                eval.reasons.join("; ")
            )),
            _ => {}
        }

        self.day_spend.spent = self.day_spend.spent.saturating_add(amount.0);
        self.payments.push(&PaymentRecord {
            to: receiver.clone(),
            amount: amount.0,
            memo,
            ts: env::block_timestamp(),
            agent: env::predecessor_account_id(),
        });

        Promise::new(receiver).transfer(NearToken::from_yoctonear(amount.0))
    }

    pub fn get_policy(&self) -> Policy {
        self.policy.clone()
    }

    pub fn get_day_spend(&self) -> DaySpend {
        let mut d = self.day_spend.clone();
        let today = current_day();
        if d.day != today {
            d.day = today;
            d.spent = 0;
        }
        d
    }

    pub fn get_balance(&self) -> U128 {
        U128(env::account_balance().as_yoctonear())
    }

    pub fn get_payment(&self, index: u64) -> Option<PaymentRecord> {
        self.payments.get(index)
    }

    pub fn get_payments_len(&self) -> u64 {
        self.payments.len()
    }

    pub fn get_report(&self, index: u64) -> Option<Report> {
        self.reports.get(index)
    }

    pub fn get_reports_len(&self) -> u64 {
        self.reports.len()
    }

    pub fn is_agent(&self, account: AccountId) -> bool {
        self.authorized_agents.get(&account).unwrap_or(false)
    }

    pub fn get_owner(&self) -> AccountId {
        self.owner.clone()
    }

    fn assert_owner(&self) {
        require!(env::predecessor_account_id() == self.owner, "owner only");
    }

    fn assert_agent_or_owner(&self) {
        let pred = env::predecessor_account_id();
        require!(
            pred == self.owner || self.authorized_agents.get(&pred).unwrap_or(false),
            "agent or owner only"
        );
    }

    fn refresh_day(&mut self) {
        let today = current_day();
        if self.day_spend.day != today {
            self.day_spend.day = today;
            self.day_spend.spent = 0;
        }
    }

    fn count_prior_payments(&self, receiver: &AccountId) -> u32 {
        let mut n = 0u32;
        for i in 0..self.payments.len() {
            if let Some(p) = self.payments.get(i) {
                if &p.to == receiver {
                    n = n.saturating_add(1);
                }
            }
        }
        n
    }

    fn count_reports(&self, target: &AccountId) -> u32 {
        let mut n = 0u32;
        for i in 0..self.reports.len() {
            if let Some(r) = self.reports.get(i) {
                if &r.target == target {
                    n = n.saturating_add(1);
                }
            }
        }
        n
    }
}

fn current_day() -> u64 {
    env::block_timestamp() / DAY_NS
}

fn looks_like_implicit(id: &AccountId) -> bool {
    let s = id.as_str();
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::testing_env;

    fn ctx(predecessor: AccountId) -> VMContextBuilder {
        let mut b = VMContextBuilder::new();
        b.current_account_id(accounts(0))
            .signer_account_id(predecessor.clone())
            .predecessor_account_id(predecessor)
            .account_balance(NearToken::from_near(10))
            .block_timestamp(1_700_000_000_000_000_000);
        b
    }

    fn setup() -> AgentFence {
        testing_env!(ctx(accounts(1)).build());
        AgentFence::new(U128(10u128.pow(23)), U128(5 * 10u128.pow(23)))
    }

    #[test]
    fn blocks_blocklisted_receiver() {
        let mut c = setup();
        testing_env!(ctx(accounts(1)).build());
        c.authorize_agent(accounts(2));
        c.block(accounts(3));
        testing_env!(ctx(accounts(2)).build());
        let ev = c.evaluate_receiver(accounts(3));
        assert_eq!(ev.verdict, Verdict::Block);
    }

    #[test]
    fn allows_allowlisted_receiver() {
        let mut c = setup();
        testing_env!(ctx(accounts(1)).build());
        c.authorize_agent(accounts(2));
        c.allow(accounts(4));
        testing_env!(ctx(accounts(2)).build());
        let ev = c.evaluate_receiver(accounts(4));
        assert_eq!(ev.verdict, Verdict::Allow);
        assert_eq!(ev.risk_score, 0);
    }

    #[test]
    fn pay_respects_per_tx_limit() {
        let mut c = setup();
        testing_env!(ctx(accounts(1)).build());
        c.authorize_agent(accounts(2));
        c.allow(accounts(4));
        testing_env!(ctx(accounts(2)).build());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = c.pay(
                accounts(4),
                U128(2 * 10u128.pow(23)),
                "too big".into(),
                false,
            );
        }));
        assert!(result.is_err());
    }

    #[test]
    fn pay_blocked_on_blocklist() {
        let mut c = setup();
        testing_env!(ctx(accounts(1)).build());
        c.authorize_agent(accounts(2));
        c.block(accounts(5));
        testing_env!(ctx(accounts(2)).build());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = c.pay(
                accounts(5),
                U128(10u128.pow(22)),
                "prompt injection payout".into(),
                false,
            );
        }));
        assert!(result.is_err());
    }

    #[test]
    fn report_raises_risk_to_warn() {
        let mut c = setup();
        testing_env!(ctx(accounts(1)).build());
        c.authorize_agent(accounts(2));
        testing_env!(ctx(accounts(2)).build());
        let shady: AccountId = "shady-merchant.testnet".parse().unwrap();
        c.report_receiver(shady.clone(), "phishing".into(), "abc123".into());
        let ev = c.evaluate_receiver(shady);
        assert_eq!(ev.verdict, Verdict::Warn);
        assert!(ev.risk_score >= 35);
    }

    #[test]
    fn successful_pay_records_history() {
        let mut c = setup();
        testing_env!(ctx(accounts(1)).build());
        c.authorize_agent(accounts(2));
        c.allow(accounts(4));
        testing_env!(ctx(accounts(2)).build());
        let _ = c.pay(accounts(4), U128(10u128.pow(22)), "api call".into(), false);
        assert_eq!(c.get_payments_len(), 1);
        let p = c.get_payment(0).unwrap();
        assert_eq!(p.to, accounts(4));
        assert_eq!(p.amount, 10u128.pow(22));
    }
}
