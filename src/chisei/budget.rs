use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone, PartialEq)]
pub enum PeriodType {
    Daily,
    Weekly,
}

impl std::str::FromStr for PeriodType {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(if s == "weekly" {
            Self::Weekly
        } else {
            Self::Daily
        })
    }
}

impl PeriodType {
    pub fn parse(s: &str) -> Self {
        if s == "weekly" {
            Self::Weekly
        } else {
            Self::Daily
        }
    }
    pub fn as_str(&self) -> &str {
        match self {
            Self::Daily => "daily",
            Self::Weekly => "weekly",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Usage {
    pub user_id: String,
    pub tokens_used: i32,
    pub max_tokens: i32,
    pub period_type: PeriodType,
    pub period_start: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PressureLevel {
    None,
    Moderate,
    Critical,
}

pub struct BudgetTracker {
    limits: Mutex<HashMap<String, (i32, PeriodType)>>, // user -> (max, period)
    usage: Mutex<HashMap<String, i32>>,                // user -> tokens_used this period
}

impl Default for BudgetTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl BudgetTracker {
    pub fn new() -> Self {
        Self {
            limits: Mutex::new(HashMap::new()),
            usage: Mutex::new(HashMap::new()),
        }
    }

    pub fn set_limit(&self, user_id: &str, max_tokens: i32, period: PeriodType) {
        self.limits
            .lock()
            .unwrap()
            .insert(user_id.into(), (max_tokens, period));
    }

    pub fn check(&self, user_id: &str, estimated: i32) -> Result<(), String> {
        let limits = self.limits.lock().unwrap();
        let (max, _) = match limits.get(user_id) {
            Some(l) => l,
            None => return Ok(()),
        };
        let usage = self.usage.lock().unwrap();
        let used = usage.get(user_id).copied().unwrap_or(0);
        if used + estimated > *max {
            return Err(format!(
                "budget exceeded: used {} + {} > {}",
                used, estimated, max
            ));
        }
        Ok(())
    }

    /// Atomically check budget and reserve estimated tokens.
    pub fn check_and_reserve(&self, user_id: &str, estimated: i32) -> Result<(), String> {
        let limits = self.limits.lock().unwrap();
        let (max, _) = match limits.get(user_id) {
            Some(l) => l,
            None => return Ok(()),
        };
        let mut usage = self.usage.lock().unwrap();
        let used = usage.get(user_id).copied().unwrap_or(0);
        if used + estimated > *max {
            return Err(format!(
                "budget exceeded: used {} + {} > {}",
                used, estimated, max
            ));
        }
        *usage.entry(user_id.into()).or_insert(0) += estimated;
        Ok(())
    }

    /// Adjust reservation to actual usage after the call completes.
    pub fn adjust(&self, user_id: &str, reserved: i32, actual: i32) {
        let mut usage = self.usage.lock().unwrap();
        let entry = usage.entry(user_id.into()).or_insert(0);
        *entry = (*entry - reserved + actual).max(0);
    }

    pub fn record(&self, user_id: &str, tokens: i32) {
        let mut usage = self.usage.lock().unwrap();
        *usage.entry(user_id.into()).or_insert(0) += tokens;
    }

    pub fn get_usage(&self, user_id: &str) -> Usage {
        let limits = self.limits.lock().unwrap();
        let (max, period) = limits
            .get(user_id)
            .cloned()
            .unwrap_or((0, PeriodType::Daily));
        let usage = self.usage.lock().unwrap();
        let used = usage.get(user_id).copied().unwrap_or(0);
        Usage {
            user_id: user_id.into(),
            tokens_used: used,
            max_tokens: max,
            period_type: period,
            period_start: 0,
        }
    }

    pub fn namespace_pressure(&self, namespace: &str) -> PressureLevel {
        let limits = self.limits.lock().unwrap();
        let usage = self.usage.lock().unwrap();
        // Aggregate all users in namespace (simplified: check if any user > 80%)
        for (user, (max, _)) in limits.iter() {
            if !user.starts_with(namespace) {
                continue;
            }
            let used = usage.get(user).copied().unwrap_or(0);
            if *max > 0 {
                let pct = used * 100 / max;
                if pct >= 90 {
                    return PressureLevel::Critical;
                }
                if pct >= 70 {
                    return PressureLevel::Moderate;
                }
            }
        }
        PressureLevel::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_budget_check_and_record() {
        let t = BudgetTracker::new();
        t.set_limit("alice", 1000, PeriodType::Daily);
        assert!(t.check("alice", 500).is_ok());
        t.record("alice", 800);
        assert!(t.check("alice", 300).is_err());
        assert!(t.check("alice", 100).is_ok()); // 800+100 < 1000... wait no 800+100=900 <= 1000
    }

    #[test]
    fn test_no_limit_allows_all() {
        let t = BudgetTracker::new();
        assert!(t.check("bob", 999999).is_ok());
    }

    #[test]
    fn test_pressure() {
        let t = BudgetTracker::new();
        t.set_limit("ns1:alice", 100, PeriodType::Daily);
        t.record("ns1:alice", 75);
        assert_eq!(t.namespace_pressure("ns1"), PressureLevel::Moderate);
        t.record("ns1:alice", 20);
        assert_eq!(t.namespace_pressure("ns1"), PressureLevel::Critical);
    }
}
