//! Dual-backend community-store dispatch for autonomy.
#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]
use super::*;

impl RuntimeDb {
    pub fn get_autonomous_envelope(
        &self,
        namespace: &str,
        envelope_id: &str,
    ) -> Result<Option<crate::sekai::autonomous_envelope::AutonomousEnvelope>, String> {
        match self {
            Self::Sqlite(db) => db.get_autonomous_envelope(namespace, envelope_id),
            Self::Postgres(_) => {
                Err(crate::sekai::autonomous_envelope::POSTGRES_UNAVAILABLE.into())
            }
        }
    }

    pub fn put_autonomous_envelope(
        &self,
        envelope: &crate::sekai::autonomous_envelope::AutonomousEnvelope,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_autonomous_envelope(envelope),
            Self::Postgres(_) => {
                Err(crate::sekai::autonomous_envelope::POSTGRES_UNAVAILABLE.into())
            }
        }
    }

    pub fn cas_autonomous_envelope(
        &self,
        expected: &crate::sekai::autonomous_envelope::AutonomousEnvelope,
        next: &crate::sekai::autonomous_envelope::AutonomousEnvelope,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.cas_autonomous_envelope(expected, next),
            Self::Postgres(_) => {
                Err(crate::sekai::autonomous_envelope::POSTGRES_UNAVAILABLE.into())
            }
        }
    }

    pub fn get_agent_autonomy(
        &self,
        namespace: &str,
        principal: &str,
        type_id: &str,
    ) -> Result<Option<crate::sekai::agent_autonomy::AgentAutonomyGrant>, String> {
        match self {
            Self::Sqlite(db) => db.get_agent_autonomy(namespace, principal, type_id),
            Self::Postgres(_) => Err(crate::sekai::agent_autonomy::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn put_agent_autonomy(
        &self,
        grant: &crate::sekai::agent_autonomy::AgentAutonomyGrant,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_agent_autonomy(grant),
            Self::Postgres(_) => Err(crate::sekai::agent_autonomy::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn put_agent_autonomy_with_receipt(
        &self,
        grant: &crate::sekai::agent_autonomy::AgentAutonomyGrant,
        decision: &crate::sekai::audit::Decision,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_agent_autonomy_with_receipt(grant, decision),
            Self::Postgres(_) => Err(crate::sekai::agent_autonomy::POSTGRES_UNAVAILABLE.into()),
        }
    }
}
