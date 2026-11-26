//! Sekai reads behind recorded eval cases (ADR 0153, #3513).
//!
//! The Chisei eval dataset calls hold the Sekai service in combined mode and
//! ask it, as the original caller, whether an Action instance is readable and
//! to run one dry-run turn. Both go through the gates the Sekai RPCs use
//! (`GetActionInstance`, `DryRunAgent`), so a recorded dataset never sees more
//! than its caller could read directly.

use super::*;

impl SekaiServiceImpl {
    /// The Sekai store, for reading a namespace's decided instances.
    pub(crate) fn recorded_case_store(&self) -> &RuntimeDb {
        self.db.runtime()
    }

    /// Whether the caller of `request` may read `instance` as
    /// `GetActionInstance` would: namespace read, tenant context, submitter,
    /// admin or approver entitlement, the instance marking and its target
    /// object. A refusal is `false`, so unreadable and missing look the same;
    /// only a store failure is an error.
    pub(crate) fn caller_reads_action_instance(
        &self,
        request: &Request<()>,
        instance: &crate::sekai::action_instance::ActionInstance,
    ) -> Result<bool, Status> {
        let principals = caller_principals(request);
        let tenant_context = request_tenant_context(self.db.runtime(), request)?;
        let policy_context = principal_policy_context(request);
        let gate = authorize_action_instance_read(
            self,
            &principals,
            &instance.namespace,
            tenant_context.as_ref(),
        )
        .and_then(|()| {
            rpc_actions::authorize_action_instance_visibility(
                self,
                &principals,
                tenant_context.as_ref(),
                &policy_context,
                instance,
            )
        });
        match gate {
            Ok(()) => Ok(true),
            Err(status)
                if matches!(
                    status.code(),
                    tonic::Code::Internal | tonic::Code::Unavailable
                ) =>
            {
                Err(status)
            }
            Err(_) => Ok(false),
        }
    }

    /// One dry-run turn as the caller of `request`, authorized as
    /// `DryRunAgent`. Records nothing.
    pub(crate) fn caller_dry_run_turn(
        &self,
        request: &Request<()>,
        namespace: &str,
        revision_digest: &str,
        member_id: &str,
        input: String,
    ) -> Result<crate::sekai::agent_dry_run::DryRunTrace, Status> {
        let principals = caller_principals(request);
        require_authenticated(&principals)?;
        let tenant_context = request_tenant_context(self.db.runtime(), request)?;
        rpc_definitions::authorized_dry_run_turn(
            self,
            &principals,
            tenant_context.as_ref(),
            namespace,
            revision_digest,
            member_id,
            input,
        )
    }

    /// The namespace's live objects and retained change history, read as the
    /// counterfactual views read them.
    pub(crate) fn namespace_object_history(
        &self,
        namespace: &str,
    ) -> Result<
        (
            Vec<crate::domain::Object>,
            Vec<crate::sekai::object_change_subscription::CommittedObjectMutation>,
        ),
        Status,
    > {
        rpc_objects::read_live_objects_and_history(self.db.runtime(), namespace)
    }
}
