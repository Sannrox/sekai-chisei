//! Backend-neutral capability-package lifecycle persistence.

use crate::db::{postgres::PostgresDb, sekai::SekaiDb};
use crate::sekai::audit::Decision;
use crate::sekai::capability_package::{
    CapabilityPackageManifest, PackageInstallation, PackageLifecycleEvent,
};

pub const POSTGRES_CAPABILITY_PACKAGE_SURFACE: &str = "sekai.capability-packages";

pub trait CapabilityPackageBackend: Send + Sync {
    fn install_capability_package(
        &self,
        namespace: &str,
        manifest: &CapabilityPackageManifest,
        actor: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<PackageInstallation, String>;

    fn upgrade_capability_package(
        &self,
        namespace: &str,
        manifest: &CapabilityPackageManifest,
        actor: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<PackageInstallation, String>;

    fn rollback_capability_package(
        &self,
        namespace: &str,
        package_name: &str,
        actor: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<PackageInstallation, String>;

    fn disable_capability_package(
        &self,
        namespace: &str,
        package_name: &str,
        actor: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<PackageInstallation, String>;

    fn uninstall_capability_package(
        &self,
        namespace: &str,
        package_name: &str,
        actor: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<(), String>;

    fn evaluate_capability_package(
        &self,
        namespace: &str,
        package_name: &str,
        actor: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<bool, String>;

    fn get_capability_package(
        &self,
        namespace: &str,
        package_name: &str,
    ) -> Result<Option<PackageInstallation>, String>;

    fn get_capability_package_manifest(
        &self,
        namespace: &str,
        package_name: &str,
        version: &str,
    ) -> Result<Option<CapabilityPackageManifest>, String>;

    fn list_capability_package_events(
        &self,
        namespace: &str,
        package_name: &str,
    ) -> Result<Vec<PackageLifecycleEvent>, String>;

    fn list_capability_package_decisions(
        &self,
        namespace: &str,
        package_name: &str,
    ) -> Result<Vec<Decision>, String>;
}

macro_rules! forward {
    ($target:ty) => {
        fn install_capability_package(
            &self,
            namespace: &str,
            manifest: &CapabilityPackageManifest,
            actor: &str,
            request_id: &str,
            now_ms: i64,
        ) -> Result<PackageInstallation, String> {
            <$target>::install_capability_package(
                self, namespace, manifest, actor, request_id, now_ms,
            )
        }
        fn upgrade_capability_package(
            &self,
            namespace: &str,
            manifest: &CapabilityPackageManifest,
            actor: &str,
            request_id: &str,
            now_ms: i64,
        ) -> Result<PackageInstallation, String> {
            <$target>::upgrade_capability_package(
                self, namespace, manifest, actor, request_id, now_ms,
            )
        }
        fn rollback_capability_package(
            &self,
            namespace: &str,
            package_name: &str,
            actor: &str,
            request_id: &str,
            now_ms: i64,
        ) -> Result<PackageInstallation, String> {
            <$target>::rollback_capability_package(
                self,
                namespace,
                package_name,
                actor,
                request_id,
                now_ms,
            )
        }
        fn disable_capability_package(
            &self,
            namespace: &str,
            package_name: &str,
            actor: &str,
            request_id: &str,
            now_ms: i64,
        ) -> Result<PackageInstallation, String> {
            <$target>::disable_capability_package(
                self,
                namespace,
                package_name,
                actor,
                request_id,
                now_ms,
            )
        }
        fn uninstall_capability_package(
            &self,
            namespace: &str,
            package_name: &str,
            actor: &str,
            request_id: &str,
            now_ms: i64,
        ) -> Result<(), String> {
            <$target>::uninstall_capability_package(
                self,
                namespace,
                package_name,
                actor,
                request_id,
                now_ms,
            )
        }
        fn evaluate_capability_package(
            &self,
            namespace: &str,
            package_name: &str,
            actor: &str,
            request_id: &str,
            now_ms: i64,
        ) -> Result<bool, String> {
            <$target>::evaluate_capability_package(
                self,
                namespace,
                package_name,
                actor,
                request_id,
                now_ms,
            )
        }
        fn get_capability_package(
            &self,
            namespace: &str,
            package_name: &str,
        ) -> Result<Option<PackageInstallation>, String> {
            <$target>::get_capability_package(self, namespace, package_name)
        }
        fn get_capability_package_manifest(
            &self,
            namespace: &str,
            package_name: &str,
            version: &str,
        ) -> Result<Option<CapabilityPackageManifest>, String> {
            <$target>::get_capability_package_manifest(self, namespace, package_name, version)
        }
        fn list_capability_package_events(
            &self,
            namespace: &str,
            package_name: &str,
        ) -> Result<Vec<PackageLifecycleEvent>, String> {
            <$target>::list_capability_package_events(self, namespace, package_name)
        }
        fn list_capability_package_decisions(
            &self,
            namespace: &str,
            package_name: &str,
        ) -> Result<Vec<Decision>, String> {
            <$target>::list_capability_package_decisions(self, namespace, package_name)
        }
    };
}

impl CapabilityPackageBackend for SekaiDb {
    forward!(SekaiDb);
}
impl CapabilityPackageBackend for PostgresDb {
    forward!(PostgresDb);
}
