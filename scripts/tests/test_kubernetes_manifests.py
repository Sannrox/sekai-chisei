"""Kubernetes manifest invariants, asserted on the parsed YAML (#3002).

Each fact is checked on the field that carries it, so a value in the wrong
place fails. Image tag and literal environment values stay in
tests/deploy_kubernetes_manifest.rs.
"""

import pathlib
import unittest

import yaml

MANIFESTS = pathlib.Path(__file__).resolve().parents[2] / "deploy" / "kubernetes" / "manifests"


def load(name: str) -> dict:
    return yaml.safe_load((MANIFESTS / name).read_text())


class StatefulSet(unittest.TestCase):
    def setUp(self):
        self.pod = load("10-statefulset.yaml")["spec"]["template"]["spec"]
        self.containers = self.pod["containers"]

    def test_ops_listens_on_every_address_for_kubelet_probes(self):
        for container in self.containers:
            with self.subTest(container=container["name"]):
                env = {entry["name"]: entry.get("value") for entry in container.get("env", [])}
                self.assertEqual(env.get("OPS_BIND"), "0.0.0.0")

    def test_probes_hit_the_ops_port(self):
        for container in self.containers:
            ports = {port["name"]: port["containerPort"] for port in container["ports"]}
            self.assertEqual(ports.get("ops"), 9464)
            for probe, path in (("livenessProbe", "/healthz"), ("readinessProbe", "/readyz")):
                with self.subTest(container=container["name"], probe=probe):
                    self.assertEqual(container[probe]["httpGet"], {"path": path, "port": "ops"})

    def test_gateway_settings_come_only_from_the_optional_secret(self):
        # #3173: without the Secret the pod starts as before, and the gateway
        # key is never a literal in the manifest.
        for container in self.containers:
            env = {entry["name"]: entry for entry in container.get("env", [])}
            for name in (
                "CHISEI_GATEWAY_KEY",
                "CHISEI_GATEWAY_URL",
                "CHISEI_GATEWAY_PROVIDED_PROVIDERS",
            ):
                with self.subTest(container=container["name"], variable=name):
                    self.assertNotIn("value", env[name])
                    self.assertEqual(
                        env[name]["valueFrom"],
                        {
                            "secretKeyRef": {
                                "name": "sekai-chisei-gateway",
                                "key": name,
                                "optional": True,
                            }
                        },
                    )

    def test_pod_meets_restricted_pod_security(self):
        context = self.pod["securityContext"]
        self.assertTrue(context["runAsNonRoot"])
        self.assertEqual(context["runAsUser"], 999)
        self.assertEqual(context["fsGroup"], 999)
        self.assertEqual(context["seccompProfile"], {"type": "RuntimeDefault"})
        # fsGroup owns /data, so no root init container is needed.
        self.assertNotIn("initContainers", self.pod)

    def test_every_container_meets_restricted_pod_security(self):
        for container in self.containers:
            with self.subTest(container=container["name"]):
                context = container["securityContext"]
                self.assertIs(context["allowPrivilegeEscalation"], False)
                self.assertEqual(context["capabilities"]["drop"], ["ALL"])
                self.assertNotEqual(context.get("runAsUser"), 0)
                self.assertIsNot(context.get("runAsNonRoot"), False)


class Service(unittest.TestCase):
    def test_exposes_grpc_and_ops_by_name_and_number(self):
        service = load("20-service.yaml")
        self.assertEqual(service["kind"], "Service")
        self.assertEqual(service["spec"]["selector"], {"app": "sekai-chisei"})
        ports = {
            port["name"]: (port["port"], port["targetPort"]) for port in service["spec"]["ports"]
        }
        self.assertEqual(ports, {"grpc": (50051, "grpc"), "ops": (9464, "ops")})


if __name__ == "__main__":
    unittest.main()
