import re

from kubernetes.dynamic.resource import ResourceField
from ocp_resources.resource import Resource

from utilities.infra import ExecCommandOnPod


def get_node_available_tls_groups(utility_pods: list, node: Resource) -> list[str]:
    """Returns the list of TLS groups supported by OpenSSL on the given node.

    Args:
        utility_pods: List of utility pods for command execution.
        node: Node resource to query.

    Returns:
        list[str]: TLS group names available on the node.
    """
    output = ExecCommandOnPod(utility_pods=utility_pods, node=node).exec(
        command="openssl list -tls-groups",
    )
    return [group.strip() for group in output.strip().split(":") if group.strip()]


def compose_openssl_pqc_command(service_spec: ResourceField, groups: str, connect_timeout: int = 10) -> str:
    """Builds an openssl s_client command with PQC group negotiation.

    Args:
        service_spec: Service spec object with clusterIP and ports.
        groups: Colon-separated TLS group names to offer (e.g. "SecP256r1MLKEM768:secp256r1").
        connect_timeout: Timeout in seconds for the TLS connection attempt.

    Returns:
        str: The openssl command string.
    """
    return (
        f"echo | timeout {connect_timeout}"
        f" openssl s_client -connect {service_spec.clusterIP}:{service_spec.ports[0].port} -groups {groups} 2>&1"
    )


def parse_peer_temp_key(openssl_output: str) -> str:
    """Extracts the Peer Temp Key or Server Temp Key value from openssl s_client output.

    Args:
        openssl_output: Raw output from openssl s_client.

    Returns:
        str: The negotiated key exchange description, or empty string if not found.
    """
    match = re.search(r"(?:Peer|Server) Temp Key:\s*(.*)", openssl_output)
    return match.group(1).strip() if match else ""
