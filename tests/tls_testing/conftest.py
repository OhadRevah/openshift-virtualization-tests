import logging

import pytest

from tests.tls_testing.constants import (
    PQC_CLASSICAL_FALLBACK_GROUP,
    PQC_GROUP_SECP256R1_MLKEM768,
    PQC_HANDSHAKE_FAILURE_INDICATOR,
)
from tests.tls_testing.utils import (
    compose_openssl_pqc_command,
    get_node_available_tls_groups,
    parse_peer_temp_key,
)
from utilities.infra import ExecCommandOnPod

LOGGER = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def node_available_tls_groups(workers_utility_pods, workers):
    return get_node_available_tls_groups(
        utility_pods=workers_utility_pods,
        node=workers[0],
    )


@pytest.fixture(scope="session")
def worker_exec(workers_utility_pods, workers):
    return ExecCommandOnPod(utility_pods=workers_utility_pods, node=workers[0])


@pytest.fixture(scope="session")
def services_without_classical_fallback(worker_exec, services_to_check_connectivity):
    """Probes each CNV service with PQC + classical fallback.

    Returns:
        dict: Services that did not fall back to classical ECDH.
    """
    pqc_groups_with_fallback = f"{PQC_GROUP_SECP256R1_MLKEM768}:{PQC_CLASSICAL_FALLBACK_GROUP}"
    failed_services = {}
    for service in services_to_check_connectivity:
        service_name = service.instance.metadata.name
        LOGGER.info(f"Probing PQC with fallback on service: {service_name}")
        command = compose_openssl_pqc_command(service_spec=service.instance.spec, groups=pqc_groups_with_fallback)
        output = worker_exec.exec(command=command, ignore_rc=True)
        peer_temp_key = parse_peer_temp_key(openssl_output=output)
        LOGGER.info(f"Service {service_name} negotiated key exchange: {peer_temp_key}")
        if not peer_temp_key or PQC_GROUP_SECP256R1_MLKEM768.lower() in peer_temp_key.lower():
            failed_services[service_name] = peer_temp_key
    return failed_services


@pytest.fixture(scope="session")
def services_accepting_pqc_only(worker_exec, services_to_check_connectivity):
    """Probes each CNV service with PQC-only (no fallback).

    Returns:
        dict: Services that did not reject the PQC-only handshake.
    """
    failed_services = {}
    for service in services_to_check_connectivity:
        service_name = service.instance.metadata.name
        LOGGER.info(f"Probing PQC-only on service: {service_name}")
        command = compose_openssl_pqc_command(service_spec=service.instance.spec, groups=PQC_GROUP_SECP256R1_MLKEM768)
        output = worker_exec.exec(command=command, ignore_rc=True)
        if PQC_HANDSHAKE_FAILURE_INDICATOR not in output:
            failed_services[service_name] = output[:200]
    return failed_services
