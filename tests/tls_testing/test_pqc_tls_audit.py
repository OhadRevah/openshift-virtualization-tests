import logging

import pytest

from tests.tls_testing.constants import (
    PQC_GROUP_SECP256R1_MLKEM768,
    PQC_GROUP_SECP384R1_MLKEM1024,
)

pytestmark = [pytest.mark.tier3, pytest.mark.iuo, pytest.mark.tls_compliance]

LOGGER = logging.getLogger(__name__)


class TestPqcNodeCapability:
    @pytest.mark.polarion("CNV-15221")
    def test_node_openssl_supports_pqc_groups(
        self,
        node_available_tls_groups,
    ):
        """Verify that worker node OpenSSL supports post-quantum TLS groups."""
        LOGGER.info(f"Available TLS groups on node: {node_available_tls_groups}")
        assert PQC_GROUP_SECP256R1_MLKEM768 in node_available_tls_groups, (
            f"PQC group {PQC_GROUP_SECP256R1_MLKEM768} not found in node TLS groups: {node_available_tls_groups}"
        )
        assert PQC_GROUP_SECP384R1_MLKEM1024 in node_available_tls_groups, (
            f"PQC group {PQC_GROUP_SECP384R1_MLKEM1024} not found in node TLS groups: {node_available_tls_groups}"
        )


class TestPqcCnvEndpoints:
    @pytest.mark.polarion("CNV-15222")
    def test_cnv_services_pqc_with_classical_fallback(
        self,
        fips_enabled_cluster,
        services_without_classical_fallback,
    ):
        """Verify CNV services fall back to classical key exchange when PQC is offered with a fallback group.

        On FIPS clusters, all services must fall back to classical ECDH (ML-KEM is not FIPS-certified).
        On non-FIPS clusters, services should negotiate PQC when Go's TLS stack supports ML-KEM.
        """
        if fips_enabled_cluster:
            assert not services_without_classical_fallback, (
                f"Expected all CNV services to fall back to classical ECDH on FIPS cluster, "
                f"but these did not: {services_without_classical_fallback}"
            )
        else:
            LOGGER.info(
                f"Non-FIPS cluster: services that did not fall back to classical ECDH: "
                f"{services_without_classical_fallback}"
            )
            assert not services_without_classical_fallback, (
                f"Expected all CNV services to fall back to classical ECDH, "
                f"but these did not: {services_without_classical_fallback}"
            )

    @pytest.mark.polarion("CNV-15223")
    def test_cnv_services_reject_pqc_only(
        self,
        fips_enabled_cluster,
        services_accepting_pqc_only,
    ):
        """Verify CNV services reject TLS handshake when only PQC groups are offered.

        On FIPS clusters, all services must reject PQC-only (ML-KEM not FIPS-certified).
        On non-FIPS clusters, services should accept PQC when Go's TLS stack supports ML-KEM.
        """
        if fips_enabled_cluster:
            assert not services_accepting_pqc_only, (
                f"Expected all CNV services to reject PQC-only TLS on FIPS cluster, "
                f"but these accepted: {services_accepting_pqc_only}"
            )
        else:
            LOGGER.info(f"Non-FIPS cluster: services that accepted PQC-only: {services_accepting_pqc_only}")
            assert not services_accepting_pqc_only, (
                f"Expected all CNV services to reject PQC-only TLS, but these accepted: {services_accepting_pqc_only}"
            )

    @pytest.mark.polarion("CNV-15224")
    def test_non_fips_services_negotiate_pqc(
        self,
        fips_enabled_cluster,
        services_without_classical_fallback,
    ):
        """Verify non-FIPS CNV services negotiate PQC key exchange (CNV-74453 PQC readiness).

        On non-FIPS clusters, services should negotiate PQC hybrid key exchange (ML-KEM)
        when offered alongside a classical fallback. This test will transition from xfail
        to pass when Go's crypto/tls adds ML-KEM support.
        On FIPS clusters, PQC is not expected (ML-KEM not yet FIPS 140-3 certified).
        """
        if fips_enabled_cluster:
            pytest.xfail(reason="FIPS clusters do not support PQC: ML-KEM is not FIPS 140-3 certified")

        if not services_without_classical_fallback:
            pytest.xfail(
                reason="Go crypto/tls does not yet support ML-KEM key exchange. "
                "All services fell back to classical ECDH. "
                "This test will pass when Go adds PQC support (CNV-74453)."
            )

        LOGGER.info(f"Services that negotiated PQC: {services_without_classical_fallback}")
        assert services_without_classical_fallback, (
            "Expected at least some CNV services to negotiate PQC on non-FIPS cluster"
        )
