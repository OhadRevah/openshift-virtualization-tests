"""Pytest conftest file for role aggregation opt-out tests."""

import pytest
from ocp_resources.cluster_role import ClusterRole
from ocp_resources.kubevirt import KubeVirt
from ocp_resources.role_binding import RoleBinding

from utilities.constants import UNPRIVILEGED_USER
from utilities.hco import ResourceEditorValidateHCOReconcile
from utilities.infra import create_ns


@pytest.fixture(scope="class")
def role_aggregation_opt_out(hyperconverged_resource_scope_class):
    with ResourceEditorValidateHCOReconcile(
        patches={hyperconverged_resource_scope_class: {"spec": {"roleAggregationStrategy": "Manual"}}},
        list_resource_reconcile=[KubeVirt],
        wait_for_reconcile_post_update=True,
    ):
        yield


@pytest.fixture(scope="class")
def admin_namespace(admin_client):
    yield from create_ns(name="role-aggregation-test-ns", admin_client=admin_client)


@pytest.fixture()
def edit_role_binding(admin_client, admin_namespace):
    with RoleBinding(
        name="unprivileged-user-edit-binding",
        namespace=admin_namespace.name,
        client=admin_client,
        subjects_kind="User",
        subjects_name=UNPRIVILEGED_USER,
        subjects_namespace=admin_namespace.name,
        role_ref_kind=ClusterRole.kind,
        role_ref_name="edit",
    ) as role_binding:
        yield role_binding


@pytest.fixture()
def view_role_binding(admin_client, admin_namespace):
    with RoleBinding(
        name="unprivileged-user-view-binding",
        namespace=admin_namespace.name,
        client=admin_client,
        subjects_kind="User",
        subjects_name=UNPRIVILEGED_USER,
        subjects_namespace=admin_namespace.name,
        role_ref_kind=ClusterRole.kind,
        role_ref_name="view",
    ) as role_binding:
        yield role_binding
