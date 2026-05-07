"""
Role Aggregation Opt-Out Tests

STP: https://github.com/RedHatQE/openshift-virtualization-tests-design-docs/pull/73
"""

import pytest
from kubernetes.dynamic.exceptions import ForbiddenError
from ocp_resources.kubevirt import KubeVirt
from ocp_resources.virtual_machine import VirtualMachine

from utilities.hco import ResourceEditorValidateHCOReconcile


@pytest.mark.usefixtures("role_aggregation_opt_out")
class TestRoleAggregationOptOut:
    """
    Tests that virtualization actions are forbidden when role aggregation opt-out is enabled.

    Preconditions:
        - Role aggregation opt-out enabled on HCO CR (roleAggregationStrategy: Manual)
    """

    @pytest.mark.polarion("CNV-69075")
    def test_project_admin_forbidden_virtualization_actions(self, unprivileged_client, namespace):
        """
        [NEGATIVE] Test that a project admin user cannot list virtualization resources
        when role aggregation opt-out is enabled.

        Preconditions:
            - Role aggregation opt-out enabled on HCO CR (roleAggregationStrategy: Manual)
            - Namespace where unprivileged user is project admin (created via ProjectRequest)

        Steps:
            1. List VirtualMachine resources in the namespace using the project admin user's client

        Expected:
            - Operation fails with ForbiddenError
        """
        with pytest.raises(ForbiddenError):
            list(VirtualMachine.get(client=unprivileged_client, namespace=namespace.name))

    @pytest.mark.polarion("CNV-69075")
    @pytest.mark.usefixtures("edit_role_binding")
    def test_edit_role_forbidden_virtualization_actions(self, unprivileged_client, admin_namespace):
        """
        [NEGATIVE] Test that a user with edit role cannot list virtualization resources
        when role aggregation opt-out is enabled.

        Preconditions:
            - Role aggregation opt-out enabled on HCO CR (roleAggregationStrategy: Manual)
            - Admin-created namespace with explicit "edit" RoleBinding for unprivileged user

        Steps:
            1. List VirtualMachine resources in the namespace using the edit-role user's client

        Expected:
            - Operation fails with ForbiddenError
        """
        with pytest.raises(ForbiddenError):
            list(VirtualMachine.get(client=unprivileged_client, namespace=admin_namespace.name))

    @pytest.mark.polarion("CNV-69075")
    @pytest.mark.usefixtures("view_role_binding")
    def test_view_role_forbidden_virtualization_actions(self, unprivileged_client, admin_namespace):
        """
        [NEGATIVE] Test that a user with view role cannot list virtualization resources
        when role aggregation opt-out is enabled.

        Preconditions:
            - Role aggregation opt-out enabled on HCO CR (roleAggregationStrategy: Manual)
            - Admin-created namespace with explicit "view" RoleBinding for unprivileged user

        Steps:
            1. List VirtualMachine resources in the namespace using the view-role user's client

        Expected:
            - Operation fails with ForbiddenError
        """
        with pytest.raises(ForbiddenError):
            list(VirtualMachine.get(client=unprivileged_client, namespace=admin_namespace.name))


@pytest.mark.polarion("CNV-69075")
def test_opt_out_disabled_restores_access(hyperconverged_resource_scope_function, unprivileged_client, namespace):
    """
    Test that disabling role aggregation opt-out restores virtualization access
    for a project admin user.

    Preconditions:
        - Namespace where unprivileged user is project admin (created via ProjectRequest)
        - HCO CR with default roleAggregationStrategy (aggregation enabled)

    Steps:
        1. Enable role aggregation opt-out on HCO CR (set roleAggregationStrategy to Manual)
        2. Verify the project admin user cannot list VirtualMachine resources (ForbiddenError)
        3. Disable role aggregation opt-out (restore HCO CR to default)
        4. List VirtualMachine resources in the namespace using the project admin user's client

    Expected:
        - Listing VirtualMachine resources succeeds without error
    """
    with ResourceEditorValidateHCOReconcile(
        patches={hyperconverged_resource_scope_function: {"spec": {"roleAggregationStrategy": "Manual"}}},
        list_resource_reconcile=[KubeVirt],
        wait_for_reconcile_post_update=True,
    ):
        with pytest.raises(ForbiddenError):
            list(VirtualMachine.get(client=unprivileged_client, namespace=namespace.name))

    list(VirtualMachine.get(client=unprivileged_client, namespace=namespace.name))
