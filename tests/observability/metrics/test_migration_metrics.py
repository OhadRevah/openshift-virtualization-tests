from datetime import datetime, timezone

import pytest
from ocp_resources.prometheus import Prometheus
from ocp_resources.resource import Resource
from ocp_resources.virtual_machine_instance import VirtualMachineInstance
from ocp_resources.virtual_machine_instance_migration import (
    VirtualMachineInstanceMigration,
)
from timeout_sampler import TimeoutExpiredError

from tests.observability.metrics.constants import (
    KUBEVIRT_VMI_MIGRATION_DATA_PROCESSED_BYTES,
    KUBEVIRT_VMI_MIGRATION_DATA_REMAINING_BYTES,
    KUBEVIRT_VMI_MIGRATION_DATA_TOTAL_BYTES,
    KUBEVIRT_VMI_MIGRATION_DIRTY_MEMORY_RATE_BYTES,
    KUBEVIRT_VMI_MIGRATION_DISK_TRANSFER_RATE_BYTES,
)
from tests.observability.metrics.utils import (
    get_metric_sum_value,
    timestamp_to_seconds,
    wait_for_expected_metric_value_sum,
    wait_for_non_empty_metrics_value,
)
from tests.observability.utils import validate_metrics_value
from utilities.constants import MIGRATION_POLICY_VM_LABEL, TIMEOUT_3MIN, TIMEOUT_5MIN
from utilities.infra import get_node_selector_dict, get_pods
from utilities.virt import VirtualMachineForTests, fedora_vm_body, running_vm


def delete_failed_migration_target_pod(admin_client, namespace, vm_name):
    """
    Deletes the virt-launcher pod that stays in Pending state after
    vm migration is triggered, aim is to delete the target pod
    """
    pods = get_pods(dyn_client=admin_client, namespace=namespace)
    for pod in pods:
        if (pod.instance.status.phase == Resource.Status.PENDING) and (vm_name in pod.name):
            pod.delete(wait=True)


def assert_metrics_values(
    prometheus: Prometheus,
    migration_metrics_dict: dict[str, str],
    initial_values: dict[str, int],
    metric_to_check: str,
) -> None:
    """
    Check all migration metrics do not change from initial values,
    except for specified metric which must increase by 1.

    Args:
        prometheus: Prometheus object
        migration_metrics_dict: Dictionary with metrics by the status it checks
        initial_values: Dictionary representing initial values of metrics
        metric_to_check: metric expected to be increased by 1
    Raises:
        AssertionError: If any metric's value does not match with expected value.
    """
    failed_metrics = {}
    migration_metrics = []
    for metric in migration_metrics_dict.values():
        migration_metrics.append(metric) if metric != metric_to_check else migration_metrics.insert(0, metric)
    for metric in migration_metrics:
        initial_value = initial_values[metric]
        expected_value = initial_value + 1 if metric == metric_to_check else initial_value
        try:
            wait_for_expected_metric_value_sum(
                prometheus=prometheus,
                metric_name=metric,
                expected_value=expected_value,
            )
        except TimeoutExpiredError:
            failed_metrics[metric] = {
                "actual": get_metric_sum_value(prometheus=prometheus, metric=metric),
                "expected": expected_value,
            }
    assert not failed_metrics, f"Metrices that failed to match expected value {failed_metrics}"


@pytest.fixture(scope="class")
def migration_metrics_dict():
    migration_metrics = {
        Resource.Status.PENDING: "kubevirt_vmi_migrations_in_pending_phase",
        VirtualMachineInstance.Status.SCHEDULING: "kubevirt_vmi_migrations_in_scheduling_phase",
        Resource.Status.RUNNING: "kubevirt_vmi_migrations_in_running_phase",
        Resource.Status.SUCCEEDED: "kubevirt_vmi_migration_succeeded",
        Resource.Status.FAILED: "kubevirt_vmi_migration_failed",
    }
    return migration_metrics


@pytest.fixture(scope="class")
def initial_migration_metrics_values(prometheus, migration_metrics_dict):
    metrics_values = {}
    for metric in migration_metrics_dict.values():
        metrics_values[metric] = get_metric_sum_value(prometheus=prometheus, metric=metric)
    yield metrics_values


@pytest.fixture(scope="class")
def vm_for_migration_metrics_test(namespace, cpu_for_migration):
    name = "vm-for-migration-metrics-test"
    with VirtualMachineForTests(
        name=name,
        namespace=namespace.name,
        body=fedora_vm_body(name=name),
        cpu_model=cpu_for_migration,
        additional_labels=MIGRATION_POLICY_VM_LABEL,
    ) as vm:
        running_vm(vm=vm, check_ssh_connectivity=False)
        yield vm


@pytest.fixture()
def vm_migration_metrics_vmim(vm_for_migration_metrics_test):
    with VirtualMachineInstanceMigration(
        name="vm-migration-metrics-vmim",
        namespace=vm_for_migration_metrics_test.namespace,
        vmi_name=vm_for_migration_metrics_test.vmi.name,
    ) as vmim:
        vmim.wait_for_status(status=vmim.Status.RUNNING, timeout=TIMEOUT_3MIN)
        yield vmim


@pytest.fixture(scope="class")
def vm_migration_metrics_vmim_scope_class(vm_for_migration_metrics_test):
    with VirtualMachineInstanceMigration(
        name="vm-migration-metrics-vmim",
        namespace=vm_for_migration_metrics_test.namespace,
        vmi_name=vm_for_migration_metrics_test.vmi.name,
    ) as vmim:
        vmim.wait_for_status(status=vmim.Status.RUNNING, timeout=TIMEOUT_3MIN)
        yield vmim


@pytest.fixture()
def vm_with_node_selector(namespace, worker_node1):
    name = "vm-with-node-selector"
    with VirtualMachineForTests(
        name=name,
        namespace=namespace.name,
        body=fedora_vm_body(name=name),
        additional_labels=MIGRATION_POLICY_VM_LABEL,
        node_selector=get_node_selector_dict(node_selector=worker_node1.name),
    ) as vm:
        running_vm(vm=vm)
        yield vm


@pytest.fixture()
def vm_with_node_selector_vmim(vm_with_node_selector):
    with VirtualMachineInstanceMigration(
        name="vm-with-node-selector-vmim",
        namespace=vm_with_node_selector.namespace,
        vmi_name=vm_with_node_selector.vmi.name,
    ) as vmim:
        yield vmim


@pytest.fixture()
def migration_succeeded(vm_migration_metrics_vmim):
    vm_migration_metrics_vmim.wait_for_status(status=vm_migration_metrics_vmim.Status.SUCCEEDED, timeout=TIMEOUT_3MIN)


@pytest.fixture(scope="class")
def migration_succeeded_scope_class(vm_migration_metrics_vmim_scope_class):
    vm_migration_metrics_vmim_scope_class.wait_for_status(
        status=vm_migration_metrics_vmim_scope_class.Status.SUCCEEDED, timeout=TIMEOUT_5MIN
    )


class TestMigrationMetrics:
    @pytest.mark.polarion("CNV-8479")
    def test_migration_metrics_succeeded(
        self,
        prometheus,
        migration_metrics_dict,
        vm_for_migration_metrics_test,
        initial_migration_metrics_values,
        vm_migration_metrics_vmim,
        migration_succeeded,
    ):
        assert_metrics_values(
            prometheus=prometheus,
            migration_metrics_dict=migration_metrics_dict,
            initial_values=initial_migration_metrics_values,
            metric_to_check=migration_metrics_dict[Resource.Status.SUCCEEDED],
        )

    @pytest.mark.polarion("CNV-8480")
    def test_migration_metrics_scheduling_and_failed(
        self,
        admin_client,
        namespace,
        prometheus,
        migration_metrics_dict,
        vm_with_node_selector,
        initial_migration_metrics_values,
        vm_with_node_selector_vmim,
    ):
        assert_metrics_values(
            prometheus=prometheus,
            migration_metrics_dict=migration_metrics_dict,
            initial_values=initial_migration_metrics_values,
            metric_to_check=migration_metrics_dict[VirtualMachineInstance.Status.SCHEDULING],
        )
        delete_failed_migration_target_pod(
            admin_client=admin_client,
            namespace=namespace,
            vm_name=vm_with_node_selector.name,
        )
        assert_metrics_values(
            prometheus=prometheus,
            migration_metrics_dict=migration_metrics_dict,
            initial_values=initial_migration_metrics_values,
            metric_to_check=migration_metrics_dict[Resource.Status.FAILED],
        )

    @pytest.mark.polarion("CNV-8481")
    def test_migration_metrics_running(
        self,
        prometheus,
        migration_metrics_dict,
        migration_policy_with_bandwidth,
        vm_for_migration_metrics_test,
        initial_migration_metrics_values,
        vm_migration_metrics_vmim,
    ):
        assert_metrics_values(
            prometheus=prometheus,
            migration_metrics_dict=migration_metrics_dict,
            initial_values=initial_migration_metrics_values,
            metric_to_check=migration_metrics_dict[Resource.Status.RUNNING],
        )


class TestKubevirtVmiMigrationMetrics:
    @pytest.mark.parametrize(
        "query",
        [
            pytest.param(KUBEVIRT_VMI_MIGRATION_DATA_PROCESSED_BYTES, marks=(pytest.mark.polarion("CNV-11417"))),
            pytest.param(
                KUBEVIRT_VMI_MIGRATION_DATA_REMAINING_BYTES,
                marks=(pytest.mark.polarion("CNV-11600")),
            ),
            pytest.param(
                KUBEVIRT_VMI_MIGRATION_DISK_TRANSFER_RATE_BYTES,
                marks=(pytest.mark.polarion("CNV-11598")),
            ),
            pytest.param(
                KUBEVIRT_VMI_MIGRATION_DIRTY_MEMORY_RATE_BYTES,
                marks=(pytest.mark.polarion("CNV-11599")),
            ),
            pytest.param(
                KUBEVIRT_VMI_MIGRATION_DATA_TOTAL_BYTES,
                marks=(pytest.mark.polarion("CNV-11802")),
            ),
        ],
    )
    @pytest.mark.jira("CNV-57777", run=False)
    def test_kubevirt_vmi_migration_metrics(
        self,
        prometheus,
        namespace,
        admin_client,
        migration_policy_with_bandwidth_scope_class,
        vm_for_migration_metrics_test,
        vm_migration_metrics_vmim_scope_class,
        query,
    ):
        minutes_passed_since_migration_start = (
            int(datetime.now(timezone.utc).timestamp())
            - timestamp_to_seconds(
                timestamp=vm_for_migration_metrics_test.vmi.instance.status.migrationState.startTimestamp
            )
        ) // 60
        wait_for_non_empty_metrics_value(
            prometheus=prometheus,
            metric_name=f"last_over_time({query.format(vm_name=vm_for_migration_metrics_test.name)}"
            f"[{minutes_passed_since_migration_start if minutes_passed_since_migration_start > 10 else 10}m])",
        )


class TestKubevirtVmiMigrationStartAndEnd:
    @pytest.mark.polarion("CNV-11809")
    def test_metric_kubevirt_vmi_migration_start_time_seconds(
        self,
        prometheus,
        vm_for_migration_metrics_test,
        vm_migration_metrics_vmim_scope_class,
    ):
        validate_metrics_value(
            prometheus=prometheus,
            metric_name=f"kubevirt_vmi_migration_start_time_seconds{{name='{vm_for_migration_metrics_test.name}'}}",
            expected_value=str(
                timestamp_to_seconds(
                    timestamp=vm_for_migration_metrics_test.vmi.instance.status.migrationState.startTimestamp
                ),
            ),
        )

    @pytest.mark.polarion("CNV-11810")
    def test_metric_kubevirt_vmi_migration_end_time_seconds(
        self,
        prometheus,
        vm_for_migration_metrics_test,
        vm_migration_metrics_vmim_scope_class,
        migration_succeeded_scope_class,
    ):
        validate_metrics_value(
            prometheus=prometheus,
            metric_name=f"kubevirt_vmi_migration_end_time_seconds{{name='{vm_for_migration_metrics_test.name}'}}",
            expected_value=str(
                timestamp_to_seconds(
                    timestamp=vm_for_migration_metrics_test.vmi.instance.status.migrationState.endTimestamp
                )
            ),
        )
