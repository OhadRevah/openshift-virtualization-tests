from utilities.constants import KUBEVIRT_STR

KUBEVIRT_STR_LOWER = KUBEVIRT_STR.lower()
KUBEVIRT_REST_CLIENT_REQUESTS_TOTAL = "kubevirt_rest_client_requests_total"
VIRT_CONTROLLER_REST_ERRORS_BURST = "VirtControllerRESTErrorsBurst"
VIRT_HANDLER_REST_ERRORS_BURST = "VirtHandlerRESTErrorsBurst"
VIRT_API_REST_ERRORS_BURST = "VirtApiRESTErrorsBurst"
VIRT_OPERATOR_REST_ERRORS_BURST = "VirtOperatorRESTErrorsBurst"
EXPECTED_METRICS_THRESHOLD = 0.2
CRITICAL_ALERTS_LIST = [
    VIRT_API_REST_ERRORS_BURST,
    VIRT_HANDLER_REST_ERRORS_BURST,
    VIRT_CONTROLLER_REST_ERRORS_BURST,
]
ROLE_BINDING_LIST = [
    "kubevirt-controller",
    "kubevirt-handler",
    "kubevirt-apiserver",
]
