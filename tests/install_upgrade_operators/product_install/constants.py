from utilities.constants import WIN_2K22, WIN_2K25, WIN_10, WIN_11

IGNORE_KIND = [
    "StorageProfile",
    "ConsoleCLIDownload",
    "ImageContentSourcePolicy",
    "VirtualMachineClusterInstancetype",
    "VirtualMachineClusterPreference",
    "Event",
]
IGNORE_NAMESPACE = [
    "openshift-marketplace",
    "openshift-cnv",
    "openshift-operator-lifecycle-manager",
    "openshift-virtualization-os-images",
]
CLUSTER_RESOURCE_ALLOWLIST = {
    "ClusterRole": [
        "openshift-cnv-group-view",
        "prometheus-k8s-ssp",
        "cdi-cronjob",
        "bridge-marker-cr",
        "kubevirt-hyperconverged-operator",
        "cdi-uploadproxy",
        "cdi-apiserver",
        "kubemacpool-manager-role",
        "kubevirt-controller",
        "kubevirt-hyperconverged-operator",
        "kubevirt-handler",
        "openshift-cnv-group-edit",
        "openshift-cnv-group-admin",
        "cdi",
        "kubevirt-exportproxy",
        "kubevirt-apiserver",
        "template:view",
        "kubevirt-hyperconverged-",
        "olm.og.openshift-cnv-",
        "kubevirt-ipam-controller-manager-role",
    ],
    "ClusterRoleBinding": [
        "hostpath-provisioner-operator-service-system:auth-delegator",
        "prometheus-k8s-ssp",
        "cdi-cronjob",
        "kubemacpool-manager-rolebinding",
        "cdi-sa",
        "kubevirt-hyperconverged-operator",
        "bridge-marker-crb",
        "ssp-operator-service-system:auth-delegator",
        "cdi-uploadproxy",
        "cdi-apiserver",
        "hco-webhook-service-system:auth-delegator",
        "kubevirt-controller",
        "kubevirt-apiserver-auth-delegator",
        "kubevirt-handler",
        "kubevirt-exportproxy",
        "kubevirt-apiserver",
        "template-validator",
        "kubevirt-hyperconverged-",
        "olm.og.openshift-cnv-kubevirt-ipam-controller-manager-rolebinding",
    ],
    "Namespace": ["openshift-cnv", "openshift-virtualization-os-images"],
    "Project": ["openshift-cnv", "openshift-virtualization-os-images"],
    "ConsoleQuickStart": ["creating-virtual-machine", "upload-boot-source", "windows-bootsource-pipeline"],
    "MachineConfig": ["rendered-worker", "rendered-master"],
    "ValidatingWebhookConfiguration": [
        "cdi-api-dataimportcron-validate",
        "virt-template-validator",
        "cdi-api-datavolume-validate",
        "cdi-api-validate",
        "virt-api-validator",
        "virt-operator-validator",
        "objecttransfer-api-validate",
        "cdi-api-populator-validate",
    ],
    "Operator": ["kubevirt-hyperconverged.openshift-cnv"],
    "MutatingWebhookConfiguration": [
        "virt-api-mutator",
        "kubemacpool-mutator",
        "cdi-api-datavolume-mutate",
        "cdi-api-pvc-mutate",
        "kubevirt-ipam-controller-mutating-webhook-configuration",
    ],
    "SecurityContextConstraints": [
        "linux-bridge",
        "containerized-data-importer",
        "kubevirt-controller",
        "bridge-marker",
        "kubevirt-handler",
    ],
    "NetworkAddonsConfig": ["cluster"],
    "ConsoleCLIDownload": ["virtctl-clidownloads-kubevirt-hyperconverged"],
    "PriorityClass": ["kubevirt-cluster-critical"],
    "ConsolePlugin": ["kubevirt-plugin"],
    "CDI": ["cdi-kubevirt-hyperconverged"],
    "CDIConfig": ["config"],
}
NAMESPACED_IGNORE_KINDS = ["Event", "Template"]
NAMESPACED_RESOURCE_ALLOWLIST = {
    "kube-system": {
        "RoleBinding": [
            "hostpath-provisioner-operator-service-auth-reader",
            "hco-webhook-service-auth-reader",
            "ssp-operator-service-auth-reader",
        ]
    },
    "openshift-config-managed": {"ConfigMap": ["grafana-dashboard-kubevirt-top-consumers"]},
    "openshift-storage": {
        "Pod": ["csi-addons", "storageclient"],
        "EndpointSlice": ["csi-addons"],
        "PodMetrics": ["csi-addons"],
        "ReplicaSet": ["csi-addons"],
        "Job": ["storageclient"],
    },
    "openshift-console": {
        "ReplicaSet": ["console"],
        "Pod": ["console"],
        "PodMetrics": ["console"],
    },
    "openshift-virtualization-os-images": {
        "ServiceAccount": ["builder", "default", "deployer"],
        "RoleBinding": [
            "system:image-builders",
            "system:image-pullers",
            "system:deployers",
        ],
        "ConfigMap": ["openshift-service-ca.crt", "kube-root-ca.crt"],
        "Role": ["os-images.kubevirt.io:view"],
        "DataImportCron": [
            "centos-stream10-image-cron",
            "centos-stream9-image-cron",
            "rhel9-image-cron",
            "rhel10-image-cron",
            "rhel8-image-cron",
            "fedora-image-cron",
        ],
        "ImageTag": ["rhel8-guest:latest", "rhel9-guest:latest"],
        "ImageStreamTag": ["rhel8-guest:latest", "rhel9-guest:latest"],
        "DataSource": [
            "centos-stream10",
            "centos-stream8",
            "centos-stream9",
            "centos7",
            "fedora",
            "rhel10",
            "rhel9",
            "rhel8",
            "rhel7",
            WIN_10,
            WIN_11,
            "win2k16",
            "win2k19",
            WIN_2K22,
            WIN_2K25,
        ],
        "ImageStream": ["rhel9-guest", "rhel8-guest"],
        "Secret": [
            "builder-token",
            "deployer-token",
            "default-dockercfg",
            "builder-dockercfg",
            "default-token",
            "deployer-dockercfg",
        ],
        "ClusterServiceVersion": ["openshift-pipelines-operator"],
        "DataVolume": [
            "rhel8",
            "rhel9",
            "rhel10",
            "fedora",
            "centos-stream9",
            "centos-stream10",
        ],
    },
}
OPENSHIFT_VIRTUALIZATION = "openshift-virtualization"
HCO_NOT_INSTALLED_ALERT = "HCOInstallationIncomplete"
