//! AWS-specific addon manifests for ClusterResourceSets
//!
//! This module generates the AWS Cloud Controller Manager (CCM) and
//! EBS CSI Driver manifests that are deployed via ClusterResourceSet
//! to AWS clusters.

/// AWS Cloud Controller Manager version
const AWS_CCM_VERSION: &str = "v1.28.3";

/// AWS EBS CSI Driver version
const AWS_EBS_CSI_VERSION: &str = "v1.28.0";

/// Generate AWS Cloud Controller Manager ClusterResourceSet manifests
///
/// Creates a ConfigMap with the CCM deployment and a ClusterResourceSet
/// that targets clusters with `ccm: external` label. The CCM sets the
/// correct providerID format (aws:///ZONE/INSTANCE_ID) on nodes.
pub fn generate_ccm_crs(namespace: &str) -> Vec<String> {
    let manifest = generate_ccm_manifest();
    let indented = indent_manifest(&manifest);

    let configmap = format!(
        r#"apiVersion: v1
kind: ConfigMap
metadata:
  name: aws-ccm
  namespace: {namespace}
data:
  aws-ccm.yaml: |
{indented}"#
    );

    let crs = format!(
        r#"apiVersion: addons.cluster.x-k8s.io/v1beta2
kind: ClusterResourceSet
metadata:
  name: aws-ccm
  namespace: {namespace}
spec:
  strategy: ApplyOnce
  clusterSelector:
    matchLabels:
      ccm: external
  resources:
    - kind: ConfigMap
      name: aws-ccm"#
    );

    vec![configmap, crs]
}

/// Generate AWS EBS CSI Driver ClusterResourceSet manifests
///
/// Creates a ConfigMap with the EBS CSI driver deployment and a
/// ClusterResourceSet that targets clusters with `csi: external` label.
pub fn generate_ebs_csi_crs(namespace: &str) -> Vec<String> {
    let manifest = generate_ebs_csi_manifest();
    let indented = indent_manifest(&manifest);

    let configmap = format!(
        r#"apiVersion: v1
kind: ConfigMap
metadata:
  name: aws-ebs-csi
  namespace: {namespace}
data:
  aws-ebs-csi.yaml: |
{indented}"#
    );

    let crs = format!(
        r#"apiVersion: addons.cluster.x-k8s.io/v1beta2
kind: ClusterResourceSet
metadata:
  name: aws-ebs-csi
  namespace: {namespace}
spec:
  strategy: ApplyOnce
  clusterSelector:
    matchLabels:
      csi: external
  resources:
    - kind: ConfigMap
      name: aws-ebs-csi"#
    );

    vec![configmap, crs]
}

/// Generate all AWS addon ClusterResourceSet manifests (CCM + CSI)
pub fn generate_all_aws_addon_crs(namespace: &str) -> Vec<String> {
    let mut manifests = generate_ccm_crs(namespace);
    manifests.extend(generate_ebs_csi_crs(namespace));
    manifests
}

fn indent_manifest(manifest: &str) -> String {
    manifest
        .lines()
        .map(|l| format!("    {}", l))
        .collect::<Vec<_>>()
        .join("\n")
}

fn generate_ccm_manifest() -> String {
    format!(
        r#"apiVersion: v1
kind: ServiceAccount
metadata:
  name: cloud-controller-manager
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cloud-controller-manager:apiserver-authentication-reader
  namespace: kube-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: extension-apiserver-authentication-reader
subjects:
  - apiGroup: ""
    kind: ServiceAccount
    name: cloud-controller-manager
    namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: system:cloud-controller-manager
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:cloud-controller-manager
subjects:
  - apiGroup: ""
    kind: ServiceAccount
    name: cloud-controller-manager
    namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: system:cloud-controller-manager
rules:
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["create", "patch", "update"]
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["*"]
  - apiGroups: [""]
    resources: ["nodes/status"]
    verbs: ["patch"]
  - apiGroups: [""]
    resources: ["services"]
    verbs: ["list", "patch", "update", "watch"]
  - apiGroups: [""]
    resources: ["services/status"]
    verbs: ["list", "patch", "update", "watch"]
  - apiGroups: [""]
    resources: ["serviceaccounts"]
    verbs: ["create", "get", "list", "watch"]
  - apiGroups: [""]
    resources: ["persistentvolumes"]
    verbs: ["get", "list", "update", "watch"]
  - apiGroups: [""]
    resources: ["endpoints"]
    verbs: ["create", "get", "list", "watch", "update"]
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["list", "watch"]
  - apiGroups: ["coordination.k8s.io"]
    resources: ["leases"]
    verbs: ["create", "get", "list", "watch", "update"]
  - apiGroups: [""]
    resources: ["serviceaccounts/token"]
    verbs: ["create"]
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: aws-cloud-controller-manager
  namespace: kube-system
  labels:
    k8s-app: aws-cloud-controller-manager
spec:
  selector:
    matchLabels:
      k8s-app: aws-cloud-controller-manager
  updateStrategy:
    type: RollingUpdate
  template:
    metadata:
      labels:
        k8s-app: aws-cloud-controller-manager
    spec:
      nodeSelector:
        node-role.kubernetes.io/control-plane: ""
      tolerations:
        - key: node.cloudprovider.kubernetes.io/uninitialized
          value: "true"
          effect: NoSchedule
        - key: node-role.kubernetes.io/control-plane
          effect: NoSchedule
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
              - matchExpressions:
                  - key: node-role.kubernetes.io/control-plane
                    operator: Exists
      serviceAccountName: cloud-controller-manager
      containers:
        - name: aws-cloud-controller-manager
          image: registry.k8s.io/provider-aws/cloud-controller-manager:{version}
          args:
            - --v=2
            - --cloud-provider=aws
            - --use-service-account-credentials=true
            - --configure-cloud-routes=false
          resources:
            requests:
              cpu: 200m
      hostNetwork: true"#,
        version = AWS_CCM_VERSION
    )
}

fn generate_ebs_csi_manifest() -> String {
    format!(
        r#"apiVersion: v1
kind: ServiceAccount
metadata:
  name: ebs-csi-controller-sa
  namespace: kube-system
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ebs-csi-node-sa
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ebs-external-attacher-role
rules:
  - apiGroups: [""]
    resources: ["persistentvolumes"]
    verbs: ["get", "list", "watch", "update", "patch"]
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["csi.storage.k8s.io"]
    resources: ["csinodeinfos"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["storage.k8s.io"]
    resources: ["volumeattachments"]
    verbs: ["get", "list", "watch", "update", "patch"]
  - apiGroups: ["storage.k8s.io"]
    resources: ["volumeattachments/status"]
    verbs: ["patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ebs-external-provisioner-role
rules:
  - apiGroups: [""]
    resources: ["persistentvolumes"]
    verbs: ["get", "list", "watch", "create", "delete"]
  - apiGroups: [""]
    resources: ["persistentvolumeclaims"]
    verbs: ["get", "list", "watch", "update"]
  - apiGroups: ["storage.k8s.io"]
    resources: ["storageclasses"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["list", "watch", "create", "update", "patch"]
  - apiGroups: ["snapshot.storage.k8s.io"]
    resources: ["volumesnapshots"]
    verbs: ["get", "list"]
  - apiGroups: ["snapshot.storage.k8s.io"]
    resources: ["volumesnapshotcontents"]
    verbs: ["get", "list"]
  - apiGroups: ["storage.k8s.io"]
    resources: ["csinodes"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["coordination.k8s.io"]
    resources: ["leases"]
    verbs: ["get", "watch", "list", "delete", "update", "create"]
  - apiGroups: ["storage.k8s.io"]
    resources: ["volumeattachments"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ebs-csi-attacher-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: ebs-external-attacher-role
subjects:
  - kind: ServiceAccount
    name: ebs-csi-controller-sa
    namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ebs-csi-provisioner-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: ebs-external-provisioner-role
subjects:
  - kind: ServiceAccount
    name: ebs-csi-controller-sa
    namespace: kube-system
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ebs-csi-controller
  namespace: kube-system
spec:
  replicas: 2
  selector:
    matchLabels:
      app: ebs-csi-controller
  template:
    metadata:
      labels:
        app: ebs-csi-controller
    spec:
      nodeSelector:
        node-role.kubernetes.io/control-plane: ""
      tolerations:
        - key: node-role.kubernetes.io/control-plane
          effect: NoSchedule
      serviceAccountName: ebs-csi-controller-sa
      containers:
        - name: ebs-plugin
          image: public.ecr.aws/ebs-csi-driver/aws-ebs-csi-driver:{version}
          args:
            - controller
            - --endpoint=$(CSI_ENDPOINT)
            - --logging-format=text
            - --v=2
          env:
            - name: CSI_ENDPOINT
              value: unix:///var/lib/csi/sockets/pluginproxy/csi.sock
            - name: CSI_NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
          volumeMounts:
            - name: socket-dir
              mountPath: /var/lib/csi/sockets/pluginproxy/
          ports:
            - containerPort: 9808
              name: healthz
          livenessProbe:
            httpGet:
              path: /healthz
              port: healthz
            initialDelaySeconds: 10
            periodSeconds: 10
        - name: csi-provisioner
          image: public.ecr.aws/eks-distro/kubernetes-csi/external-provisioner:v3.6.2-eks-1-28-11
          args:
            - --csi-address=$(ADDRESS)
            - --v=2
            - --feature-gates=Topology=true
            - --leader-election=true
          env:
            - name: ADDRESS
              value: /var/lib/csi/sockets/pluginproxy/csi.sock
          volumeMounts:
            - name: socket-dir
              mountPath: /var/lib/csi/sockets/pluginproxy/
        - name: csi-attacher
          image: public.ecr.aws/eks-distro/kubernetes-csi/external-attacher:v4.4.2-eks-1-28-11
          args:
            - --csi-address=$(ADDRESS)
            - --v=2
            - --leader-election=true
          env:
            - name: ADDRESS
              value: /var/lib/csi/sockets/pluginproxy/csi.sock
          volumeMounts:
            - name: socket-dir
              mountPath: /var/lib/csi/sockets/pluginproxy/
        - name: liveness-probe
          image: public.ecr.aws/eks-distro/kubernetes-csi/livenessprobe:v2.11.0-eks-1-28-11
          args:
            - --csi-address=/csi/csi.sock
          volumeMounts:
            - name: socket-dir
              mountPath: /csi
      volumes:
        - name: socket-dir
          emptyDir: {{}}
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ebs-csi-node
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: ebs-csi-node
  template:
    metadata:
      labels:
        app: ebs-csi-node
    spec:
      tolerations:
        - operator: Exists
      serviceAccountName: ebs-csi-node-sa
      containers:
        - name: ebs-plugin
          image: public.ecr.aws/ebs-csi-driver/aws-ebs-csi-driver:{version}
          args:
            - node
            - --endpoint=$(CSI_ENDPOINT)
            - --logging-format=text
            - --v=2
          env:
            - name: CSI_ENDPOINT
              value: unix:/csi/csi.sock
            - name: CSI_NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
          securityContext:
            privileged: true
          volumeMounts:
            - name: kubelet-dir
              mountPath: /var/lib/kubelet
              mountPropagation: Bidirectional
            - name: plugin-dir
              mountPath: /csi
            - name: device-dir
              mountPath: /dev
        - name: node-driver-registrar
          image: public.ecr.aws/eks-distro/kubernetes-csi/node-driver-registrar:v2.9.2-eks-1-28-11
          args:
            - --csi-address=$(ADDRESS)
            - --kubelet-registration-path=$(DRIVER_REG_SOCK_PATH)
            - --v=2
          env:
            - name: ADDRESS
              value: /csi/csi.sock
            - name: DRIVER_REG_SOCK_PATH
              value: /var/lib/kubelet/plugins/ebs.csi.aws.com/csi.sock
          volumeMounts:
            - name: plugin-dir
              mountPath: /csi
            - name: registration-dir
              mountPath: /registration
        - name: liveness-probe
          image: public.ecr.aws/eks-distro/kubernetes-csi/livenessprobe:v2.11.0-eks-1-28-11
          args:
            - --csi-address=/csi/csi.sock
          volumeMounts:
            - name: plugin-dir
              mountPath: /csi
      volumes:
        - name: kubelet-dir
          hostPath:
            path: /var/lib/kubelet
            type: Directory
        - name: plugin-dir
          hostPath:
            path: /var/lib/kubelet/plugins/ebs.csi.aws.com/
            type: DirectoryOrCreate
        - name: registration-dir
          hostPath:
            path: /var/lib/kubelet/plugins_registry/
            type: Directory
        - name: device-dir
          hostPath:
            path: /dev
            type: Directory
---
apiVersion: storage.k8s.io/v1
kind: CSIDriver
metadata:
  name: ebs.csi.aws.com
spec:
  attachRequired: true
  podInfoOnMount: false
---
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: ebs-sc
  annotations:
    storageclass.kubernetes.io/is-default-class: "true"
provisioner: ebs.csi.aws.com
volumeBindingMode: WaitForFirstConsumer
parameters:
  type: gp3"#,
        version = AWS_EBS_CSI_VERSION
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ccm_crs() {
        let manifests = generate_ccm_crs("capi-test");

        assert_eq!(manifests.len(), 2);
        assert!(manifests[0].contains("kind: ConfigMap"));
        assert!(manifests[0].contains("name: aws-ccm"));
        assert!(manifests[1].contains("kind: ClusterResourceSet"));
        assert!(manifests[1].contains("ccm: external"));
    }

    #[test]
    fn test_generate_ebs_csi_crs() {
        let manifests = generate_ebs_csi_crs("capi-test");

        assert_eq!(manifests.len(), 2);
        assert!(manifests[0].contains("kind: ConfigMap"));
        assert!(manifests[0].contains("name: aws-ebs-csi"));
        assert!(manifests[1].contains("kind: ClusterResourceSet"));
        assert!(manifests[1].contains("csi: external"));
    }

    #[test]
    fn test_generate_all_aws_addon_crs() {
        let manifests = generate_all_aws_addon_crs("capi-test");

        assert_eq!(manifests.len(), 4); // 2 for CCM + 2 for CSI
    }

    #[test]
    fn test_ccm_manifest_contains_required_resources() {
        let manifest = generate_ccm_manifest();

        assert!(manifest.contains("kind: ServiceAccount"));
        assert!(manifest.contains("kind: ClusterRole"));
        assert!(manifest.contains("kind: ClusterRoleBinding"));
        assert!(manifest.contains("kind: DaemonSet"));
        assert!(manifest.contains("cloud-controller-manager"));
    }

    #[test]
    fn test_ebs_csi_manifest_contains_required_resources() {
        let manifest = generate_ebs_csi_manifest();

        assert!(manifest.contains("kind: ServiceAccount"));
        assert!(manifest.contains("kind: Deployment"));
        assert!(manifest.contains("kind: DaemonSet"));
        assert!(manifest.contains("kind: CSIDriver"));
        assert!(manifest.contains("kind: StorageClass"));
        assert!(manifest.contains("ebs.csi.aws.com"));
    }
}
