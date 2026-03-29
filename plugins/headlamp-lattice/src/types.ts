/**
 * LatticeService CRD type definitions (lattice.dev/v1alpha1)
 *
 * Field names use camelCase to match the Rust CRD's
 * `#[serde(rename_all = "camelCase")]` serialization.
 *
 * RuntimeSpec is `#[serde(flatten)]` in Rust, so its fields
 * (sidecars, sysctls, hostNetwork, etc.) appear directly on the spec,
 * NOT nested under a `runtime` key.
 */

// -- Top-level CRD --------------------------------------------------------

export interface LatticeServiceCRD {
  metadata: {
    name: string;
    namespace: string;
    creationTimestamp: string;
    generation?: number;
    resourceVersion?: string;
    uid?: string;
    labels?: Record<string, string>;
    annotations?: Record<string, string>;
  };
  spec: LatticeServiceSpec;
  status?: LatticeServiceStatus;
}

// -- Spec (RuntimeSpec fields are flattened in) ----------------------------

export interface LatticeServiceSpec {
  workload: WorkloadSpec;
  replicas: number;
  autoscaling?: AutoscalingSpec;
  deploy: DeploySpec;
  ingress?: IngressSpec;
  topology?: WorkloadNetworkTopology;
  observability?: ObservabilitySpec;
  backup?: ServiceBackupSpec;

  // Flattened from RuntimeSpec
  sidecars?: Record<string, SidecarSpec>;
  sysctls?: Record<string, string>;
  hostNetwork?: boolean;
  shareProcessNamespace?: boolean;
  automountServiceAccountToken?: boolean;
  imagePullSecrets?: string[];
}

export interface LatticeServiceStatus {
  phase: ServicePhase;
  message?: string;
  conditions: Condition[];
  observedGeneration?: number;
  resolvedDependencies: Record<string, string>;
  cost?: CostEstimate;
  metrics?: MetricsSnapshot;
}

export type ServicePhase = 'Pending' | 'Compiling' | 'Ready' | 'Failed';

export interface Condition {
  type: string;
  status: string;
  reason?: string;
  message?: string;
  lastTransitionTime?: string;
}

export interface CostEstimate {
  monthlyUsd?: number;
}

export interface MetricsSnapshot {
  cpuUsage?: string;
  memoryUsage?: string;
}

// -- Workload -------------------------------------------------------------

export interface WorkloadSpec {
  containers: Record<string, ContainerSpec>;
  resources: Record<string, ResourceSpec>;
  service?: ServicePortsSpec;
}

// -- Containers -----------------------------------------------------------

export interface ContainerSpec {
  image: string;
  command?: string[];
  args?: string[];
  workingDir?: string;
  variables: Record<string, string>;
  resources?: ResourceRequirements;
  files: Record<string, FileMount>;
  volumes: Record<string, VolumeMount>;
  livenessProbe?: Probe;
  readinessProbe?: Probe;
  startupProbe?: Probe;
  envFrom: string[];
  security?: SecurityContext;
}

export interface SidecarSpec extends ContainerSpec {
  init?: boolean;
}

export interface ResourceRequirements {
  requests?: ResourceQuantity;
  limits?: ResourceQuantity;
}

export interface ResourceQuantity {
  cpu?: string;
  memory?: string;
}

// -- Resources (mesh deps, volumes, secrets, GPUs) ------------------------

export interface ResourceSpec {
  type: ResourceType;
  class?: string;
  id?: string;
  metadata?: ResourceMetadata;
  params: ResourceParams;
  direction: DependencyDirection;
  namespace?: string;
}

export type ResourceType = 'service' | 'external-service' | 'volume' | 'secret' | 'gpu' | string;
export type DependencyDirection = 'outbound' | 'inbound' | 'both';

export interface ResourceMetadata {
  annotations?: Record<string, string>;
}

export type ResourceParams =
  | VolumeParams
  | SecretParams
  | ExternalServiceParams
  | GpuParams
  | Record<string, unknown>;

export interface VolumeParams {
  size?: string;
  storageClass?: string;
  accessMode?: string;
  allowedConsumers?: string[];
}

export interface SecretParams {
  provider: string;
  keys?: string[];
  refreshInterval?: string;
  secretType?: string;
}

export interface ExternalServiceParams {
  endpoints: Record<string, string>;
  resolution?: string;
}

export interface GpuParams {
  count: number;
  memory?: string;
  compute?: number;
  model?: string;
  tolerations?: boolean;
}

// -- Ports ----------------------------------------------------------------

export interface ServicePortsSpec {
  ports: Record<string, PortSpec>;
}

export interface PortSpec {
  port: number;
  targetPort?: number;
  protocol?: string;
}

// -- Ingress --------------------------------------------------------------

export interface IngressSpec {
  gatewayClass?: string;
  routes: Record<string, RouteSpec>;
}

export interface RouteSpec {
  kind: 'HTTPRoute' | 'GRPCRoute' | 'TCPRoute';
  hosts: string[];
  port?: string;
  listenPort?: number;
  rules?: RouteRule[];
  tls?: IngressTls;
  advertise?: AdvertiseConfig;
}

export interface RouteRule {
  matches?: Record<string, unknown>[];
  filters?: Record<string, unknown>[];
}

export interface IngressTls {
  secretName?: string;
  issuerRef?: CertIssuerRef;
}

export interface CertIssuerRef {
  name: string;
  kind?: string;
  group?: string;
}

export interface AdvertiseConfig {
  allowedServices: string[];
}

// -- Autoscaling ----------------------------------------------------------

export interface AutoscalingSpec {
  max: number;
  metrics: AutoscalingMetric[];
}

export interface AutoscalingMetric {
  metric: string;
  target: number;
}

// -- Deploy ---------------------------------------------------------------

export interface DeploySpec {
  strategy: 'Rolling' | 'Canary';
  canary?: CanarySpec;
}

export interface CanarySpec {
  interval?: string;
  threshold?: number;
  maxWeight?: number;
  stepWeight?: number;
}

// -- Misc -----------------------------------------------------------------

export interface FileMount {
  content?: string;
  binaryContent?: string;
  source?: string;
  mode?: string;
  noExpand?: boolean;
}

export interface VolumeMount {
  source?: string;
  path?: string;
  readOnly?: boolean;
  medium?: string;
  sizeLimit?: string;
}

export interface Probe {
  httpGet?: { path: string; port: number; scheme?: string };
  exec?: { command: string[] };
  initialDelaySeconds?: number;
  periodSeconds?: number;
  timeoutSeconds?: number;
  failureThreshold?: number;
  successThreshold?: number;
}

export interface SecurityContext {
  capabilities?: string[];
  dropCapabilities?: string[];
  privileged?: boolean;
  readOnlyRootFilesystem?: boolean;
  runAsNonRoot?: boolean;
  runAsUser?: number;
  runAsGroup?: number;
  allowPrivilegeEscalation?: boolean;
  seccompProfile?: string;
  apparmorProfile?: string;
  allowedBinaries?: string[];
}

export interface ServiceBackupSpec {
  [key: string]: unknown;
}

export interface WorkloadNetworkTopology {
  [key: string]: unknown;
}

export interface ObservabilitySpec {
  [key: string]: unknown;
}

// -- Derived helpers (attached by useLatticeServiceList) -------------------

export interface MeshDep {
  name: string;
  namespace?: string;
}

export interface SecretDep {
  name: string;
  provider: string;
  keys?: string[];
}

export interface GpuDep {
  name: string;
  count: number;
  model?: string;
}

export interface EnrichedLatticeService extends LatticeServiceCRD {
  phase: ServicePhase | 'Unknown';
  replicas: number;
  containers: Record<string, ContainerSpec>;
  resources: Record<string, ResourceSpec>;
  outboundDeps: MeshDep[];
  inboundDeps: MeshDep[];
  secrets: SecretDep[];
  gpus: GpuDep[];
}
