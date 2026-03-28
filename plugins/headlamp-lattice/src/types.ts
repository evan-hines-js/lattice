/** LatticeService CRD type definitions (lattice.dev/v1alpha1) */

export interface LatticeServiceSpec {
  workload: WorkloadSpec;
  replicas: number;
  autoscaling?: AutoscalingSpec;
  runtime: RuntimeSpec;
  backup?: ServiceBackupSpec;
  deploy: DeploySpec;
  ingress?: IngressSpec;
  topology?: WorkloadNetworkTopology;
  observability?: ObservabilitySpec;
}

export interface LatticeServiceStatus {
  phase: ServicePhase;
  message?: string;
  conditions: Condition[];
  observed_generation?: number;
  resolved_dependencies: Record<string, string>;
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
  monthly_usd?: number;
}

export interface MetricsSnapshot {
  cpu_usage?: string;
  memory_usage?: string;
}

// Workload
export interface WorkloadSpec {
  containers: Record<string, ContainerSpec>;
  resources: Record<string, ResourceSpec>;
  service?: ServicePortsSpec;
}

export interface RuntimeSpec {
  sidecars: Record<string, SidecarSpec>;
  sysctls: Record<string, string>;
  host_network?: boolean;
  share_process_namespace?: boolean;
  automount_service_account_token?: boolean;
  image_pull_secrets: string[];
}

// Containers
export interface ContainerSpec {
  image: string;
  command?: string[];
  args?: string[];
  working_dir?: string;
  variables: Record<string, string>;
  resources?: ResourceRequirements;
  files: Record<string, FileMount>;
  volumes: Record<string, VolumeMount>;
  liveness_probe?: Probe;
  readiness_probe?: Probe;
  startup_probe?: Probe;
  env_from: string[];
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

// Resources (mesh dependencies, volumes, secrets, GPUs)
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
  storage_class?: string;
  access_mode?: string;
  allowed_consumers?: string[];
}

export interface SecretParams {
  provider: string;
  keys?: string[];
  refresh_interval?: string;
  secret_type?: string;
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

// Ports
export interface ServicePortsSpec {
  ports: Record<string, PortSpec>;
}

export interface PortSpec {
  port: number;
  target_port?: number;
  protocol?: string;
}

// Ingress
export interface IngressSpec {
  gateway_class?: string;
  routes: Record<string, RouteSpec>;
}

export interface RouteSpec {
  kind: 'HTTPRoute' | 'GRPCRoute' | 'TCPRoute';
  hosts: string[];
  port?: string;
  listen_port?: number;
  rules?: RouteRule[];
  tls?: IngressTls;
  advertise?: AdvertiseConfig;
}

export interface RouteRule {
  matches?: Record<string, unknown>[];
  filters?: Record<string, unknown>[];
}

export interface IngressTls {
  secret_name?: string;
  issuer_ref?: CertIssuerRef;
}

export interface CertIssuerRef {
  name: string;
  kind?: string;
  group?: string;
}

export interface AdvertiseConfig {
  allowed_services: string[];
}

// Autoscaling
export interface AutoscalingSpec {
  max: number;
  metrics: AutoscalingMetric[];
}

export interface AutoscalingMetric {
  metric: string;
  target: number;
}

// Deploy
export interface DeploySpec {
  strategy: 'Rolling' | 'Canary';
  canary?: CanarySpec;
}

export interface CanarySpec {
  interval?: string;
  threshold?: number;
  max_weight?: number;
  step_weight?: number;
}

// Misc
export interface FileMount {
  content?: string;
  binary_content?: string;
  source?: string;
  mode?: string;
  no_expand?: boolean;
}

export interface VolumeMount {
  source?: string;
  path?: string;
  read_only?: boolean;
  medium?: string;
  size_limit?: string;
}

export interface Probe {
  http_get?: { path: string; port: number; scheme?: string };
  exec?: { command: string[] };
  initial_delay_seconds?: number;
  period_seconds?: number;
  timeout_seconds?: number;
  failure_threshold?: number;
  success_threshold?: number;
}

export interface SecurityContext {
  capabilities?: string[];
  drop_capabilities?: string[];
  privileged?: boolean;
  read_only_root_filesystem?: boolean;
  run_as_non_root?: boolean;
  run_as_user?: number;
  run_as_group?: number;
  allow_privilege_escalation?: boolean;
  seccomp_profile?: string;
  apparmor_profile?: string;
  allowed_binaries?: string[];
}

export interface ServiceBackupSpec {
  // Velero backup hooks
  [key: string]: unknown;
}

export interface WorkloadNetworkTopology {
  // Volcano PodGroup scheduling
  [key: string]: unknown;
}

export interface ObservabilitySpec {
  // Metrics configuration
  [key: string]: unknown;
}
