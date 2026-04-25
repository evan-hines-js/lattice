//! Render the Volcano helm chart + vGPU device plugin.
//!
//! Outputs `$OUT_DIR/volcano.yaml` and `$OUT_DIR/volcano-vgpu-device-plugin.yaml`.
//! The vGPU device plugin is patched with a GPU-node nodeSelector so it
//! doesn't crash on non-GPU nodes with `NVML ERROR_LIBRARY_NOT_FOUND`.

use std::path::PathBuf;

const VOLCANO_VALUES_YAML: &str = r#"custom:
  scheduler_config_override: |
    actions: "enqueue, allocate, backfill"
    tiers:
    - plugins:
      - name: priority
      - name: gang
      - name: conformance
    - plugins:
      - name: drf
      - name: deviceshare
        arguments:
          deviceshare.VGPUEnable: true
      - name: predicates
      - name: proportion
      - name: nodeorder
      - name: binpack
      - name: network-topology-aware
  webhooks_namespace_selector_expressions:
  - key: kubernetes.io/metadata.name
    operator: NotIn
    values:
    - lattice-system
"#;

fn main() {
    let versions = lattice_helm_build::read_versions().expect("read versions.toml");
    let chart = versions
        .charts
        .get("volcano")
        .expect("versions.toml missing [charts.volcano]");
    let chart_path =
        lattice_helm_build::ensure_chart("volcano", chart).expect("ensure volcano chart");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));

    // Write the values file next to the OUT_DIR so `--values <path>` can read it.
    let values_path = out_dir.join("volcano-values.yaml");
    std::fs::write(&values_path, VOLCANO_VALUES_YAML).expect("write volcano-values.yaml");

    let yaml = lattice_helm_build::render_chart(
        &chart_path,
        "volcano",
        "volcano-system",
        &[
            "--set",
            "custom.enabled=true",
            "--set",
            "basic.controller_enabled=true",
            "--set",
            "basic.scheduler_enabled=true",
            "--set",
            "basic.admission_enabled=true",
            "--values",
            values_path.to_str().expect("values path utf-8"),
        ],
    )
    .expect("render volcano chart");
    std::fs::write(out_dir.join("volcano.yaml"), yaml).expect("write volcano.yaml");

    // vGPU device plugin: plain YAML download, then patch with a GPU-only
    // nodeSelector. Without the selector, the plugin crashes on non-GPU nodes.
    let vgpu_resource = versions
        .resources
        .get("volcano-vgpu-device-plugin")
        .expect("versions.toml missing [resources.volcano-vgpu-device-plugin]");
    let vgpu_src = lattice_helm_build::ensure_resource("volcano-vgpu-device-plugin", vgpu_resource)
        .expect("ensure volcano-vgpu-device-plugin resource");
    let raw = std::fs::read_to_string(&vgpu_src)
        .unwrap_or_else(|e| panic!("read {}: {e}", vgpu_src.display()));
    let patched = raw.replace(
        "      priorityClassName: \"system-node-critical\"",
        "      nodeSelector:\n        nvidia.com/gpu.present: \"true\"\n      priorityClassName: \"system-node-critical\"",
    );
    std::fs::write(out_dir.join("volcano-vgpu-device-plugin.yaml"), patched)
        .expect("write volcano-vgpu-device-plugin.yaml");

    println!("cargo:rustc-env=VOLCANO_VERSION={}", chart.version);
}
