use std::path::Path;
use std::process::Command;

/// Helm chart versions - must match src/infra/*.rs
const CILIUM_VERSION: &str = "1.16.5";
const ISTIO_VERSION: &str = "1.24.2";
const CERT_MANAGER_VERSION: &str = "1.16.2"; // Required by CAPI

/// CAPI version - pinned to Lattice release
const CAPI_VERSION: &str = "1.9.4";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile proto files
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/agent.proto"], &["proto"])?;

    // Re-run if proto files change
    println!("cargo:rerun-if-changed=proto/agent.proto");

    // Download helm charts for local development/testing if they don't exist
    download_helm_charts()?;

    // Download CAPI providers for offline clusterctl init
    download_capi_providers()?;

    Ok(())
}

/// Download helm charts for local testing if not present
fn download_helm_charts() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let charts_dir = Path::new(&manifest_dir).join("test-charts");

    // Check if all required charts exist
    let cilium_chart = charts_dir.join(format!("cilium-{}.tgz", CILIUM_VERSION));
    let base_chart = charts_dir.join(format!("base-{}.tgz", ISTIO_VERSION));
    let istiod_chart = charts_dir.join(format!("istiod-{}.tgz", ISTIO_VERSION));
    let cert_manager_chart = charts_dir.join(format!("cert-manager-v{}.tgz", CERT_MANAGER_VERSION));

    // Set env var for tests to find charts
    println!(
        "cargo:rustc-env=LATTICE_CHARTS_DIR={}",
        charts_dir.display()
    );

    if cilium_chart.exists() && base_chart.exists() && istiod_chart.exists() && cert_manager_chart.exists() {
        // All charts present, nothing to do
        return Ok(());
    }

    // Check if helm is available
    if Command::new("helm").arg("version").output().is_err() {
        eprintln!("helm not found, skipping chart download");
        return Ok(());
    }

    // Create charts directory
    std::fs::create_dir_all(&charts_dir)?;

    // Add repos (ignore errors if already added)
    let _ = Command::new("helm")
        .args(["repo", "add", "cilium", "https://helm.cilium.io/"])
        .output();
    let _ = Command::new("helm")
        .args([
            "repo",
            "add",
            "istio",
            "https://istio-release.storage.googleapis.com/charts",
        ])
        .output();
    let _ = Command::new("helm")
        .args([
            "repo",
            "add",
            "jetstack",
            "https://charts.jetstack.io",
        ])
        .output();
    let _ = Command::new("helm").args(["repo", "update"]).output();

    // Pull charts if not present
    if !cilium_chart.exists() {
        eprintln!("Downloading Cilium chart v{}...", CILIUM_VERSION);
        let status = Command::new("helm")
            .args(["pull", "cilium/cilium", "--version", CILIUM_VERSION])
            .arg("--destination")
            .arg(&charts_dir)
            .status()?;
        if !status.success() {
            eprintln!("Failed to download Cilium chart");
        }
    }

    if !base_chart.exists() {
        eprintln!("Downloading Istio base chart v{}...", ISTIO_VERSION);
        let status = Command::new("helm")
            .args(["pull", "istio/base", "--version", ISTIO_VERSION])
            .arg("--destination")
            .arg(&charts_dir)
            .status()?;
        if !status.success() {
            eprintln!("Failed to download Istio base chart");
        }
    }

    if !istiod_chart.exists() {
        eprintln!("Downloading Istio istiod chart v{}...", ISTIO_VERSION);
        let status = Command::new("helm")
            .args(["pull", "istio/istiod", "--version", ISTIO_VERSION])
            .arg("--destination")
            .arg(&charts_dir)
            .status()?;
        if !status.success() {
            eprintln!("Failed to download Istio istiod chart");
        }
    }

    if !cert_manager_chart.exists() {
        eprintln!("Downloading cert-manager chart v{}...", CERT_MANAGER_VERSION);
        let status = Command::new("helm")
            .args(["pull", "jetstack/cert-manager", "--version", CERT_MANAGER_VERSION])
            .arg("--destination")
            .arg(&charts_dir)
            .status()?;
        if !status.success() {
            eprintln!("Failed to download cert-manager chart");
        }
    }

    Ok(())
}

/// Download CAPI providers for offline clusterctl init
fn download_capi_providers() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let providers_dir = Path::new(&manifest_dir).join("test-providers");

    // Set env var for clusterctl config location
    let config_path = providers_dir.join("clusterctl.yaml");
    println!(
        "cargo:rustc-env=CLUSTERCTL_CONFIG={}",
        config_path.display()
    );

    // Provider directories (clusterctl local repository structure)
    let core_dir = providers_dir.join("cluster-api").join(format!("v{}", CAPI_VERSION));
    let bootstrap_dir = providers_dir.join("bootstrap-kubeadm").join(format!("v{}", CAPI_VERSION));
    let controlplane_dir = providers_dir.join("control-plane-kubeadm").join(format!("v{}", CAPI_VERSION));
    let docker_dir = providers_dir.join("infrastructure-docker").join(format!("v{}", CAPI_VERSION));

    let core = core_dir.join("core-components.yaml");
    let core_metadata = core_dir.join("metadata.yaml");
    let bootstrap = bootstrap_dir.join("bootstrap-components.yaml");
    let bootstrap_metadata = bootstrap_dir.join("metadata.yaml");
    let controlplane = controlplane_dir.join("control-plane-components.yaml");
    let controlplane_metadata = controlplane_dir.join("metadata.yaml");
    let docker = docker_dir.join("infrastructure-components-development.yaml");
    let docker_metadata = docker_dir.join("metadata.yaml");

    // Check if all files exist
    let all_exist = core.exists() && core_metadata.exists()
        && bootstrap.exists() && bootstrap_metadata.exists()
        && controlplane.exists() && controlplane_metadata.exists()
        && docker.exists() && docker_metadata.exists()
        && config_path.exists();

    if all_exist {
        return Ok(());
    }

    // Check if curl is available
    if Command::new("curl").arg("--version").output().is_err() {
        eprintln!("curl not found, skipping CAPI provider download");
        return Ok(());
    }

    eprintln!("Downloading CAPI providers v{}...", CAPI_VERSION);

    // Create provider directories
    std::fs::create_dir_all(&core_dir)?;
    std::fs::create_dir_all(&bootstrap_dir)?;
    std::fs::create_dir_all(&controlplane_dir)?;
    std::fs::create_dir_all(&docker_dir)?;

    // Download components and metadata from GitHub releases
    let base_url = format!("https://github.com/kubernetes-sigs/cluster-api/releases/download/v{}", CAPI_VERSION);

    download_file(&format!("{}/core-components.yaml", base_url), &core);
    download_file(&format!("{}/metadata.yaml", base_url), &core_metadata);
    download_file(&format!("{}/bootstrap-components.yaml", base_url), &bootstrap);
    // Bootstrap and control-plane share metadata with core
    std::fs::copy(&core_metadata, &bootstrap_metadata).ok();
    download_file(&format!("{}/control-plane-components.yaml", base_url), &controlplane);
    std::fs::copy(&core_metadata, &controlplane_metadata).ok();
    download_file(&format!("{}/infrastructure-components-development.yaml", base_url), &docker);
    std::fs::copy(&core_metadata, &docker_metadata).ok();

    // Create clusterctl.yaml with explicit provider definitions using file:// URLs
    // This prevents clusterctl from trying to reach GitHub at all
    let config_content = format!(r#"# Clusterctl config for offline/air-gapped CAPI installation
# Explicit provider definitions with local file:// URLs

providers:
  - name: "cluster-api"
    url: "file://{providers_dir}/cluster-api/v{version}/core-components.yaml"
    type: "CoreProvider"
  - name: "kubeadm"
    url: "file://{providers_dir}/bootstrap-kubeadm/v{version}/bootstrap-components.yaml"
    type: "BootstrapProvider"
  - name: "kubeadm"
    url: "file://{providers_dir}/control-plane-kubeadm/v{version}/control-plane-components.yaml"
    type: "ControlPlaneProvider"
  - name: "docker"
    url: "file://{providers_dir}/infrastructure-docker/v{version}/infrastructure-components-development.yaml"
    type: "InfrastructureProvider"
"#,
        providers_dir = providers_dir.display(),
        version = CAPI_VERSION,
    );
    std::fs::write(&config_path, config_content)?;

    Ok(())
}

fn download_file(url: &str, dest: &Path) {
    if dest.exists() {
        return;
    }
    eprintln!("  Downloading {}...", dest.file_name().unwrap().to_string_lossy());
    let _ = Command::new("curl")
        .args(["-fsSL", "-o"])
        .arg(dest)
        .arg(url)
        .status();
}
