//! Build script: render the Tetragon helm chart into `$OUT_DIR/tetragon.yaml`
//! and expose the version as `TETRAGON_VERSION` for `env!()` at compile time.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Versions {
    charts: HashMap<String, Chart>,
}

#[derive(Debug, Deserialize)]
struct Chart {
    version: String,
    #[serde(default)]
    repo: Option<String>,
    #[serde(default)]
    chart: Option<String>,
    #[serde(default)]
    filename: Option<String>,
}

fn workspace_root() -> PathBuf {
    Path::new(&std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate parent")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn ensure_chart_downloaded(name: &str, chart: &Chart, dir: &Path) -> PathBuf {
    let filename = chart
        .filename
        .as_ref()
        .unwrap_or_else(|| panic!("chart {name} missing filename"))
        .replace("{version}", &chart.version);
    let path = dir.join(&filename);
    if path.exists() {
        return path;
    }

    let chart_ref = chart
        .chart
        .as_ref()
        .unwrap_or_else(|| panic!("chart {name} missing chart ref"));

    eprintln!("cargo:warning=Downloading missing chart: {filename}");

    std::fs::create_dir_all(dir).expect("create charts dir");

    let mut cmd = Command::new("helm");
    if chart_ref.starts_with("oci://") {
        cmd.args([
            "pull",
            chart_ref,
            "--version",
            &format!("v{}", chart.version),
            "--destination",
            &dir.to_string_lossy(),
        ]);
    } else {
        let repo = chart
            .repo
            .as_ref()
            .unwrap_or_else(|| panic!("non-OCI chart {name} missing repo"));
        let alias = chart_ref.split('/').next().unwrap_or(name);
        let repo_status = Command::new("helm")
            .args(["repo", "add", alias, repo, "--force-update"])
            .output()
            .expect("helm repo add");
        if !repo_status.status.success() {
            let stderr = String::from_utf8_lossy(&repo_status.stderr);
            panic!("helm repo add {alias} failed: {stderr}");
        }
        cmd.args([
            "pull",
            chart_ref,
            "--version",
            &chart.version,
            "--destination",
            &dir.to_string_lossy(),
        ]);
    }

    let output = cmd
        .output()
        .unwrap_or_else(|e| panic!("helm pull {chart_ref}: {e}"));
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("helm pull {chart_ref} failed: {stderr}");
    }
    assert!(
        path.exists(),
        "helm pull succeeded but {} not found",
        path.display()
    );
    path
}

fn render_chart(chart_path: &Path, release: &str, namespace: &str, extra: &[&str]) -> String {
    let output = Command::new("helm")
        .args([
            "template",
            release,
            &chart_path.to_string_lossy(),
            "--namespace",
            namespace,
            "--include-crds",
        ])
        .args(extra)
        .output()
        .unwrap_or_else(|e| panic!("helm template {release}: {e}"));
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("helm template {release} failed: {stderr}");
    }
    String::from_utf8(output.stdout).expect("helm template utf-8")
}

fn main() {
    let root = workspace_root();
    let versions_path = root.join("versions.toml");
    println!("cargo:rerun-if-changed={}", versions_path.display());

    let raw = std::fs::read_to_string(&versions_path)
        .unwrap_or_else(|e| panic!("read {}: {}", versions_path.display(), e));
    let versions: Versions = toml::from_str(&raw).expect("versions.toml parse");

    let chart = versions
        .charts
        .get("tetragon")
        .expect("versions.toml missing [charts.tetragon]");

    // Download chart into the workspace's shared charts dir (same location
    // lattice-infra uses) so concurrent builds don't duplicate work.
    let charts_dir = root.join("test-charts");
    let chart_tgz = ensure_chart_downloaded("tetragon", chart, &charts_dir);

    // Tetragon install values:
    // - `crds.installMethod=helm`: render TracingPolicy/TracingPolicyNamespaced
    //   inline so they're present before the operator starts creating custom
    //   resources. The default ("operator") races with Lattice applying
    //   TracingPolicy immediately.
    let yaml = render_chart(
        &chart_tgz,
        "tetragon",
        "kube-system",
        &[
            "--set",
            "tetragon.enablePolicyFilter=true",
            "--set",
            "tetragon.enablePolicyFilterDebug=false",
            "--set",
            "rthooks.enabled=false",
            "--set",
            "crds.installMethod=helm",
        ],
    );

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(out_dir.join("tetragon.yaml"), yaml).expect("write tetragon.yaml");

    println!("cargo:rustc-env=TETRAGON_VERSION={}", chart.version);
}
