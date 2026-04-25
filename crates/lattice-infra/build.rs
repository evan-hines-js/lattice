//! Copy the Gateway API CRD bundle into `$OUT_DIR` for embedding.
//!
//! Per-dependency helm charts each render themselves in their own install
//! crate's build script; this crate now only handles the static Gateway API
//! CRD bundle that survives in bootstrap.

use std::path::PathBuf;

fn main() {
    let versions = lattice_helm_build::read_versions().expect("read versions.toml");
    let gateway = versions
        .resources
        .get("gateway-api")
        .expect("versions.toml missing [resources.gateway-api]");
    let src = lattice_helm_build::ensure_resource("gateway-api", gateway)
        .expect("ensure gateway-api resource");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let content =
        std::fs::read_to_string(&src).unwrap_or_else(|e| panic!("read {}: {e}", src.display()));
    std::fs::write(out_dir.join("gateway-api-crds.yaml"), content)
        .expect("write gateway-api-crds.yaml");

    println!("cargo:rustc-env=GATEWAY_API_VERSION={}", gateway.version);
}
