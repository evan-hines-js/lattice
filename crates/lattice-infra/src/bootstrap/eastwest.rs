//! East-west gateway infrastructure for Istio ambient.
//!
//! Generates the east-west Gateway resource (HBONE port 15008, `istio-east-west` class).

use lattice_common::mesh::HBONE_PORT;

/// Generate the east-west Gateway resource for cross-cluster traffic.
pub fn generate_eastwest_gateway(cluster_name: &str) -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "Gateway",
        "metadata": {
            "name": "istio-eastwestgateway",
            "namespace": "istio-system",
            "labels": {
                "topology.istio.io/network": cluster_name,
                "app.kubernetes.io/managed-by": "lattice"
            }
        },
        "spec": {
            "gatewayClassName": "istio-east-west",
            "listeners": [{
                "name": "mesh",
                "port": HBONE_PORT,
                "protocol": "HBONE",
                "tls": {
                    "mode": "Terminate",
                    "options": {
                        "gateway.istio.io/tls-terminate-mode": "ISTIO_MUTUAL"
                    }
                }
            }]
        }
    }))
    .expect("serialize eastwest gateway")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eastwest_gateway() {
        let manifest = generate_eastwest_gateway("workload-1");
        let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();

        assert_eq!(parsed["metadata"]["name"], "istio-eastwestgateway");
        assert_eq!(
            parsed["metadata"]["labels"]["topology.istio.io/network"],
            "workload-1"
        );
        assert_eq!(parsed["spec"]["gatewayClassName"], "istio-east-west");
        assert_eq!(parsed["spec"]["listeners"][0]["port"], HBONE_PORT);
        assert_eq!(parsed["spec"]["listeners"][0]["protocol"], "HBONE");
        assert_eq!(
            parsed["spec"]["listeners"][0]["tls"]["options"]["gateway.istio.io/tls-terminate-mode"],
            "ISTIO_MUTUAL"
        );
    }
}
