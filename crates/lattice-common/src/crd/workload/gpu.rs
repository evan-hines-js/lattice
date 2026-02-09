//! GPU resource specification shared across all Lattice workload CRDs.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Parse a GPU memory string into MiB.
///
/// Accepts "20Gi" → 20480, "512Mi" → 512, bare number → MiB.
pub(crate) fn parse_gpu_memory_mib(memory: &str) -> Result<u64, String> {
    let memory = memory.trim();
    if memory.ends_with("Gi") {
        let num = memory
            .trim_end_matches("Gi")
            .parse::<u64>()
            .map_err(|_| format!("invalid gpu memory: {memory}, use Gi or Mi suffix"))?;
        Ok(num * 1024)
    } else if memory.ends_with("Mi") {
        memory
            .trim_end_matches("Mi")
            .parse::<u64>()
            .map_err(|_| format!("invalid gpu memory: {memory}, use Gi or Mi suffix"))
    } else {
        // Bare number treated as MiB
        memory
            .parse::<u64>()
            .map_err(|_| format!("invalid gpu memory: {memory}, use Gi or Mi suffix"))
    }
}

/// GPU resource specification
///
/// Configures GPU allocation for a service. Supports both full GPU allocation
/// (standard NVIDIA device plugin) and fractional sharing via HAMi.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GPUSpec {
    /// Number of GPUs requested (must be > 0)
    pub count: u32,

    /// GPU memory limit (e.g., "20Gi", "512Mi"). Enables HAMi fractional sharing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,

    /// GPU compute percentage (1-100). Enables HAMi fractional sharing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compute: Option<u32>,

    /// GPU model selector (e.g., "H100", "A100", "L4"). Maps to node selector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,

    /// Whether to add nvidia.com/gpu toleration (default: true)
    #[serde(default = "crate::crd::default_true")]
    pub tolerations: bool,
}

impl Default for GPUSpec {
    fn default() -> Self {
        Self {
            count: 0,
            memory: None,
            compute: None,
            model: None,
            tolerations: true,
        }
    }
}

impl GPUSpec {
    /// Returns true if HAMi fractional sharing is needed (memory or compute set)
    pub fn needs_hami(&self) -> bool {
        self.memory.is_some() || self.compute.is_some()
    }

    /// Returns true if this is a full GPU allocation (no fractional fields)
    pub fn is_full_gpu(&self) -> bool {
        !self.needs_hami()
    }

    /// Validate the GPU specification
    pub fn validate(&self) -> Result<(), String> {
        if self.count == 0 {
            return Err("gpu.count must be greater than 0".to_string());
        }

        if let Some(compute) = self.compute {
            if compute == 0 || compute > 100 {
                return Err("gpu.compute must be between 1 and 100".to_string());
            }
        }

        if let Some(ref memory) = self.memory {
            parse_gpu_memory_mib(memory)?;
        }

        Ok(())
    }

    /// Parse the memory field into MiB, if present.
    pub fn memory_mib(&self) -> Option<Result<u64, String>> {
        self.memory.as_ref().map(|m| parse_gpu_memory_mib(m))
    }

    /// Map a short GPU model name to the `nvidia.com/gpu.product` NFD label value.
    ///
    /// Known models are mapped to their full NVIDIA product names.
    /// Unknown models are passed through as-is.
    /// Returns None if no model is set.
    pub fn product_label(&self) -> Option<String> {
        self.model
            .as_ref()
            .map(|model| match model.to_uppercase().as_str() {
                "H100" => "NVIDIA-H100-80GB-HBM3".to_string(),
                "H100SXM" => "NVIDIA-H100-80GB-HBM3".to_string(),
                "H100PCIE" => "NVIDIA-H100-PCIe".to_string(),
                "A100" => "NVIDIA-A100-SXM4-80GB".to_string(),
                "A100-80G" => "NVIDIA-A100-SXM4-80GB".to_string(),
                "A100-40G" => "NVIDIA-A100-SXM4-40GB".to_string(),
                "A10G" => "NVIDIA-A10G".to_string(),
                "L40S" => "NVIDIA-L40S".to_string(),
                "L40" => "NVIDIA-L40".to_string(),
                "L4" => "NVIDIA-L4".to_string(),
                "T4" => "NVIDIA-Tesla-T4".to_string(),
                "V100" => "NVIDIA-Tesla-V100-SXM2-16GB".to_string(),
                _ => model.to_string(),
            })
    }

    /// Build a node selector map for GPU model selection.
    ///
    /// Returns a BTreeMap with `nvidia.com/gpu.product` set to the product label
    /// if a model is specified, or None otherwise.
    pub fn node_selector(&self) -> Option<std::collections::BTreeMap<String, String>> {
        self.product_label().map(|label| {
            let mut selector = std::collections::BTreeMap::new();
            selector.insert("nvidia.com/gpu.product".to_string(), label);
            selector
        })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpu_valid_full_gpu() {
        let gpu = GPUSpec {
            count: 1,
            ..Default::default()
        };
        assert!(gpu.validate().is_ok());
        assert!(gpu.is_full_gpu());
        assert!(!gpu.needs_hami());
    }

    #[test]
    fn gpu_valid_multi_gpu() {
        let gpu = GPUSpec {
            count: 4,
            model: Some("H100".to_string()),
            ..Default::default()
        };
        assert!(gpu.validate().is_ok());
        assert!(gpu.is_full_gpu());
    }

    #[test]
    fn gpu_valid_fractional() {
        let gpu = GPUSpec {
            count: 1,
            memory: Some("20Gi".to_string()),
            compute: Some(30),
            ..Default::default()
        };
        assert!(gpu.validate().is_ok());
        assert!(gpu.needs_hami());
        assert!(!gpu.is_full_gpu());
    }

    #[test]
    fn gpu_zero_count_fails() {
        let gpu = GPUSpec {
            count: 0,
            ..Default::default()
        };
        let err = gpu.validate().unwrap_err();
        assert!(err.contains("count must be greater than 0"));
    }

    #[test]
    fn gpu_compute_out_of_range() {
        let gpu = GPUSpec {
            count: 1,
            compute: Some(0),
            ..Default::default()
        };
        assert!(gpu.validate().is_err());

        let gpu = GPUSpec {
            count: 1,
            compute: Some(101),
            ..Default::default()
        };
        assert!(gpu.validate().is_err());
    }

    #[test]
    fn gpu_invalid_memory_format() {
        let gpu = GPUSpec {
            count: 1,
            memory: Some("notanumber".to_string()),
            ..Default::default()
        };
        assert!(gpu.validate().is_err());
    }

    #[test]
    fn parse_gpu_memory_gi() {
        assert_eq!(parse_gpu_memory_mib("20Gi").unwrap(), 20480);
        assert_eq!(parse_gpu_memory_mib("1Gi").unwrap(), 1024);
    }

    #[test]
    fn parse_gpu_memory_mi() {
        assert_eq!(parse_gpu_memory_mib("512Mi").unwrap(), 512);
        assert_eq!(parse_gpu_memory_mib("8192Mi").unwrap(), 8192);
    }

    #[test]
    fn parse_gpu_memory_bare_number() {
        assert_eq!(parse_gpu_memory_mib("1024").unwrap(), 1024);
    }

    #[test]
    fn parse_gpu_memory_invalid() {
        assert!(parse_gpu_memory_mib("abc").is_err());
        assert!(parse_gpu_memory_mib("").is_err());
        assert!(parse_gpu_memory_mib("10Xi").is_err());
    }

    #[test]
    fn gpu_memory_mib_method() {
        let gpu = GPUSpec {
            count: 1,
            memory: Some("8Gi".to_string()),
            ..Default::default()
        };
        assert_eq!(gpu.memory_mib().unwrap().unwrap(), 8192);

        let gpu_none = GPUSpec {
            count: 1,
            ..Default::default()
        };
        assert!(gpu_none.memory_mib().is_none());
    }

    #[test]
    fn gpu_product_label_known_models() {
        let gpu = |model: &str| GPUSpec {
            count: 1,
            model: Some(model.to_string()),
            ..Default::default()
        };

        assert_eq!(
            gpu("H100").product_label().unwrap(),
            "NVIDIA-H100-80GB-HBM3"
        );
        assert_eq!(
            gpu("A100").product_label().unwrap(),
            "NVIDIA-A100-SXM4-80GB"
        );
        assert_eq!(gpu("L4").product_label().unwrap(), "NVIDIA-L4");
        assert_eq!(gpu("T4").product_label().unwrap(), "NVIDIA-Tesla-T4");
        assert_eq!(gpu("L40S").product_label().unwrap(), "NVIDIA-L40S");
    }

    #[test]
    fn gpu_product_label_unknown_passthrough() {
        let gpu = GPUSpec {
            count: 1,
            model: Some("custom-gpu-xyz".to_string()),
            ..Default::default()
        };
        assert_eq!(gpu.product_label().unwrap(), "custom-gpu-xyz");
    }

    #[test]
    fn gpu_product_label_none_when_no_model() {
        let gpu = GPUSpec {
            count: 1,
            ..Default::default()
        };
        assert!(gpu.product_label().is_none());
    }

    #[test]
    fn gpu_node_selector_with_model() {
        let gpu = GPUSpec {
            count: 1,
            model: Some("L4".to_string()),
            ..Default::default()
        };
        let selector = gpu.node_selector().unwrap();
        assert_eq!(selector.get("nvidia.com/gpu.product").unwrap(), "NVIDIA-L4");
    }

    #[test]
    fn gpu_node_selector_none_without_model() {
        let gpu = GPUSpec {
            count: 1,
            ..Default::default()
        };
        assert!(gpu.node_selector().is_none());
    }
}
