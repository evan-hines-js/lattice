//! Per-controller resource cache backed by kube-rs reflector watches.
//!
//! Each controller builds its own `ResourceCache` with exactly the resource
//! types it needs. All reads are memory hits — controllers never call the
//! K8s API at point of use.
//!
//! Duplicate watches across controllers are cheap: each is a single
//! persistent HTTP connection to the API server's watch cache.
//!
//! ```rust,ignore
//! let cache = ResourceCache::builder()
//!     .watch(Api::<LatticeQuota>::namespaced(client.clone(), "lattice-system"))
//!     .watch(Api::<Namespace>::all(client.clone()))
//!     .build();
//!
//! // In reconcile — zero API calls:
//! let quotas: Vec<Arc<LatticeQuota>> = cache.list::<LatticeQuota>();
//! let ns: Option<Arc<Namespace>> = cache.get::<Namespace>("my-namespace");
//! ```

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use futures::StreamExt;
use kube::api::Api;
use kube::runtime::reflector::{self, ObjectRef, Store};
use kube::runtime::watcher::{self, Config as WatcherConfig};
use kube::runtime::WatchStreamExt;
use kube::Resource;

/// Watcher timeout — must be less than the kube client read_timeout (30s).
const WATCH_TIMEOUT_SECS: u32 = 25;

// ---------------------------------------------------------------------------
// Type-erased store
// ---------------------------------------------------------------------------

trait AnyStore: Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn type_name(&self) -> &'static str;
}

struct TypedStore<K>
where
    K: Resource<DynamicType = ()> + Clone + fmt::Debug + Send + Sync + 'static,
{
    store: Store<K>,
}

impl<K> AnyStore for TypedStore<K>
where
    K: Resource<DynamicType = ()> + Clone + fmt::Debug + Send + Sync + 'static,
{
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn type_name(&self) -> &'static str {
        std::any::type_name::<K>()
    }
}

// ---------------------------------------------------------------------------
// ResourceCache
// ---------------------------------------------------------------------------

/// In-memory cache of Kubernetes resources backed by reflector watches.
///
/// Built per-controller with exactly the types that controller needs.
/// All reads are local — no API calls at point of use.
#[derive(Clone)]
pub struct ResourceCache {
    stores: Arc<HashMap<TypeId, Arc<dyn AnyStore>>>,
}

impl ResourceCache {
    /// Create a builder.
    pub fn builder() -> ResourceCacheBuilder {
        ResourceCacheBuilder {
            stores: HashMap::new(),
        }
    }

    /// Create an empty cache (no watches). Used in tests.
    pub fn empty() -> Self {
        Self {
            stores: Arc::new(HashMap::new()),
        }
    }

    /// List all cached objects of type `K`.
    ///
    /// Returns an empty vec if the type was not registered.
    pub fn list<K>(&self) -> Vec<Arc<K>>
    where
        K: Resource<DynamicType = ()> + Clone + fmt::Debug + Send + Sync + 'static,
    {
        match self.store_for::<K>() {
            Some(store) => store.state(),
            None => vec![],
        }
    }

    /// List cached objects of type `K` that match the given predicate.
    ///
    /// Filters in memory — no API calls. Returns an empty vec if the type
    /// was not registered.
    pub fn list_filtered<K>(&self, predicate: impl Fn(&K) -> bool) -> Vec<Arc<K>>
    where
        K: Resource<DynamicType = ()> + Clone + fmt::Debug + Send + Sync + 'static,
    {
        match self.store_for::<K>() {
            Some(store) => store.state().into_iter().filter(|obj| predicate(obj)).collect(),
            None => vec![],
        }
    }

    /// Get a single cached object by name (cluster-scoped resources).
    pub fn get<K>(&self, name: &str) -> Option<Arc<K>>
    where
        K: Resource<DynamicType = ()> + Clone + fmt::Debug + Send + Sync + 'static,
    {
        self.store_for::<K>()?.get(&ObjectRef::new(name))
    }

    /// Get a single cached object by name and namespace.
    pub fn get_namespaced<K>(&self, name: &str, namespace: &str) -> Option<Arc<K>>
    where
        K: Resource<DynamicType = ()> + Clone + fmt::Debug + Send + Sync + 'static,
    {
        self.store_for::<K>()?
            .get(&ObjectRef::new(name).within(namespace))
    }

    fn store_for<K>(&self) -> Option<&Store<K>>
    where
        K: Resource<DynamicType = ()> + Clone + fmt::Debug + Send + Sync + 'static,
    {
        self.stores
            .get(&TypeId::of::<K>())
            .and_then(|s| s.as_any().downcast_ref::<TypedStore<K>>())
            .map(|ts| &ts.store)
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for constructing a `ResourceCache`.
pub struct ResourceCacheBuilder {
    stores: HashMap<TypeId, Arc<dyn AnyStore>>,
}

impl ResourceCacheBuilder {
    /// Register a resource type to watch with the default `WatcherConfig`.
    /// Spawns a background watcher.
    pub fn watch<K>(self, api: Api<K>) -> Self
    where
        K: Resource<DynamicType = ()>
            + Clone
            + fmt::Debug
            + Send
            + Sync
            + serde::de::DeserializeOwned
            + 'static,
    {
        self.watch_with(api, WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS))
    }

    /// Register a resource type to watch with a custom `WatcherConfig`.
    /// Spawns a background watcher.
    pub fn watch_with<K>(mut self, api: Api<K>, config: WatcherConfig) -> Self
    where
        K: Resource<DynamicType = ()>
            + Clone
            + fmt::Debug
            + Send
            + Sync
            + serde::de::DeserializeOwned
            + 'static,
    {
        let (reader, writer) = reflector::store();
        let stream = watcher::watcher(api, config);

        let type_name = std::any::type_name::<K>();
        tokio::spawn(async move {
            let mut stream = std::pin::pin!(reflector::reflector(writer, stream)
                .default_backoff()
                .applied_objects());
            while let Some(result) = stream.next().await {
                if let Err(e) = result {
                    tracing::debug!(
                        resource = type_name,
                        error = %e,
                        "Cache watcher error (will reconnect)"
                    );
                }
            }
            tracing::warn!(resource = type_name, "Cache watcher stream ended");
        });

        self.stores
            .insert(TypeId::of::<K>(), Arc::new(TypedStore { store: reader }));
        self
    }

    /// Seed objects into the cache without spawning a watcher.
    ///
    /// Inserts each object via the reflector writer, then stores only the
    /// reader. Useful for tests that need pre-populated caches.
    pub fn seed<K>(mut self, objects: Vec<K>) -> Self
    where
        K: Resource<DynamicType = ()> + Clone + fmt::Debug + Send + Sync + 'static,
    {
        let (reader, mut writer) = reflector::store();
        for obj in objects {
            writer.apply_watcher_event(&watcher::Event::Apply(obj));
        }
        self.stores
            .insert(TypeId::of::<K>(), Arc::new(TypedStore { store: reader }));
        self
    }

    /// Build the cache. All watchers are already running.
    pub fn build(self) -> ResourceCache {
        let type_names: Vec<&str> = self.stores.values().map(|s| s.type_name()).collect();
        tracing::info!(types = ?type_names, "Resource cache ready");
        ResourceCache {
            stores: Arc::new(self.stores),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{ConfigMap, Namespace};
    use kube::api::ObjectMeta;

    fn make_namespace(name: &str) -> Namespace {
        Namespace {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn make_configmap(name: &str, namespace: &str) -> ConfigMap {
        ConfigMap {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn empty_cache_returns_empty() {
        let cache = ResourceCache::empty();
        let result = cache.list::<Namespace>();
        assert!(result.is_empty());
        assert!(cache.get::<Namespace>("test").is_none());
        assert!(cache.get_namespaced::<ConfigMap>("cm", "ns").is_none());
    }

    #[test]
    fn seed_and_list() {
        let cache = ResourceCache::builder()
            .seed(vec![make_namespace("alpha"), make_namespace("beta")])
            .build();

        let namespaces = cache.list::<Namespace>();
        assert_eq!(namespaces.len(), 2);
    }

    #[test]
    fn seed_and_get() {
        let cache = ResourceCache::builder()
            .seed(vec![make_namespace("alpha")])
            .build();

        assert!(cache.get::<Namespace>("alpha").is_some());
        assert!(cache.get::<Namespace>("missing").is_none());
    }

    #[test]
    fn seed_namespaced_and_get() {
        let cache = ResourceCache::builder()
            .seed(vec![
                make_configmap("cm1", "ns-a"),
                make_configmap("cm2", "ns-b"),
            ])
            .build();

        assert!(cache.get_namespaced::<ConfigMap>("cm1", "ns-a").is_some());
        assert!(cache.get_namespaced::<ConfigMap>("cm1", "ns-b").is_none());
    }

    #[test]
    fn list_filtered_returns_matching() {
        let cache = ResourceCache::builder()
            .seed(vec![
                make_configmap("app-config", "prod"),
                make_configmap("db-config", "prod"),
                make_configmap("app-config", "staging"),
            ])
            .build();

        let prod_only = cache.list_filtered::<ConfigMap>(|cm| {
            cm.metadata.namespace.as_deref() == Some("prod")
        });
        assert_eq!(prod_only.len(), 2);

        let app_only = cache.list_filtered::<ConfigMap>(|cm| {
            cm.metadata.name.as_deref() == Some("app-config")
        });
        assert_eq!(app_only.len(), 2);
    }

    #[test]
    fn list_filtered_on_unregistered_type_returns_empty() {
        let cache = ResourceCache::empty();
        let result = cache.list_filtered::<Namespace>(|_| true);
        assert!(result.is_empty());
    }
}
