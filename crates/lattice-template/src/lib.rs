//! Template expansion for Lattice
//!
//! Walks `serde_json::Value` trees and expands two kinds of template expressions:
//!
//! - **`${dotted.path}`** — resolved from a `TemplateContext` (flat map of paths to values)
//! - **`${secret.RESOURCE.KEY}`** — secret references, handled per `SecretMode`
//! - **`$secret` directives** — objects in the tree replaced with K8s Secret names
//! - **`$${...}`** — escape syntax, produces literal `${...}`
//!
//! No Jinja2, no regex, no YAML parsing. Input is already `serde_json::Value`.

mod context;
mod directive;
mod error;
mod expand;
mod inline;
pub use context::{TemplateContext, TemplateContextBuilder};
pub use directive::{DirectiveKeyMapping, SecretDirective};
pub use error::TemplateError;
pub use expand::{expand, ExpandOptions, Expansion, SecretMode};
pub use inline::InlineSecretRef;
pub use lattice_core::template_types::{
    has_template_syntax, StaticString, StaticStringError, TemplateString,
};
