//! Entitlement sources: what a task's root principal may touch, and the
//! records rules look up to check it.
//!
//! A policy names its source:
//!
//! ```yaml
//! entitlements:
//!   source: file
//!   path: entitlements.yaml     # relative to the policy file
//! ```
//!
//! The source answers two questions:
//! - **Who is the root?** `principals.<id>` becomes `writ.root.*` for a task
//!   started with `writ run --principal <id>`.
//! - **What is this record?** A rule's `lookup:` binds a name to
//!   `tables.<table>.<key>`, so conditions can say `charge.customer`.
//!
//! In this build the only source is a file (a mock). A real one (Stripe
//! customer ownership, a CRM, IdP groups) implements [`EntitlementSource`].

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::PolicyError;

/// Answers entitlement questions for a task. Implementations must be
/// deterministic for the life of a task: decisions are recorded with the
/// source's hash, so `writ replay` can reproduce them.
pub trait EntitlementSource: fmt::Debug + Send + Sync {
    /// The attributes of `principal` (`writ.root.<name>`), or `None` if the
    /// source doesn't know the principal. An unknown principal is entitled
    /// to nothing.
    fn root_attributes(&self, principal: &str) -> Option<Map<String, Value>>;
    /// The record `key` in `table`, or `None` if there is none.
    fn lookup(&self, table: &str, key: &str) -> Option<Value>;
    /// True when `table` exists, so a policy referring to a missing table is
    /// an error when the task starts rather than a denial on every call.
    fn has_table(&self, table: &str) -> bool;
}

/// `source: file`: a YAML file with `principals` and `tables`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileSource {
    #[serde(default)]
    principals: BTreeMap<String, Map<String, Value>>,
    #[serde(default)]
    tables: BTreeMap<String, BTreeMap<String, Value>>,
}

/// Attribute names `writ.root` already uses for itself.
const RESERVED_ROOT_FIELDS: &[&str] = &["principal", "verified"];

impl FileSource {
    pub fn from_yaml_str(text: &str) -> Result<Self, PolicyError> {
        let source: FileSource =
            serde_norway::from_str(text).map_err(|e| PolicyError::Invalid(format!("entitlement source: {e}")))?;
        for (principal, attributes) in &source.principals {
            if let Some(field) = RESERVED_ROOT_FIELDS.iter().find(|f| attributes.contains_key(**f)) {
                return Err(PolicyError::Invalid(format!(
                    "entitlement source: principal `{principal}` sets `{field}`, which writ sets itself"
                )));
            }
        }
        Ok(source)
    }
}

impl EntitlementSource for FileSource {
    fn root_attributes(&self, principal: &str) -> Option<Map<String, Value>> {
        self.principals.get(principal).cloned()
    }

    fn lookup(&self, table: &str, key: &str) -> Option<Value> {
        self.tables.get(table)?.get(key).cloned()
    }

    fn has_table(&self, table: &str) -> bool {
        self.tables.contains_key(table)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SOURCE: &str = r#"
principals:
  alice@example.com:
    entitled_customers: [cus_alice]
tables:
  charges:
    ch_1: { customer: cus_alice, amount: 40.00 }
"#;

    #[test]
    fn answers_roots_and_lookups() {
        let s = FileSource::from_yaml_str(SOURCE).unwrap();
        assert_eq!(
            s.root_attributes("alice@example.com").unwrap()["entitled_customers"],
            json!(["cus_alice"])
        );
        assert!(s.root_attributes("mallory").is_none());
        assert_eq!(s.lookup("charges", "ch_1").unwrap()["customer"], "cus_alice");
        assert!(s.lookup("charges", "ch_2").is_none());
        assert!(s.lookup("refunds", "ch_1").is_none());
        assert!(s.has_table("charges") && !s.has_table("refunds"));
    }

    #[test]
    fn rejects_bad_sources() {
        assert!(FileSource::from_yaml_str("principal: {}\n").is_err(), "typo");
        assert!(FileSource::from_yaml_str("principals:\n  a:\n    verified: true\n").is_err());
        assert!(FileSource::from_yaml_str("principals:\n  a:\n    principal: b\n").is_err());
    }
}
