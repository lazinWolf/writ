//! Writs: signed task tokens.
//!
//! `writ run` gets a token from writd when it creates a task and passes it to
//! the agent as `WRIT_TOKEN`. Every `writ wrap` the agent starts presents it
//! to join the task. The token is a [Biscuit]: writd signs its first block
//! with a key that exists only in writd's memory, so nothing else can mint
//! one, and a writd restart (which ends every task anyway) invalidates them
//! all.
//!
//! The first block (the *authority*) names the task, its namespace, the
//! hash of the policy it was created with, the root principal (if any), and
//! an expiry. writd trusts only this block for who the token is for.
//!
//! Anyone holding a token can append a block without asking writd: that is
//! `writ fork`. A fork block may carry a narrowing policy, a label for the
//! lineage, and an earlier expiry. Biscuit guarantees blocks can be added
//! but never removed or changed, and writd only ever uses fork blocks to
//! restrict (their policies are intersected with the task's, most
//! restrictive outcome wins), so it doesn't matter who wrote them.
//!
//! What this does and doesn't buy, in cooperative mode: task ids (shown by
//! `writ ps`, written to the log) no longer carry authority, a child given a
//! forked token can't recover its parent's, and wrapped servers never see
//! the token. A process running as the same user can still read another's
//! environment (`/proc/<pid>/environ`), so this isn't a boundary against
//! same-user code; that needs mediated mode (plan-v2.md §5.2).
//!
//! [Biscuit]: https://www.biscuitsec.org

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use biscuit_auth::builder::{self, Term};
use biscuit_auth::{AuthorizerBuilder, AuthorizerLimits, Biscuit, BlockBuilder, KeyPair, UnverifiedBiscuit};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Environment variable carrying the agent's writ token.
pub const TOKEN_ENV: &str = "WRIT_TOKEN";

/// How long a task's token is valid unless `writ run --ttl` says otherwise.
pub const DEFAULT_TTL: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("not a writ token: {0}")]
    Malformed(String),
    #[error("the writ token is not signed by this writd (it may predate a writd restart): {0}")]
    Signature(String),
    #[error("the writ token was refused: {0}")]
    Refused(String),
}

/// What the authority block says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Claims {
    pub task: String,
    pub namespace: String,
    pub policy_sha256: String,
    pub principal: Option<String>,
    /// Unix seconds.
    pub expires: u64,
}

/// One `writ fork` block, as written by whoever forked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Fork {
    /// The block's revocation id, hex: unique to this fork, and shared by
    /// every token forked from it.
    pub id: String,
    pub label: Option<String>,
    /// Narrowing policies' YAML text (`writ fork` writes at most one).
    #[serde(skip)]
    pub policies: Vec<String>,
    /// Unix seconds, if the fork set an earlier expiry.
    pub expires: Option<u64>,
}

/// A token writd has checked: its signature, every block's checks
/// (including expiry), and the authority block's claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub claims: Claims,
    /// Fork blocks, oldest first. `forks.len()` is the token's depth.
    pub forks: Vec<Fork>,
    /// The earliest expiry of any block, Unix seconds.
    pub expires: u64,
    /// Identifies this exact token in the log without revealing it.
    pub fingerprint: String,
}

/// What a `writ fork` block adds.
#[derive(Debug, Clone, Default)]
pub struct ForkSpec<'a> {
    pub label: Option<&'a str>,
    pub policy: Option<&'a str>,
    pub ttl: Option<Duration>,
}

/// Mints and verifies tokens with a key generated when writd starts.
pub struct Issuer {
    keys: KeyPair,
}

impl Default for Issuer {
    fn default() -> Self {
        Issuer { keys: KeyPair::new() }
    }
}

impl Issuer {
    pub fn mint(&self, claims: &Claims) -> Result<String, TokenError> {
        let mut params = HashMap::new();
        params.insert("task".to_string(), builder::string(&claims.task));
        params.insert("namespace".to_string(), builder::string(&claims.namespace));
        params.insert("policy".to_string(), builder::string(&claims.policy_sha256));
        params.insert("expires".to_string(), date(claims.expires));
        let mut block = Biscuit::builder()
            .code_with_params(
                r#"
                writ_task({task});
                writ_namespace({namespace});
                writ_policy({policy});
                writ_expires({expires});
                check if time($t), $t <= {expires};
                "#,
                params,
                HashMap::new(),
            )
            .map_err(internal)?;
        if let Some(principal) = &claims.principal {
            block = block
                .fact(builder::fact("writ_principal", &[builder::string(principal)]))
                .map_err(internal)?;
        }
        block.build(&self.keys).map_err(internal)?.to_base64().map_err(internal)
    }

    pub fn verify(&self, token: &str) -> Result<Verified, TokenError> {
        let token = token.trim();
        let parsed = UnverifiedBiscuit::from_base64(token).map_err(|e| TokenError::Malformed(e.to_string()))?;
        let biscuit = parsed
            .clone()
            .verify(self.keys.public())
            .map_err(|e| TokenError::Signature(e.to_string()))?;

        let mut authorizer = AuthorizerBuilder::new()
            // Biscuit's default budget is 1ms, which a loaded machine (or a debug
            // build) can miss. Still bounded: a fork block's Datalog is the forker's.
            .set_limits(AuthorizerLimits {
                max_time: Duration::from_millis(250),
                ..AuthorizerLimits::default()
            })
            .time()
            .code("allow if true;")
            .map_err(internal)?
            .build(&biscuit)
            .map_err(refused)?;
        // Runs every block's checks, expiry included.
        authorizer.authorize().map_err(refused)?;

        // `query` sees only the authority block (and the authorizer): forks can't
        // claim another task or principal.
        let one = |authorizer: &mut biscuit_auth::Authorizer, rule: &str| -> Result<String, TokenError> {
            let mut found: Vec<(String,)> = authorizer.query(rule).map_err(refused)?;
            match found.len() {
                1 => Ok(found.remove(0).0),
                n => Err(TokenError::Refused(format!("expected one `{rule}`, found {n}"))),
            }
        };
        let task = one(&mut authorizer, "r($x) <- writ_task($x)")?;
        let namespace = one(&mut authorizer, "r($x) <- writ_namespace($x)")?;
        let policy_sha256 = one(&mut authorizer, "r($x) <- writ_policy($x)")?;
        let principals: Vec<(String,)> = authorizer.query("r($x) <- writ_principal($x)").map_err(refused)?;
        if principals.len() > 1 {
            return Err(TokenError::Refused("more than one principal".into()));
        }
        let root_expiry: Vec<(SystemTime,)> = authorizer.query("r($x) <- writ_expires($x)").map_err(refused)?;
        let [(root_expiry,)] = root_expiry[..] else {
            return Err(TokenError::Refused("no expiry".into()));
        };
        let claims = Claims {
            task,
            namespace,
            policy_sha256,
            principal: principals.into_iter().next().map(|p| p.0),
            expires: unix(root_expiry),
        };

        let forks = read_forks(&mut authorizer, &biscuit.revocation_identifiers())?;
        let expires = forks.iter().filter_map(|f| f.expires).fold(claims.expires, u64::min);
        Ok(Verified {
            claims,
            forks,
            expires,
            fingerprint: fingerprint(token),
        })
    }
}

/// Appends a fork block. Needs no key and no writd: any holder can narrow
/// a token, and nobody can widen one.
pub fn fork(token: &str, spec: &ForkSpec) -> Result<String, TokenError> {
    let parsed = UnverifiedBiscuit::from_base64(token.trim()).map_err(|e| TokenError::Malformed(e.to_string()))?;
    let depth = parsed.block_count() as i64;
    let mut block = BlockBuilder::new()
        .fact(builder::fact(
            "writ_fork",
            &[
                builder::int(depth),
                builder::string(spec.label.unwrap_or("")),
                // Bytes, not a string: policy text is arbitrary.
                builder::bytes(spec.policy.unwrap_or("").as_bytes()),
            ],
        ))
        .map_err(internal)?;
    if let Some(ttl) = spec.ttl {
        let expires = now().saturating_add(ttl.as_secs());
        let mut params = HashMap::new();
        params.insert("depth".to_string(), builder::int(depth));
        params.insert("expires".to_string(), date(expires));
        block = block
            .code_with_params(
                "writ_fork_expires({depth}, {expires}); check if time($t), $t <= {expires};",
                params,
                HashMap::new(),
            )
            .map_err(internal)?;
    }
    parsed.append(block).map_err(internal)?.to_base64().map_err(internal)
}

/// Fork blocks' facts. Only the authority block is signed by writd; these
/// are each forker's say-so, which is fine: they can only narrow. A block may
/// even write facts claiming another block's depth: that adds narrowing to
/// that fork, never removes any.
fn read_forks(authorizer: &mut biscuit_auth::Authorizer, ids: &[Vec<u8>]) -> Result<Vec<Fork>, TokenError> {
    // `query_all` sees every block's facts, unlike `query`.
    let rows: Vec<(i64, String, Vec<u8>)> = authorizer
        .query_all("r($d, $l, $p) <- writ_fork($d, $l, $p)")
        .map_err(refused)?;
    let expiries: Vec<(i64, SystemTime)> = authorizer
        .query_all("r($d, $e) <- writ_fork_expires($d, $e)")
        .map_err(refused)?;
    let depth = ids.len().saturating_sub(1) as i64;
    if let Some((d, _, _)) = rows.iter().find(|(d, _, _)| !(1..=depth).contains(d)) {
        return Err(TokenError::Refused(format!(
            "a fork block claims depth {d} in a token {depth} deep"
        )));
    }
    let mut forks = Vec::new();
    for d in 1..=depth {
        let mine: Vec<_> = rows.iter().filter(|(rd, _, _)| *rd == d).collect();
        if mine.is_empty() {
            return Err(TokenError::Refused(format!("fork block {d} has no writ_fork fact")));
        }
        let mut policies = Vec::new();
        for (_, _, policy) in &mine {
            if !policy.is_empty() {
                let text = String::from_utf8(policy.clone())
                    .map_err(|_| TokenError::Refused(format!("fork block {d}'s policy is not UTF-8")))?;
                policies.push(text);
            }
        }
        forks.push(Fork {
            id: hex(&ids[d as usize]),
            label: mine.iter().map(|(_, l, _)| l).find(|l| !l.is_empty()).cloned(),
            policies,
            expires: expiries.iter().filter(|(ed, _)| *ed == d).map(|(_, e)| unix(*e)).min(),
        });
    }
    Ok(forks)
}

/// `sha256:` plus the first 16 hex digits of the token's hash.
pub fn fingerprint(token: &str) -> String {
    format!("sha256:{}", hex(&Sha256::digest(token.trim().as_bytes())[..8]))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn date(unix_secs: u64) -> Term {
    builder::date(&(UNIX_EPOCH + Duration::from_secs(unix_secs)))
}

fn unix(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn internal(e: impl std::fmt::Display) -> TokenError {
    TokenError::Malformed(e.to_string())
}

fn refused(e: impl std::fmt::Debug) -> TokenError {
    TokenError::Refused(format!("{e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(expires: u64) -> Claims {
        Claims {
            task: "tsk_1".into(),
            namespace: "ns".into(),
            policy_sha256: "abc".into(),
            principal: Some("alice@example.com".into()),
            expires,
        }
    }

    #[test]
    fn round_trips_claims() {
        let issuer = Issuer::default();
        let token = issuer.mint(&claims(now() + 60)).unwrap();
        let v = issuer.verify(&token).unwrap();
        assert_eq!(v.claims, claims(now() + 60).clone_with_expires(v.claims.expires));
        assert!(v.forks.is_empty());
        assert_eq!(v.fingerprint, fingerprint(&token));
    }

    impl Claims {
        fn clone_with_expires(mut self, expires: u64) -> Self {
            self.expires = expires;
            self
        }
    }

    #[test]
    fn another_writd_or_a_bare_id_is_refused() {
        let token = Issuer::default().mint(&claims(now() + 60)).unwrap();
        assert!(matches!(
            Issuer::default().verify(&token),
            Err(TokenError::Signature(_))
        ));
        assert!(matches!(
            Issuer::default().verify("tsk_0123"),
            Err(TokenError::Malformed(_))
        ));
    }

    #[test]
    fn expired_tokens_are_refused() {
        let issuer = Issuer::default();
        let token = issuer.mint(&claims(now() - 1)).unwrap();
        assert!(matches!(issuer.verify(&token), Err(TokenError::Refused(_))));
    }

    #[test]
    fn forks_narrow_and_shorten_but_cannot_rename() {
        let issuer = Issuer::default();
        let root = issuer.mint(&claims(now() + 3600)).unwrap();
        let child = fork(
            &root,
            &ForkSpec {
                label: Some("billing"),
                policy: Some("version: 1\nnamespace: ns\ncapabilities: []\n"),
                ttl: Some(Duration::from_secs(60)),
            },
        )
        .unwrap();
        let grandchild = fork(&child, &ForkSpec::default()).unwrap();
        let v = issuer.verify(&grandchild).unwrap();
        assert_eq!(v.claims.task, "tsk_1");
        assert_eq!(v.forks.len(), 2);
        assert_eq!(v.forks[0].label.as_deref(), Some("billing"));
        assert!(v.forks[0].policies[0].contains("capabilities"));
        assert!(v.expires <= now() + 60 && v.expires < v.claims.expires);
        assert_eq!(
            (&v.forks[1].label, v.forks[1].policies.len(), v.forks[1].expires),
            (&None, 0, None)
        );
        assert_ne!(v.forks[0].id, v.forks[1].id);
        // A sibling forked from the same parent shares the parent's fork id.
        let sibling = issuer.verify(&fork(&child, &ForkSpec::default()).unwrap()).unwrap();
        assert_eq!(sibling.forks[0].id, v.forks[0].id);
        assert_ne!(sibling.forks[1].id, v.forks[1].id);

        // A fork claiming another task is ignored: only the authority block names it.
        let parsed = UnverifiedBiscuit::from_base64(&root).unwrap();
        let sneaky = parsed
            .append(
                BlockBuilder::new()
                    .code(r#"writ_task("tsk_other"); writ_principal("mallory"); writ_fork(1, "", hex:00);"#)
                    .unwrap(),
            )
            .unwrap()
            .to_base64()
            .unwrap();
        let v = issuer.verify(&sneaky).unwrap();
        assert_eq!(v.claims.task, "tsk_1");
        assert_eq!(v.claims.principal.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn an_expired_fork_is_refused_and_a_fork_without_its_fact_too() {
        let issuer = Issuer::default();
        let root = issuer.mint(&claims(now() + 3600)).unwrap();
        let expired = fork(
            &root,
            &ForkSpec {
                ttl: Some(Duration::ZERO),
                ..Default::default()
            },
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(1100));
        assert!(matches!(issuer.verify(&expired), Err(TokenError::Refused(_))));

        let bare = UnverifiedBiscuit::from_base64(&root)
            .unwrap()
            .append(BlockBuilder::new())
            .unwrap()
            .to_base64()
            .unwrap();
        assert!(matches!(issuer.verify(&bare), Err(TokenError::Refused(_))));
    }
}
