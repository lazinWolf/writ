//! Tool-name patterns. `*` matches any run of characters (including `.`);
//! every other character matches itself.

pub fn matches(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    let (mut pi, mut ni) = (0, 0);
    // Position of the last `*` seen, and the name index it was matched against.
    let mut backtrack: Option<(usize, usize)> = None;

    while ni < n.len() {
        if pi < p.len() && p[pi] == '*' {
            backtrack = Some((pi, ni));
            pi += 1;
        } else if pi < p.len() && p[pi] == n[ni] {
            pi += 1;
            ni += 1;
        } else if let Some((star, matched)) = backtrack {
            // Let the last `*` absorb one more character and retry.
            pi = star + 1;
            ni = matched + 1;
            backtrack = Some((star, matched + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn literal_and_wildcards() {
        assert!(matches("stripe.refund", "stripe.refund"));
        assert!(!matches("stripe.refund", "stripe.refunds"));
        assert!(matches("postgres.*", "postgres.query"));
        assert!(matches("postgres.*", "postgres."));
        assert!(!matches("postgres.*", "postgresql.query"));
        assert!(matches("*", ""));
        assert!(matches("*", "anything.at.all"));
        assert!(matches("*_delete", "row_delete"));
        assert!(matches("a*b*c", "a-x-b-y-c"));
        assert!(!matches("a*b*c", "a-x-c-y-b"));
    }
}
