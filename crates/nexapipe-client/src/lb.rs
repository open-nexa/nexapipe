use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadBalancingStrategy {
    RoundRobin,
    Random,
}

pub struct RoundRobinBalancer {
    index: AtomicUsize,
}

impl Default for RoundRobinBalancer {
    fn default() -> Self {
        Self::new()
    }
}

impl RoundRobinBalancer {
    pub fn new() -> Self {
        Self {
            index: AtomicUsize::new(0),
        }
    }

    /// The next backend that is not known to be down, or `None` when every one
    /// is.
    ///
    /// One step per candidate at most, and the counter keeps moving even when
    /// every index it lands on is skipped: a caller that comes back after a
    /// failure has to be able to reach a backend that answers, and a rotation
    /// that stopped on a dead index would hand out the same dead connection
    /// however many times it was asked.
    pub fn select(&self, candidates: &[bool]) -> Option<usize> {
        let count = candidates.len();
        if count == 0 {
            return None;
        }
        for _ in 0..count {
            let current = self.index.fetch_add(1, Ordering::Relaxed);
            let index = current % count;
            if candidates[index] {
                return Some(index);
            }
        }
        None
    }
}

pub struct RandomBalancer;

impl Default for RandomBalancer {
    fn default() -> Self {
        Self::new()
    }
}

impl RandomBalancer {
    pub fn new() -> Self {
        Self
    }

    /// One of the backends that is not known to be down, or `None` when every
    /// one is.
    ///
    /// Counting the usable ones and walking to the nth, rather than picking an
    /// index and scanning forward: scanning forward gives a backend a share
    /// proportional to the size of the gap in front of it, so one dead backend
    /// would quietly double the traffic of the one behind it.
    pub fn select(&self, candidates: &[bool]) -> Option<usize> {
        let usable = candidates.iter().filter(|candidate| **candidate).count();
        if usable == 0 {
            return None;
        }
        let nth = fastrand::usize(0..usable);
        candidates
            .iter()
            .enumerate()
            .filter(|(_, candidate)| **candidate)
            .nth(nth)
            .map(|(index, _)| index)
    }
}

/// Chooses which of a domain's backends serves the next request.
///
/// `candidates` is one flag per backend: true where nothing has said the
/// backend is down. `None` means every one of them is, and what that is worth
/// is the caller's decision rather than the balancer's — see
/// [`crate::endpoint_group::DomainPools::get_connection`].
pub trait LoadBalancer {
    fn select(&self, candidates: &[bool]) -> Option<usize>;
}

impl LoadBalancer for RoundRobinBalancer {
    fn select(&self, candidates: &[bool]) -> Option<usize> {
        self.select(candidates)
    }
}

impl LoadBalancer for RandomBalancer {
    fn select(&self, candidates: &[bool]) -> Option<usize> {
        self.select(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The point of the whole exercise: a backend the probe found dead does not
    /// get another request until it answers again.
    #[test]
    fn the_rotation_skips_a_backend_that_is_down() {
        let balancer = RoundRobinBalancer::new();
        let candidates = [true, false, true];

        let chosen: Vec<usize> = (0..4)
            .map(|_| balancer.select(&candidates).expect("two backends are up"))
            .collect();

        assert!(chosen.iter().all(|index| candidates[*index]), "{chosen:?}");
        // Skipping must not mean sticking: both healthy backends still serve.
        assert!(chosen.contains(&0) && chosen.contains(&2), "{chosen:?}");
    }

    #[test]
    fn every_backend_down_is_none_not_the_first_one() {
        let candidates = [false, false];
        assert_eq!(RoundRobinBalancer::new().select(&candidates), None);
        assert_eq!(RandomBalancer::new().select(&candidates), None);
        assert_eq!(RoundRobinBalancer::new().select(&[]), None);
        assert_eq!(RandomBalancer::new().select(&[]), None);
    }

    /// A random choice that scans forward from a random index would favour the
    /// backend behind a dead one; every usable backend has to stay equally
    /// likely.
    #[test]
    fn the_random_choice_only_ever_returns_a_usable_index() {
        let balancer = RandomBalancer::new();
        let candidates = [true, false, false, true];

        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let index = balancer.select(&candidates).expect("two backends are up");
            assert!(candidates[index], "picked a backend that is down");
            seen.insert(index);
        }

        assert_eq!(
            seen.len(),
            2,
            "both healthy backends must be reachable: {seen:?}"
        );
    }
}
