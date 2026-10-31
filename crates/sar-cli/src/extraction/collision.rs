// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Bounded ledger of which SAR logical path owns which destination object.
//!
//! Two distinct Full Logical Entry Paths collide when they identify the same
//! destination filesystem object (specification Section 22.4). Whether they do
//! is a property of the destination filesystem (case folding, Unicode
//! normalization, aliases, ...), so this module never folds or normalizes names
//! itself. Instead the extraction backends report the identity of the object
//! each logical path actually reached (a device/inode pair on Unix) and the
//! ledger records which logical path claimed it first. A later, different
//! logical path reaching an already claimed object is a collision.
//!
//! Logical paths are kept as an exact-bytes component tree, so the original
//! SAR spelling is preserved and compared exactly. Repeating the identical
//! logical path maps to the same tree node and is never a collision.

use std::collections::HashMap;

use sar_core::{ResourceLimits, SarError};

pub(crate) type NodeId = usize;

/// Node of the logical-path tree that represents the extraction root.
pub(crate) const ROOT_NODE: NodeId = 0;

/// Fixed bookkeeping cost charged per logical node and per claimed object, on
/// top of the component bytes, so the ledger stays inside the pipeline memory
/// budget regardless of how many tiny components an archive declares.
const ENTRY_OVERHEAD_BYTES: u64 = 128;

/// Identity of a destination filesystem object as reported by the host.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum ObjectId {
    #[cfg(unix)]
    Inode { device: u64, inode: u64 },
    /// Canonical on-disk path; the only identity the non-Unix fallback
    /// backend can obtain without platform-specific APIs.
    #[cfg(not(unix))]
    CanonicalPath(std::path::PathBuf),
}

impl ObjectId {
    pub(crate) fn accounted_bytes(&self) -> u64 {
        match self {
            #[cfg(unix)]
            Self::Inode { .. } => ENTRY_OVERHEAD_BYTES,
            #[cfg(not(unix))]
            Self::CanonicalPath(path) => {
                ENTRY_OVERHEAD_BYTES.saturating_add(path.as_os_str().len() as u64)
            }
        }
    }
}

pub(crate) struct CollisionLedger {
    limits: ResourceLimits,
    used_bytes: u64,
    next_node: NodeId,
    children: HashMap<(NodeId, String), NodeId>,
    owners: HashMap<ObjectId, NodeId>,
    current: HashMap<NodeId, ObjectId>,
}

impl CollisionLedger {
    pub(crate) fn new(limits: ResourceLimits) -> Self {
        Self {
            limits,
            used_bytes: 0,
            next_node: ROOT_NODE + 1,
            children: HashMap::new(),
            owners: HashMap::new(),
            current: HashMap::new(),
        }
    }

    /// Bookkeeping bytes currently charged against the pipeline memory budget.
    #[cfg(test)]
    pub(crate) fn used_bytes(&self) -> u64 {
        self.used_bytes
    }

    fn charge(&mut self, bytes: u64) -> Result<(), SarError> {
        let total = self
            .used_bytes
            .checked_add(bytes)
            .ok_or(SarError::Overflow("collision ledger byte count"))?;
        self.limits.check_total_pipeline_memory(total)?;
        self.used_bytes = total;
        Ok(())
    }

    fn refund(&mut self, bytes: u64) {
        self.used_bytes = self.used_bytes.saturating_sub(bytes);
    }

    /// Returns the node for `component` below `parent`, interning it exactly
    /// as spelled. Interning is charged before anything is stored.
    pub(crate) fn child(&mut self, parent: NodeId, component: &str) -> Result<NodeId, SarError> {
        if let Some(node) = self.children.get(&(parent, component.to_string())) {
            return Ok(*node);
        }
        let component_bytes =
            u64::try_from(component.len()).map_err(|_| SarError::Overflow("component length"))?;
        self.charge(ENTRY_OVERHEAD_BYTES.saturating_add(component_bytes))?;
        let node = self.next_node;
        self.next_node = node
            .checked_add(1)
            .ok_or(SarError::Overflow("collision ledger node count"))?;
        self.children.insert((parent, component.to_string()), node);
        Ok(node)
    }

    /// `check` for a logical path that may not be interned yet, so a collision
    /// is reported before any capacity is charged for the new path.
    pub(crate) fn check_candidate(
        &self,
        parent: NodeId,
        component: &str,
        id: &ObjectId,
    ) -> Result<(), SarError> {
        let node = self.children.get(&(parent, component.to_string())).copied();
        match self.owners.get(id) {
            Some(owner) if Some(*owner) != node => Err(SarError::PathCollision(
                "distinct archive paths map to the same destination filesystem object",
            )),
            _ => Ok(()),
        }
    }

    /// Fails with `PathCollision` when `id` is already owned by a different
    /// logical path. An unclaimed object, including any pre-existing one, is
    /// never evidence of a collision.
    pub(crate) fn check(&self, node: NodeId, id: &ObjectId) -> Result<(), SarError> {
        match self.owners.get(id) {
            Some(owner) if *owner != node => Err(SarError::PathCollision(
                "distinct archive paths map to the same destination filesystem object",
            )),
            _ => Ok(()),
        }
    }

    /// Checks `id` against other owners and reserves the bookkeeping bytes
    /// needed to record it for `node`, before the publishing mutation. Replacing
    /// the node's own previous claim only needs the net growth, so replacement
    /// is never rejected at an exact limit boundary. The reservation must be
    /// passed to `commit` after publication or to `release` if it fails.
    #[must_use = "a reservation must be committed or released"]
    pub(crate) fn reserve(&mut self, node: NodeId, id: &ObjectId) -> Result<Reservation, SarError> {
        self.check(node, id)?;
        let previous = match self.current.get(&node) {
            Some(existing) if existing == id => 0,
            Some(existing) => existing.accounted_bytes(),
            None => 0,
        };
        let charged = if self.current.get(&node) == Some(id) {
            0
        } else {
            id.accounted_bytes().saturating_sub(previous)
        };
        self.charge(charged)?;
        Ok(Reservation { charged })
    }

    /// Gives back a reservation whose publication did not happen.
    pub(crate) fn release(&mut self, reservation: Reservation) {
        self.refund(reservation.charged);
    }

    /// Records that `node` now owns `id` after successful publication. It
    /// cannot fail and allocates no budgeted capacity beyond the reservation.
    /// A repeated logical path replaces the identity it previously owned, so
    /// recycled inode numbers cannot produce stale matches.
    pub(crate) fn commit(&mut self, node: NodeId, id: ObjectId, reservation: Reservation) {
        let new_bytes = id.accounted_bytes();
        if self.current.get(&node) == Some(&id) {
            return;
        }
        let mut previous_bytes = 0;
        if let Some(previous) = self.current.insert(node, id.clone()) {
            self.owners.remove(&previous);
            previous_bytes = previous.accounted_bytes();
        }
        // The reservation covered the net growth; give back whatever the
        // actual replacement turned out not to need.
        let needed = new_bytes.saturating_sub(previous_bytes);
        self.refund(reservation.charged.saturating_sub(needed));
        self.refund(previous_bytes.saturating_sub(new_bytes));
        self.owners.insert(id, node);
    }

    /// Reserves and commits in one step for directory claims, which have no
    /// publication mutation in between.
    pub(crate) fn claim(&mut self, node: NodeId, id: ObjectId) -> Result<(), SarError> {
        let reservation = self.reserve(node, &id)?;
        self.commit(node, id, reservation);
        Ok(())
    }
}

/// Bookkeeping bytes already charged for an identity that is about to be
/// recorded.
#[derive(Debug)]
pub(crate) struct Reservation {
    charged: u64,
}

#[cfg(all(test, unix))]
mod tests {
    use sar_core::{ResourceLimits, SarError, SarStatus};

    use super::{CollisionLedger, ObjectId, ROOT_NODE};

    fn id(inode: u64) -> ObjectId {
        ObjectId::Inode { device: 1, inode }
    }

    fn path(ledger: &mut CollisionLedger, components: &[&str]) -> usize {
        components.iter().fold(ROOT_NODE, |node, component| {
            ledger.child(node, component).expect("child")
        })
    }

    #[test]
    fn same_object_under_distinct_spellings_is_a_collision() {
        let mut ledger = CollisionLedger::new(ResourceLimits::default());
        let upper = path(&mut ledger, &["Dir"]);
        let lower = path(&mut ledger, &["dir"]);
        assert_ne!(upper, lower, "spellings are never folded");
        ledger.claim(upper, id(7)).expect("first claim");
        let err = ledger.claim(lower, id(7)).expect_err("collision");
        assert_eq!(err.status(), SarStatus::ErrPathCollision);
    }

    #[test]
    fn nested_components_collide_through_a_shared_directory_identity() {
        let mut ledger = CollisionLedger::new(ResourceLimits::default());
        let first = path(&mut ledger, &["Dir"]);
        ledger.claim(first, id(3)).expect("claim");
        let second = path(&mut ledger, &["dir"]);
        assert!(matches!(
            ledger.check(second, &id(3)),
            Err(SarError::PathCollision(_))
        ));
        // A different identity below the colliding spelling never matches.
        let nested = path(&mut ledger, &["dir", "f"]);
        ledger.check(nested, &id(4)).expect("distinct object");
    }

    #[test]
    fn repeated_logical_path_and_unclaimed_objects_are_not_collisions() {
        let mut ledger = CollisionLedger::new(ResourceLimits::default());
        let node = path(&mut ledger, &["a", "b"]);
        assert_eq!(node, path(&mut ledger, &["a", "b"]));
        ledger.claim(node, id(1)).expect("claim");
        ledger.claim(node, id(1)).expect("same identity again");
        ledger.check(node, &id(99)).expect("unclaimed object");
    }

    #[test]
    fn replacement_releases_the_previous_identity() {
        let mut ledger = CollisionLedger::new(ResourceLimits::default());
        let a = path(&mut ledger, &["a"]);
        let b = path(&mut ledger, &["b"]);
        ledger.claim(a, id(5)).expect("claim");
        ledger.claim(a, id(6)).expect("replaced by repeated path");
        let before = ledger.used_bytes();
        // Inode 5 was freed by the replacement and may be reused by another path.
        ledger.claim(b, id(5)).expect("recycled inode");
        assert!(ledger.check(a, &id(6)).is_ok());
        assert!(ledger.check(b, &id(6)).is_err());
        assert_eq!(ledger.used_bytes(), before + super::ENTRY_OVERHEAD_BYTES);
    }

    #[test]
    fn bookkeeping_is_bounded_by_the_pipeline_memory_limit() {
        let limits = ResourceLimits {
            max_total_pipeline_memory: 1024,
            ..ResourceLimits::default()
        };
        let mut ledger = CollisionLedger::new(limits);
        let mut failure = None;
        for index in 0..64u64 {
            match ledger.child(ROOT_NODE, &format!("name-{index}")) {
                Ok(_) => {}
                Err(err) => {
                    failure = Some(err);
                    break;
                }
            }
        }
        let err = failure.expect("limit reached before 64 nodes");
        assert!(matches!(err, SarError::LimitExceeded(_)), "{err:?}");
        assert!(ledger.used_bytes() <= 1024);
    }

    #[test]
    fn reservation_is_exact_released_on_failure_and_never_fails_on_commit() {
        let probe = |limit| {
            CollisionLedger::new(ResourceLimits {
                max_total_pipeline_memory: limit,
                ..ResourceLimits::default()
            })
        };
        let need = 128 + 1 + 128; // node + one-byte component + claimed object
        let mut exact = probe(need);
        let node = exact.child(ROOT_NODE, "a").expect("node");
        let reservation = exact.reserve(node, &id(1)).expect("exact fit");
        exact.commit(node, id(1), reservation);
        assert_eq!(exact.used_bytes(), need);

        let mut short = probe(need - 1);
        let node = short.child(ROOT_NODE, "a").expect("node");
        let before = short.used_bytes();
        assert!(matches!(
            short.reserve(node, &id(1)),
            Err(SarError::LimitExceeded(_))
        ));
        assert_eq!(short.used_bytes(), before);

        let mut released = probe(need);
        let node = released.child(ROOT_NODE, "a").expect("node");
        let reservation = released.reserve(node, &id(1)).expect("reserve");
        released.release(reservation);
        assert_eq!(released.used_bytes(), before);
        let again = released.reserve(node, &id(2)).expect("capacity is back");
        released.commit(node, id(2), again);
    }

    #[test]
    fn replacement_at_the_exact_limit_needs_no_extra_capacity() {
        let mut ledger = CollisionLedger::new(ResourceLimits {
            max_total_pipeline_memory: 128 + 1 + 128,
            ..ResourceLimits::default()
        });
        let node = ledger.child(ROOT_NODE, "a").expect("node");
        ledger.claim(node, id(1)).expect("first");
        ledger.claim(node, id(2)).expect("replacement at boundary");
        ledger.claim(node, id(2)).expect("same identity again");
        let other = ledger.child(ROOT_NODE, "b");
        assert!(other.is_err(), "no spare capacity was created");
    }

    #[test]
    fn reserve_reports_collision_before_capacity() {
        let mut ledger = CollisionLedger::new(ResourceLimits {
            max_total_pipeline_memory: 128 + 1 + 128 + 128 + 1,
            ..ResourceLimits::default()
        });
        let a = ledger.child(ROOT_NODE, "a").expect("a");
        let b = ledger.child(ROOT_NODE, "b").expect("b");
        ledger.claim(a, id(1)).expect("claim");
        let err = ledger.reserve(b, &id(1)).expect_err("collision wins");
        assert_eq!(err.status(), SarStatus::ErrPathCollision);
    }
}
