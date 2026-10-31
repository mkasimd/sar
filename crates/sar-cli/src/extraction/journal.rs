// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Run-owned temporary artifacts and the record of destination changes.
//!
//! Every staging file, staging symlink, probe file and moved-aside directory
//! this run creates is registered here together with an open descriptor of its
//! parent directory and the identity (device/inode) it had when created.
//! Cleanup only ever acts on a registered artifact, through that descriptor,
//! and only while the name still reaches the registered identity. A name that
//! merely looks like `.sar-tmp-*` is never evidence of ownership, and nothing
//! scans the destination.
//!
//! Bookkeeping is bounded by `MAX_TRACKED_ARTIFACTS` (live and unresolved
//! artifacts together); the bound is checked before the object is created.
//! Nothing here survives the process: there is no journal on disk, so a crash
//! can leave artifacts behind that no later run recognizes.

use std::cell::{Cell, RefCell};

use rustix::{fd::OwnedFd, fs::AtFlags, io::Errno};
use sar_core::SarError;

use super::{
    io_error, object_id,
    replace::{self, DoomedDirectory},
};
use crate::extraction::{
    collision::{CollisionLedger, ObjectId},
    report::ExtractionReport,
};

/// Most run-owned artifacts tracked at once. An ordinary run holds at most a
/// staging object plus one moved-aside directory; the rest is slack for
/// artifacts a failed cleanup had to leave behind.
pub(super) const MAX_TRACKED_ARTIFACTS: usize = 8;

/// Reserved parent descriptor for an artifact about to be created, obtained
/// (and the capacity bound checked) before any filesystem mutation.
pub(super) struct Slot {
    dir: OwnedFd,
    location: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct Token(u64);

enum Kind {
    /// Staging file, staging symlink or probe file: removed by identity.
    Object,
    /// A run-created directory renamed aside to `name`, formerly `final_name`.
    Aside {
        final_name: String,
        doomed: DoomedDirectory,
    },
}

struct Artifact {
    token: Token,
    dir: OwnedFd,
    name: String,
    location: String,
    /// `None` when the identity could not be read, so nothing may be removed.
    id: Option<ObjectId>,
    kind: Kind,
}

#[derive(Default)]
pub(super) struct Journal {
    changed: Cell<bool>,
    next_token: Cell<u64>,
    live: RefCell<Vec<Artifact>>,
    unresolved: RefCell<Vec<String>>,
}

/// Unlinks `name` below `dir` only if it still is the object registered as
/// `id`. Returns whether something was removed (`false` if already gone).
fn unlink_if_identical(dir: &OwnedFd, name: &str, id: &ObjectId) -> Result<bool, SarError> {
    match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) if &object_id(&stat)? == id => {
            rustix::fs::unlinkat(dir, name, AtFlags::empty()).map_err(io_error)?;
            Ok(true)
        }
        Ok(_) => Err(SarError::AlreadyExists(
            "temporary object no longer is the object this run created",
        )),
        Err(Errno::NOENT) => Ok(false),
        Err(errno) => Err(io_error(errno)),
    }
}

impl Journal {
    pub(super) fn new(destination_created: bool) -> Self {
        let journal = Self::default();
        journal.changed.set(destination_created);
        journal
    }

    /// Records a change that stays in the destination.
    pub(super) fn note_change(&self) {
        self.changed.set(true);
    }

    pub(super) fn slot(&self, dir: &OwnedFd, location: &str) -> Result<Slot, SarError> {
        let held = self.live.borrow().len() + self.unresolved.borrow().len();
        if held >= MAX_TRACKED_ARTIFACTS {
            return Err(SarError::LimitExceeded(
                "too many run-owned temporary objects are tracked during extraction",
            ));
        }
        Ok(Slot {
            dir: dir.try_clone()?,
            location: location.to_string(),
        })
    }

    fn track(&self, slot: Slot, name: &str, id: Option<ObjectId>, kind: Kind) -> Token {
        let token = Token(self.next_token.get());
        self.next_token.set(token.0.wrapping_add(1));
        self.live.borrow_mut().push(Artifact {
            token,
            dir: slot.dir,
            name: name.to_string(),
            location: slot.location,
            id,
            kind,
        });
        token
    }

    pub(super) fn track_object(&self, slot: Slot, name: &str, id: Option<ObjectId>) -> Token {
        self.track(slot, name, id, Kind::Object)
    }

    pub(super) fn track_aside(
        &self,
        slot: Slot,
        name: &str,
        final_name: &str,
        doomed: DoomedDirectory,
    ) -> Token {
        let id = Some(doomed.id().clone());
        let kind = Kind::Aside {
            final_name: final_name.to_string(),
            doomed,
        };
        self.track(slot, name, id, kind)
    }

    /// The artifact no longer exists under its temporary name (it was renamed
    /// into place), so there is nothing left to clean up.
    pub(super) fn retire(&self, token: Token) {
        self.live.borrow_mut().retain(|a| a.token != token);
    }

    fn take(&self, token: Token) -> Option<Artifact> {
        let mut live = self.live.borrow_mut();
        let index = live.iter().position(|a| a.token == token)?;
        Some(live.remove(index))
    }

    fn leave(&self, artifact: &Artifact, why: &str) {
        self.note_change();
        self.unresolved.borrow_mut().push(format!(
            "{why}: temporary object '{}' (for destination path {:?}) was left in place",
            artifact.name, artifact.location
        ));
    }

    /// Removes an unpublished staging object or probe by identity. Anything
    /// else at that name is left alone. A failure is recorded as unresolved
    /// and also returned. Unknown (already retired) tokens are ignored.
    pub(super) fn discard(&self, token: Token) -> Result<(), SarError> {
        let Some(artifact) = self.take(token) else {
            return Ok(());
        };
        self.discard_artifact(&artifact)
    }

    fn discard_artifact(&self, artifact: &Artifact) -> Result<(), SarError> {
        let Some(id) = artifact.id.as_ref() else {
            self.leave(artifact, "its identity could not be verified");
            return Err(SarError::Internal(
                "identity of a temporary object could not be verified",
            ));
        };
        match unlink_if_identical(&artifact.dir, &artifact.name, id) {
            Ok(_) => Ok(()),
            Err(err) => {
                self.leave(artifact, &format!("cleanup failed ({err})"));
                Err(err)
            }
        }
    }

    /// Confirms that the object moved aside is the one that was verified.
    pub(super) fn verify_aside(&self, token: Token) -> Result<(), SarError> {
        let live = self.live.borrow();
        match live.iter().find(|a| a.token == token) {
            Some(Artifact {
                dir,
                name,
                kind: Kind::Aside { doomed, .. },
                ..
            }) => replace::aside_is_verified(dir, name, doomed),
            _ => Ok(()),
        }
    }

    /// Puts a moved-aside directory back under its original name after a
    /// failed publication. It is never overwritten onto anything: if the name
    /// is occupied or the rename fails, the directory stays aside and the
    /// failed restoration is recorded as unresolved.
    pub(super) fn restore(&self, token: Token) {
        let Some(artifact) = self.take(token) else {
            return;
        };
        let Kind::Aside { final_name, doomed } = &artifact.kind else {
            return;
        };
        if let Err(err) = replace::restore_aside(&artifact.dir, &artifact.name, final_name, doomed)
        {
            self.leave(
                &artifact,
                &format!("the replaced directory could not be restored ({err})"),
            );
        }
    }

    /// Removes the moved-aside subtree after the replacement was published.
    /// Recognized run-created content is removed; anything else stays and the
    /// published final object is kept. Incomplete removal is an error.
    pub(super) fn remove_aside(
        &self,
        ledger: &RefCell<CollisionLedger>,
        token: Token,
    ) -> Result<(), SarError> {
        let Some(artifact) = self.take(token) else {
            return Ok(());
        };
        let Artifact {
            token,
            dir,
            name,
            location,
            id,
            kind,
        } = artifact;
        let Kind::Aside { final_name, doomed } = kind else {
            return Ok(());
        };
        match replace::remove_aside(ledger, &dir, &name, &doomed) {
            Ok(()) => Ok(()),
            Err(err) => {
                let artifact = Artifact {
                    token,
                    dir,
                    name,
                    location,
                    id,
                    kind: Kind::Aside { final_name, doomed },
                };
                self.leave(
                    &artifact,
                    &format!("the replacement was published but the moved-aside directory could not be fully removed ({err})"),
                );
                Err(err)
            }
        }
    }

    /// Final accounting for a failed run. Artifacts still registered (none in
    /// ordinary operation, because their owners discard them) get one last
    /// identity-verified cleanup attempt.
    pub(super) fn report(&self) -> ExtractionReport {
        let remaining: Vec<Artifact> = self.live.borrow_mut().drain(..).collect();
        for artifact in remaining {
            match artifact.kind {
                Kind::Object => {
                    let _ = self.discard_artifact(&artifact);
                }
                Kind::Aside { .. } => {
                    self.leave(&artifact, "the directory replacement was interrupted")
                }
            }
        }
        ExtractionReport {
            partial_changes: self.changed.get() || !self.unresolved.borrow().is_empty(),
            cleanup_failures: self.unresolved.borrow().clone(),
        }
    }

    /// Whether any run-owned temporary object is still registered or
    /// unresolved; a successful run must have none.
    pub(super) fn holds_artifacts(&self) -> bool {
        !self.live.borrow().is_empty() || !self.unresolved.borrow().is_empty()
    }

    pub(super) fn location(&self, token: Token) -> String {
        self.live
            .borrow()
            .iter()
            .find(|a| a.token == token)
            .map(|a| a.location.clone())
            .unwrap_or_default()
    }
}
