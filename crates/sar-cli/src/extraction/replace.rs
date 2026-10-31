// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Conservative removal of directory subtrees that this extraction run created.
//!
//! The final logical state (specification Section 6.1.5) can require a later
//! non-directory Entry to replace a directory together with its earlier
//! descendants. This module only ever removes objects the run itself created,
//! identified by the device/inode identities recorded in the collision ledger.
//! Anything else (a pre-existing directory, or any unrecognized entry found
//! inside a run-created directory) makes the replacement fail with
//! `SAR_ERR_ALREADY_EXISTS` before a single object is removed.
//!
//! Every step is descriptor-relative: directories are opened by name with
//! `O_NOFOLLOW | O_DIRECTORY`, identity is re-checked on the opened descriptor,
//! and removal uses `unlinkat` on that descriptor, so substituting a symlink
//! or a parent directory cannot redirect a deletion.

use std::{cell::RefCell, ffi::CString};

use rustix::{
    fd::OwnedFd,
    fs::{AtFlags, Dir, FileType, Mode, OFlags, Stat},
    io::Errno,
};
use sar_core::SarError;

use super::{fresh_temp_name, hook, io_error, object_id};
use crate::extraction::collision::{CollisionLedger, NodeId, ObjectId};

/// Deepest directory nesting removed in one replacement. Each level keeps one
/// descriptor open, so this bounds descriptor use independently of the archive.
const MAX_REPLACE_DEPTH: usize = 64;

fn open_directory_at(parent: &OwnedFd, name: impl rustix::path::Arg) -> Result<OwnedFd, Errno> {
    rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

fn not_ours() -> SarError {
    SarError::AlreadyExists(
        "refusing to remove a directory entry that this extraction did not create",
    )
}

fn changed() -> SarError {
    SarError::AlreadyExists("destination changed while a replaced directory was being removed")
}

fn name_str(name: &CString) -> Result<&str, SarError> {
    name.to_str().map_err(|_| not_ours())
}

/// Lists `fd`, failing as soon as the number of entries exceeds `budget` (the
/// number of objects this run could legitimately own). Memory is therefore
/// bounded by `budget` names of at most `NAME_MAX` bytes plus their metadata,
/// whatever an adversary placed in the directory.
fn listing(fd: &OwnedFd, budget: usize) -> Result<Vec<(CString, Stat)>, SarError> {
    let mut dir = Dir::read_from(fd).map_err(io_error)?;
    let mut names = Vec::new();
    let mut count = 0usize;
    while let Some(entry) = dir.read() {
        let entry = entry.map_err(io_error)?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        count = count
            .checked_add(1)
            .ok_or(SarError::Overflow("directory entry count"))?;
        if count > budget {
            return Err(not_ours());
        }
        let stat = rustix::fs::statat(fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(io_error)?;
        names.push((name.to_owned(), stat));
    }
    Ok(names)
}

/// Read-only proof that every object below `fd` was created by this run.
fn verify_tree(
    ledger: &RefCell<CollisionLedger>,
    fd: &OwnedFd,
    node: NodeId,
    depth: usize,
) -> Result<(), SarError> {
    if depth > MAX_REPLACE_DEPTH {
        return Err(SarError::LimitExceeded(
            "directory being replaced is nested too deeply to remove safely",
        ));
    }
    let budget = ledger.borrow().claimed_objects();
    let entries = listing(fd, budget)?;
    for (name, stat) in entries {
        let id = object_id(&stat)?;
        if !ledger.borrow().is_created_child(node, name.to_bytes(), &id) {
            return Err(not_ours());
        }
        if FileType::from_raw_mode(stat.st_mode) == FileType::Directory {
            let child = open_directory_at(fd, name.as_c_str()).map_err(|_| changed())?;
            let opened = object_id(&rustix::fs::fstat(&child).map_err(io_error)?)?;
            if opened != id {
                return Err(changed());
            }
            let child_node = ledger
                .borrow()
                .lookup(node, name_str(&name)?)
                .ok_or_else(not_ours)?;
            verify_tree(ledger, &child, child_node, depth + 1)?;
        }
    }
    Ok(())
}

/// Removes everything below `fd`, re-verifying ownership of each object
/// immediately before it is unlinked.
fn delete_tree(
    ledger: &RefCell<CollisionLedger>,
    fd: &OwnedFd,
    node: NodeId,
    depth: usize,
) -> Result<(), SarError> {
    if depth > MAX_REPLACE_DEPTH {
        return Err(SarError::LimitExceeded(
            "directory being replaced is nested too deeply to remove safely",
        ));
    }
    let budget = ledger.borrow().claimed_objects();
    let entries = listing(fd, budget)?;
    for (name, stat) in entries {
        let id = object_id(&stat)?;
        if !ledger.borrow().is_created_child(node, name.to_bytes(), &id) {
            return Err(not_ours());
        }
        let flags = if FileType::from_raw_mode(stat.st_mode) == FileType::Directory {
            let child = open_directory_at(fd, name.as_c_str()).map_err(|_| changed())?;
            let opened = object_id(&rustix::fs::fstat(&child).map_err(io_error)?)?;
            if opened != id {
                return Err(changed());
            }
            let child_node = ledger
                .borrow()
                .lookup(node, name_str(&name)?)
                .ok_or_else(not_ours)?;
            delete_tree(ledger, &child, child_node, depth + 1)?;
            AtFlags::REMOVEDIR
        } else {
            AtFlags::empty()
        };
        rustix::fs::unlinkat(fd, name.as_c_str(), flags).map_err(io_error)?;
        ledger.borrow_mut().forget(&id);
    }
    Ok(())
}

/// A run-created directory proven removable, still reachable by name.
pub(super) struct DoomedDirectory {
    fd: OwnedFd,
    id: ObjectId,
    node: NodeId,
}

/// Looks at `name` below `dir`. `Ok(None)` means it is not a directory (or is
/// absent), so ordinary rename replacement applies. A directory is returned
/// only when this run created it, it is owned by `node`, and its whole subtree
/// was created by this run; otherwise the replacement is refused. Nothing is
/// modified.
pub(super) fn find_replaceable_directory(
    ledger: &RefCell<CollisionLedger>,
    dir: &OwnedFd,
    name: &str,
    node: NodeId,
) -> Result<Option<DoomedDirectory>, SarError> {
    match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) if FileType::from_raw_mode(stat.st_mode) == FileType::Directory => {}
        Ok(_) | Err(Errno::NOENT) => return Ok(None),
        Err(errno) => return Err(io_error(errno)),
    }
    let fd = open_directory_at(dir, name).map_err(|_| changed())?;
    let id = object_id(&rustix::fs::fstat(&fd).map_err(io_error)?)?;
    if !ledger.borrow().is_created_by(node, &id) {
        return Err(SarError::AlreadyExists(
            "refusing to replace a directory that this extraction did not create",
        ));
    }
    verify_tree(ledger, &fd, node, 0)?;
    Ok(Some(DoomedDirectory { fd, id, node }))
}

/// Moves the verified directory out of the way under a private name, then
/// confirms the object that moved is the one that was verified.
pub(super) fn move_aside(
    parent: &OwnedFd,
    name: &str,
    doomed: &DoomedDirectory,
) -> Result<String, SarError> {
    let before = rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(io_error)?;
    if object_id(&before)? != doomed.id {
        return Err(changed());
    }
    let aside = fresh_temp_name()?;
    match rustix::fs::statat(parent, aside.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
        Err(Errno::NOENT) => {}
        Ok(_) => return Err(changed()),
        Err(errno) => return Err(io_error(errno)),
    }
    hook("before-aside");
    rustix::fs::renameat(parent, name, parent, aside.as_str()).map_err(io_error)?;
    let moved = rustix::fs::statat(parent, aside.as_str(), AtFlags::SYMLINK_NOFOLLOW)
        .map_err(io_error)
        .and_then(|stat| object_id(&stat));
    if moved.as_ref().ok() != Some(&doomed.id) {
        let _ = rustix::fs::renameat(parent, aside.as_str(), parent, name);
        return Err(changed());
    }
    Ok(aside)
}

/// Puts a moved-aside directory back after a failed publication.
pub(super) fn restore_aside(parent: &OwnedFd, aside: &str, name: &str) {
    let _ = rustix::fs::renameat(parent, aside, parent, name);
}

/// Removes the moved-aside subtree through the descriptor that was verified,
/// then the (now empty) aside directory itself.
pub(super) fn remove_aside(
    ledger: &RefCell<CollisionLedger>,
    parent: &OwnedFd,
    aside: &str,
    doomed: DoomedDirectory,
) -> Result<(), SarError> {
    hook("before-delete-replaced");
    // Re-prove ownership of the moved subtree so that nothing is removed if
    // unrecognized content appeared between the preflight and the move.
    verify_tree(ledger, &doomed.fd, doomed.node, 0)?;
    delete_tree(ledger, &doomed.fd, doomed.node, 0)?;
    rustix::fs::unlinkat(parent, aside, AtFlags::REMOVEDIR).map_err(io_error)?;
    Ok(())
}
