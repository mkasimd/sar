// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Anchored, descriptor-relative extraction backend for Unix-like systems.
//!
//! Confinement model: the caller-selected extraction root is resolved exactly
//! once (a symlink at the root path is followed at that moment, and only then)
//! and held as an open directory descriptor. Every later operation is a `*at`
//! system call relative to a directory descriptor obtained by walking archive
//! path components one at a time with `O_NOFOLLOW | O_DIRECTORY`. No archive
//! controlled path string is ever resolved from the working directory or the
//! filesystem root again, so replacing any path component after it was opened
//! cannot redirect a mutation: the kernel keeps operating on the object that
//! was opened. Only portable POSIX primitives are used (no `openat2`).

use std::{
    cell::{Cell, RefCell},
    fs::{self, File},
    io,
    path::Path,
    rc::Rc,
};

use rustix::{
    fd::OwnedFd,
    fs::{AtFlags, FileType, Mode, OFlags, RawMode, Stat},
    io::Errno,
};
use sar_core::{ResourceLimits, SarError};

use crate::extraction::{
    collision::{CollisionLedger, NodeId, ObjectId, ROOT_NODE},
    metadata::apply_fd_metadata,
    paths::{SafeRelativePath, check_plain_components},
    policy::ExtractMetadataOptions,
};

const TEMP_PREFIX: &str = ".sar-tmp-";
const TEMP_RANDOM_BYTES: usize = 16;
const TEMP_ATTEMPTS: usize = 16;
const DIRECTORY_MODE: u32 = 0o700;
const STAGING_MODE: u32 = 0o600;

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn io_error(errno: Errno) -> SarError {
    SarError::Io(io::Error::from(errno))
}

fn widen<T: TryInto<u64>>(value: T) -> Result<u64, SarError> {
    value
        .try_into()
        .map_err(|_| SarError::Overflow("filesystem object identity"))
}

/// Identity of the object a `stat` result describes: device and inode, which
/// the destination filesystem itself assigns, whatever names reach the object.
fn object_id(stat: &Stat) -> Result<ObjectId, SarError> {
    Ok(ObjectId::Inode {
        device: widen(stat.st_dev)?,
        inode: widen(stat.st_ino)?,
    })
}

fn raw_mode(mode: u32) -> Result<Mode, SarError> {
    let raw = RawMode::try_from(mode).map_err(|_| SarError::Overflow("file mode"))?;
    Ok(Mode::from_raw_mode(raw))
}

#[cfg(test)]
pub(crate) mod test_hooks {
    use std::cell::RefCell;

    type Hook = Box<dyn FnMut(&str)>;

    thread_local! {
        static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
    }

    pub(crate) fn install(hook: impl FnMut(&str) + 'static) {
        HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    pub(crate) fn clear() {
        HOOK.with(|slot| *slot.borrow_mut() = None);
    }

    pub(super) fn fire(point: &str) {
        let taken = HOOK.with(|slot| slot.borrow_mut().take());
        if let Some(mut hook) = taken {
            hook(point);
            HOOK.with(|slot| {
                let mut slot = slot.borrow_mut();
                if slot.is_none() {
                    *slot = Some(hook);
                }
            });
        }
    }
}

/// Deterministic race-injection points; compiled out of non-test builds.
#[inline]
fn hook(_point: &str) {
    #[cfg(test)]
    test_hooks::fire(_point);
}

/// Fails with `PathCollision` when the object currently reachable as `name`
/// is owned by a different logical path. Nothing is followed or modified; a
/// missing name or an object this run never claimed is not a collision.
fn check_final_name(
    ledger: &RefCell<CollisionLedger>,
    dir: &OwnedFd,
    name: &str,
    node: NodeId,
) -> Result<(), SarError> {
    match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => ledger.borrow().check(node, &object_id(&stat)?),
        Err(Errno::NOENT) => Ok(()),
        Err(errno) => Err(io_error(errno)),
    }
}

/// Open directory descriptor fixing the extraction scope for one run, together
/// with the ledger of which logical path owns which destination object.
pub(crate) struct ExtractionRoot {
    dir: OwnedFd,
    ledger: Rc<RefCell<CollisionLedger>>,
}

impl ExtractionRoot {
    /// Creates the root if missing, then resolves it once and anchors it.
    pub(crate) fn open(path: &Path, limits: ResourceLimits) -> Result<Self, SarError> {
        fs::create_dir_all(path)?;
        let dir = rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io_error)?;
        Ok(Self {
            dir,
            ledger: Rc::new(RefCell::new(CollisionLedger::new(limits))),
        })
    }

    /// Walks `components` below the root, creating missing directories. Every
    /// directory reached is claimed for its logical prefix; reaching one that a
    /// differently spelled prefix already owns is a collision. That check runs
    /// right after the component is opened, and a component that was created
    /// by this walk is empty and unaliased, so no mutation can precede it.
    fn ensure_directory(&self, components: &[String]) -> Result<(OwnedFd, NodeId), SarError> {
        let mut current = self.dir.try_clone()?;
        let mut node = ROOT_NODE;
        for component in components {
            current = open_component(&current, component, true)?;
            let stat = rustix::fs::fstat(&current).map_err(io_error)?;
            let id = object_id(&stat)?;
            let mut ledger = self.ledger.borrow_mut();
            ledger.check_candidate(node, component, &id)?;
            node = ledger.child(node, component)?;
            ledger.claim(node, id)?;
        }
        Ok((current, node))
    }

    /// Walks `components` below the root without creating or claiming anything.
    fn open_directory(&self, components: &[String]) -> Result<OwnedFd, SarError> {
        let mut current = self.dir.try_clone()?;
        for component in components {
            current = open_component(&current, component, false)?;
        }
        Ok(current)
    }

    /// Creates a directory (mode never wider than 0o700) and returns nothing;
    /// pending metadata is applied later by `apply_directory_metadata`.
    pub(crate) fn create_directory(&self, rel: &SafeRelativePath) -> Result<(), SarError> {
        self.ensure_directory(rel.components()).map(drop)
    }

    /// Resolves the destination directory and the logical node of the final
    /// name, refusing to continue when the final name already reaches an
    /// object owned by a different logical path.
    fn prepare_final(&self, rel: &SafeRelativePath) -> Result<(OwnedFd, NodeId, String), SarError> {
        let (dir, parent) = self.ensure_directory(rel.parent_components())?;
        let final_name = rel.file_name()?.to_string();
        match rustix::fs::statat(&dir, final_name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => {
                let id = object_id(&stat)?;
                self.ledger
                    .borrow()
                    .check_candidate(parent, &final_name, &id)?;
            }
            Err(Errno::NOENT) => {}
            Err(errno) => return Err(io_error(errno)),
        }
        let node = self.ledger.borrow_mut().child(parent, &final_name)?;
        Ok((dir, node, final_name))
    }

    /// Stages a new regular file next to its final name. The staging file is
    /// always created private (0600, subject to the umask) and stays so until
    /// publication, when `publish` gives it the mode an ordinary `creat(0666)`
    /// would have received unless permission restoration set one.
    pub(crate) fn stage_file(&self, rel: &SafeRelativePath) -> Result<StagedFile, SarError> {
        let (dir, node, final_name) = self.prepare_final(rel)?;
        reject_existing_directory(
            &dir,
            &final_name,
            "refusing to replace existing directory with file output",
        )?;
        hook("after-parent-open");
        let mode = raw_mode(STAGING_MODE)?;
        let (fd, temp_name) = create_unique(|name| {
            rustix::fs::openat(
                &dir,
                name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                mode,
            )
        })?;
        let staged_id = object_id(&rustix::fs::fstat(&fd).map_err(io_error)?)?;
        Ok(StagedFile {
            dir,
            temp_name,
            final_name,
            ledger: Rc::clone(&self.ledger),
            node,
            staged_id,
            file: File::from(fd),
            permissions_restored: Cell::new(false),
            published: false,
        })
    }

    /// Creates a symlink atomically: a uniquely named link is created in the
    /// destination directory and then renamed over the final name.
    pub(crate) fn create_symlink(
        &self,
        rel: &SafeRelativePath,
        target: &str,
    ) -> Result<(), SarError> {
        let (dir, node, final_name) = self.prepare_final(rel)?;
        let final_name = final_name.as_str();
        reject_existing_directory(
            &dir,
            final_name,
            "refusing to replace existing directory with symlink",
        )?;
        hook("after-parent-open");
        let ((), temp_name) = create_unique(|name| rustix::fs::symlinkat(target, &dir, name))?;
        let published = self.publish_symlink(&dir, &temp_name, final_name, node);
        if published.is_err() {
            let _ = rustix::fs::unlinkat(&dir, temp_name.as_str(), AtFlags::empty());
        }
        published
    }

    fn publish_symlink(
        &self,
        dir: &OwnedFd,
        temp_name: &str,
        final_name: &str,
        node: NodeId,
    ) -> Result<(), SarError> {
        let stat =
            rustix::fs::statat(dir, temp_name, AtFlags::SYMLINK_NOFOLLOW).map_err(io_error)?;
        let id = object_id(&stat)?;
        hook("before-publish");
        check_final_name(&self.ledger, dir, final_name, node)?;
        let reservation = self.ledger.borrow_mut().reserve(node, &id)?;
        if let Err(errno) = rustix::fs::renameat(dir, temp_name, dir, final_name) {
            self.ledger.borrow_mut().release(reservation);
            return Err(io_error(errno));
        }
        self.ledger.borrow_mut().commit(node, id, reservation);
        Ok(())
    }

    /// Restores metadata on a directory created during this run through its
    /// own descriptor, never through a re-resolved pathname.
    pub(crate) fn apply_directory_metadata(
        &self,
        rel: &SafeRelativePath,
        permissions: Option<u16>,
        owner: Option<u32>,
        timestamps: Option<[u64; 3]>,
        options: ExtractMetadataOptions,
    ) -> Result<(), SarError> {
        let dir = self.open_directory(rel.components())?;
        hook("before-directory-metadata");
        apply_fd_metadata(&dir, permissions, owner, timestamps, options)
    }
}

fn open_component(parent: &OwnedFd, name: &str, create: bool) -> Result<OwnedFd, SarError> {
    check_plain_components([name])?;
    match rustix::fs::openat(parent, name, directory_flags(), Mode::empty()) {
        Ok(fd) => return Ok(fd),
        Err(Errno::NOENT) if create => {}
        Err(errno) => return Err(classify_open_failure(parent, name, errno)),
    }

    match rustix::fs::mkdirat(parent, name, raw_mode(DIRECTORY_MODE)?) {
        Ok(()) => {
            hook("after-mkdir");
            let fd = rustix::fs::openat(parent, name, directory_flags(), Mode::empty())
                .map_err(|errno| classify_open_failure(parent, name, errno))?;
            // The umask can only narrow 0o700; restore owner rwx on the new
            // directory through its descriptor so extraction can proceed.
            rustix::fs::fchmod(&fd, raw_mode(DIRECTORY_MODE)?).map_err(io_error)?;
            Ok(fd)
        }
        Err(Errno::EXIST) => rustix::fs::openat(parent, name, directory_flags(), Mode::empty())
            .map_err(|errno| classify_open_failure(parent, name, errno)),
        Err(errno) => Err(io_error(errno)),
    }
}

fn classify_open_failure(parent: &OwnedFd, name: &str, errno: Errno) -> SarError {
    match rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => match FileType::from_raw_mode(stat.st_mode) {
            FileType::Symlink => {
                SarError::PathEscape("refusing to traverse an existing symlink during extraction")
            }
            FileType::Directory => io_error(errno),
            _ => SarError::Malformed("path component exists but is not a directory"),
        },
        Err(_) => io_error(errno),
    }
}

fn reject_existing_directory(
    dir: &OwnedFd,
    name: &str,
    message: &'static str,
) -> Result<(), SarError> {
    match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) if FileType::from_raw_mode(stat.st_mode) == FileType::Directory => {
            Err(SarError::Malformed(message))
        }
        Ok(_) | Err(Errno::NOENT) => Ok(()),
        Err(errno) => Err(io_error(errno)),
    }
}

/// Runs `create` with fresh short random names until one is created
/// exclusively. Names are independent of the archived basename.
fn create_unique<T>(
    mut create: impl FnMut(&str) -> Result<T, Errno>,
) -> Result<(T, String), SarError> {
    for _ in 0..TEMP_ATTEMPTS {
        let mut random = [0u8; TEMP_RANDOM_BYTES];
        getrandom::fill(&mut random)
            .map_err(|_| SarError::Internal("system randomness unavailable"))?;
        let mut name = String::from(TEMP_PREFIX);
        for byte in random {
            name.push_str(&format!("{byte:02x}"));
        }
        match create(&name) {
            Ok(value) => return Ok((value, name)),
            Err(Errno::EXIST) => {}
            Err(errno) => return Err(io_error(errno)),
        }
    }
    Err(SarError::Io(io::Error::from(io::ErrorKind::AlreadyExists)))
}

/// An unpublished staging file held open inside its destination directory.
/// Dropping it without `publish` removes the staging file.
pub(crate) struct StagedFile {
    dir: OwnedFd,
    temp_name: String,
    final_name: String,
    ledger: Rc<RefCell<CollisionLedger>>,
    node: NodeId,
    staged_id: ObjectId,
    file: File,
    permissions_restored: Cell<bool>,
    published: bool,
}

/// Mode an ordinary `creat(0666)` in `dir` would produce (umask and default
/// ACLs included), learned from an empty probe file so the process umask is
/// never read or changed.
fn default_file_mode(dir: &OwnedFd) -> Result<Mode, SarError> {
    let mode = raw_mode(0o666)?;
    let (probe, name) = create_unique(|name| {
        rustix::fs::openat(
            dir,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            mode,
        )
    })?;
    let stat = rustix::fs::fstat(&probe);
    let removed = rustix::fs::unlinkat(dir, name.as_str(), AtFlags::empty());
    let stat = stat.map_err(io_error)?;
    removed.map_err(io_error)?;
    Ok(Mode::from_raw_mode(stat.st_mode & 0o777))
}
impl StagedFile {
    pub(crate) fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    /// Applies metadata to the open staging file, before publication.
    pub(crate) fn apply_metadata(
        &self,
        permissions: Option<u16>,
        owner: Option<u32>,
        timestamps: Option<[u64; 3]>,
        options: ExtractMetadataOptions,
    ) -> Result<(), SarError> {
        apply_fd_metadata(&self.file, permissions, owner, timestamps, options)?;
        if options.preserve_permissions && permissions.is_some() {
            self.permissions_restored.set(true);
        }
        Ok(())
    }

    /// Atomically renames the staging file over the final name. Unless
    /// permission restoration chose a mode, the file first receives the
    /// default mode a plain create would have had (still before publication).
    pub(crate) fn publish(mut self) -> Result<(), SarError> {
        if !self.permissions_restored.get() {
            let mode = default_file_mode(&self.dir)?;
            rustix::fs::fchmod(&self.file, mode).map_err(io_error)?;
        }
        hook("before-publish");
        // Re-checked at the last moment: the final name may have come to reach
        // an object owned by another logical path since staging began.
        check_final_name(&self.ledger, &self.dir, &self.final_name, self.node)?;
        let reservation = self
            .ledger
            .borrow_mut()
            .reserve(self.node, &self.staged_id)?;
        if let Err(errno) = rustix::fs::renameat(
            &self.dir,
            self.temp_name.as_str(),
            &self.dir,
            self.final_name.as_str(),
        ) {
            self.ledger.borrow_mut().release(reservation);
            return Err(io_error(errno));
        }
        self.published = true;
        self.ledger
            .borrow_mut()
            .commit(self.node, self.staged_id.clone(), reservation);
        Ok(())
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        if !self.published {
            let _ = rustix::fs::unlinkat(&self.dir, self.temp_name.as_str(), AtFlags::empty());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt, symlink},
        path::{Path, PathBuf},
        rc::Rc,
    };

    use rustix::fs::{Mode, OFlags};
    use sar_core::{ResourceLimits, SarError};
    use tempfile::{TempDir, tempdir};

    use super::{ExtractionRoot, create_unique, test_hooks};
    use crate::extraction::{paths::SafeRelativePath, policy::ExtractMetadataOptions};

    fn rel(parts: &[&str]) -> SafeRelativePath {
        SafeRelativePath::from_components(parts.iter().map(|part| (*part).to_string()).collect())
            .expect("safe path")
    }

    struct Fixture {
        _td: TempDir,
        root_path: PathBuf,
        outside: PathBuf,
    }

    fn fixture() -> Fixture {
        let td = tempdir().expect("tmp");
        let root_path = td.path().join("root");
        let outside = td.path().join("outside");
        fs::create_dir(&root_path).expect("root");
        fs::create_dir(&outside).expect("outside");
        Fixture {
            _td: td,
            root_path,
            outside,
        }
    }

    /// Moves `dir` aside and puts a symlink to `outside` in its place.
    fn swap_for_symlink(dir: &Path, outside: &Path) -> PathBuf {
        let moved = dir.with_file_name(format!(
            "{}.moved",
            dir.file_name().expect("name").to_string_lossy()
        ));
        fs::rename(dir, &moved).expect("move aside");
        symlink(outside, dir).expect("symlink swap");
        moved
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(dir)
            .expect("read_dir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }

    struct HookGuard;
    impl Drop for HookGuard {
        fn drop(&mut self) {
            test_hooks::clear();
        }
    }

    fn swap_at(point: &'static str, dir: PathBuf, outside: PathBuf) -> HookGuard {
        test_hooks::install(move |fired| {
            if fired == point {
                swap_for_symlink(&dir, &outside);
            }
        });
        HookGuard
    }

    const WANT_PERMS_AND_TIMES: ExtractMetadataOptions = ExtractMetadataOptions {
        preserve_permissions: true,
        preserve_times: true,
        preserve_owner: false,
        allow_symlinks: false,
    };

    #[test]
    fn symlinked_root_is_resolved_once_and_then_fixed() {
        let fx = fixture();
        let real = fx.root_path.join("real");
        fs::create_dir(&real).expect("real");
        let link = fx.root_path.join("link");
        symlink(&real, &link).expect("link");

        let root = ExtractionRoot::open(&link, ResourceLimits::default()).expect("open");
        fs::remove_file(&link).expect("remove link");
        symlink(&fx.outside, &link).expect("substitute root symlink");

        let mut staged = root.stage_file(&rel(&["sub", "f.txt"])).expect("stage");
        use std::io::Write;
        staged.file_mut().write_all(b"data").expect("write");
        staged.publish().expect("publish");
        root.create_symlink(&rel(&["l"]), "target")
            .expect("symlink");

        assert_eq!(fs::read(real.join("sub/f.txt")).expect("read"), b"data");
        assert!(real.join("l").is_symlink());
        assert!(entries(&fx.outside).is_empty());
    }

    #[test]
    fn existing_symlink_or_file_components_are_refused() {
        let fx = fixture();
        symlink(&fx.outside, fx.root_path.join("d")).expect("dir symlink");
        fs::write(fx.outside.join("file"), b"x").expect("file");
        symlink(fx.outside.join("file"), fx.root_path.join("s")).expect("file symlink");
        fs::write(fx.root_path.join("plain"), b"x").expect("plain");
        let root = ExtractionRoot::open(&fx.root_path, ResourceLimits::default()).expect("open");

        for parts in [&["d", "f"][..], &["s", "f"][..], &["d", "x", "f"][..]] {
            let err = root.stage_file(&rel(parts)).err().expect("refused");
            assert!(
                matches!(&err, SarError::PathEscape(msg) if msg.contains("existing symlink")),
                "{err:?}"
            );
        }
        let err = root
            .stage_file(&rel(&["plain", "f"]))
            .err()
            .expect("refused");
        assert!(matches!(&err, SarError::Malformed(msg) if msg.contains("not a directory")));
        assert!(root.create_symlink(&rel(&["d", "l"]), "t").is_err());
        assert!(root.create_directory(&rel(&["d", "sub"])).is_err());
        assert_eq!(entries(&fx.outside), vec!["file".to_string()]);
    }

    #[test]
    fn parent_replaced_after_check_cannot_redirect_staging_or_publication() {
        for point in ["after-parent-open", "before-publish"] {
            let fx = fixture();
            let root =
                ExtractionRoot::open(&fx.root_path, ResourceLimits::default()).expect("open");
            root.create_directory(&rel(&["d"])).expect("mkdir");
            let _guard = swap_at(point, fx.root_path.join("d"), fx.outside.clone());

            let mut staged = root.stage_file(&rel(&["d", "f.txt"])).expect("stage");
            use std::io::Write;
            staged.file_mut().write_all(b"payload").expect("write");
            staged.publish().expect("publish");

            assert!(entries(&fx.outside).is_empty(), "escaped at {point}");
            let moved = fx.root_path.join("d.moved");
            assert_eq!(entries(&moved), vec!["f.txt".to_string()], "at {point}");
        }
    }

    #[test]
    fn parent_replaced_cannot_redirect_symlink_creation() {
        for point in ["after-parent-open", "before-publish"] {
            let fx = fixture();
            let root =
                ExtractionRoot::open(&fx.root_path, ResourceLimits::default()).expect("open");
            root.create_directory(&rel(&["d"])).expect("mkdir");
            let _guard = swap_at(point, fx.root_path.join("d"), fx.outside.clone());

            root.create_symlink(&rel(&["d", "l"]), "target")
                .expect("symlink");

            assert!(entries(&fx.outside).is_empty(), "escaped at {point}");
            assert!(fx.root_path.join("d.moved/l").is_symlink());
            assert_eq!(
                entries(&fx.root_path.join("d.moved")),
                vec!["l".to_string()]
            );
        }
    }

    #[test]
    fn directory_metadata_follows_descriptor_not_replaced_path() {
        let fx = fixture();
        let root = ExtractionRoot::open(&fx.root_path, ResourceLimits::default()).expect("open");
        root.create_directory(&rel(&["d"])).expect("mkdir");
        fs::set_permissions(&fx.outside, fs::Permissions::from_mode(0o755)).expect("chmod");
        let outside_before = fs::metadata(&fx.outside).expect("stat");
        let _guard = swap_at(
            "before-directory-metadata",
            fx.root_path.join("d"),
            fx.outside.clone(),
        );

        root.apply_directory_metadata(
            &rel(&["d"]),
            Some(0o500),
            None,
            Some([1_000_000_000, 1_000_000_001, 0]),
            WANT_PERMS_AND_TIMES,
        )
        .expect("metadata");

        let outside_after = fs::metadata(&fx.outside).expect("stat");
        assert_eq!(outside_after.mode(), outside_before.mode());
        assert_eq!(outside_after.mtime(), outside_before.mtime());
        let moved = fs::metadata(fx.root_path.join("d.moved")).expect("moved");
        assert_eq!(moved.mode() & 0o777, 0o500);
        assert_eq!(moved.mtime(), 1_000_000_000);
        assert_eq!(moved.atime(), 1_000_000_001);
        // Restore write access so the temporary directory can be removed.
        fs::set_permissions(
            fx.root_path.join("d.moved"),
            fs::Permissions::from_mode(0o700),
        )
        .expect("restore");
    }

    #[test]
    fn directory_metadata_refuses_component_replaced_before_open() {
        let fx = fixture();
        let root = ExtractionRoot::open(&fx.root_path, ResourceLimits::default()).expect("open");
        root.create_directory(&rel(&["d"])).expect("mkdir");
        fs::set_permissions(&fx.outside, fs::Permissions::from_mode(0o755)).expect("chmod");
        swap_for_symlink(&fx.root_path.join("d"), &fx.outside);

        let err = root
            .apply_directory_metadata(&rel(&["d"]), Some(0o500), None, None, WANT_PERMS_AND_TIMES)
            .expect_err("replaced component");
        assert!(matches!(&err, SarError::PathEscape(msg) if msg.contains("existing symlink")));
        assert_eq!(
            fs::metadata(&fx.outside).expect("stat").mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn file_metadata_is_applied_to_staging_file_before_publication() {
        let fx = fixture();
        let root = ExtractionRoot::open(&fx.root_path, ResourceLimits::default()).expect("open");
        let seen = Rc::new(RefCell::new(None));
        let observed = Rc::clone(&seen);
        let dir = fx.root_path.clone();
        test_hooks::install(move |point| {
            if point == "before-publish" {
                let temp = entries(&dir)
                    .into_iter()
                    .find(|name| name.starts_with(".sar-tmp-"))
                    .expect("staging file present");
                let meta = fs::metadata(dir.join(temp)).expect("stat");
                *observed.borrow_mut() = Some((meta.mode() & 0o777, meta.mtime()));
            }
        });
        let _guard = HookGuard;

        let mut staged = root.stage_file(&rel(&["f"])).expect("stage");
        let staging_mode = {
            let temp = entries(&fx.root_path).into_iter().next().expect("temp");
            fs::metadata(fx.root_path.join(temp)).expect("stat").mode() & 0o777
        };
        assert_eq!(staging_mode & 0o077, 0, "staging file must start private");
        use std::io::Write;
        staged.file_mut().write_all(b"x").expect("write");
        staged
            .apply_metadata(
                Some(0o640),
                None,
                Some([1_100_000_000, 1_100_000_001, 0]),
                WANT_PERMS_AND_TIMES,
            )
            .expect("metadata");
        staged.publish().expect("publish");

        assert_eq!(*seen.borrow(), Some((0o640, 1_100_000_000)));
        let meta = fs::metadata(fx.root_path.join("f")).expect("final");
        assert_eq!((meta.mode() & 0o7777, meta.mtime()), (0o640, 1_100_000_000));
        assert_eq!(entries(&fx.root_path), vec!["f".to_string()]);
    }

    #[test]
    fn staging_file_is_private_until_publication_then_gets_default_mode() {
        let fx = fixture();
        fs::set_permissions(&fx.root_path, fs::Permissions::from_mode(0o777)).expect("chmod");
        let root = ExtractionRoot::open(&fx.root_path, ResourceLimits::default()).expect("open");
        let reference = fx.root_path.join("reference");
        fs::File::create(&reference).expect("reference");
        let default_mode = fs::metadata(&reference).expect("stat").mode() & 0o777;
        fs::remove_file(&reference).expect("remove");

        let seen = Rc::new(RefCell::new(None));
        let observed = Rc::clone(&seen);
        let dir = fx.root_path.clone();
        test_hooks::install(move |point| {
            if point == "before-publish" {
                let temp = entries(&dir)
                    .into_iter()
                    .find(|name| name.starts_with(".sar-tmp-"))
                    .expect("staging file present");
                *observed.borrow_mut() =
                    Some(fs::metadata(dir.join(temp)).expect("stat").mode() & 0o777);
            }
        });
        let _guard = HookGuard;

        let mut staged = root.stage_file(&rel(&["f"])).expect("stage");
        use std::io::Write;
        staged.file_mut().write_all(b"secret").expect("write");
        let temp = entries(&fx.root_path).into_iter().next().expect("temp");
        let mode = fs::metadata(fx.root_path.join(temp)).expect("stat").mode() & 0o777;
        assert_eq!(mode & 0o077, 0, "partially written staging file is private");
        staged
            .apply_metadata(None, None, None, ExtractMetadataOptions::default())
            .expect("no-op metadata");
        staged.publish().expect("publish");

        assert_eq!(*seen.borrow(), Some(default_mode), "mode set before rename");
        assert_eq!(
            fs::metadata(fx.root_path.join("f")).expect("final").mode() & 0o777,
            default_mode
        );
        assert_eq!(entries(&fx.root_path), vec!["f".to_string()]);
    }

    #[test]
    fn owner_restoration_uses_descriptor_and_never_follows_replaced_path() {
        let fx = fixture();
        let root = ExtractionRoot::open(&fx.root_path, ResourceLimits::default()).expect("open");
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        let options = ExtractMetadataOptions {
            preserve_owner: true,
            ..Default::default()
        };

        if rustix::process::geteuid().is_root() {
            // Privileged environment only: chown to a different owner while
            // the destination directory is swapped for a symlink.
            root.create_directory(&rel(&["d"])).expect("mkdir");
            let _guard = swap_at(
                "before-directory-metadata",
                fx.root_path.join("d"),
                fx.outside.clone(),
            );
            let (other_uid, other_gid) = (4242u32, 4243u32);
            root.apply_directory_metadata(
                &rel(&["d"]),
                None,
                Some(other_uid | (other_gid << 16)),
                None,
                options,
            )
            .expect("chown");
            let outside = fs::metadata(&fx.outside).expect("stat");
            assert_eq!((outside.uid(), outside.gid()), (uid, gid));
            let moved = fs::metadata(fx.root_path.join("d.moved")).expect("stat");
            assert_eq!((moved.uid(), moved.gid()), (other_uid, other_gid));
        } else if uid <= 0xFFFF && gid <= 0xFFFF {
            let staged = root.stage_file(&rel(&["f"])).expect("stage");
            staged
                .apply_metadata(None, Some(uid | (gid << 16)), None, options)
                .expect("fchown to self");
            staged.publish().expect("publish");
        }
    }

    #[test]
    fn directories_are_never_group_or_world_accessible_while_created() {
        let fx = fixture();
        let root = ExtractionRoot::open(&fx.root_path, ResourceLimits::default()).expect("open");
        let modes = Rc::new(RefCell::new(Vec::new()));
        let observed = Rc::clone(&modes);
        let base = fx.root_path.clone();
        test_hooks::install(move |point| {
            if point == "after-mkdir" {
                for path in ["a", "a/b"] {
                    if let Ok(meta) = fs::symlink_metadata(base.join(path)) {
                        observed.borrow_mut().push((path, meta.mode() & 0o777));
                    }
                }
            }
        });
        let _guard = HookGuard;

        root.create_directory(&rel(&["a", "b"])).expect("mkdir");

        let modes = modes.borrow();
        assert_eq!(modes.len(), 3, "a at first and second mkdir, then a/b");
        assert!(modes.iter().all(|(_, mode)| mode & 0o077 == 0), "{modes:?}");
        for dir in ["a", "a/b"] {
            assert_eq!(
                fs::metadata(fx.root_path.join(dir)).expect("stat").mode() & 0o777,
                0o700
            );
        }
    }

    #[test]
    fn maximum_length_basenames_stage_and_publish() {
        let fx = fixture();
        let root = ExtractionRoot::open(&fx.root_path, ResourceLimits::default()).expect("open");
        for len in [250usize, 255] {
            let name = "n".repeat(len);
            let mut staged = root.stage_file(&rel(&[name.as_str()])).expect("stage");
            use std::io::Write;
            staged.file_mut().write_all(b"x").expect("write");
            staged.publish().expect("publish");
            assert!(fx.root_path.join(&name).is_file());
            root.create_symlink(&rel(&["d", name.as_str()]), "t")
                .expect("symlink");
            assert!(fx.root_path.join("d").join(&name).is_symlink());
        }
        assert!(
            entries(&fx.root_path)
                .iter()
                .all(|name| !name.starts_with(".sar-tmp-"))
        );
    }

    #[test]
    fn unpublished_staging_file_is_removed_on_drop() {
        let fx = fixture();
        let root = ExtractionRoot::open(&fx.root_path, ResourceLimits::default()).expect("open");
        let staged = root.stage_file(&rel(&["f"])).expect("stage");
        assert_eq!(entries(&fx.root_path).len(), 1);
        drop(staged);
        assert!(entries(&fx.root_path).is_empty());
    }

    #[test]
    fn exclusive_creation_does_not_follow_existing_symlink() {
        let fx = fixture();
        let victim = fx.outside.join("victim");
        fs::write(&victim, b"keep").expect("victim");
        symlink(&victim, fx.root_path.join("taken")).expect("symlink");
        let root = ExtractionRoot::open(&fx.root_path, ResourceLimits::default()).expect("open");

        let errno = rustix::fs::openat(
            &root.dir,
            "taken",
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .expect_err("must not follow");
        assert_eq!(errno, rustix::io::Errno::EXIST);
        assert_eq!(fs::read(&victim).expect("read"), b"keep");

        let result = create_unique(|_| Err::<(), _>(rustix::io::Errno::EXIST));
        assert!(
            matches!(result, Err(SarError::Io(ref e)) if e.kind() == std::io::ErrorKind::AlreadyExists)
        );
    }

    #[test]
    fn symlink_publication_replaces_existing_file_without_touching_target() {
        let fx = fixture();
        let victim = fx.outside.join("victim");
        fs::write(&victim, b"keep").expect("victim");
        fs::hard_link(&victim, fx.root_path.join("l")).expect("hardlink");
        let root = ExtractionRoot::open(&fx.root_path, ResourceLimits::default()).expect("open");

        root.create_symlink(&rel(&["l"]), "t").expect("symlink");

        assert!(fx.root_path.join("l").is_symlink());
        assert_eq!(fs::read(&victim).expect("read"), b"keep");
    }

    #[test]
    fn refuses_replacing_existing_directory() {
        let fx = fixture();
        fs::create_dir(fx.root_path.join("d")).expect("dir");
        let root = ExtractionRoot::open(&fx.root_path, ResourceLimits::default()).expect("open");
        assert!(root.stage_file(&rel(&["d"])).is_err());
        assert!(root.create_symlink(&rel(&["d"]), "t").is_err());
        assert!(fx.root_path.join("d").is_dir());
    }

    #[test]
    fn dot_components_cannot_be_walked() {
        assert!(SafeRelativePath::from_components(vec!["..".to_string()]).is_err());
        assert!(SafeRelativePath::from_components(vec!["a/b".to_string()]).is_err());
        assert!(SafeRelativePath::from_components(vec![".".to_string()]).is_err());
    }

    fn publish_bytes(root: &ExtractionRoot, parts: &[&str], data: &[u8]) -> Result<(), SarError> {
        use std::io::Write;
        let mut staged = root.stage_file(&rel(parts))?;
        staged.file_mut().write_all(data).expect("write");
        staged.publish()
    }

    fn is_collision(result: Result<(), SarError>) -> bool {
        matches!(result, Err(SarError::PathCollision(_)))
    }

    /// Directory for filesystem-behavior probes. `SAR_TEST_FS_PROBE_DIR` may
    /// name a directory on a case-insensitive or normalizing filesystem (for
    /// example a casefold ext4/tmpfs directory or an APFS volume).
    fn probe_dir() -> TempDir {
        match std::env::var_os("SAR_TEST_FS_PROBE_DIR") {
            Some(base) => tempfile::tempdir_in(base).expect("probe dir"),
            None => tempdir().expect("probe dir"),
        }
    }

    fn fs_folds_case(dir: &Path) -> bool {
        fs::write(dir.join("Probe-Case"), b"").expect("probe");
        let folds = fs::symlink_metadata(dir.join("probe-case")).is_ok();
        fs::remove_file(dir.join("Probe-Case")).expect("cleanup");
        folds
    }

    fn fs_folds_unicode_normalization(dir: &Path) -> bool {
        fs::write(dir.join("Probe-\u{e9}"), b"").expect("probe");
        let folds = fs::symlink_metadata(dir.join("Probe-e\u{301}")).is_ok();
        fs::remove_file(dir.join("Probe-\u{e9}")).expect("cleanup");
        folds
    }

    #[test]
    fn distinct_paths_without_a_filesystem_collision_extract_normally() {
        let fx = fixture();
        let root = ExtractionRoot::open(&fx.root_path, ResourceLimits::default()).expect("open");
        publish_bytes(&root, &["Dir", "a"], b"1").expect("Dir/a");
        publish_bytes(&root, &["dir", "a"], b"2").expect("dir/a");
        publish_bytes(&root, &["b"], b"3").expect("b");
        root.create_symlink(&rel(&["c"]), "b").expect("symlink");
        // Only meaningful on a case-sensitive destination, where the two
        // spellings are different objects; folding hosts are covered below.
        if !fs_folds_case(&fx.root_path) {
            assert_eq!(fs::read(fx.root_path.join("Dir/a")).expect("read"), b"1");
            assert_eq!(fs::read(fx.root_path.join("dir/a")).expect("read"), b"2");
        }
    }

    #[test]
    fn repeated_identical_logical_path_is_not_a_collision() {
        let fx = fixture();
        let root = ExtractionRoot::open(&fx.root_path, ResourceLimits::default()).expect("open");
        publish_bytes(&root, &["d", "f"], b"first").expect("first");
        publish_bytes(&root, &["d", "f"], b"second").expect("repeat");
        root.create_directory(&rel(&["d"])).expect("repeated dir");
        root.create_symlink(&rel(&["l"]), "t").expect("link");
        root.create_symlink(&rel(&["l"]), "u")
            .expect("repeated link");
        assert_eq!(fs::read(fx.root_path.join("d/f")).expect("read"), b"second");
        assert_eq!(
            fs::read_link(fx.root_path.join("l")).expect("link"),
            Path::new("u")
        );
    }

    #[test]
    fn replaced_object_does_not_leave_a_stale_identity_behind() {
        let fx = fixture();
        let root = ExtractionRoot::open(&fx.root_path, ResourceLimits::default()).expect("open");
        // Repeatedly replacing one path frees and recycles inode numbers while
        // other paths keep being created; none of that may look like a collision.
        for round in 0..32 {
            publish_bytes(&root, &["a"], format!("a{round}").as_bytes()).expect("a");
            publish_bytes(&root, &[format!("n{round}").as_str()], b"n").expect("n");
        }
    }

    #[test]
    fn existing_destination_objects_without_a_competing_archive_path_are_replaced() {
        let fx = fixture();
        fs::write(fx.root_path.join("keep"), b"old").expect("old");
        fs::write(fx.root_path.join("twin-a"), b"shared").expect("twin");
        fs::hard_link(fx.root_path.join("twin-a"), fx.root_path.join("twin-b")).expect("alias");
        fs::create_dir(fx.root_path.join("existing")).expect("dir");
        let root = ExtractionRoot::open(&fx.root_path, ResourceLimits::default()).expect("open");

        publish_bytes(&root, &["keep"], b"new").expect("replace pre-existing file");
        publish_bytes(&root, &["existing", "f"], b"x").expect("reuse pre-existing directory");
        // Pre-existing aliases are unrelated to each other: each archive path
        // replaces only its own name.
        publish_bytes(&root, &["twin-a"], b"a").expect("twin-a");
        publish_bytes(&root, &["twin-b"], b"b").expect("twin-b");
        assert_eq!(fs::read(fx.root_path.join("keep")).expect("read"), b"new");
        assert_eq!(fs::read(fx.root_path.join("twin-a")).expect("read"), b"a");
        assert_eq!(fs::read(fx.root_path.join("twin-b")).expect("read"), b"b");
    }

    #[test]
    fn alias_to_an_object_owned_by_another_path_is_refused_before_mutation() {
        let fx = fixture();
        let root = ExtractionRoot::open(&fx.root_path, ResourceLimits::default()).expect("open");
        publish_bytes(&root, &["sub", "first"], b"owner").expect("first");
        // A second name for the same object, as a folding or normalizing
        // filesystem would present for a differently spelled path.
        fs::hard_link(
            fx.root_path.join("sub/first"),
            fx.root_path.join("sub/alias"),
        )
        .expect("alias");

        let err = root
            .stage_file(&rel(&["sub", "alias"]))
            .err()
            .expect("refused");
        assert!(matches!(err, SarError::PathCollision(_)), "{err:?}");
        assert_eq!(
            entries(&fx.root_path.join("sub")),
            vec!["alias".to_string(), "first".to_string()],
            "no staging file was created"
        );
        assert_eq!(
            fs::read(fx.root_path.join("sub/first")).expect("read"),
            b"owner"
        );
        assert_eq!(
            fs::read(fx.root_path.join("sub/alias")).expect("read"),
            b"owner"
        );
        // The owning path itself is still a plain repeat.
        publish_bytes(&root, &["sub", "first"], b"again").expect("repeat");
    }

    #[test]
    fn alias_to_a_symlink_owned_by_another_path_is_refused() {
        let fx = fixture();
        let root = ExtractionRoot::open(&fx.root_path, ResourceLimits::default()).expect("open");
        root.create_symlink(&rel(&["one"]), "target")
            .expect("symlink");
        if fs::hard_link(fx.root_path.join("one"), fx.root_path.join("two")).is_err() {
            eprintln!("SKIPPED: hard links to symlinks are unavailable on this filesystem");
            return;
        }
        assert!(is_collision(root.create_symlink(&rel(&["two"]), "other")));
        assert!(is_collision(root.stage_file(&rel(&["two"])).map(drop)));
        assert_eq!(
            fs::read_link(fx.root_path.join("one")).expect("link"),
            Path::new("target")
        );
        assert_eq!(
            entries(&fx.root_path),
            vec!["one".to_string(), "two".to_string()]
        );
    }

    #[test]
    fn alias_appearing_after_staging_is_caught_before_publication() {
        for symlink_entry in [false, true] {
            let fx = fixture();
            let root =
                ExtractionRoot::open(&fx.root_path, ResourceLimits::default()).expect("open");
            publish_bytes(&root, &["first"], b"owner").expect("first");
            let first = fx.root_path.join("first");
            let alias = fx.root_path.join("alias");
            test_hooks::install(move |point| {
                if point == "before-publish" && !alias.exists() {
                    fs::hard_link(&first, &alias).expect("alias");
                }
            });
            let _guard = HookGuard;

            let result = if symlink_entry {
                root.create_symlink(&rel(&["alias"]), "t")
            } else {
                publish_bytes(&root, &["alias"], b"intruder")
            };

            assert!(is_collision(result), "symlink_entry={symlink_entry}");
            assert_eq!(
                fs::read(fx.root_path.join("first")).expect("read"),
                b"owner"
            );
            assert_eq!(
                fs::read(fx.root_path.join("alias")).expect("read"),
                b"owner"
            );
            assert!(
                entries(&fx.root_path)
                    .iter()
                    .all(|name| !name.starts_with(".sar-tmp-")),
                "staging object removed"
            );
        }
    }

    #[test]
    fn collisions_never_touch_objects_outside_the_root_and_symlinks_stay_refused() {
        let fx = fixture();
        let victim = fx.outside.join("victim");
        fs::write(&victim, b"keep").expect("victim");
        symlink(&fx.outside, fx.root_path.join("d")).expect("dir symlink");
        let root = ExtractionRoot::open(&fx.root_path, ResourceLimits::default()).expect("open");

        let err = root
            .stage_file(&rel(&["d", "victim"]))
            .err()
            .expect("refused");
        assert!(matches!(&err, SarError::PathEscape(_)), "{err:?}");
        assert_eq!(fs::read(&victim).expect("read"), b"keep");
        assert_eq!(entries(&fx.outside), vec!["victim".to_string()]);
    }

    #[test]
    fn collision_bookkeeping_is_bounded_by_the_pipeline_memory_limit() {
        let fx = fixture();
        let limits = ResourceLimits {
            max_total_pipeline_memory: 2048,
            ..ResourceLimits::default()
        };
        let root = ExtractionRoot::open(&fx.root_path, limits).expect("open");
        let mut failure = None;
        for index in 0..64 {
            let name = format!("f{index}");
            if let Err(err) = publish_bytes(&root, &[name.as_str()], b"x") {
                failure = Some(err);
                break;
            }
        }
        let err = failure.expect("limit reached");
        assert!(matches!(err, SarError::LimitExceeded(_)), "{err:?}");
        assert!(
            entries(&fx.root_path)
                .iter()
                .all(|name| !name.starts_with(".sar-tmp-"))
        );
    }

    #[test]
    fn case_insensitive_filesystems_report_collisions_for_differently_cased_paths() {
        let probe = probe_dir();
        if !fs_folds_case(probe.path()) {
            eprintln!("SKIPPED: destination filesystem is case-sensitive");
            return;
        }
        let root = ExtractionRoot::open(probe.path(), ResourceLimits::default()).expect("open");
        publish_bytes(&root, &["Readme"], b"upper").expect("first");
        assert!(is_collision(publish_bytes(&root, &["README"], b"lower")));
        assert_eq!(
            fs::read(probe.path().join("Readme")).expect("read"),
            b"upper"
        );

        // Nested: differently cased intermediate directories name one directory.
        publish_bytes(&root, &["Dir", "x"], b"x").expect("Dir/x");
        assert!(is_collision(publish_bytes(&root, &["dir", "y"], b"y")));
        assert!(is_collision(root.create_directory(&rel(&["DIR"]))));
        assert_eq!(entries(&probe.path().join("Dir")), vec!["x".to_string()]);
    }

    #[test]
    fn normalizing_filesystems_report_collisions_for_equivalent_unicode_paths() {
        let probe = probe_dir();
        if !fs_folds_unicode_normalization(probe.path()) {
            eprintln!("SKIPPED: destination filesystem does not normalize Unicode names");
            return;
        }
        let root = ExtractionRoot::open(probe.path(), ResourceLimits::default()).expect("open");
        publish_bytes(&root, &["caf\u{e9}"], b"nfc").expect("first");
        assert!(is_collision(publish_bytes(&root, &["cafe\u{301}"], b"nfd")));
        publish_bytes(&root, &["d\u{e9}", "f"], b"1").expect("nested first");
        assert!(is_collision(publish_bytes(
            &root,
            &["de\u{301}", "g"],
            b"2"
        )));
    }

    /// Ledger bytes for one top-level one-byte-named object: the logical node
    /// (128 + 1 component byte) plus the claimed object (128).
    const ONE_OBJECT_BUDGET: u64 = 128 + 1 + 128;

    fn tight(extra: i64) -> ResourceLimits {
        ResourceLimits {
            max_total_pipeline_memory: ONE_OBJECT_BUDGET.checked_add_signed(extra).expect("limit"),
            ..ResourceLimits::default()
        }
    }

    fn used(root: &ExtractionRoot) -> u64 {
        root.ledger.borrow().used_bytes()
    }

    fn publish_kind(
        root: &ExtractionRoot,
        symlink_entry: bool,
        name: &str,
    ) -> Result<(), SarError> {
        if symlink_entry {
            root.create_symlink(&rel(&[name]), "t")
        } else {
            publish_bytes(root, &[name], b"x")
        }
    }

    #[test]
    fn publication_at_the_exact_ledger_limit_succeeds_and_one_byte_less_fails_cleanly() {
        for symlink_entry in [false, true] {
            let fx = fixture();
            let root = ExtractionRoot::open(&fx.root_path, tight(0)).expect("open");
            publish_kind(&root, symlink_entry, "f").expect("exact limit");
            assert!(fs::symlink_metadata(fx.root_path.join("f")).is_ok());
            assert_eq!(used(&root), ONE_OBJECT_BUDGET);

            let fx = fixture();
            let root = ExtractionRoot::open(&fx.root_path, tight(-1)).expect("open");
            let err = publish_kind(&root, symlink_entry, "f").expect_err("one byte short");
            assert!(matches!(err, SarError::LimitExceeded(_)), "{err:?}");
            // Refused before publication: no final object, no staging leftovers.
            assert!(entries(&fx.root_path).is_empty(), "symlink={symlink_entry}");
            assert_eq!(used(&root), 128 + 1, "reservation was not retained");
        }
    }

    #[test]
    fn failed_rename_releases_the_reserved_capacity() {
        for symlink_entry in [false, true] {
            let fx = fixture();
            let root = ExtractionRoot::open(&fx.root_path, tight(0)).expect("open");
            let target = fx.root_path.join("f");
            // An unclaimed directory appearing at the final name makes the
            // rename fail after the reservation was taken.
            test_hooks::install(move |point| {
                if point == "before-publish" && !target.exists() {
                    fs::create_dir(&target).expect("obstacle");
                }
            });
            let guard = HookGuard;
            let err = publish_kind(&root, symlink_entry, "f").expect_err("rename fails");
            assert!(matches!(err, SarError::Io(_)), "{err:?}");
            drop(guard);
            assert_eq!(used(&root), 128 + 1, "reservation released");
            assert_eq!(entries(&fx.root_path), vec!["f".to_string()]);

            fs::remove_dir(fx.root_path.join("f")).expect("clear obstacle");
            publish_kind(&root, symlink_entry, "f").expect("capacity is available again");
            assert_eq!(used(&root), ONE_OBJECT_BUDGET);
        }
    }

    #[test]
    fn same_path_replacement_succeeds_under_a_tight_limit() {
        for symlink_entry in [false, true] {
            let fx = fixture();
            let root = ExtractionRoot::open(&fx.root_path, tight(0)).expect("open");
            for _ in 0..8 {
                publish_kind(&root, symlink_entry, "f").expect("replacement at the boundary");
                assert_eq!(used(&root), ONE_OBJECT_BUDGET);
            }
        }
    }

    #[test]
    fn collision_takes_precedence_over_the_ledger_limit() {
        let fx = fixture();
        let root = ExtractionRoot::open(&fx.root_path, tight(0)).expect("open");
        publish_bytes(&root, &["f"], b"owner").expect("first");
        fs::hard_link(fx.root_path.join("f"), fx.root_path.join("g")).expect("alias");
        // "g" would not fit, but the alias is reported as the collision it is.
        assert!(is_collision(publish_bytes(&root, &["g"], b"x")));
        assert!(is_collision(root.create_symlink(&rel(&["g"]), "t")));
    }
}
