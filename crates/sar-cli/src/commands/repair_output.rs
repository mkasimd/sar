// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Secure publication of the `repair` output archive (`M13-EXTRACT-007`).
//!
//! Confinement model (Unix): the output's parent directory is resolved exactly
//! once, as the caller wrote it, and held as an open directory descriptor.
//! Every later step is a `*at` call relative to that descriptor, so replacing
//! any component of the output path afterwards cannot redirect staging or
//! publication: the kernel keeps operating on the directory that was opened.
//!
//! Staging file: created exclusively (`O_CREAT | O_EXCL | O_NOFOLLOW`) with a
//! random private name and mode `0600`, so a pre-existing object of any kind
//! (including a symlink) at that name is never opened, truncated or followed.
//! The repaired bytes are written and verified through the staged descriptor,
//! never by reopening a pathname. Before publication the staging name is
//! checked to still reach the object this run created (device and inode), and
//! the file receives the mode a plain create would have had. The staging file
//! is then renamed over the requested name inside the same directory. A
//! symlink at the requested name is replaced, never followed.
//!
//! Residual race: POSIX has no identity-checked `rename` or `unlink`. Between
//! the identity check and the `renameat`/`unlinkat` that follows, a process
//! with write access to the output directory can still substitute the staging
//! name. Publication re-checks the final name afterwards and fails if it does
//! not reach the staged object, and cleanup never removes an object whose
//! identity differs, but neither can undo a substitution inside that window.
//! Targets without this backend refuse the repair output operation.

#[cfg(unix)]
pub(crate) use imp::write_verified_output;
#[cfg(not(unix))]
pub(crate) use unsupported::{require_secure_output_backend, write_verified_output};

#[cfg(not(unix))]
mod unsupported {
    use std::{fs::File, path::Path};

    use sar_core::SarError;

    /// Without descriptor-relative primitives no path-based substitute can
    /// meet the staging requirements, so the output operation is refused.
    pub(crate) fn require_secure_output_backend() -> Result<(), SarError> {
        Err(SarError::Unsupported(
            "secure repair output is not implemented on this platform",
        ))
    }

    pub(crate) fn write_verified_output(
        _output: &Path,
        _bytes: &[u8],
        _verify: &mut dyn FnMut(&File) -> Result<(), SarError>,
    ) -> Result<(), SarError> {
        require_secure_output_backend()
    }
}

#[cfg(unix)]
mod imp {
    use std::{
        fs::File,
        io::{self, Seek, Write},
        os::unix::ffi::OsStrExt,
        path::Path,
    };

    use rustix::{
        fd::OwnedFd,
        fs::{AtFlags, FileType, Mode, OFlags, RawMode, Stat},
        io::Errno,
    };
    use sar_core::SarError;

    const TEMP_PREFIX: &str = ".sar-repair-";
    const TEMP_RANDOM_BYTES: usize = 16;
    const TEMP_ATTEMPTS: usize = 16;
    const STAGING_MODE: RawMode = 0o600;
    const PROBE_MODE: RawMode = 0o666;

    #[cfg(test)]
    pub(super) mod test_hooks {
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

    /// What became of the staging file after a failure.
    #[derive(Debug)]
    pub(super) enum Cleanup {
        /// No staging file existed.
        NotNeeded,
        /// The staging file was identified and removed.
        Removed,
        /// The staging name no longer reaches anything.
        Gone,
        /// The name reaches an object this run did not create, or the staged
        /// object could not be identified; it was deliberately left alone.
        Refused(&'static str),
        /// Removal of the identified staging file failed.
        Failed(io::Error),
    }

    #[derive(Debug)]
    pub(super) struct Failure {
        pub(super) error: SarError,
        pub(super) cleanup: Cleanup,
        pub(super) temp_name: Option<String>,
    }

    impl Failure {
        fn clean(error: SarError) -> Self {
            Self {
                error,
                cleanup: Cleanup::NotNeeded,
                temp_name: None,
            }
        }
    }

    enum Stage {
        /// The requested output was not touched.
        Unpublished(SarError),
        /// The rename succeeded; no staging file remains to clean up.
        Published(SarError),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Identity {
        device: u64,
        inode: u64,
    }

    fn io_error(errno: Errno) -> SarError {
        SarError::Io(io::Error::from(errno))
    }

    fn widen<T: TryInto<u64>>(value: T) -> Result<u64, SarError> {
        value
            .try_into()
            .map_err(|_| SarError::Overflow("filesystem object identity"))
    }

    fn identity(stat: &Stat) -> Result<Identity, SarError> {
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(SarError::Internal(
                "repair staging object is not a regular file",
            ));
        }
        Ok(Identity {
            device: widen(stat.st_dev)?,
            inode: widen(stat.st_ino)?,
        })
    }

    fn fresh_temp_name() -> Result<String, SarError> {
        let mut random = [0u8; TEMP_RANDOM_BYTES];
        getrandom::fill(&mut random)
            .map_err(|_| SarError::Internal("system randomness unavailable"))?;
        let mut name = String::from(TEMP_PREFIX);
        for byte in random {
            name.push_str(&format!("{byte:02x}"));
        }
        Ok(name)
    }

    /// Creates a file exclusively under a fresh name, retrying a bounded number
    /// of times when the name is taken. An existing object is never opened.
    fn create_exclusive(
        dir: &OwnedFd,
        flags: OFlags,
        mode: RawMode,
        names: &mut dyn FnMut() -> Result<String, SarError>,
    ) -> Result<(File, String), SarError> {
        let mode = Mode::from_raw_mode(mode);
        for _ in 0..TEMP_ATTEMPTS {
            let name = names()?;
            match rustix::fs::openat(
                dir,
                name.as_str(),
                flags | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                mode,
            ) {
                Ok(fd) => return Ok((File::from(fd), name)),
                Err(Errno::EXIST) => {}
                Err(errno) => return Err(io_error(errno)),
            }
        }
        Err(SarError::Io(io::Error::from(io::ErrorKind::AlreadyExists)))
    }

    /// Removes `name` only while it still reaches the object with `id`.
    fn discard(dir: &OwnedFd, name: &str, id: Identity) -> Cleanup {
        match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(Errno::NOENT) => Cleanup::Gone,
            Err(errno) => Cleanup::Failed(io::Error::from(errno)),
            Ok(stat) => match identity(&stat) {
                Ok(current) if current == id => {
                    match rustix::fs::unlinkat(dir, name, AtFlags::empty()) {
                        Ok(()) | Err(Errno::NOENT) => Cleanup::Removed,
                        Err(errno) => Cleanup::Failed(io::Error::from(errno)),
                    }
                }
                _ => Cleanup::Refused(
                    "the staging name no longer reaches the object this run created",
                ),
            },
        }
    }

    /// Mode an ordinary `creat(0666)` in `dir` would produce (umask and default
    /// ACLs included), learned from an empty probe file so the process umask is
    /// never read or changed.
    fn default_file_mode(
        dir: &OwnedFd,
        names: &mut dyn FnMut() -> Result<String, SarError>,
    ) -> Result<Mode, Failure> {
        probe_mode(dir, names, &mut |probe| {
            rustix::fs::fstat(probe).map_err(io_error)
        })
    }

    /// Every path after the exclusive probe creation accounts for the probe: it
    /// is removed only while its name still reaches the object this run
    /// created, and an unidentifiable, substituted or unremovable probe is
    /// reported as the failure's cleanup state instead of being deleted or
    /// ignored. A probe that remains is never a success.
    fn probe_mode(
        dir: &OwnedFd,
        names: &mut dyn FnMut() -> Result<String, SarError>,
        inspect: &mut dyn FnMut(&File) -> Result<Stat, SarError>,
    ) -> Result<Mode, Failure> {
        let (probe, name) =
            create_exclusive(dir, OFlags::WRONLY, PROBE_MODE, names).map_err(Failure::clean)?;
        let left = |error, cleanup| Failure {
            error,
            cleanup,
            temp_name: Some(name.clone()),
        };
        let stat = match inspect(&probe) {
            Ok(stat) => stat,
            Err(error) => {
                return Err(left(
                    error,
                    Cleanup::Refused("the permission probe could not be identified"),
                ));
            }
        };
        let id = match identity(&stat) {
            Ok(id) => id,
            Err(error) => {
                return Err(left(
                    error,
                    Cleanup::Refused("the permission probe could not be identified"),
                ));
            }
        };
        hook("probe-created");
        match discard(dir, &name, id) {
            Cleanup::Removed | Cleanup::Gone => Ok(Mode::from_raw_mode(stat.st_mode & 0o777)),
            Cleanup::Failed(err) => Err(left(
                SarError::Internal("the permission probe could not be removed"),
                Cleanup::Failed(err),
            )),
            Cleanup::Refused(why) => Err(left(
                SarError::Internal("the permission probe was replaced before cleanup"),
                Cleanup::Refused(why),
            )),
            Cleanup::NotNeeded => Err(left(
                SarError::Internal("the permission probe state is unknown"),
                Cleanup::Refused("the permission probe state is unknown"),
            )),
        }
    }

    fn open_parent(parent: &Path) -> Result<OwnedFd, SarError> {
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        rustix::fs::open(
            parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io_error)
    }

    /// Splits the requested output into its parent directory and a final name
    /// that is a single plain component.
    fn split_output(output: &Path) -> Result<(&Path, &str), SarError> {
        let raw = output.as_os_str().as_bytes();
        let tail = raw.rsplit(|b| *b == b'/').next().unwrap_or(raw);
        let name = output
            .file_name()
            .filter(|name| name.as_bytes() == tail)
            .and_then(|name| name.to_str())
            .ok_or(SarError::InvalidInput(
                "repair output must name a file (not a directory path, '.' or '..')",
            ))?;
        Ok((output.parent().unwrap_or(Path::new("")), name))
    }

    /// Stages, verifies and publishes `bytes` as `output`. `verify` receives the
    /// staged descriptor rewound to the start. On failure the primary error is
    /// returned and a cleanup problem is reported separately on stderr.
    pub(crate) fn write_verified_output(
        output: &Path,
        bytes: &[u8],
        verify: &mut dyn FnMut(&File) -> Result<(), SarError>,
    ) -> Result<(), SarError> {
        write_with_names(output, bytes, verify, &mut fresh_temp_name).map_err(report)
    }

    fn report(failure: Failure) -> SarError {
        let temp = failure.temp_name.as_deref().unwrap_or("<none>");
        match &failure.cleanup {
            Cleanup::Refused(why) => {
                eprintln!("repair: warning: left staging file {temp} in place: {why}")
            }
            Cleanup::Failed(err) => {
                eprintln!("repair: warning: could not remove staging file {temp}: {err}");
            }
            Cleanup::NotNeeded | Cleanup::Removed | Cleanup::Gone => {}
        }
        failure.error
    }

    pub(super) fn write_with_names(
        output: &Path,
        bytes: &[u8],
        verify: &mut dyn FnMut(&File) -> Result<(), SarError>,
        names: &mut dyn FnMut() -> Result<String, SarError>,
    ) -> Result<(), Failure> {
        let (parent, name) = split_output(output).map_err(Failure::clean)?;
        let dir = open_parent(parent).map_err(Failure::clean)?;
        publish_in(&dir, name, bytes, verify, names)
    }

    fn publish_in(
        dir: &OwnedFd,
        final_name: &str,
        bytes: &[u8],
        verify: &mut dyn FnMut(&File) -> Result<(), SarError>,
        names: &mut dyn FnMut() -> Result<String, SarError>,
    ) -> Result<(), Failure> {
        let mode = default_file_mode(dir, names)?;
        let (mut file, temp) =
            create_exclusive(dir, OFlags::RDWR, STAGING_MODE, names).map_err(Failure::clean)?;
        let id = match rustix::fs::fstat(&file)
            .map_err(io_error)
            .and_then(|stat| identity(&stat))
        {
            Ok(id) => id,
            Err(error) => {
                return Err(Failure {
                    error,
                    cleanup: Cleanup::Refused("the staged object could not be identified"),
                    temp_name: Some(temp),
                });
            }
        };
        match stage_and_publish(dir, &temp, final_name, id, mode, &mut file, bytes, verify) {
            Ok(()) => Ok(()),
            Err(Stage::Published(error)) => Err(Failure {
                error,
                cleanup: Cleanup::NotNeeded,
                temp_name: Some(temp),
            }),
            Err(Stage::Unpublished(error)) => {
                let cleanup = discard(dir, &temp, id);
                Err(Failure {
                    error,
                    cleanup,
                    temp_name: Some(temp),
                })
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn stage_and_publish(
        dir: &OwnedFd,
        temp: &str,
        final_name: &str,
        id: Identity,
        mode: Mode,
        file: &mut File,
        bytes: &[u8],
        verify: &mut dyn FnMut(&File) -> Result<(), SarError>,
    ) -> Result<(), Stage> {
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .and_then(|()| file.rewind())
            .map_err(|err| Stage::Unpublished(SarError::Io(err)))?;
        hook("after-stage");
        verify(file).map_err(Stage::Unpublished)?;
        rustix::fs::fchmod(&*file, mode).map_err(|errno| Stage::Unpublished(io_error(errno)))?;
        hook("before-publish");

        let current = rustix::fs::statat(dir, temp, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|errno| Stage::Unpublished(io_error(errno)))?;
        if identity(&current).ok() != Some(id) {
            return Err(Stage::Unpublished(SarError::PathEscape(
                "repair staging file was replaced before publication",
            )));
        }
        rustix::fs::renameat(dir, temp, dir, final_name)
            .map_err(|errno| Stage::Unpublished(io_error(errno)))?;

        match rustix::fs::statat(dir, final_name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) if identity(&stat).ok() == Some(id) => Ok(()),
            _ => Err(Stage::Published(SarError::PathEscape(
                "repair output does not reach the verified staged file after publication",
            ))),
        }
    }

    #[cfg(test)]
    mod tests {
        use std::{
            cell::Cell,
            fs,
            os::unix::{fs::PermissionsExt, fs::symlink},
            path::PathBuf,
            rc::Rc,
        };

        use tempfile::tempdir;

        use super::{test_hooks, *};

        fn ok_verify() -> impl FnMut(&File) -> Result<(), SarError> {
            |file| {
                use std::io::Read;
                let mut head = [0u8; 4];
                let mut file = file;
                file.read_exact(&mut head)
                    .map_err(|_| SarError::Malformed("staged file is not readable from 0"))?;
                assert_eq!(&head, b"NEW!");
                Ok(())
            }
        }

        fn failing_verify() -> impl FnMut(&File) -> Result<(), SarError> {
            |_| Err(SarError::Malformed("verification rejected"))
        }

        fn run(
            output: &Path,
            verify: &mut dyn FnMut(&File) -> Result<(), SarError>,
        ) -> Result<(), Failure> {
            test_hooks::clear();
            write_with_names(output, b"NEW! repaired", verify, &mut fresh_temp_name)
        }

        fn names_in(dir: &Path) -> Vec<String> {
            let mut names: Vec<String> = fs::read_dir(dir)
                .expect("read_dir")
                .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        }

        #[test]
        fn publishes_verified_bytes_with_default_mode_and_no_leftovers() {
            let td = tempdir().expect("tmp");
            let out = td.path().join("out.sar");
            run(&out, &mut ok_verify()).expect("publish");
            assert_eq!(fs::read(&out).expect("read"), b"NEW! repaired");
            assert_eq!(names_in(td.path()), ["out.sar"]);
            let mode = fs::metadata(&out).expect("meta").permissions().mode() & 0o777;
            assert_ne!(mode, 0, "mode must come from the default create mode");
            assert_eq!(mode & !0o666, 0, "no execute bits");
        }

        #[test]
        fn replaces_existing_output() {
            let td = tempdir().expect("tmp");
            let out = td.path().join("out.sar");
            fs::write(&out, b"old").expect("write");
            run(&out, &mut ok_verify()).expect("publish");
            assert_eq!(fs::read(&out).expect("read"), b"NEW! repaired");
        }

        #[test]
        fn destination_symlink_is_replaced_not_followed() {
            let td = tempdir().expect("tmp");
            let victim = td.path().join("victim");
            fs::write(&victim, b"victim").expect("write");
            let out = td.path().join("out.sar");
            symlink(&victim, &out).expect("symlink");
            run(&out, &mut ok_verify()).expect("publish");
            assert_eq!(fs::read(&victim).expect("read"), b"victim");
            assert!(
                !fs::symlink_metadata(&out)
                    .expect("meta")
                    .file_type()
                    .is_symlink()
            );
            assert_eq!(fs::read(&out).expect("read"), b"NEW! repaired");
        }

        #[test]
        fn legacy_tmp_name_symlink_and_file_are_untouched() {
            let td = tempdir().expect("tmp");
            let victim = td.path().join("victim");
            fs::write(&victim, b"victim").expect("write");
            let out = td.path().join("out.sar");
            symlink(&victim, td.path().join("out.sar.tmp")).expect("symlink");
            run(&out, &mut ok_verify()).expect("publish");
            assert_eq!(fs::read(&victim).expect("read"), b"victim");
            assert!(
                fs::symlink_metadata(td.path().join("out.sar.tmp"))
                    .expect("meta")
                    .file_type()
                    .is_symlink()
            );

            let td = tempdir().expect("tmp");
            let out = td.path().join("out.sar");
            let legacy = td.path().join("out.sar.tmp");
            fs::write(&legacy, b"keep me").expect("write");
            run(&out, &mut ok_verify()).expect("publish");
            assert_eq!(fs::read(&legacy).expect("read"), b"keep me");
            assert_eq!(fs::read(&out).expect("read"), b"NEW! repaired");
        }

        #[test]
        fn name_collisions_are_skipped_and_never_followed_or_truncated() {
            let td = tempdir().expect("tmp");
            let victim = td.path().join("victim");
            fs::write(&victim, b"victim").expect("write");
            fs::write(td.path().join(".sar-a"), b"keep").expect("write");
            symlink(&victim, td.path().join(".sar-b")).expect("symlink");
            let mut queue2: Vec<&str> = vec![".sar-probe", ".sar-a", ".sar-b", ".sar-c"];
            queue2.reverse();
            let mut names2 = || Ok(queue2.pop().expect("name").to_owned());
            let out = td.path().join("out.sar");
            test_hooks::clear();
            write_with_names(&out, b"NEW! repaired", &mut ok_verify(), &mut names2)
                .expect("publish");
            assert_eq!(fs::read(td.path().join(".sar-a")).expect("read"), b"keep");
            assert_eq!(fs::read(&victim).expect("read"), b"victim");
            assert!(
                fs::symlink_metadata(td.path().join(".sar-b"))
                    .expect("meta")
                    .file_type()
                    .is_symlink()
            );
            assert_eq!(fs::read(&out).expect("read"), b"NEW! repaired");
            assert!(!td.path().join(".sar-c").exists());
        }

        #[test]
        fn name_generation_retries_are_bounded() {
            let td = tempdir().expect("tmp");
            fs::write(td.path().join(".sar-taken"), b"keep").expect("write");
            let calls = Cell::new(0usize);
            let mut names = || {
                calls.set(calls.get() + 1);
                Ok(".sar-taken".to_owned())
            };
            // Probe also collides, so the bound is hit during probing.
            let out = td.path().join("out.sar");
            test_hooks::clear();
            let failure = write_with_names(&out, b"NEW!", &mut ok_verify(), &mut names)
                .expect_err("must fail");
            assert!(
                matches!(failure.error, SarError::Io(ref e) if e.kind() == io::ErrorKind::AlreadyExists)
            );
            assert_eq!(calls.get(), TEMP_ATTEMPTS);
            assert_eq!(
                fs::read(td.path().join(".sar-taken")).expect("read"),
                b"keep"
            );
            assert!(!out.exists());
        }

        #[test]
        fn staging_name_collisions_exhaust_after_bounded_attempts() {
            let td = tempdir().expect("tmp");
            fs::write(td.path().join(".sar-taken"), b"keep").expect("write");
            let calls = Cell::new(0usize);
            let mut names = || {
                let n = calls.get();
                calls.set(n + 1);
                Ok(if n == 0 {
                    ".sar-probe".to_owned()
                } else {
                    ".sar-taken".to_owned()
                })
            };
            let out = td.path().join("out.sar");
            test_hooks::clear();
            let failure = write_with_names(&out, b"NEW!", &mut ok_verify(), &mut names)
                .expect_err("must fail");
            assert!(
                matches!(failure.error, SarError::Io(ref e) if e.kind() == io::ErrorKind::AlreadyExists)
            );
            assert_eq!(calls.get(), 1 + TEMP_ATTEMPTS);
            assert!(matches!(failure.cleanup, Cleanup::NotNeeded));
            assert_eq!(names_in(td.path()), [".sar-taken"]);
        }

        #[test]
        fn verification_failure_removes_staging_file_and_keeps_existing_output() {
            let td = tempdir().expect("tmp");
            let out = td.path().join("out.sar");
            fs::write(&out, b"old").expect("write");
            let failure = run(&out, &mut failing_verify()).expect_err("must fail");
            assert!(matches!(
                failure.error,
                SarError::Malformed("verification rejected")
            ));
            assert!(matches!(failure.cleanup, Cleanup::Removed));
            assert_eq!(fs::read(&out).expect("read"), b"old");
            assert_eq!(names_in(td.path()), ["out.sar"]);
        }

        #[test]
        fn publication_failure_preserves_primary_error_and_removes_staging_file() {
            let td = tempdir().expect("tmp");
            let out = td.path().join("out.sar");
            fs::create_dir(&out).expect("dir");
            let failure = run(&out, &mut ok_verify()).expect_err("must fail");
            assert!(matches!(failure.error, SarError::Io(_)));
            assert!(matches!(failure.cleanup, Cleanup::Removed));
            assert!(out.is_dir());
            assert_eq!(names_in(td.path()), ["out.sar"]);
        }

        fn temp_in(dir: &Path) -> PathBuf {
            names_in(dir)
                .into_iter()
                .find(|n| n.starts_with(TEMP_PREFIX))
                .map(|n| dir.join(n))
                .expect("staging file")
        }

        #[test]
        fn staging_substitution_before_publication_is_refused_and_left_alone() {
            for as_symlink in [false, true] {
                let td = tempdir().expect("tmp");
                let dir = td.path().to_path_buf();
                let victim = dir.join("victim");
                fs::write(&victim, b"victim").expect("write");
                let out = dir.join("out.sar");
                fs::write(&out, b"old").expect("write");
                let seen = Rc::new(Cell::new(false));
                let seen_hook = Rc::clone(&seen);
                let hook_dir = dir.clone();
                let hook_victim = victim.clone();
                test_hooks::install(move |point| {
                    if point == "before-publish" {
                        let temp = temp_in(&hook_dir);
                        fs::remove_file(&temp).expect("remove");
                        if as_symlink {
                            symlink(&hook_victim, &temp).expect("symlink");
                        } else {
                            fs::write(&temp, b"attacker").expect("write");
                        }
                        seen_hook.set(true);
                    }
                });
                let failure = write_with_names(
                    &out,
                    b"NEW! repaired",
                    &mut ok_verify(),
                    &mut fresh_temp_name,
                )
                .expect_err("must fail");
                test_hooks::clear();
                assert!(seen.get());
                assert!(matches!(failure.error, SarError::PathEscape(_)));
                assert!(matches!(failure.cleanup, Cleanup::Refused(_)));
                assert_eq!(fs::read(&out).expect("read"), b"old");
                assert_eq!(fs::read(&victim).expect("read"), b"victim");
                let leftover = temp_in(&dir);
                if as_symlink {
                    assert!(
                        fs::symlink_metadata(&leftover)
                            .expect("meta")
                            .file_type()
                            .is_symlink()
                    );
                } else {
                    assert_eq!(fs::read(&leftover).expect("read"), b"attacker");
                }
            }
        }

        #[test]
        fn verification_failure_with_substituted_staging_file_reports_refused_cleanup() {
            let td = tempdir().expect("tmp");
            let dir = td.path().to_path_buf();
            let out = dir.join("out.sar");
            let hook_dir = dir.clone();
            test_hooks::install(move |point| {
                if point == "after-stage" {
                    let temp = temp_in(&hook_dir);
                    fs::remove_file(&temp).expect("remove");
                    fs::write(&temp, b"attacker").expect("write");
                }
            });
            let failure = write_with_names(
                &out,
                b"NEW! repaired",
                &mut failing_verify(),
                &mut fresh_temp_name,
            )
            .expect_err("must fail");
            test_hooks::clear();
            assert!(matches!(
                failure.error,
                SarError::Malformed("verification rejected")
            ));
            assert!(matches!(failure.cleanup, Cleanup::Refused(_)));
            assert_eq!(fs::read(temp_in(&dir)).expect("read"), b"attacker");
            assert!(!out.exists());
        }

        #[test]
        fn parent_component_substitution_cannot_redirect_publication() {
            let td = tempdir().expect("tmp");
            let base = td.path();
            let sub = base.join("sub");
            fs::create_dir(&sub).expect("dir");
            let moved = base.join("moved");
            let hook_sub = sub.clone();
            let hook_moved = moved.clone();
            test_hooks::install(move |point| {
                if point == "before-publish" {
                    fs::rename(&hook_sub, &hook_moved).expect("rename");
                    fs::create_dir(&hook_sub).expect("attacker dir");
                    symlink("/nonexistent-target", hook_sub.join("out.sar")).expect("symlink");
                }
            });
            let out = sub.join("out.sar");
            write_with_names(
                &out,
                b"NEW! repaired",
                &mut ok_verify(),
                &mut fresh_temp_name,
            )
            .expect("publish into the originally opened directory");
            test_hooks::clear();
            assert_eq!(
                fs::read(moved.join("out.sar")).expect("read"),
                b"NEW! repaired"
            );
            assert_eq!(names_in(&moved), ["out.sar"]);
            assert_eq!(names_in(&sub), ["out.sar"]);
            assert!(
                fs::symlink_metadata(sub.join("out.sar"))
                    .expect("meta")
                    .file_type()
                    .is_symlink()
            );
        }

        #[test]
        fn probe_inspection_failure_is_reported_and_probe_is_not_deleted() {
            let td = tempdir().expect("tmp");
            let dir = open_parent(td.path()).expect("dir");
            let mut names = || Ok(".sar-probe".to_owned());
            let failure = probe_mode(&dir, &mut names, &mut |_| {
                Err(SarError::Io(io::Error::from(
                    io::ErrorKind::PermissionDenied,
                )))
            })
            .expect_err("must fail");
            assert!(matches!(failure.error, SarError::Io(_)));
            assert!(matches!(failure.cleanup, Cleanup::Refused(_)));
            assert_eq!(failure.temp_name.as_deref(), Some(".sar-probe"));
            assert!(td.path().join(".sar-probe").exists());
        }

        #[test]
        fn unchanged_probe_is_removed_and_yields_the_default_mode() {
            let td = tempdir().expect("tmp");
            let dir = open_parent(td.path()).expect("dir");
            let mut names = || Ok(".sar-probe".to_owned());
            test_hooks::clear();
            let mode = probe_mode(&dir, &mut names, &mut |p| {
                rustix::fs::fstat(p).map_err(io_error)
            })
            .expect("mode");
            assert_ne!(mode.as_raw_mode() & 0o600, 0);
            assert!(names_in(td.path()).is_empty());
        }

        #[test]
        fn substituted_probe_is_not_deleted_and_is_reported() {
            for as_symlink in [false, true] {
                let td = tempdir().expect("tmp");
                let victim = td.path().join("victim");
                fs::write(&victim, b"victim").expect("write");
                let probe = td.path().join(".sar-probe");
                let (hook_probe, hook_victim) = (probe.clone(), victim.clone());
                test_hooks::install(move |point| {
                    if point == "probe-created" {
                        fs::remove_file(&hook_probe).expect("remove");
                        if as_symlink {
                            symlink(&hook_victim, &hook_probe).expect("symlink");
                        } else {
                            fs::write(&hook_probe, b"attacker").expect("write");
                        }
                    }
                });
                let dir = open_parent(td.path()).expect("dir");
                let mut names = || Ok(".sar-probe".to_owned());
                let failure = probe_mode(&dir, &mut names, &mut |p| {
                    rustix::fs::fstat(p).map_err(io_error)
                })
                .expect_err("must fail");
                test_hooks::clear();
                assert!(matches!(failure.error, SarError::Internal(_)));
                assert!(matches!(failure.cleanup, Cleanup::Refused(_)));
                assert_eq!(failure.temp_name.as_deref(), Some(".sar-probe"));
                assert_eq!(fs::read(&victim).expect("read"), b"victim");
                if as_symlink {
                    assert!(
                        fs::symlink_metadata(&probe)
                            .expect("meta")
                            .file_type()
                            .is_symlink()
                    );
                } else {
                    assert_eq!(fs::read(&probe).expect("read"), b"attacker");
                }
            }
        }

        #[test]
        fn probe_substitution_fails_the_whole_repair_without_publishing() {
            let td = tempdir().expect("tmp");
            let out = td.path().join("out.sar");
            fs::write(&out, b"old").expect("write");
            let dir_path = td.path().to_path_buf();
            test_hooks::install(move |point| {
                if point == "probe-created" {
                    let probe = names_in(&dir_path)
                        .into_iter()
                        .find(|n| n.starts_with(TEMP_PREFIX))
                        .expect("probe");
                    fs::remove_file(dir_path.join(&probe)).expect("remove");
                    fs::write(dir_path.join(&probe), b"attacker").expect("write");
                }
            });
            let failure = write_with_names(
                &out,
                b"NEW! repaired",
                &mut ok_verify(),
                &mut fresh_temp_name,
            )
            .expect_err("must fail");
            test_hooks::clear();
            assert!(matches!(failure.cleanup, Cleanup::Refused(_)));
            assert_eq!(fs::read(&out).expect("read"), b"old");
            assert_eq!(
                names_in(td.path()).len(),
                2,
                "output plus the left-alone object"
            );
        }

        #[test]
        fn output_must_name_a_plain_file() {
            for bad in ["", ".", "..", "dir/", "dir/.", "dir/..", "/"] {
                let failure = write_with_names(
                    Path::new(bad),
                    b"NEW!",
                    &mut ok_verify(),
                    &mut fresh_temp_name,
                )
                .expect_err(bad);
                assert!(matches!(failure.error, SarError::InvalidInput(_)), "{bad}");
            }
        }
    }
}
