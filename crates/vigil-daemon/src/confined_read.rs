//! Linux descriptor-bound reads. No pathname is reopened after authorization.
use crate::Result;
use rustix::fs::{open, openat2, Mode, OFlags, ResolveFlags, CWD};
use std::fs::File;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

pub const MAX_READ: u64 = 4096;

pub struct ConfinedWorkspace(File);

pub struct OpenedRead {
    file: File,
    pub device: u64,
    pub inode: u64,
}

impl ConfinedWorkspace {
    pub fn open(path: &Path, agent_uid: u32) -> Result<Self> {
        let file = File::from(openat2(
            CWD,
            path,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS,
        )?);
        if file.metadata()?.uid() != agent_uid {
            return Err("workspace must belong to the configured agent".into());
        }
        Ok(Self(file))
    }

    pub fn prepare(&self, resource: &str, agent_uid: u32) -> Result<OpenedRead> {
        let path = Path::new(resource);
        if resource.is_empty()
            || path.is_absolute()
            || path
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err("read requires a relative path without traversal".into());
        }
        // O_PATH inspects the object without invoking a device's open handler or
        // waiting for a FIFO writer. The kernel resolves beneath the pinned root.
        let pinned = File::from(openat2(
            &self.0,
            path,
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_XDEV,
        )?);
        let meta = pinned.metadata()?;
        if !meta.is_file() || meta.uid() != agent_uid || meta.nlink() != 1 || meta.len() > MAX_READ
        {
            return Err("read requires a bounded, singly linked, agent-owned regular file".into());
        }
        // Linux cannot read an O_PATH descriptor. Reopen our own pinned descriptor,
        // never the caller's path. /proc and the process descriptor table are trusted
        // OS infrastructure; lack of procfs is a hard failure, with no path fallback.
        let file = File::from(open(
            format!("/proc/self/fd/{}", pinned.as_raw_fd()),
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let reopened = file.metadata()?;
        if reopened.dev() != meta.dev()
            || reopened.ino() != meta.ino()
            || !reopened.is_file()
            || reopened.uid() != agent_uid
            || reopened.nlink() != 1
        {
            return Err("pinned read identity changed".into());
        }
        Ok(OpenedRead {
            file,
            device: meta.dev(),
            inode: meta.ino(),
        })
    }
}

impl OpenedRead {
    pub fn read(self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.file.take(MAX_READ + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_READ {
            return Err("file grew beyond read limit".into());
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("vigil-read-{}", rand::random::<u64>()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn workspace(&self) -> ConfinedWorkspace {
            ConfinedWorkspace::open(&self.0, rustix::process::geteuid().as_raw()).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn path_replacement_cannot_redirect_an_open_read() {
        let f = Fixture::new();
        let uid = rustix::process::geteuid().as_raw();
        fs::write(f.0.join("safe"), b"original").unwrap();
        let opened = f.workspace().prepare("safe", uid).unwrap();
        fs::rename(f.0.join("safe"), f.0.join("old")).unwrap();
        symlink("/etc/passwd", f.0.join("safe")).unwrap();
        assert_eq!(opened.read().unwrap(), b"original");
    }

    #[test]
    fn links_traversal_and_wrong_owner_are_refused() {
        let f = Fixture::new();
        let uid = rustix::process::geteuid().as_raw();
        fs::write(f.0.join("safe"), b"safe").unwrap();
        symlink("safe", f.0.join("link")).unwrap();
        symlink("/etc", f.0.join("dirlink")).unwrap();
        let w = f.workspace();
        for path in [
            "",
            "../safe",
            "/etc/passwd",
            "link",
            "dirlink/passwd",
            "safe/../safe",
        ] {
            assert!(w.prepare(path, uid).is_err(), "{path}");
        }
        assert!(w.prepare("safe", uid.wrapping_add(1)).is_err());
        fs::hard_link(f.0.join("safe"), f.0.join("hard")).unwrap();
        assert!(w.prepare("hard", uid).is_err());
    }

    #[test]
    fn oversized_files_and_growth_are_refused() {
        let f = Fixture::new();
        let uid = rustix::process::geteuid().as_raw();
        fs::write(f.0.join("safe"), b"small").unwrap();
        let w = f.workspace();
        let opened = w.prepare("safe", uid).unwrap();
        fs::write(f.0.join("safe"), vec![0; MAX_READ as usize + 1]).unwrap();
        assert!(opened.read().is_err());
        assert!(w.prepare("safe", uid).is_err());
    }

    #[test]
    fn workspace_replacement_does_not_rebind_root() {
        let f = Fixture::new();
        let uid = rustix::process::geteuid().as_raw();
        let root = f.0.join("root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("safe"), b"original").unwrap();
        let w = ConfinedWorkspace::open(&root, uid).unwrap();
        fs::rename(&root, f.0.join("old-root")).unwrap();
        fs::create_dir(&root).unwrap();
        fs::write(root.join("safe"), b"replacement").unwrap();
        assert_eq!(w.prepare("safe", uid).unwrap().read().unwrap(), b"original");
    }
}
