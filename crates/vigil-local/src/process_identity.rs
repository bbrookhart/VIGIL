//! Deciding whether a PID still names the process VIGIL recorded.
//!
//! # Why
//!
//! A PID is not an identity. It is a small integer the kernel reuses, and on macOS it wraps
//! at around 99998. Signalling by PID alone means that between recording a process and
//! deciding to stop it, the number may have been handed to something else — a shell, a build
//! job, the user's editor. Killing the wrong process is worse than failing to contain an
//! agent, so termination refuses to act unless the process still matches what was recorded.
//!
//! # What
//!
//! A process is identified by `(pid, os_started_at, executable)`. The kernel's start time is
//! the discriminator: a recycled PID belongs to a process that started later, so its start
//! time differs. The executable is compared as well, so a mismatch is caught even in the
//! degenerate case where the clock reading is equal.
//!
//! Identity is read with `ps`, not with a system call. This crate is `#![forbid(unsafe_code)]`
//! and every route to `sysctl`/`proc_pidinfo` is FFI, so the choice is a bounded subprocess or
//! nothing. `ps` is in the base system, is not resolved through `PATH`, and is run with a
//! deadline and no inherited stdin.
//!
//! # Assumptions
//!
//! `lstart` has one-second granularity. Distinguishing two processes that share a PID
//! therefore fails only if a PID wraps and is reassigned *within the same second* **and** the
//! new process runs the same executable path. That needs ~100k process creations in under a
//! second on the same machine. It is a real gap and it is why this is called evidence of
//! identity rather than proof of it; an OS-verified identity needs Endpoint Security, which
//! this build does not have (ADR 0005).
//!
//! # Failure mode
//!
//! Every uncertain answer is a refusal to signal. If `ps` cannot be run, times out, or
//! returns something unparseable, [`identify`] returns an error and the caller must not
//! signal. A process that is simply gone returns `Ok(None)`, which is a different and safe
//! outcome: there is nothing to stop.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use vigil_common::{Result, VigilError};

/// `ps` is not expected to take milliseconds, let alone seconds. A bound this generous only
/// ever fires when the system is pathological, and firing is a refusal, not a kill.
const PS_TIMEOUT_MS: u64 = 5_000;

/// Absolute path: identity must never be decided by a binary found through `PATH`.
const PS_PATH: &str = "/bin/ps";

/// What the operating system currently says about a PID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    /// The kernel's start time for this process, as `ps -o lstart=` renders it.
    ///
    /// Stored and compared verbatim rather than parsed. Re-formatting a timestamp is a chance
    /// to normalise two different instants into the same string, and this value's only job is
    /// to differ when the process differs.
    pub os_started_at: String,
    /// The executable path as the kernel reports it.
    pub executable: String,
    /// Whether the process has exited but not yet been reaped by its parent.
    ///
    /// A zombie still occupies its PID, so `ps` reports it — but it is dead, and its command
    /// reads `<defunct>` rather than its executable. Treating that changed command as a
    /// recycled PID would be wrong twice over: it is the same process, and it is already
    /// gone. Callers deciding whether to signal must read this before comparing identity.
    pub is_zombie: bool,
}

impl ProcessIdentity {
    /// Whether this is the same process as one recorded earlier.
    ///
    /// Both halves are compared against values captured by this same function at spawn, so
    /// the comparison is `ps` output against `ps` output. Comparing the observed command
    /// against the executable path the caller *asked* to run would not be equivalent: `ps`
    /// reports its own rendering of the command, and a mismatch in formatting would read as
    /// a recycled PID.
    ///
    /// A recording missing either half never matches. Nodes from before identity capture
    /// existed cannot be told apart from a recycled PID, and "cannot distinguish" has to
    /// read as "do not signal".
    pub fn matches_recorded(
        &self,
        recorded_start: Option<&str>,
        recorded_executable: Option<&str>,
    ) -> bool {
        let (Some(recorded_start), Some(recorded_executable)) =
            (recorded_start, recorded_executable)
        else {
            return false;
        };
        self.os_started_at == recorded_start && self.executable == recorded_executable
    }
}

/// Read the current identity of `pid`.
///
/// `Ok(None)` means no such process — it exited, which is the outcome termination wanted.
/// `Err` means the question could not be answered, which must never be treated as absence.
pub fn identify(pid: u32) -> Result<Option<ProcessIdentity>> {
    // PID 0 and 1 are the kernel and launchd. Neither can be a VIGIL-managed process, and
    // asking about them is a sign the caller's bookkeeping is wrong.
    if pid <= 1 {
        return Err(VigilError::InvalidRequest(format!(
            "refusing to inspect pid {pid}: it cannot be a managed process"
        )));
    }

    let output = run_bounded(
        Command::new(PS_PATH)
            .arg("-o")
            .arg("lstart=,state=,comm=")
            .arg("-p")
            .arg(pid.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null()),
    )?;

    parse_ps_output(pid, &output)
}

/// Turn one `ps -o lstart=,state=,comm=` line into an identity.
///
/// Separated from [`identify`] so it can be exercised against arbitrary bytes without
/// spawning anything. `ps` output is not attacker-controlled in the ordinary case, but an
/// executable path is, and this is the code that turns bytes into something termination acts
/// on.
pub fn parse_ps_output(pid: u32, output: &str) -> Result<Option<ProcessIdentity>> {
    let line = output.trim();
    if line.is_empty() {
        // `ps` prints nothing and exits non-zero for a pid that does not exist.
        return Ok(None);
    }

    // `lstart` renders as five whitespace-separated fields ("Sun Aug 30 16:34:01 2026"),
    // so the date cannot be taken by splitting from the left on whitespace alone. State
    // follows, then the command, which may itself contain spaces.
    let mut fields = line.split_whitespace();
    let date: Vec<&str> = (&mut fields).take(5).collect();
    if date.len() < 5 {
        return Err(VigilError::Unavailable {
            component: "process_identity",
            reason: format!("could not read a start time for pid {pid} from `{line}`"),
        });
    }
    let Some(state) = fields.next() else {
        return Err(VigilError::Unavailable {
            component: "process_identity",
            reason: format!("could not read a process state for pid {pid} from `{line}`"),
        });
    };
    let executable = fields.collect::<Vec<_>>().join(" ");
    if executable.is_empty() {
        return Err(VigilError::Unavailable {
            component: "process_identity",
            reason: format!("could not read a command for pid {pid} from `{line}`"),
        });
    }

    Ok(Some(ProcessIdentity {
        pid,
        os_started_at: date.join(" "),
        executable,
        // The state column carries flags after the primary letter (`Z+`, `S<`), so only the
        // first character is meaningful.
        is_zombie: state.starts_with('Z'),
    }))
}

/// Run a command to completion under a deadline, returning its stdout.
///
/// A child that outlives its deadline is killed and reported as unavailable. Leaving it
/// running would leak a process on every timeout.
fn run_bounded(command: &mut Command) -> Result<String> {
    let mut child = command.spawn().map_err(|error| VigilError::Unavailable {
        component: "process_identity",
        reason: format!("could not run {PS_PATH}: {error}"),
    })?;

    let deadline = Instant::now() + Duration::from_millis(PS_TIMEOUT_MS);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(VigilError::Unavailable {
                        component: "process_identity",
                        reason: format!("{PS_PATH} exceeded its {PS_TIMEOUT_MS}ms bound"),
                    });
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => {
                return Err(VigilError::Unavailable {
                    component: "process_identity",
                    reason: format!("could not wait for {PS_PATH}: {error}"),
                })
            }
        }
    }

    let mut buffer = String::new();
    if let Some(mut stdout) = child.stdout.take() {
        stdout
            .read_to_string(&mut buffer)
            .map_err(|error| VigilError::Unavailable {
                component: "process_identity",
                reason: format!("could not read {PS_PATH} output: {error}"),
            })?;
    }
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A child that stays alive until it is dropped.
    struct Sleeper(std::process::Child);

    impl Sleeper {
        fn spawn() -> Self {
            Self(
                Command::new("/bin/sleep")
                    .arg("30")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("spawn sleeper"),
            )
        }

        fn pid(&self) -> u32 {
            self.0.id()
        }
    }

    impl Drop for Sleeper {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn a_live_process_reports_a_start_time_and_command() {
        let sleeper = Sleeper::spawn();
        let identity = identify(sleeper.pid())
            .expect("identify")
            .expect("the process is alive");
        assert_eq!(identity.pid, sleeper.pid());
        assert!(identity.executable.contains("sleep"), "{identity:?}");
        assert!(
            identity.os_started_at.split_whitespace().count() >= 5,
            "start time did not parse as a full date: {identity:?}"
        );
    }

    #[test]
    fn identity_is_stable_across_reads() {
        // The value is only useful if reading it twice gives the same answer; a start time
        // that drifted would refuse to signal a process that had not changed.
        let sleeper = Sleeper::spawn();
        let first = identify(sleeper.pid()).expect("identify").expect("alive");
        let second = identify(sleeper.pid()).expect("identify").expect("alive");
        assert_eq!(first, second);
    }

    #[test]
    fn an_exited_process_is_absent_rather_than_an_error() {
        let mut sleeper = Sleeper::spawn();
        let pid = sleeper.pid();
        sleeper.0.kill().expect("kill");
        sleeper.0.wait().expect("reap");
        // Absence is the outcome termination wants, and must be distinguishable from a
        // failure to answer.
        assert_eq!(identify(pid).expect("identify"), None);
    }

    #[test]
    fn the_kernel_and_launchd_are_refused() {
        // Not "returns None": asking at all means the caller's bookkeeping is wrong, and
        // silently answering would let a bad node id walk into a signal to launchd.
        assert!(identify(0).is_err());
        assert!(identify(1).is_err());
    }

    #[test]
    fn a_recorded_identity_without_a_start_time_never_matches() {
        // Processes recorded before identity capture existed are indistinguishable from a
        // recycled PID. "Cannot distinguish" has to read as "do not signal".
        let identity = ProcessIdentity {
            pid: 42,
            os_started_at: "Sun Aug 30 16:34:01 2026".to_string(),
            executable: "sleep".to_string(),
            is_zombie: false,
        };
        assert!(!identity.matches_recorded(None, Some("sleep")));
        // Missing the observed command is equally disqualifying.
        assert!(!identity.matches_recorded(Some("Sun Aug 30 16:34:01 2026"), None));
    }

    #[test]
    fn a_different_start_time_or_executable_does_not_match() {
        let identity = ProcessIdentity {
            pid: 42,
            os_started_at: "Sun Aug 30 16:34:01 2026".to_string(),
            executable: "sleep".to_string(),
            is_zombie: false,
        };
        assert!(identity.matches_recorded(Some("Sun Aug 30 16:34:01 2026"), Some("sleep")));
        // The recycled-PID case: same pid, same executable, later start.
        assert!(!identity.matches_recorded(Some("Sun Aug 30 16:34:02 2026"), Some("sleep")));
        // The same pid reused by something else entirely.
        assert!(!identity.matches_recorded(Some("Sun Aug 30 16:34:01 2026"), Some("bash")));
    }

    #[test]
    fn a_signalled_but_unreaped_process_is_reported_as_a_zombie() {
        // Discovered by the termination tests: a child that has been signalled but whose
        // parent has not reaped it still holds its pid, and `ps` renders its command as
        // `<defunct>`. Comparing that against the recorded command would read as a recycled
        // pid and refuse to finish the job, so the state has to be read explicitly.
        let mut sleeper = Sleeper::spawn();
        let pid = sleeper.pid();
        assert!(!identify(pid).expect("identify").expect("alive").is_zombie);

        sleeper.0.kill().expect("kill");
        // Deliberately not reaped.
        std::thread::sleep(std::time::Duration::from_millis(300));

        let zombie = identify(pid)
            .expect("identify")
            .expect("still holds the pid");
        assert!(zombie.is_zombie, "{zombie:?}");
        // `ps` output for a zombie is platform-specific: GNU may render `<defunct>`, while
        // BSD/macOS may retain the command name. The explicit process state is the contract.
        sleeper.0.wait().expect("reap");
    }
}
