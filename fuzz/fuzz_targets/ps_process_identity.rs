//! Fuzz the `ps` output parser that decides whether a PID may be signalled.
//!
//! Termination refuses to act unless the live process still matches the identity recorded at
//! spawn (ADR 0041). Both sides of that comparison come out of this parser, so a parse that
//! can be steered is directly a wrong-process kill: make the parser produce, for a recycled
//! PID, the same `(os_started_at, executable)` pair it produced for the original, and VIGIL
//! signals whatever now holds the number.
//!
//! An executable path is attacker-influenced — an agent chooses what it runs — and that path
//! is the tail of the line being parsed.
//!
//! Returning an error is always safe: the caller refuses to signal.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vigil_local::parse_ps_output;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let Ok(parsed) = parse_ps_output(4242, text) else {
        // A refusal to parse is a refusal to signal. Always safe.
        return;
    };
    let Some(identity) = parsed else {
        // Absent process. The caller treats this as "already exited", which does not signal.
        return;
    };

    assert_eq!(identity.pid, 4242, "the parser invented a different pid");

    // The start time is the discriminator between a process and a recycled PID. An empty or
    // whitespace-only value would compare equal across two unrelated processes, collapsing
    // the distinction the whole check rests on.
    assert!(
        !identity.os_started_at.trim().is_empty(),
        "an empty start time was accepted (input: {text:?})"
    );
    assert_eq!(
        identity.os_started_at.split_whitespace().count(),
        5,
        "start time `{}` is not a full five-field date, so it did not come from lstart \
         (input: {text:?})",
        identity.os_started_at
    );

    // Same argument for the command half of the identity.
    assert!(
        !identity.executable.trim().is_empty(),
        "an empty command was accepted (input: {text:?})"
    );

    // Neither half may carry a newline. Both are stored in SQLite and compared verbatim; a
    // value that spans lines would not survive the round trip it is compared across.
    assert!(
        !identity.os_started_at.contains('\n') && !identity.executable.contains('\n'),
        "a newline survived into an identity field (input: {text:?})"
    );

    // Parsing must be deterministic: the recorded value and the value read back at
    // termination are produced by separate invocations of this function.
    let again = parse_ps_output(4242, text)
        .expect("a second parse of the same input failed")
        .expect("a second parse of the same input found no process");
    assert_eq!(identity, again, "parsing the same input twice disagreed");
});
