//! Fuzz the `security` attribute-dump parser behind secret metadata.
//!
//! The dump carries fields whoever created the Keychain item controls — notably the
//! description. VIGIL reads the item's *kind* out of this dump, and the kind decides which
//! purposes the credential may serve (ADR 0042). An item that could forge its kind could
//! claim purposes it should not have.
//!
//! `security` escapes newlines inside values, which is what makes a line-oriented parse safe;
//! `a_crafted_description_cannot_forge_the_secret_kind` asserts that against the real tool.
//! This target covers the other half: that arbitrary bytes cannot make the parser fabricate an
//! attribute that was not in its input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vigil_local::KeychainSecretProvider;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let attributes = KeychainSecretProvider::attributes(text);

    for (name, value) in &attributes {
        // A name is one quoted token. One carrying a quote would mean the split walked past
        // its own field and read part of a neighbouring one.
        assert!(
            !name.contains('"'),
            "attribute name `{name}` spans a quote boundary (input: {text:?})"
        );

        // `<NULL>` means the attribute is unset. Recording it as a value would let an absent
        // kind read as a present one.
        assert_ne!(value, "<NULL>", "an unset attribute was recorded as a value");

        // The property that carries the security weight, and the only one here that is not
        // true by construction: an attribute may only come from a line whose key really is
        // that attribute. If `icmt` could be picked up out of the *middle* of some other
        // field — a description, say — then an item could declare a kind it does not have and
        // claim purposes it should not serve.
        //
        // Substring checks against the whole input would pass trivially, because every value
        // is a slice of it. This checks the line structure instead.
        let declared_on_its_own_line = text.lines().any(|line| {
            let line = line.trim_start();
            line.starts_with(&format!("\"{name}\"")) || line.starts_with(name.as_str())
        });
        assert!(
            declared_on_its_own_line,
            "attribute `{name}` was parsed out of a line that does not declare it \
             (input: {text:?})"
        );
    }

    // Deterministic, for the same reason as the process parser: metadata is read more than
    // once and the answers have to agree.
    assert_eq!(
        attributes,
        KeychainSecretProvider::attributes(text),
        "parsing the same dump twice disagreed"
    );
});
