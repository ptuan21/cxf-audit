use credential_exchange_format::{
    Account, B64Url, Credential, EditableField, EditableFieldString, Header, Item, NoteCredential,
    Version,
};

/// A minimal, spec-shaped CXF export document. This is a plaintext placeholder,
/// NOT a real HPKE-encrypted export — see README. It exists so the zip-slip PoC
/// carries CXF-realistic content rather than an arbitrary blob.
pub fn sample_header() -> Header {
    let note = NoteCredential {
        content: EditableField {
            id: None,
            value: EditableFieldString(
                "placeholder — cxf-audit PoC, not a real HPKE-encrypted payload".into(),
            )
            .into(),
            label: None,
            extensions: None,
        },
    };

    let item = Item {
        id: B64Url::from(b"cxf-audit-item".as_slice()),
        creation_at: None,
        modified_at: None,
        title: "cxf-audit PoC item".into(),
        subtitle: None,
        favorite: None,
        scope: None,
        credentials: vec![Credential::Note(Box::new(note))],
        tags: None,
        extensions: None,
    };

    let account = Account {
        id: B64Url::from(b"cxf-audit-account".as_slice()),
        username: "cxf-audit".into(),
        email: "research@example.invalid".into(),
        full_name: None,
        collections: vec![],
        items: vec![item],
        extensions: None,
    };

    Header {
        version: Version { major: 1, minor: 0 },
        exporter_rp_id: "cxf-audit.research".into(),
        exporter_display_name: "cxf-audit research tool".into(),
        timestamp: 0,
        accounts: vec![account],
    }
}
