pub const MAX_ECHO_BYTES: usize = 1024;

pub const FACET_LOGGER: [u8; 16] = [
    0x2a, 0xa2, 0xe8, 0x95, 0x90, 0xbb, 0x47, 0x95, 0x98, 0x42, 0x06, 0x6f, 0x17, 0x4e, 0x7f, 0x20,
];

pub const FACET_DOCUMENT: [u8; 16] = [
    0x94, 0x65, 0xfa, 0x66, 0xde, 0xe4, 0x49, 0x42, 0xab, 0x33, 0xa0, 0xf5, 0x95, 0x99, 0x4f, 0xf0,
];
pub const METHOD_ID_LOG_INFO: u32 = 0xd399_d6df;
pub const METHOD_ID_DOCUMENT_APPEND: u32 = 0x26b9_023e;

pub fn handle_invoke(facet_id: &[u8], method_id: u32, payload: &[u8]) -> Vec<u8> {
    if facet_id.len() != 16 {
        return Vec::new();
    }

    let mut facet = [0u8; 16];
    facet.copy_from_slice(facet_id);

    if facet == FACET_LOGGER && method_id == METHOD_ID_LOG_INFO {
        return Vec::new();
    }

    if facet == FACET_DOCUMENT && method_id == METHOD_ID_DOCUMENT_APPEND {
        return payload[..payload.len().min(MAX_ECHO_BYTES)].to_vec();
    }

    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::{
        handle_invoke, FACET_DOCUMENT, FACET_LOGGER, MAX_ECHO_BYTES, METHOD_ID_DOCUMENT_APPEND, METHOD_ID_LOG_INFO,
    };

    #[test]
    fn log_info_returns_empty_payload() {
        let out = handle_invoke(&FACET_LOGGER, METHOD_ID_LOG_INFO, b"ignored");
        assert!(out.is_empty());
    }

    #[test]
    fn document_append_echoes_payload() {
        let payload = b"hello from test";
        let out = handle_invoke(&FACET_DOCUMENT, METHOD_ID_DOCUMENT_APPEND, payload);
        assert_eq!(out, payload);
    }

    #[test]
    fn document_append_caps_payload_size() {
        let payload = vec![b'x'; MAX_ECHO_BYTES + 128];
        let out = handle_invoke(&FACET_DOCUMENT, METHOD_ID_DOCUMENT_APPEND, &payload);
        assert_eq!(out.len(), MAX_ECHO_BYTES);
        assert_eq!(out, payload[..MAX_ECHO_BYTES]);
    }

    #[test]
    fn unknown_method_returns_empty_payload() {
        let out = handle_invoke(&FACET_DOCUMENT, 999, b"hello");
        assert!(out.is_empty());
    }
}
