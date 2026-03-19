use crate::sanitization::sanitize;

/// Resolve a human-readable function label from Parca metadata.
///
/// Prefers `function.name` → `function.systemName` → `mapping.file` → `"<unknown>"`.
pub(super) fn resolve_function_label(meta: &Option<super::TopNodeMeta>) -> String {
    let Some(meta) = meta else {
        return "<unknown>".to_string();
    };

    if let Some(ref func) = meta.function {
        if let Some(ref name) = func.name {
            if !name.is_empty() {
                return name.clone();
            }
        }
        if let Some(ref system_name) = func.system_name {
            if !system_name.is_empty() {
                return system_name.clone();
            }
        }
    }

    if let Some(ref mapping) = meta.mapping {
        if let Some(ref file) = mapping.file {
            if !file.is_empty() {
                return file.clone();
            }
        }
    }

    "<unknown>".to_string()
}

/// Sanitize a function label for tag-boundary safety.
///
/// Parca data comes from a trusted internal service containing compiled C++ debug
/// symbols. Not peer-influenced. Sanitization is for **tag-boundary safety**
/// (preventing `</profiling-data>` from appearing in output), not adversarial
/// prompt injection.
pub(super) fn sanitize_function_label(name: &str) -> String {
    let sanitized = sanitize(name);
    if sanitized.len() > 200 {
        let mut truncated = String::with_capacity(203);
        for (i, ch) in sanitized.char_indices() {
            if i >= 200 {
                break;
            }
            truncated.push(ch);
        }
        truncated.push_str("...");
        truncated
    } else {
        sanitized
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parca::{ParcaFunction, ParcaMapping, TopNodeMeta};

    // ── resolve_function_label ────────────────────────────────────────

    #[test]
    fn prefers_name_over_system_name() {
        let meta = Some(TopNodeMeta {
            function: Some(ParcaFunction {
                name: Some("CConnman::AcceptConnection".into()),
                system_name: Some("_ZN7CConnman16AcceptConnectionEv".into()),
                filename: Some("/src/net.cpp".into()),
            }),
            mapping: None,
        });
        assert_eq!(resolve_function_label(&meta), "CConnman::AcceptConnection");
    }

    #[test]
    fn falls_back_to_system_name() {
        let meta = Some(TopNodeMeta {
            function: Some(ParcaFunction {
                name: None,
                system_name: Some("_ZN7CConnman16AcceptConnectionEv".into()),
                filename: None,
            }),
            mapping: None,
        });
        assert_eq!(
            resolve_function_label(&meta),
            "_ZN7CConnman16AcceptConnectionEv"
        );
    }

    #[test]
    fn falls_back_to_mapping_file() {
        let meta = Some(TopNodeMeta {
            function: None,
            mapping: Some(ParcaMapping {
                file: Some("/usr/bin/bitcoind".into()),
            }),
        });
        assert_eq!(resolve_function_label(&meta), "/usr/bin/bitcoind");
    }

    #[test]
    fn returns_unknown_when_all_empty() {
        let meta = Some(TopNodeMeta {
            function: Some(ParcaFunction {
                name: Some(String::new()),
                system_name: Some(String::new()),
                filename: None,
            }),
            mapping: Some(ParcaMapping {
                file: Some(String::new()),
            }),
        });
        assert_eq!(resolve_function_label(&meta), "<unknown>");
    }

    #[test]
    fn returns_unknown_when_none() {
        assert_eq!(resolve_function_label(&None), "<unknown>");
    }

    // ── sanitize_function_label ───────────────────────────────────────

    #[test]
    fn escapes_angle_brackets_in_cpp_templates() {
        assert_eq!(
            sanitize_function_label("std::vector<int>"),
            "std::vector&lt;int&gt;"
        );
    }

    #[test]
    fn escapes_ampersand() {
        assert_eq!(sanitize_function_label("foo&bar"), "foo&amp;bar");
    }

    #[test]
    fn truncates_over_200_chars() {
        let long_name = "a".repeat(250);
        let result = sanitize_function_label(&long_name);
        assert!(result.ends_with("..."));
        // 200 chars of content + "..."
        assert_eq!(result.len(), 203);
    }

    #[test]
    fn preserves_short_names() {
        assert_eq!(
            sanitize_function_label("CConnman::AcceptConnection"),
            "CConnman::AcceptConnection"
        );
    }
}
