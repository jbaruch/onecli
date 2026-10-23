//! Twin of policy-translation/google-write.ts: ambiguous writes fail destructive.
use super::graphql::count_top_level_literal_keys;

fn ordinary_json(value: &serde_json::Value, depth: usize) -> bool {
    if depth > 64 {
        return false;
    }
    match value {
        serde_json::Value::Array(values) => values.iter().all(|v| ordinary_json(v, depth + 1)),
        serde_json::Value::Object(values) => values.values().all(|v| ordinary_json(v, depth + 1)),
        _ => true, // serde_json already rejects overflowing numbers and lone surrogates.
    }
}

pub(super) fn classify_google_write(
    provider: &str,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> &'static str {
    if method == "DELETE"
        || (provider == "gmail"
            && path
                .split('?')
                .next()
                .is_some_and(|p| p.ends_with("/trash")))
    {
        return "destructive";
    }
    const SAFE_OPTIONS: &[&str] = &[
        "fields",
        "prettyPrint",
        "alt",
        "quotaUser",
        "key",
        "sendUpdates",
        "sendNotifications",
        "supportsAttachments",
        "conferenceDataVersion",
        "maxAttendees",
        "alwaysIncludeEmail",
    ];
    if path.split('?').nth(1).is_some_and(|query| {
        !query.is_empty()
            && query
                .split('&')
                .any(|p| !SAFE_OPTIONS.contains(&p.split('=').next().unwrap_or("")))
    }) {
        return "destructive";
    }
    let Some(bytes) = body else {
        return "destructive";
    };
    if bytes.len() > 1024 * 1024 {
        return "destructive";
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return "destructive";
    };
    let Some(record) = value.as_object() else {
        return "destructive";
    };
    if !ordinary_json(&value, 1) {
        return "destructive";
    }
    if provider == "google-calendar" {
        let count = count_top_level_literal_keys(bytes, b"status");
        if !(0..=1).contains(&count)
            || record
                .keys()
                .any(|k| k.to_lowercase() == "status" && k != "status")
        {
            return "destructive";
        }
        return match record.get("status") {
            None => "ordinary",
            Some(v) if matches!(v.as_str(), Some("confirmed" | "tentative")) => "ordinary",
            _ => "destructive",
        };
    }
    if provider != "gmail" {
        return "destructive";
    }
    const KEYS: &[&str] = &[
        "addLabelIds",
        "removeLabelIds",
        "add_label_ids",
        "remove_label_ids",
        "ids",
    ];
    for (key, labels) in record {
        if !KEYS.contains(&key.as_str()) || count_top_level_literal_keys(bytes, key.as_bytes()) != 1
        {
            return "destructive";
        }
        let Some(labels) = labels.as_array() else {
            return "destructive";
        };
        if labels.iter().any(|label| {
            !label.as_str().is_some_and(|s| {
                !s.is_empty()
                    && s.bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
            })
        }) {
            return "destructive";
        }
    }
    for (camel, snake) in [
        ("addLabelIds", "add_label_ids"),
        ("removeLabelIds", "remove_label_ids"),
    ] {
        if record.contains_key(camel) && record.contains_key(snake) {
            return "destructive";
        }
    }
    let added = record
        .get("addLabelIds")
        .or_else(|| record.get("add_label_ids"));
    if added.and_then(|a| a.as_array()).is_some_and(|labels| {
        labels
            .iter()
            .any(|v| v.as_str().is_some_and(|s| s.eq_ignore_ascii_case("TRASH")))
    }) {
        "destructive"
    } else {
        "ordinary"
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn utf8_byte_cap_requires_destructive_permission() {
        for description in ["x".repeat(1024 * 1024), "😀".repeat(300_000)] {
            let body =
                serde_json::to_vec(&serde_json::json!({"description": description})).unwrap();
            assert_eq!(
                super::classify_google_write(
                    "google-calendar",
                    "PATCH",
                    "/calendar/v3/calendars/primary/events/fixture",
                    Some(&body)
                ),
                "destructive"
            );
        }
    }
}
