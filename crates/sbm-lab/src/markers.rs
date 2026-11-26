use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Marker {
    pub name: String,
    pub fields: BTreeMap<String, String>,
    pub raw: String,
}

pub fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for next in chars.by_ref() {
                    if next.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(ch);
    }
    out
}

pub fn parse_markers(text: &str) -> Vec<Marker> {
    let clean = strip_ansi(text);
    let mut markers = parse_prefix(&clean, "SBM-LAB-MARKER:");
    markers.extend(parse_prefix(&clean, "SBM_MARK "));
    markers
}

pub fn log_tail(text: &str, lines: usize) -> String {
    let kept: Vec<&str> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    let start = kept.len().saturating_sub(lines);
    kept[start..]
        .iter()
        .map(|line| {
            let mut short = line.chars().take(240).collect::<String>();
            if line.chars().count() > 240 {
                short.push('…');
            }
            short
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn parse_prefix(clean: &str, prefix: &str) -> Vec<Marker> {
    let mut markers = Vec::new();
    for (index, part) in clean.split(prefix).enumerate() {
        if index == 0 {
            continue;
        }
        if !part.contains('\n') && !part.contains('\r') {
            continue;
        }
        let line = part
            .split(['\n', '\r'])
            .next()
            .unwrap_or("")
            .trim()
            .trim_matches('\0');
        if line.is_empty() {
            continue;
        }
        let mut tokens = line.split_whitespace();
        let Some(name) = tokens.next() else {
            continue;
        };
        let mut fields = BTreeMap::new();
        for token in tokens {
            if let Some((key, value)) = token.split_once('=') {
                fields.insert(key.to_string(), value.to_string());
            }
        }
        markers.push(Marker {
            name: name.to_string(),
            fields,
            raw: line.to_string(),
        });
    }
    markers
}

pub fn firmware_banner(text: &str) -> Option<String> {
    for line in text.lines() {
        if let Some(rest) = line.split("FirmwareVersionString:").nth(1)
            && let Some(start) = rest.find('"')
            && let Some(end) = rest[start + 1..].find('"')
        {
            return Some(rest[start + 1..start + 1 + end].to_string());
        }
        if let Some(rest) = line.split("version ").nth(1) {
            let token = rest.split_whitespace().next().unwrap_or("");
            if token.starts_with("edk2-") {
                return Some(token.to_string());
            }
        }
    }
    None
}

pub fn boot_target_paths(markers: &[Marker]) -> Vec<String> {
    markers
        .iter()
        .filter(|m| m.name == "boot-target")
        .filter_map(|m| m.fields.get("path").cloned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_markers_and_strips_ansi() {
        let text = "\u{1b}[2Jnoise\r\nSBM-LAB-MARKER:efi-launched\r\nSBM-LAB-MARKER:boot-target path=\\EFI\\sbm-lab\\alpha.efi\r\nSBM-LAB-MARKER:discovery-done count=1\r\n";
        let markers = parse_markers(text);
        assert_eq!(markers[0].name, "efi-launched");
        assert_eq!(
            markers[1].fields.get("path").map(String::as_str),
            Some("\\EFI\\sbm-lab\\alpha.efi")
        );
        assert_eq!(
            markers[2].fields.get("count").map(String::as_str),
            Some("1")
        );
        let partial = "SBM-LAB-MARKER:efi-launched\r\nSBM-LAB-MARKER:boo";
        assert_eq!(parse_markers(partial).len(), 1);
        let menu = "SBM_MARK menu_ready us=15\nSBM_MARK key c\nSBM_MARK fixture_started\n";
        let marks = parse_markers(menu);
        assert_eq!(marks[0].name, "menu_ready");
        assert_eq!(marks[0].fields.get("us").map(String::as_str), Some("15"));
        assert_eq!(marks[1].raw, "key c");
        assert_eq!(marks[2].name, "fixture_started");
    }

    #[test]
    fn reads_firmware_banner() {
        let text =
            "FirmwareVersionString:     \"edk2-stable202408-prebuilt.qemu.org\" (35 chars)\n";
        assert_eq!(
            firmware_banner(text).as_deref(),
            Some("edk2-stable202408-prebuilt.qemu.org")
        );
        let aarch64 = "UEFI firmware (version edk2-stable202408-prebuilt.qemu.org built at 16:28:50 on Sep 12 2024)\n";
        assert_eq!(
            firmware_banner(aarch64).as_deref(),
            Some("edk2-stable202408-prebuilt.qemu.org")
        );
    }
}
