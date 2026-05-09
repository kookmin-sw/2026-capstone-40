use std::collections::HashSet;

const BLOCK_SKIP: &[&str] = &[
    "script", "style", "head", "link", "meta", "noscript", "iframe", "svg", "canvas", "template",
];

const STRUCTURAL: &[&str] = &[
    "html",
    "body",
    "div",
    "section",
    "article",
    "aside",
    "main",
    "header",
    "footer",
    "nav",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "p",
    "ul",
    "ol",
    "li",
    "table",
    "thead",
    "tbody",
    "tfoot",
    "tr",
    "th",
    "td",
    "form",
    "input",
    "button",
    "select",
    "textarea",
    "label",
    "figure",
    "figcaption",
];

const VOID_STRUCTURAL: &[&str] = &["input"];

pub(crate) fn strip_noise_blocks(html: &str) -> String {
    let bytes = html.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut cursor = 0;

    while cursor < bytes.len() {
        if bytes[cursor] == b'<' {
            if let Some(next) = skip_comment(bytes, cursor) {
                cursor = next;
                continue;
            }
            if let Some(next) = skip_noise_tag(bytes, cursor) {
                cursor = next;
                continue;
            }
        }

        out.push(bytes[cursor]);
        cursor += 1;
    }

    String::from_utf8_lossy(&out).into_owned()
}

pub(crate) fn visible_text(clean: &str) -> String {
    let bytes = clean.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 3);
    let mut cursor = 0;

    while cursor < bytes.len() {
        match bytes[cursor] {
            b'<' => {
                cursor = skip_tag(bytes, cursor);
                push_space_once(&mut out);
            }
            b'&' => cursor = skip_entity(bytes, cursor),
            b if b.is_ascii_whitespace() => {
                push_space_once(&mut out);
                cursor += 1;
            }
            b if b.is_ascii_alphanumeric() => {
                out.push(b.to_ascii_lowercase());
                cursor += 1;
            }
            _ => cursor += 1,
        }
    }

    String::from_utf8_lossy(&out).trim().to_string()
}

pub(crate) fn extract_tag_bigrams(clean: &str) -> HashSet<String> {
    let bytes = clean.as_bytes();
    let mut bigrams = HashSet::new();
    let mut stack = vec!["_root".to_string()];
    let mut cursor = 0;

    while cursor < bytes.len() {
        if bytes[cursor] == b'<' && cursor + 1 < bytes.len() {
            let is_close = bytes[cursor + 1] == b'/';
            let name_start = if is_close { cursor + 2 } else { cursor + 1 };
            let name = read_tag_name(bytes, name_start);

            if STRUCTURAL.contains(&name.as_str()) {
                if is_close {
                    pop_to_matching_tag(&mut stack, &name);
                } else {
                    if let Some(parent) = stack.last() {
                        bigrams.insert(format!("{parent}>{name}"));
                    }
                    if !VOID_STRUCTURAL.contains(&name.as_str()) {
                        stack.push(name);
                    }
                }
            }

            cursor = skip_tag(bytes, cursor);
        } else {
            cursor += 1;
        }
    }

    bigrams
}

pub(crate) fn extract_css_classes(clean: &str) -> HashSet<String> {
    let bytes = clean.as_bytes();
    let mut classes = HashSet::new();
    let mut cursor = 0;

    while cursor + 6 < bytes.len() {
        if case_insensitive_eq(&bytes[cursor..cursor + 6], b"class=") {
            cursor += 6;
            let delimiter = match bytes.get(cursor) {
                Some(b'"') => {
                    cursor += 1;
                    b'"'
                }
                Some(b'\'') => {
                    cursor += 1;
                    b'\''
                }
                _ => b' ',
            };

            let value_start = cursor;
            while cursor < bytes.len() && bytes[cursor] != delimiter && bytes[cursor] != b'>' {
                cursor += 1;
            }
            insert_class_tokens(&mut classes, &bytes[value_start..cursor]);
        } else {
            cursor += 1;
        }
    }

    classes
}

pub(crate) fn extract_tag_text(html: &str, tag: &str) -> Option<String> {
    let bytes = html.as_bytes();
    let open = format!("<{tag}");
    let close = format!("</{tag}>");

    let tag_start = find_case_insensitive(bytes, 0, open.as_bytes())?;
    let content_start = bytes[tag_start..].iter().position(|&byte| byte == b'>')? + tag_start + 1;
    let content_end = find_case_insensitive(bytes, content_start, close.as_bytes())?;

    let raw = strip_tags(&html[content_start..content_end]);
    let text = raw.trim().to_string();
    (!text.is_empty()).then_some(text)
}

pub(crate) fn tokenize(text: &str) -> HashSet<String> {
    text.split_ascii_whitespace()
        .filter(|word| word.len() >= 2)
        .map(str::to_ascii_lowercase)
        .collect()
}

fn skip_comment(bytes: &[u8], cursor: usize) -> Option<usize> {
    let is_comment = bytes.get(cursor + 1) == Some(&b'!')
        && bytes.get(cursor + 2) == Some(&b'-')
        && bytes.get(cursor + 3) == Some(&b'-');
    if !is_comment {
        return None;
    }
    find_case_insensitive(bytes, cursor + 4, b"-->").map(|pos| pos + 3)
}

fn skip_noise_tag(bytes: &[u8], cursor: usize) -> Option<usize> {
    let name = read_tag_name(bytes, cursor + 1);
    let skipped = BLOCK_SKIP.iter().find(|&&tag| tag == name)?;
    let close = format!("</{skipped}>");
    find_case_insensitive(bytes, cursor, close.as_bytes()).map(|pos| pos + close.len())
}

fn skip_tag(bytes: &[u8], cursor: usize) -> usize {
    bytes[cursor..]
        .iter()
        .position(|&byte| byte == b'>')
        .map_or(bytes.len(), |offset| cursor + offset + 1)
}

fn skip_entity(bytes: &[u8], cursor: usize) -> usize {
    let after_amp = cursor + 1;
    bytes[after_amp..]
        .iter()
        .take(8)
        .position(|&byte| byte == b';')
        .map_or(cursor + 1, |offset| after_amp + offset + 1)
}

fn push_space_once(out: &mut Vec<u8>) {
    if out.last() != Some(&b' ') {
        out.push(b' ');
    }
}

fn pop_to_matching_tag(stack: &mut Vec<String>, name: &str) {
    if let Some(pos) = stack.iter().rposition(|tag| tag == name) {
        stack.truncate(pos);
    }
}

fn insert_class_tokens(classes: &mut HashSet<String>, raw: &[u8]) {
    if let Ok(value) = std::str::from_utf8(raw) {
        for token in value
            .split_ascii_whitespace()
            .filter(|token| !token.is_empty())
        {
            classes.insert(token.to_ascii_lowercase());
        }
    }
}

fn strip_tags(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_tag = false;

    for ch in text.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }

    out
}

fn read_tag_name(bytes: &[u8], start: usize) -> String {
    bytes[start..]
        .iter()
        .take(16)
        .map(u8::to_ascii_lowercase)
        .take_while(u8::is_ascii_alphanumeric)
        .map(char::from)
        .collect()
}

fn find_case_insensitive(bytes: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(from);
    }
    bytes
        .windows(needle.len())
        .enumerate()
        .skip(from)
        .find_map(|(idx, window)| case_insensitive_eq(window, needle).then_some(idx))
}

fn case_insensitive_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}
