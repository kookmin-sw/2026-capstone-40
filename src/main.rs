use pulldown_cmark::{Options, Parser, html};
use std::fs;
use std::io;
use std::path::Path;

const PAGES: &[Page] = &[
    Page {
        source: "book/index.md",
        output: "index.html",
        title: "Overview",
    },
    Page {
        source: "book/architecture.md",
        output: "architecture.html",
        title: "Architecture",
    },
    Page {
        source: "book/implementation.md",
        output: "implementation.html",
        title: "Implementation",
    },
    Page {
        source: "book/demo.md",
        output: "demo.html",
        title: "Demo",
    },
    Page {
        source: "book/usage.md",
        output: "usage.html",
        title: "Usage",
    },
    Page {
        source: "book/team.md",
        output: "team.html",
        title: "Team",
    },
    Page {
        source: "book/wasm.md",
        output: "interactive-demo.html",
        title: "Interactive Demo",
    },
];

struct Page {
    source: &'static str,
    output: &'static str,
    title: &'static str,
}

fn main() -> io::Result<()> {
    let out_dir = Path::new("site");
    if out_dir.exists() {
        fs::remove_dir_all(out_dir)?;
    }
    fs::create_dir_all(out_dir)?;

    fs::write(out_dir.join("style.css"), stylesheet())?;
    fs::write(out_dir.join(".nojekyll"), "")?;

    for page in PAGES {
        let markdown = fs::read_to_string(page.source)?;
        let content = markdown_to_html(&markdown);
        fs::write(out_dir.join(page.output), render_page(page, &content))?;
    }

    fs::write(out_dir.join("404.html"), render_not_found())?;
    println!("generated {}", out_dir.display());
    Ok(())
}

fn markdown_to_html(markdown: &str) -> String {
    let mut options = Options::empty();
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_FOOTNOTES);
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TASKLISTS);

    let parser = Parser::new_ext(markdown, options);
    let mut out = String::new();
    html::push_html(&mut out, parser);
    out
}

fn render_page(page: &Page, content: &str) -> String {
    let nav = PAGES
        .iter()
        .map(|item| {
            let class = if item.output == page.output {
                " class=\"active\""
            } else {
                ""
            };
            format!(
                "<a{class} href=\"{}\">{}</a>",
                item.output,
                escape_html(item.title)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title} | Capstone 2026</title>
  <meta name="description" content="Rust-based traffic-to-domain risk monitoring capstone project">
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <header class="site-header">
    <div>
      <p class="eyebrow">Capstone 2026 Team 40</p>
      <a class="brand" href="index.html">Traffic-to-Domain Risk Monitor</a>
    </div>
    <nav aria-label="Main navigation">
{nav}
    </nav>
  </header>
  <main>
    <article class="content">
{content}
    </article>
  </main>
</body>
</html>
"#,
        title = escape_html(page.title),
        nav = nav,
        content = content,
    )
}

fn render_not_found() -> String {
    render_page(
        &Page {
            source: "",
            output: "404.html",
            title: "Not Found",
        },
        "<h1>Page not found</h1>\n<p>The requested page is not part of the Capstone 2026 documentation.</p>",
    )
}

fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn stylesheet() -> &'static str {
    r#":root {
  color-scheme: dark;
  --bg: #10130f;
  --panel: #171d16;
  --panel-2: #20291f;
  --text: #eef4e8;
  --muted: #b8c5b1;
  --line: #3a4637;
  --accent: #9ccf63;
  --accent-2: #f0b35a;
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  line-height: 1.65;
  color: var(--text);
  background:
    linear-gradient(90deg, rgba(255, 255, 255, 0.03) 1px, transparent 1px),
    linear-gradient(180deg, rgba(255, 255, 255, 0.03) 1px, transparent 1px),
    linear-gradient(145deg, #10130f, #151b15 42%, #1c2117);
  background-size: 44px 44px, 44px 44px, auto;
}

a {
  color: var(--accent);
}

.site-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 1.5rem;
  padding: 1.25rem clamp(1rem, 4vw, 3rem);
  border-bottom: 1px solid var(--line);
  background: rgba(16, 19, 15, 0.9);
  position: sticky;
  top: 0;
  backdrop-filter: blur(12px);
}

.brand {
  display: inline-block;
  color: var(--text);
  font-weight: 800;
  font-size: clamp(1.2rem, 2vw, 1.8rem);
  text-decoration: none;
}

.eyebrow {
  margin: 0 0 0.2rem;
  color: var(--accent-2);
  font-size: 0.78rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

nav {
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 0.45rem;
  max-width: 46rem;
}

nav a {
  padding: 0.42rem 0.62rem;
  border: 1px solid transparent;
  color: var(--muted);
  text-decoration: none;
  border-radius: 6px;
}

nav a.active,
nav a:hover {
  border-color: var(--line);
  color: var(--text);
  background: var(--panel-2);
}

main {
  width: min(980px, calc(100% - 2rem));
  margin: 0 auto;
  padding: clamp(2rem, 5vw, 4.5rem) 0;
}

.content {
  display: flow-root;
}

h1 {
  max-width: 12ch;
  margin: 0 0 1rem;
  font-size: clamp(2.4rem, 7vw, 5.8rem);
  line-height: 0.95;
}

h2 {
  margin-top: 2.6rem;
  padding-top: 1.2rem;
  border-top: 1px solid var(--line);
  font-size: clamp(1.45rem, 3vw, 2.2rem);
}

h3 {
  margin-top: 1.8rem;
  color: var(--accent-2);
}

p,
li {
  color: var(--muted);
}

p:first-of-type {
  max-width: 66ch;
  font-size: 1.12rem;
  color: var(--text);
}

ul,
ol {
  padding-left: 1.35rem;
}

table {
  width: 100%;
  border-collapse: collapse;
  margin: 1.25rem 0;
  overflow: hidden;
  border: 1px solid var(--line);
}

th,
td {
  padding: 0.8rem;
  border-bottom: 1px solid var(--line);
  text-align: left;
  vertical-align: top;
}

th {
  color: var(--text);
  background: var(--panel-2);
}

code {
  padding: 0.12rem 0.28rem;
  border-radius: 4px;
  color: #fff6db;
  background: rgba(240, 179, 90, 0.16);
}

pre {
  padding: 1rem;
  overflow-x: auto;
  border: 1px solid var(--line);
  background: var(--panel);
}

pre code {
  padding: 0;
  background: transparent;
}

@media (max-width: 760px) {
  .site-header {
    position: static;
    display: block;
  }

  nav {
    justify-content: flex-start;
    margin-top: 1rem;
  }
}
"#
}
