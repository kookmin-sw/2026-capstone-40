use crate::{Page, Site};
use pulldown_cmark::{Options, Parser, html};

pub fn markdown_to_html(markdown: &str) -> String {
    let options = Options::ENABLE_TABLES
        | Options::ENABLE_FOOTNOTES
        | Options::ENABLE_STRIKETHROUGH
        | Options::ENABLE_TASKLISTS;
    let parser = Parser::new_ext(markdown, options);
    let mut out = String::new();
    html::push_html(&mut out, parser);
    out
}

pub fn render_page(site: &Site, pages: &[Page], page: &Page, content: &str) -> String {
    let nav = build_nav(pages, page);
    let title = escape_html(page.title);
    let site_title = escape_html(site.title);
    let site_description = escape_html(site.description);
    let eyebrow = escape_html(site.eyebrow);

    format!(
        r#"<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="generator" content="capstone-pages">
  <title>{title} | {site_title}</title>
  <meta name="description" content="{site_description}">
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <header class="site-header">
    <div>
      <p class="eyebrow">{eyebrow}</p>
      <a class="brand" href="index.html">{site_title}</a>
    </div>
    <nav aria-label="주요 내비게이션">
{nav}
    </nav>
  </header>
  <main>
    <article class="content">
{content}
    </article>
  </main>
  <footer class="site-footer">
    <span>{eyebrow}</span>
    <span>2026</span>
  </footer>
</body>
</html>
"#
    )
}

pub fn render_not_found(site: &Site, pages: &[Page]) -> String {
    let page = Page {
        source: "",
        output: "404.html",
        title: "페이지 없음",
    };
    render_page(
        site,
        pages,
        &page,
        "<h1>페이지를 찾을 수 없습니다</h1>\n<p>요청한 페이지는 Capstone 2026 문서에 포함되어 있지 않습니다.</p>",
    )
}

fn build_nav(pages: &[Page], current: &Page) -> String {
    pages
        .iter()
        .map(|p| {
            let active = if p.output == current.output {
                " class=\"active\" aria-current=\"page\""
            } else {
                ""
            };
            format!(
                "      <a{active} href=\"{}\">{}</a>",
                p.output,
                escape_html(p.title)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
