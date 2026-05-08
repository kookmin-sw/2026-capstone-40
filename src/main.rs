mod render;

use render::{markdown_to_html, render_not_found, render_page};
use std::fs;
use std::io;
use std::path::Path;

pub struct Page {
    pub source: &'static str,
    pub output: &'static str,
    pub title: &'static str,
}

const PAGES: &[Page] = &[
    Page { source: "book/index.md",          output: "index.html",          title: "개요"       },
    Page { source: "book/architecture.md",   output: "architecture.html",   title: "아키텍처"   },
    Page { source: "book/implementation.md", output: "implementation.html", title: "구현"       },
    Page { source: "book/demo.md",           output: "demo.html",           title: "데모"       },
    Page { source: "book/usage.md",          output: "usage.html",          title: "사용법"     },
    Page { source: "book/team.md",           output: "team.html",           title: "팀 소개"    },
];

fn main() -> io::Result<()> {
    let out = Path::new("site");
    if out.exists() {
        fs::remove_dir_all(out)?;
    }
    fs::create_dir_all(out)?;

    fs::write(out.join("style.css"), include_str!("style.css"))?;
    fs::write(out.join(".nojekyll"), "")?;

    let mut count = 0usize;
    for page in PAGES {
        match fs::read_to_string(page.source) {
            Ok(md) => {
                let html = render_page(PAGES, page, &markdown_to_html(&md));
                fs::write(out.join(page.output), html)?;
                println!("  built  {}", page.output);
                count += 1;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                eprintln!("  skip   {} (missing: {})", page.output, page.source);
            }
            Err(e) => return Err(e),
        }
    }

    fs::write(out.join("404.html"), render_not_found(PAGES))?;
    println!("  done   {count} page(s) → {}/", out.display());
    Ok(())
}
