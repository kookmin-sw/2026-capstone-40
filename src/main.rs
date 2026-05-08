mod render;

use render::{markdown_to_html, render_not_found, render_page};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

const SITE: Site = Site {
    title: "Traffic-to-Domain Risk Monitor",
    eyebrow: "Capstone 2026 Team 40",
    description: "Rust 기반 traffic-to-domain 위험 모니터링 캡스톤 프로젝트",
    output_dir: "site",
    assets_dir: "assets",
};

pub struct Page {
    pub source: &'static str,
    pub output: &'static str,
    pub title: &'static str,
}

pub struct Site {
    pub title: &'static str,
    pub eyebrow: &'static str,
    pub description: &'static str,
    pub output_dir: &'static str,
    pub assets_dir: &'static str,
}

const PAGES: &[Page] = &[
    Page {
        source: "book/index.md",
        output: "index.html",
        title: "개요",
    },
    Page {
        source: "book/architecture.md",
        output: "architecture.html",
        title: "아키텍처",
    },
    Page {
        source: "book/implementation.md",
        output: "implementation.html",
        title: "구현",
    },
    Page {
        source: "book/demo.md",
        output: "demo.html",
        title: "데모",
    },
    Page {
        source: "book/usage.md",
        output: "usage.html",
        title: "사용법",
    },
    Page {
        source: "book/team.md",
        output: "team.html",
        title: "팀 소개",
    },
];

fn main() -> io::Result<()> {
    let stats = build_site(&SITE, PAGES)?;
    println!(
        "  done   {} page(s), {} skipped, {} asset(s) -> {}/",
        stats.built, stats.skipped, stats.assets, SITE.output_dir
    );
    Ok(())
}

fn build_site(site: &Site, pages: &[Page]) -> io::Result<BuildStats> {
    let output_dir = Path::new(site.output_dir);
    prepare_output_dir(output_dir)?;
    write_static_assets(output_dir)?;

    let mut stats = BuildStats::default();
    stats.assets = copy_assets(
        Path::new(site.assets_dir),
        &output_dir.join(site.assets_dir),
    )?;

    for page in pages {
        match build_page(site, pages, page, output_dir) {
            Ok(()) => {
                println!("  built  {}", page.output);
                stats.built += 1;
            }
            Err(BuildPageError::MissingSource { source }) => {
                eprintln!("  skip   {} (missing: {})", page.output, source.display());
                stats.skipped += 1;
            }
            Err(BuildPageError::Io(err)) => return Err(err),
        }
    }

    fs::write(output_dir.join("404.html"), render_not_found(site, pages))?;
    Ok(stats)
}

fn prepare_output_dir(path: &Path) -> io::Result<()> {
    if path.exists() {
        fs::remove_dir_all(path)?;
    }
    fs::create_dir_all(path)
}

fn write_static_assets(output_dir: &Path) -> io::Result<()> {
    fs::write(output_dir.join("style.css"), include_str!("style.css"))?;
    fs::write(output_dir.join(".nojekyll"), "")
}

fn copy_assets(source_dir: &Path, target_dir: &Path) -> io::Result<usize> {
    if !source_dir.exists() {
        return Ok(0);
    }

    let mut copied = 0;
    copy_dir_recursive(source_dir, target_dir, &mut copied)?;
    Ok(copied)
}

fn copy_dir_recursive(source_dir: &Path, target_dir: &Path, copied: &mut usize) -> io::Result<()> {
    fs::create_dir_all(target_dir)?;

    for entry in fs::read_dir(source_dir)? {
        let entry = entry?;
        let source = entry.path();
        let target = target_dir.join(entry.file_name());
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            copy_dir_recursive(&source, &target, copied)?;
        } else if file_type.is_file() {
            fs::copy(&source, &target)?;
            *copied += 1;
        }
    }

    Ok(())
}

fn build_page(
    site: &Site,
    pages: &[Page],
    page: &Page,
    output_dir: &Path,
) -> Result<(), BuildPageError> {
    let markdown = fs::read_to_string(page.source).map_err(|err| {
        if err.kind() == io::ErrorKind::NotFound {
            BuildPageError::MissingSource {
                source: PathBuf::from(page.source),
            }
        } else {
            BuildPageError::Io(err)
        }
    })?;

    let html = render_page(site, pages, page, &markdown_to_html(&markdown));
    fs::write(output_dir.join(page.output), html).map_err(BuildPageError::Io)
}

#[derive(Default)]
struct BuildStats {
    built: usize,
    skipped: usize,
    assets: usize,
}

enum BuildPageError {
    MissingSource { source: PathBuf },
    Io(io::Error),
}
