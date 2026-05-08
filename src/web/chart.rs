//! Server-side SVG chart rendering. No external crates — pure string formatting.
//! All color constants are kept out of raw string delimiters to avoid `"#` termination.

const GRID:     &str = "#e2e8f0";
const BASELINE: &str = "#cbd5e1";
const LABEL_FG: &str = "#94a3b8";
const MUTED_FG: &str = "#64748b";

pub struct Series<'a> {
    pub label:  &'static str,
    pub color:  &'static str, // hex e.g. "#3b82f6"
    pub values: &'a [u64],    // oldest → newest, one bucket per point
}

// ---- sparkline (80×32 px) --------------------------------------------------

pub fn sparkline(values: &[u64], color: &str) -> Vec<u8> {
    const W: u64 = 80;
    const H: u64 = 32;
    const P: u64 = 2;
    let mid = H / 2;

    let max = values.iter().copied().max().unwrap_or(0);

    let svg = if max == 0 || values.is_empty() {
        format!(
            r#"<svg viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg">
  <line x1="{P}" y1="{mid}" x2="{}" y2="{mid}"
        stroke="{color}" stroke-width="1.5" stroke-opacity="0.2" stroke-dasharray="3 2"/>
</svg>"#,
            W - P
        )
    } else {
        let n = values.len() as u64;
        let iw = W - 2 * P;
        let ih = H - 2 * P;

        let coords: Vec<(u64, u64)> = values
            .iter()
            .enumerate()
            .map(|(i, &v)| {
                let x = P + i as u64 * iw / (n - 1).max(1);
                let y = P + ih - (v * ih / max);
                (x, y)
            })
            .collect();

        let line_pts = pts_str(&coords);
        let fx = coords.first().map_or(P, |&(x, _)| x);
        let lx = coords.last().map_or(W - P, |&(x, _)| x);
        let bot = H - P;

        format!(
            r#"<svg viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg">
  <polygon points="{fx},{bot} {line_pts} {lx},{bot}"
           fill="{color}" fill-opacity="0.15"/>
  <polyline points="{line_pts}"
            fill="none" stroke="{color}" stroke-width="1.5"
            stroke-linecap="round" stroke-linejoin="round"/>
</svg>"#
        )
    };

    svg.into_bytes()
}

// ---- traffic chart (600×140 viewBox) ---------------------------------------

pub fn traffic_chart(series: &[Series<'_>]) -> Vec<u8> {
    const W: u64 = 600;
    const H: u64 = 140;
    const PL: u64 = 28; // left  (y labels)
    const PB: u64 = 18; // bottom (x labels)
    const PT: u64 = 8;
    const PR: u64 = 8;

    let iw = W - PL - PR;
    let ih = H - PT - PB;
    let y0 = PT + ih; // x-axis baseline

    let max = series
        .iter()
        .flat_map(|s| s.values.iter().copied())
        .max()
        .unwrap_or(0)
        .max(1);

    let n_pts = series.iter().map(|s| s.values.len()).max().unwrap_or(0) as u64;

    let mut out = format!(
        r#"<svg viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg" style="width:100%;height:140px">"#
    );

    // horizontal grid lines + Y labels
    for step in 1u64..=3 {
        let y   = PT + step * ih / 4;
        let val = max * (4 - step) / 4;
        out.push_str(&format!(
            r#"<line x1="{PL}" y1="{y}" x2="{}" y2="{y}" stroke="{GRID}" stroke-width="0.5"/>"#,
            W - PR
        ));
        out.push_str(&format!(
            r#"<text x="{}" y="{}" font-size="8" fill="{LABEL_FG}" text-anchor="end">{val}</text>"#,
            PL - 3,
            y + 3
        ));
    }

    // baseline
    out.push_str(&format!(
        r#"<line x1="{PL}" y1="{y0}" x2="{}" y2="{y0}" stroke="{BASELINE}" stroke-width="1"/>"#,
        W - PR
    ));

    // series
    for s in series {
        if s.values.is_empty() {
            continue;
        }
        let n = s.values.len() as u64;
        let color = s.color;

        let coords: Vec<(u64, u64)> = s
            .values
            .iter()
            .enumerate()
            .map(|(i, &v)| {
                let x = PL + i as u64 * iw / (n - 1).max(1);
                let y = PT + ih - (v * ih / max);
                (x, y)
            })
            .collect();

        let line_pts = pts_str(&coords);
        let fx = coords.first().map_or(PL, |&(x, _)| x);
        let lx = coords.last().map_or(W - PR, |&(x, _)| x);

        out.push_str(&format!(
            r#"<polygon points="{fx},{y0} {line_pts} {lx},{y0}" fill="{color}" fill-opacity="0.08"/>"#
        ));
        out.push_str(&format!(
            r#"<polyline points="{line_pts}" fill="none" stroke="{color}" stroke-width="2"
                        stroke-linecap="round" stroke-linejoin="round"/>"#
        ));

        // end-of-line label
        if let Some(&(lx2, ly)) = coords.last() {
            out.push_str(&format!(
                r#"<text x="{}" y="{}" font-size="8" fill="{color}" font-weight="600">{}</text>"#,
                lx2 + 3,
                ly + 3,
                s.label
            ));
        }
    }

    // X axis time labels
    if n_pts > 1 {
        for i in 0u64..=4 {
            let x    = PL + i * iw / 4;
            let mins = (4 - i) * (n_pts - 1) / 4;
            let label = if mins == 0 { "now".into() } else { format!("-{mins}m") };
            out.push_str(&format!(
                r#"<text x="{x}" y="{}" font-size="8" fill="{LABEL_FG}" text-anchor="middle">{label}</text>"#,
                H - 3
            ));
        }
    } else {
        // empty state label
        let cx = PL + iw / 2;
        let cy = PT + ih / 2;
        out.push_str(&format!(
            r#"<text x="{cx}" y="{cy}" font-size="11" fill="{MUTED_FG}" text-anchor="middle">No data yet</text>"#
        ));
    }

    out.push_str("</svg>");
    out.into_bytes()
}

fn pts_str(coords: &[(u64, u64)]) -> String {
    coords
        .iter()
        .map(|(x, y)| format!("{x},{y}"))
        .collect::<Vec<_>>()
        .join(" ")
}
