//! authentik-rs: the metrics text 2026.2.7's Go server serves on
//! `listen.metrics` `/metrics`.
//!
//! `prometheus/client_golang` (`promhttp.HandlerFor` on the default gatherer,
//! text format 0.0.4) sorts families by name, a family's metrics by label
//! values, and each metric's labels by name (`le` last), and formats values
//! with `strconv.FormatFloat(v, 'g', -1, 64)`. The Rust recorder's output is
//! re-rendered that way, together with the default registry's `process_*` and
//! `promhttp_*` collectors. The `go_*` runtime collector has no Rust
//! equivalent and is not emitted.

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs,
    sync::atomic::{AtomicI64, AtomicU64, Ordering},
};

/// `promhttp` text format 0.0.4 content type (`client_golang` `expfmt`).
pub(super) const CONTENT_TYPE: &str =
    "text/plain; version=0.0.4; charset=utf-8; escaping=underscores";

/// `prometheus.DefBuckets`
pub(super) const GO_DEFAULT_BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// `strconv.FormatFloat(v, 'g', -1, 64)`: shortest round-trip digits, in
/// exponent form when the decimal exponent is below -4 or at least 6 (the
/// precision `'g'` uses for shortest output), with a sign and at least two
/// exponent digits.
pub(super) fn go_float(v: f64) -> String {
    if v.is_nan() {
        return "NaN".to_owned();
    }
    if v.is_infinite() {
        return if v > 0.0 { "+Inf" } else { "-Inf" }.to_owned();
    }
    if v == 0.0_f64 {
        return if v.is_sign_negative() { "-0" } else { "0" }.to_owned();
    }
    let sci = format!("{v:e}");
    let (mantissa, exp) = sci.split_once('e').expect("LowerExp has an exponent");
    let exp: i32 = exp.parse().expect("LowerExp exponent is an integer");
    if (-4_i32..6_i32).contains(&exp) {
        format!("{v}")
    } else {
        let sign = if exp < 0 { '-' } else { '+' };
        format!("{mantissa}e{sign}{:02}", exp.unsigned_abs())
    }
}

struct Sample {
    /// Label pairs as written, values still escaped.
    labels: Vec<(String, String)>,
    suffix: &'static str,
    value: f64,
}

#[derive(Default)]
struct Family {
    help: Option<String>,
    kind: Option<String>,
    samples: Vec<Sample>,
}

fn parse_labels(raw: &str) -> Vec<(String, String)> {
    let mut labels = Vec::new();
    let mut rest = raw;
    while let Some((name, after)) = rest.split_once("=\"") {
        let name = name.trim_start_matches(',').trim().to_owned();
        let mut end = 0;
        let bytes = after.as_bytes();
        while end < bytes.len() && bytes[end] != b'"' {
            end += if bytes[end] == b'\\' { 2 } else { 1 };
        }
        let end = end.min(after.len());
        labels.push((name, after[..end].to_owned()));
        rest = after.get(end + 1..).unwrap_or("");
    }
    labels
}

/// Re-render text-format families the way `client_golang` writes them.
pub(super) fn render(text: &str) -> String {
    let mut families: BTreeMap<String, Family> = BTreeMap::new();
    let mut current = String::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("# HELP ") {
            let (name, help) = rest.split_once(' ').unwrap_or((rest, ""));
            name.clone_into(&mut current);
            families.entry(current.clone()).or_default().help = Some(help.to_owned());
        } else if let Some(rest) = line.strip_prefix("# TYPE ") {
            let (name, kind) = rest.split_once(' ').unwrap_or((rest, "untyped"));
            name.clone_into(&mut current);
            families.entry(current.clone()).or_default().kind = Some(kind.to_owned());
        } else if !line.is_empty() && !line.starts_with('#') {
            let (series, value) = line.rsplit_once(' ').unwrap_or((line, ""));
            // Rust also parses `+Inf`/`-Inf`/`NaN`.
            let Ok(value) = value.parse::<f64>() else {
                continue;
            };
            let (name, labels) = match series.split_once('{') {
                Some((name, labels)) => (name, parse_labels(labels.trim_end_matches('}'))),
                None => (series, Vec::new()),
            };
            let (family, suffix) = ["_bucket", "_sum", "_count"]
                .into_iter()
                .find_map(|suffix| {
                    name.strip_suffix(suffix)
                        .filter(|base| *base == current)
                        .map(|base| (base.to_owned(), suffix))
                })
                .unwrap_or_else(|| (name.to_owned(), ""));
            families.entry(family).or_default().samples.push(Sample {
                labels,
                suffix,
                value,
            });
        }
    }

    let mut out = String::new();
    for (name, family) in families {
        if family.samples.is_empty() {
            continue;
        }
        if let Some(help) = &family.help {
            let _ = writeln!(out, "# HELP {name} {help}");
        }
        let _ = writeln!(
            out,
            "# TYPE {name} {}",
            family.kind.as_deref().unwrap_or("untyped")
        );
        // One metric per label set (without `le`), sorted by label values.
        let mut metrics: BTreeMap<Vec<(String, String)>, Vec<&Sample>> = BTreeMap::new();
        for sample in &family.samples {
            let mut key: Vec<(String, String)> = sample
                .labels
                .iter()
                .filter(|(label, _)| label != "le")
                .cloned()
                .collect();
            key.sort();
            metrics.entry(key).or_default().push(sample);
        }
        let mut metrics: Vec<_> = metrics.into_iter().collect();
        metrics.sort_by(|(a, _), (b, _)| a.iter().map(|(_, v)| v).cmp(b.iter().map(|(_, v)| v)));
        for (labels, samples) in metrics {
            let mut buckets: Vec<(f64, f64)> = Vec::new();
            let mut others: Vec<&Sample> = Vec::new();
            for sample in samples {
                if sample.suffix == "_bucket" {
                    let le = sample
                        .labels
                        .iter()
                        .find(|(label, _)| label == "le")
                        .and_then(|(_, v)| match v.as_str() {
                            "+Inf" => Some(f64::INFINITY),
                            v => v.parse().ok(),
                        })
                        .unwrap_or(f64::INFINITY);
                    buckets.push((le, sample.value));
                } else {
                    others.push(sample);
                }
            }
            buckets.sort_by(|a, b| a.0.total_cmp(&b.0));
            let write = |out: &mut String, suffix: &str, le: Option<f64>, value: f64| {
                let mut pairs: Vec<String> =
                    labels.iter().map(|(k, v)| format!("{k}=\"{v}\"")).collect();
                if let Some(le) = le {
                    pairs.push(format!("le=\"{}\"", go_float(le)));
                }
                let pairs = if pairs.is_empty() {
                    String::new()
                } else {
                    format!("{{{}}}", pairs.join(","))
                };
                let _ = writeln!(out, "{name}{suffix}{pairs} {}", go_float(value));
            };
            for (le, value) in buckets {
                write(&mut out, "_bucket", Some(le), value);
            }
            for suffix in ["", "_sum", "_count"] {
                for sample in others.iter().filter(|s| s.suffix == suffix) {
                    write(&mut out, suffix, None, sample.value);
                }
            }
        }
    }
    out
}

/// `prometheus/procfs`'s fixed `userHZ`.
const USER_HZ: f64 = 100.0;

fn limit(limits: &str, name: &str) -> Option<f64> {
    let line = limits.lines().find(|line| line.starts_with(name))?;
    let soft = line[name.len()..].split_whitespace().next()?;
    Some(if soft == "unlimited" {
        // procfs parses "unlimited" as the maximum uint64.
        #[expect(clippy::as_conversions, clippy::cast_precision_loss, reason = "as Go")]
        let max = u64::MAX as f64;
        max
    } else {
        soft.parse().ok()?
    })
}

/// `client_golang`'s process collector (Linux), in its registry text form.
pub(super) fn process_text() -> String {
    let mut out = String::new();
    let mut family = |name: &str, help: &str, kind: &str, value: Option<f64>| {
        if let Some(value) = value {
            let _ = write!(
                out,
                "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {}\n",
                go_float(value)
            );
        }
    };
    let stat = fs::read_to_string("/proc/self/stat").unwrap_or_default();
    // Fields after the parenthesised command name, starting at field 3.
    let fields: Vec<&str> = stat
        .rsplit_once(')')
        .map(|(_, rest)| rest.split_whitespace().collect())
        .unwrap_or_default();
    let field = |n: usize| {
        let v = fields.get(n - 3)?;
        v.parse::<f64>().ok()
    };
    let boot_time = fs::read_to_string("/proc/stat").ok().and_then(|stat| {
        stat.lines()
            .find_map(|line| line.strip_prefix("btime "))?
            .trim()
            .parse::<f64>()
            .ok()
    });
    let limits = fs::read_to_string("/proc/self/limits").unwrap_or_default();
    // `stat` rss × page size; `status` VmRSS is the same counter in kB.
    let resident = fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("VmRSS:"))
                .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<f64>().ok())
                .map(|kb| kb * 1024.0_f64)
        });
    let open_fds = fs::read_dir("/proc/self/fd").ok().map(|dir| {
        #[expect(
            clippy::as_conversions,
            clippy::cast_precision_loss,
            reason = "fd count"
        )]
        let count = dir.count() as f64;
        count
    });
    let net = fs::read_to_string("/proc/self/net/dev").ok().map(|dev| {
        dev.lines()
            .skip(2)
            .filter_map(|line| line.split_once(':'))
            .map(|(_, counters)| {
                let counters: Vec<f64> = counters
                    .split_whitespace()
                    .filter_map(|v| v.parse().ok())
                    .collect();
                (
                    counters.first().copied().unwrap_or(0.0_f64),
                    counters.get(8).copied().unwrap_or(0.0_f64),
                )
            })
            .fold((0.0_f64, 0.0_f64), |(rx, tx), (r, t)| (rx + r, tx + t))
    });

    family(
        "process_cpu_seconds_total",
        "Total user and system CPU time spent in seconds.",
        "counter",
        field(14)
            .zip(field(15))
            .map(|(utime, stime)| (utime + stime) / USER_HZ),
    );
    family(
        "process_max_fds",
        "Maximum number of open file descriptors.",
        "gauge",
        limit(&limits, "Max open files"),
    );
    family(
        "process_network_receive_bytes_total",
        "Number of bytes received by the process over the network.",
        "counter",
        net.map(|(rx, _)| rx),
    );
    family(
        "process_network_transmit_bytes_total",
        "Number of bytes sent by the process over the network.",
        "counter",
        net.map(|(_, tx)| tx),
    );
    family(
        "process_open_fds",
        "Number of open file descriptors.",
        "gauge",
        open_fds,
    );
    family(
        "process_resident_memory_bytes",
        "Resident memory size in bytes.",
        "gauge",
        resident,
    );
    family(
        "process_start_time_seconds",
        "Start time of the process since unix epoch in seconds.",
        "gauge",
        field(22)
            .zip(boot_time)
            .map(|(start, boot)| boot + start / USER_HZ),
    );
    family(
        "process_virtual_memory_bytes",
        "Virtual memory size in bytes.",
        "gauge",
        field(23),
    );
    family(
        "process_virtual_memory_max_bytes",
        "Maximum amount of virtual memory available in bytes.",
        "gauge",
        limit(&limits, "Max address space"),
    );
    out
}

/// `promhttp.InstrumentMetricHandler`'s two collectors.
#[derive(Default)]
pub(super) struct PromHttp {
    in_flight: AtomicI64,
    ok: AtomicU64,
}

impl PromHttp {
    /// Mark a scrape as in flight; the guard counts it as served (code 200)
    /// when dropped, after the text has been gathered, as Go does.
    pub(super) fn scrape(&self) -> ScrapeGuard<'_> {
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        ScrapeGuard(self)
    }

    pub(super) fn text(&self) -> String {
        format!(
            "# HELP promhttp_metric_handler_requests_in_flight Current number of scrapes being \
             served.\n# TYPE promhttp_metric_handler_requests_in_flight \
             gauge\npromhttp_metric_handler_requests_in_flight {}\n# HELP \
             promhttp_metric_handler_requests_total Total number of scrapes by HTTP status \
             code.\n# TYPE promhttp_metric_handler_requests_total \
             counter\npromhttp_metric_handler_requests_total{{code=\"200\"}} \
             {}\npromhttp_metric_handler_requests_total{{code=\"500\"}} \
             0\npromhttp_metric_handler_requests_total{{code=\"503\"}} 0\n",
            self.in_flight.load(Ordering::SeqCst),
            self.ok.load(Ordering::SeqCst),
        )
    }
}

pub(super) struct ScrapeGuard<'a>(&'a PromHttp);

#[expect(clippy::missing_trait_methods, reason = "pin_drop is not used")]
impl Drop for ScrapeGuard<'_> {
    fn drop(&mut self) {
        self.0.ok.fetch_add(1, Ordering::SeqCst);
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_float_matches_format_float_g() {
        // Expected values from Go 1.25.5 strconv.FormatFloat(v, 'g', -1, 64).
        let cases: [(f64, &str); 16] = [
            (1_048_576.0, "1.048576e+06"),
            (9.96, "9.96"),
            (16.0, "16"),
            (41.687_316_063_000_004, "41.687316063000004"),
            (1.793_372_699_344_645_7e9, "1.7933726993446457e+09"),
            (1.844_674_407_370_955_2e19, "1.8446744073709552e+19"),
            (0.005, "0.005"),
            (0.000_01, "1e-05"),
            (123_456.0, "123456"),
            (f64::INFINITY, "+Inf"),
            (0.0, "0"),
            (999_999.0, "999999"),
            (1e6, "1e+06"),
            (0.0001, "0.0001"),
            (1e21, "1e+21"),
            (2.5, "2.5"),
        ];
        for (v, go) in cases {
            assert_eq!(go_float(v), go, "{v}");
        }
    }

    #[test]
    fn render_sorts_like_client_golang() {
        let rust = "# HELP b_metric B help\n# TYPE b_metric gauge\nb_metric{z=\"1\",a=\"2\"} \
                    3\nb_metric{z=\"0\",a=\"2\"} 1000000\n\n# HELP a_hist A help\n# TYPE a_hist \
                    histogram\na_hist_bucket{dest=\"core\",le=\"+Inf\"} \
                    2\na_hist_bucket{dest=\"core\",le=\"0.5\"} 1\na_hist_sum{dest=\"core\"} \
                    0.75\na_hist_count{dest=\"core\"} 2\n";
        assert_eq!(
            render(rust),
            "# HELP a_hist A help\n# TYPE a_hist \
             histogram\na_hist_bucket{dest=\"core\",le=\"0.5\"} \
             1\na_hist_bucket{dest=\"core\",le=\"+Inf\"} 2\na_hist_sum{dest=\"core\"} \
             0.75\na_hist_count{dest=\"core\"} 2\n# HELP b_metric B help\n# TYPE b_metric \
             gauge\nb_metric{a=\"2\",z=\"0\"} 1e+06\nb_metric{a=\"2\",z=\"1\"} 3\n"
        );
    }

    #[test]
    fn process_text_has_every_family() {
        let text = process_text();
        for name in [
            "process_cpu_seconds_total",
            "process_max_fds",
            "process_network_receive_bytes_total",
            "process_network_transmit_bytes_total",
            "process_open_fds",
            "process_resident_memory_bytes",
            "process_start_time_seconds",
            "process_virtual_memory_bytes",
            "process_virtual_memory_max_bytes",
        ] {
            assert!(
                text.contains(&format!("\n{name} ")),
                "{name} missing:\n{text}"
            );
        }
    }
}
