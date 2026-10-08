/*-
 * #%L
 * ngx_pep
 * %%
 * (C) tech@Spree GmbH, 2026, licensed for gematik GmbH
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 * #L%
 */

//! Client-side latency + throughput to stdout, wrk2-style, via HdrHistogram.
//!
//! Workers never touch a histogram directly (no lock contention across the
//! task pool): each fires a non-blocking `Sample` down an mpsc to a single
//! aggregator task that owns the histograms, prints a rolling report at a fixed
//! interval (`REPORT_INTERVAL_SECS`), and a cumulative summary when the last
//! `Recorder` drops.
//!
//! Coordinated omission is handled by HdrHistogram's `record_correct`: when a
//! recorded latency exceeds the expected inter-request interval, the tail is
//! back-filled so a stall shows up as many slow samples, not one. (We can't
//! measure from a per-request scheduled deadline here — the governor is a
//! single shared limiter, so per-worker request timing isn't well defined.)

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use hdrhistogram::Histogram;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

const REPORT_INTERVAL_SECS: u64 = 30;

pub struct Sample {
    pub label: &'static str,
    pub latency_us: u64,
}

enum Msg {
    Sample(Sample),
    Error(String),
    Reset,
}

#[derive(Clone)]
pub struct Recorder(UnboundedSender<Msg>);

impl Recorder {
    /// Time an awaited call and record its client-observed round-trip latency.
    pub async fn time<F, T>(&self, label: &'static str, fut: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        let t0 = Instant::now();
        let out = fut.await;
        let _ = self.0.send(Msg::Sample(Sample {
            label,
            latency_us: t0.elapsed().as_micros() as u64,
        }));
        out
    }

    /// Discard everything recorded so far and restart the clock. Call when
    /// ramp-up completes: CO correction assumes the full target rate was
    /// intended, which doesn't hold while workers are still starting — so
    /// ramp samples are dropped rather than (over-)corrected, and the
    /// histograms cover pure steady state.
    pub fn reset(&self) {
        let _ = self.0.send(Msg::Reset);
    }

    /// Tally an error for the end-of-run table. Counted by message across the
    /// WHOLE run (a stats reset does not clear the tally — errors are
    /// diagnostics, not statistics).
    pub fn error(&self, msg: String) {
        let _ = self.0.send(Msg::Error(msg));
    }
}

/// Spawn the aggregator. `expected_interval_us` enables coordinated-omission
/// correction: set it to the per-stream inter-request interval — for an
/// N-thread closed loop that is `1_000_000 * threads / target_rps`, not the
/// global `1_000_000 / target_rps` (the global value over-inflates the back-fill
/// by a factor of `threads`). `None` records raw with no back-fill.
pub fn spawn(expected_interval_us: Option<u64>) -> Recorder {
    let (tx, rx) = unbounded_channel();
    tokio::spawn(aggregate(rx, expected_interval_us));
    Recorder(tx)
}

async fn aggregate(mut rx: UnboundedReceiver<Msg>, iv: Option<u64>) {
    // 3 significant figures, microseconds, auto-resizing.
    let mut total: BTreeMap<&'static str, Histogram<u64>> = BTreeMap::new();
    let mut window: BTreeMap<&'static str, Histogram<u64>> = BTreeMap::new();
    let mut win_n = 0u64;
    // real completed-request counts, kept separate from histogram len() because
    // record_correct() inflates len() with CO back-fill samples
    let mut total_n = 0u64;
    let mut errors: BTreeMap<String, u64> = BTreeMap::new();
    let mut start = Instant::now();

    let mut tick = tokio::time::interval(Duration::from_secs(REPORT_INTERVAL_SECS));
    tick.tick().await; // drop the immediate first tick

    loop {
        tokio::select! {
            got = rx.recv() => {
                let Some(msg) = got else { break }; // all Recorders dropped -> final dump
                let s = match msg {
                    Msg::Sample(s) => s,
                    Msg::Error(e) => {
                        *errors.entry(e).or_insert(0) += 1;
                        continue;
                    }
                    Msg::Reset => {
                        total.clear();
                        window.clear();
                        win_n = 0;
                        total_n = 0;
                        start = Instant::now();
                        tick.reset();
                        println!("\n=== stats reset (ramp-up complete) ===");
                        continue;
                    }
                };
                let record = |h: &mut Histogram<u64>| match iv {
                    Some(iv) => { let _ = h.record_correct(s.latency_us, iv); }
                    None => { h.saturating_record(s.latency_us); }
                };
                // record under the op's own label plus a shared "ALL" rollup
                for key in [s.label, "ALL"] {
                    record(total.entry(key).or_insert_with(|| Histogram::new(3).unwrap()));
                    record(window.entry(key).or_insert_with(|| Histogram::new(3).unwrap()));
                }
                win_n += 1;
                total_n += 1;
            }
            _ = tick.tick() => {
                let secs = start.elapsed().as_secs_f64();
                report(&format!("last {REPORT_INTERVAL_SECS}s"), &window, win_n, REPORT_INTERVAL_SECS as f64);
                // whole-run rollup too: only it has the sample volume to fill the
                // tail past ~p99.9 (a 10s window collapses those quantiles to max)
                report("cumulative", &total, total_n, secs);
                println!();
                window.clear();
                win_n = 0;
            }
        }
    }

    let secs = start.elapsed().as_secs_f64();
    report("final", &total, total_n, secs);
    println!();
    report_errors(&errors);
}

fn report_errors(errors: &BTreeMap<String, u64>) {
    if errors.is_empty() {
        println!("\n=== errors ===  none");
        return;
    }
    let mut rows: Vec<(&String, &u64)> = errors.iter().collect();
    rows.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    let total: u64 = errors.values().sum();
    println!("\n=== errors ===  total {total}");
    for (msg, n) in rows {
        println!("{n:>6} {msg}");
    }
}

fn report(title: &str, hists: &BTreeMap<&'static str, Histogram<u64>>, count: u64, secs: f64) {
    let rps = if secs > 0.0 {
        count as f64 / secs
    } else {
        f64::NAN
    };
    let ms = |v: u64| v as f64 / 1000.0;
    let Some(all) = hists.get("ALL").filter(|h| !h.is_empty()) else {
        println!("\n=== {title} ===  Requests/sec: {rps:.2}  (no samples)");
        return;
    };
    println!("=== {title} ===");
    println!(
        "  Latency  Avg {:.2}ms  Stdev {:.2}ms  Max {:.2}ms",
        all.mean() / 1000.0,
        all.stdev() / 1000.0,
        ms(all.max())
    );
    for q in [0.5, 0.75, 0.9, 0.99, 0.999, 0.9999, 0.99999, 1.0] {
        println!(
            "{:>9.3}% {:>10.2}ms",
            q * 100.0,
            ms(all.value_at_quantile(q))
        );
    }
    println!(
        "#[Min = {:.3}ms Mean = {:.3}ms Std = {:.3}ms Max = {:.3}ms Count={} Requests={} Req/s={:.2}]",
        all.min() as f64 / 1000.0,
        all.mean() / 1000.0,
        all.stdev() / 1000.0,
        all.max() as f64 / 1000.0,
        all.len(),
        count,
        rps
    );
}
