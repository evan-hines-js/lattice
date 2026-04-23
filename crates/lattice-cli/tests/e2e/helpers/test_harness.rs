//! Test harness for run-all-and-report test execution.
#![cfg(feature = "provider-e2e")]

use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::Mutex;
use std::time::Duration;

use futures::FutureExt;
use tokio::time::Instant;
use tracing::info;

use super::diagnostics::panic_message;

pub struct TestResult {
    pub name: String,
    pub passed: bool,
    pub duration: Duration,
    pub error: Option<String>,
}

pub struct TestHarness {
    suite: String,
    results: std::sync::Arc<Mutex<Vec<TestResult>>>,
    started: Instant,
}

impl TestHarness {
    pub fn new(suite: &str) -> Self {
        Self {
            suite: suite.to_string(),
            results: std::sync::Arc::new(Mutex::new(Vec::new())),
            started: Instant::now(),
        }
    }

    pub async fn run<F, Fut>(&self, name: &str, f: F)
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(), String>>,
    {
        let start = Instant::now();
        let result = AssertUnwindSafe(f()).catch_unwind().await;
        let (passed, error) = match result {
            Ok(Ok(())) => (true, None),
            Ok(Err(e)) => (false, Some(e)),
            Err(panic) => (false, Some(format!("PANIC: {}", panic_message(&*panic)))),
        };
        self.results.lock().unwrap().push(TestResult {
            name: name.to_string(),
            passed,
            duration: start.elapsed(),
            error,
        });
    }

    pub fn record(&self, name: &str, passed: bool, duration: Duration, error: Option<String>) {
        self.results.lock().unwrap().push(TestResult {
            name: name.to_string(),
            passed,
            duration,
            error,
        });
    }

    pub fn finish(&self) -> Result<(), String> {
        let results = self.results.lock().unwrap();
        let aggregate_duration: Duration = results.iter().map(|r| r.duration).sum();
        let wall_duration = self.started.elapsed();
        let passed = results.iter().filter(|r| r.passed).count();
        let failed = results.iter().filter(|r| !r.passed).count();

        info!("========================================");
        info!("  {}", self.suite.to_uppercase());
        info!("========================================");
        for r in results.iter() {
            let tag = if r.passed { "PASS" } else { "FAIL" };
            info!("  {tag}  {:40} {:.1}s", r.name, r.duration.as_secs_f64());
            if let Some(ref e) = r.error {
                // Truncate very long errors to keep the summary readable
                let truncated = if e.len() > 200 { &e[..200] } else { e };
                info!("        -> {truncated}");
            }
        }
        info!("----------------------------------------");
        // Wall is the real phase duration; aggregate is the sum of
        // per-task durations. For concurrent phases aggregate >> wall
        // by the effective parallelism factor; sequential phases have
        // aggregate ≈ wall.
        info!(
            "  {} passed, {} failed in {:.1}s wall ({:.1}s aggregate)",
            passed,
            failed,
            wall_duration.as_secs_f64(),
            aggregate_duration.as_secs_f64()
        );
        info!("========================================");

        if failed > 0 {
            let failures: Vec<_> = results
                .iter()
                .filter(|r| !r.passed)
                .map(|r| r.name.as_str())
                .collect();
            Err(format!(
                "{} test(s) failed in {}: {}",
                failed,
                self.suite,
                failures.join(", ")
            ))
        } else {
            Ok(())
        }
    }
}
