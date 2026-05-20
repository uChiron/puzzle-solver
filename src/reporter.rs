use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use human_format::Formatter;

pub struct Report {
    pub hashes: u64,
    pub last_key: String,
}

#[derive(Clone)]
pub struct Reporter {
    last_key: String,
    rate: u64,
    interval: Duration,
    report_at: Instant,
}

impl Reporter {
    pub fn clean() -> Self {
        Self {
            last_key: String::new(),
            rate: 0,
            report_at: Instant::now(),
            interval: Duration::from_secs(10),
        }
    }

    pub fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            last_key: String::new(),
            rate: 0,
            report_at: Instant::now(),
            interval: Duration::from_secs(1),
        }))
    }

    pub fn update(&mut self, report: Report) {
        self.rate += report.hashes;
        self.last_key = report.last_key;

        let duration = Instant::now().duration_since(self.report_at);

        if duration.gt(&self.interval) {
            let count = self.rate.div_ceil(duration.as_secs());

            let mut scales = human_format::Scales::new();

            scales.with_base(1000);
            scales.with_suffixes(vec!["H/s", "KH/s", "MH/s", "GH/s", "TH/s", "PH/s", "EH/s"]);

            let number = Formatter::new()
                .with_scales(scales)
                .format(count as f64);

            println!("Hashrate: {} | Last key: {}", number, self.last_key);

            self.rate = 0;
            self.report_at = Instant::now();
        }
    }
}