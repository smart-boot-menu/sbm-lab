use crate::accel::ExecutionClass;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct SummaryStats {
    pub n: u32,
    pub p50_ms: u64,
    pub p95_ms: u64,
    pub max_ms: u64,
    pub min_ms: u64,
}

pub fn summarize(mut samples: Vec<u64>) -> SummaryStats {
    if samples.is_empty() {
        return SummaryStats {
            n: 0,
            p50_ms: 0,
            p95_ms: 0,
            max_ms: 0,
            min_ms: 0,
        };
    }
    samples.sort_unstable();
    SummaryStats {
        n: u32::try_from(samples.len()).unwrap_or(u32::MAX),
        p50_ms: percentile(&samples, 50.0),
        p95_ms: percentile(&samples, 95.0),
        max_ms: *samples.last().unwrap_or(&0),
        min_ms: samples[0],
    }
}

/// Index `round(percent/100 * (n - 1))` into a sorted sample.
/// `methodology_complete` elsewhere requires n >= 10.
pub fn percentile(sorted: &[u64], percent: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((percent / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[rank.min(sorted.len() - 1)]
}

pub fn methodology_complete(n: u32) -> bool {
    n >= 10
}

pub fn class_note(class: ExecutionClass, cross_arch: bool) -> &'static str {
    match (class, cross_arch) {
        (ExecutionClass::Emulation, true) => {
            "TCG cross-architecture emulation is not representative of physical hardware."
        }
        (ExecutionClass::Emulation, false) => {
            "TCG emulation is not representative of physical hardware."
        }
        (ExecutionClass::AcceleratedVirtualization, _) => {
            "Accelerated virtualization is not a physical-hardware measurement."
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_of_ten_samples() {
        let samples: Vec<u64> = (1..=10).collect();
        let stats = summarize(samples);
        assert_eq!(stats.p50_ms, 6);
        assert_eq!(stats.min_ms, 1);
        assert_eq!(stats.max_ms, 10);
        assert!(methodology_complete(stats.n));
        assert!(!methodology_complete(3));
    }
}
