//! A real wall-clock timer for the CTAP core (OpenSK's `TestClock` is manual).

use opensk::api::clock::Clock;
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct RealTimer {
    /// `None` means "already elapsed" (the required default behavior).
    deadline: Option<Instant>,
}

pub struct RealClock;

impl Clock for RealClock {
    type Timer = RealTimer;

    fn make_timer(&mut self, milliseconds: usize) -> Self::Timer {
        RealTimer {
            deadline: Some(Instant::now() + Duration::from_millis(milliseconds as u64)),
        }
    }

    fn is_elapsed(&mut self, timer: &Self::Timer) -> bool {
        match timer.deadline {
            Some(d) => Instant::now() >= d,
            None => true,
        }
    }

    #[cfg(feature = "debug_ctap")]
    fn timestamp_us(&mut self) -> usize {
        // Microseconds since the first call (process start, in practice).
        static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
        START.get_or_init(Instant::now).elapsed().as_micros() as usize
    }
}
