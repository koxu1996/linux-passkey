//! Virtual FIDO2 USB-HID device via /dev/uhid, implementing OpenSK's
//! `HidConnection` (send = write INPUT report, recv = next OUTPUT report).
//!
//! A background thread reads uhid into an inbox. OpenSK reads nothing while it
//! waits for the user during built-in UV, so the approval code (`presence.rs`,
//! `fingerprint.rs`) checks the inbox itself for CTAPHID_CANCEL and for the
//! host closing the device.

use opensk::api::connection::{HidConnection, RecvStatus, UsbEndpoint};
use opensk::ctap::status_code::{Ctap2StatusCode, CtapResult};
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};
use uhid_virt::{Bus, CreateParams, InputEvent, OutputEvent, StreamError, UHID_EVENT_SIZE};

const REPORT_SIZE: usize = 64;
const CTAPHID_CANCEL: u8 = 0x91;

/// FIDO CTAPHID report descriptor: usage page 0xF1D0, 64-byte in/out reports.
pub const FIDO_HID_REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
    0x09, 0x01, // Usage (CTAP HID)
    0xA1, 0x01, // Collection (Application)
    0x09, 0x20, //   Usage (Data In)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x81, 0x02, //   Input (Data,Var,Abs)
    0x09, 0x21, //   Usage (Data Out)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x91, 0x02, //   Output (Data,Var,Abs)
    0xC0, // End Collection
];

/// Reports from the host, filled by the reader thread.
struct Inbox {
    state: Mutex<InboxState>,
    ready: Condvar,
}

struct InboxState {
    packets: VecDeque<[u8; 64]>,
    /// How many times the host closed the device (last opener went away).
    closes: u64,
    /// The device is gone (read error or STOP): recv fails from now on.
    failed: bool,
    /// [`wake`] was called: the next recv returns at once.
    woken: bool,
}

static INBOX: Inbox = Inbox {
    state: Mutex::new(InboxState { packets: VecDeque::new(), closes: 0, failed: false, woken: false }),
    ready: Condvar::new(),
};

fn inbox() -> std::sync::MutexGuard<'static, InboxState> {
    INBOX.state.lock().unwrap_or_else(|e| e.into_inner())
}

/// Count of host closes so far; a change means the host gave up on the request.
pub fn closes() -> u64 {
    inbox().closes
}

/// The next report from the host, if one is waiting.
pub fn take_packet() -> Option<[u8; 64]> {
    inbox().packets.pop_front()
}

/// Remove a waiting CTAPHID_CANCEL for channel `cid`; true if there was one.
/// Other reports stay queued for the main loop.
pub fn take_cancel(cid: [u8; 4]) -> bool {
    let mut st = inbox();
    let found = st.packets.iter().position(|p| p[..4] == cid && p[4] == CTAPHID_CANCEL);
    found.is_some_and(|i| st.packets.remove(i).is_some())
}

/// Make a waiting (or the next) recv return early, for work that doesn't come
/// from the host (D-Bus requests).
pub fn wake() {
    inbox().woken = true;
    INBOX.ready.notify_all();
}

/// Queue a CTAPHID_CANCEL for channel `cid`, as if the host had sent it: how a
/// D-Bus request is cancelled while it waits for the user.
pub fn push_cancel(cid: [u8; 4]) {
    let mut pkt = [0u8; 64];
    pkt[..4].copy_from_slice(&cid);
    pkt[4] = CTAPHID_CANCEL;
    inbox().packets.push_back(pkt);
    INBOX.ready.notify_all();
}

pub struct UhidConnection {
    /// None for CLI commands, which need an Env but no virtual device.
    file: Option<File>,
}

impl UhidConnection {
    pub fn create() -> anyhow::Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/uhid")?;
        let params = CreateParams {
            name: String::from("linux-passkey FIDO2"),
            phys: String::new(),
            uniq: String::new(),
            bus: Bus::USB,
            vendor: 0x1209,
            product: 0xF1D0,
            version: 0,
            country: 0,
            rd_data: FIDO_HID_REPORT_DESCRIPTOR.to_vec(),
        };
        let event: [u8; UHID_EVENT_SIZE] = InputEvent::Create(params).into();
        file.write_all(&event)?;
        let reader = file.try_clone()?;
        std::thread::spawn(move || read_events(reader));
        Ok(UhidConnection { file: Some(file) })
    }

    /// A connection with no device behind it (send/recv fail).
    pub fn detached() -> Self {
        UhidConnection { file: None }
    }
}

fn hw_err() -> Ctap2StatusCode {
    Ctap2StatusCode::CTAP2_ERR_VENDOR_HARDWARE_FAILURE
}

/// Reader thread: move uhid events into the inbox until the device goes away.
fn read_events(mut file: File) {
    let mut event = [0u8; UHID_EVENT_SIZE];
    loop {
        if file.read_exact(&mut event).is_err() {
            break;
        }
        match OutputEvent::try_from(event) {
            Ok(OutputEvent::Output { data }) => {
                // hidraw may prepend a report-ID byte (0x00); strip it.
                let stripped = data.len() == REPORT_SIZE + 1 && data[0] == 0;
                let payload: &[u8] = if stripped {
                    &data[1..]
                } else {
                    &data[..data.len().min(REPORT_SIZE)]
                };
                let n = payload.len().min(REPORT_SIZE);
                let mut pkt = [0u8; 64];
                pkt[..n].copy_from_slice(&payload[..n]);
                inbox().packets.push_back(pkt);
                INBOX.ready.notify_all();
            }
            Ok(OutputEvent::Open) => tracing::info!("host opened HID device"),
            Ok(OutputEvent::Close) => {
                tracing::info!("host closed HID device");
                // Reports the host left behind are for a transaction nobody waits for.
                let mut st = inbox();
                st.closes += 1;
                st.packets.clear();
            }
            Ok(OutputEvent::Start { .. }) => tracing::debug!("HID device started"),
            Ok(OutputEvent::Stop) => {
                tracing::info!("HID device stopped by host");
                break;
            }
            Ok(_) => {} // GetReport / SetReport — ignore
            Err(StreamError::UnknownEventType(t)) => {
                tracing::debug!("unknown uhid event type {t}, ignoring")
            }
            Err(StreamError::Io(_)) => break,
        }
    }
    inbox().failed = true;
    INBOX.ready.notify_all();
}

impl HidConnection for UhidConnection {
    fn send(&mut self, buf: &[u8; 64], _endpoint: UsbEndpoint) -> CtapResult<()> {
        // For a D-Bus request (keepalives): no host listens there.
        if buf[..4] == crate::request::INTERNAL_CID {
            return Ok(());
        }
        let event: [u8; UHID_EVENT_SIZE] = InputEvent::Input { data: buf }.into();
        let file = self.file.as_mut().ok_or_else(hw_err)?;
        file.write_all(&event).map_err(|_| hw_err())
    }

    /// Wait up to `timeout_ms` for the next data OUTPUT report from the host.
    fn recv(&mut self, buf: &mut [u8; 64], timeout_ms: usize) -> CtapResult<RecvStatus> {
        if self.file.is_none() {
            return Err(hw_err());
        }
        let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
        let mut st = inbox();
        loop {
            if let Some(pkt) = st.packets.pop_front() {
                *buf = pkt;
                return Ok(RecvStatus::Received(UsbEndpoint::MainHid));
            }
            if st.failed {
                return Err(hw_err());
            }
            if st.woken {
                st.woken = false;
                return Ok(RecvStatus::Timeout);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(RecvStatus::Timeout);
            }
            st = INBOX.ready.wait_timeout(st, left).unwrap_or_else(|e| e.into_inner()).0;
        }
    }
}
