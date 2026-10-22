//! Virtual FIDO2 USB-HID device via /dev/uhid, implementing OpenSK's
//! `HidConnection` (send = write INPUT report, recv = read next OUTPUT report).

use opensk::api::connection::{HidConnection, RecvStatus, UsbEndpoint};
use opensk::ctap::status_code::{Ctap2StatusCode, CtapResult};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use uhid_virt::{Bus, CreateParams, InputEvent, OutputEvent, StreamError, UHID_EVENT_SIZE};

const REPORT_SIZE: usize = 64;

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

impl HidConnection for UhidConnection {
    fn send(&mut self, buf: &[u8; 64], _endpoint: UsbEndpoint) -> CtapResult<()> {
        let event: [u8; UHID_EVENT_SIZE] = InputEvent::Input { data: buf }.into();
        let file = self.file.as_mut().ok_or_else(hw_err)?;
        file.write_all(&event).map_err(|_| hw_err())
    }

    /// Block reading uhid events until the host sends a data OUTPUT report.
    /// (The CTAP core only calls this from our main loop; control events are
    /// handled internally. `timeout_ms` is ignored — we block for the next cmd.)
    fn recv(&mut self, buf: &mut [u8; 64], _timeout_ms: usize) -> CtapResult<RecvStatus> {
        let file = self.file.as_mut().ok_or_else(hw_err)?;
        let mut event = [0u8; UHID_EVENT_SIZE];
        loop {
            file.read_exact(&mut event).map_err(|_| hw_err())?;
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
                    buf[..n].copy_from_slice(&payload[..n]);
                    buf[n..].fill(0);
                    return Ok(RecvStatus::Received(UsbEndpoint::MainHid));
                }
                Ok(OutputEvent::Open) => tracing::info!("host opened HID device"),
                Ok(OutputEvent::Close) => tracing::info!("host closed HID device"),
                Ok(OutputEvent::Start { .. }) => tracing::debug!("HID device started"),
                Ok(OutputEvent::Stop) => {
                    tracing::info!("HID device stopped by host");
                    return Err(hw_err());
                }
                Ok(_) => {} // GetReport / SetReport — ignore
                Err(StreamError::UnknownEventType(t)) => {
                    tracing::debug!("unknown uhid event type {t}, ignoring")
                }
                Err(StreamError::Io(_)) => return Err(hw_err()),
            }
        }
    }
}
