//! Classic Bluetooth task — connects to Classic HID devices (keyboards and
//! the Magic Trackpad 2).
//!
//! This module handles the full Classic BT connection lifecycle:
//! ACL → Auth → Encrypt → L2CAP → HIDP, then forwards received HID reports
//! to `HID_REPORT_CHANNEL` for USB translation.
//!
//! What happens after the HID channels open depends on the device profile:
//!
//! - **Keyboard**: ask for boot protocol, then forward each input report to
//!   the USB boot keyboard interface.
//! - **Magic Trackpad**: enable multitouch, poll battery, and forward touch
//!   reports for reclocked passthrough.
//!
//! The profile comes from the stored bond when there is one, and otherwise
//! from the Class of Device seen during Inquiry, so a keyboard works from its
//! first connection without being told what it is.
//!
//! Runs concurrently with the BLE slot tasks and connection manager on Core 0.

use core::cell::RefCell;
use core::fmt::Write as _;
use core::sync::atomic::Ordering;

use bt2usb_core::classic::{cod_is_keyboard, cod_is_peripheral, translate_keyboard_report};
use bt_classic_host::hidp::ReportType;
use bt_classic_host::{
    ClassicRunner, HidClient, HostResources, L2capState, LinkEvent, PairingEvent,
};
use bt_hci::param::{BdAddr, ConnHandle};
use defmt::*;
use embassy_futures::select::{select3, Either3};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::blocking_mutex::Mutex as BlockingMutex;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Instant, Ticker, Timer};

/// One-shot gate fired by `classic_bt_task` after it has (re)issued the
/// merged `SetEventMask`. The BLE connection manager awaits this signal
/// exactly once before it runs any scan or connect, so the mask update can
/// never race an in-flight `LE Create Connection`. Only one waiter (the
/// manager loop) consumes it; slot tasks are driven by the manager via
/// channel commands, so they inherit the gate transitively.
pub static CLASSIC_INIT_DONE: Signal<CriticalSectionRawMutex, ()> = Signal::new();

/// Cache of what the most recent Classic Inquiry told us about each device,
/// keyed by BD address.
///
/// Two things are worth keeping. The EIR name is consumed by
/// `store_classic_bond` after a successful pair, so the human-readable name
/// ends up in flash alongside the link key. The Class of Device says whether
/// the device is a keyboard or a pointing device, which is how a keyboard
/// gets the right profile on its first connection — before any bond exists to
/// read it from.
///
/// This is a simple ring of recent entries — small and static, not a
/// long-lived database. Scans overwrite older entries as needed.
const MAX_CACHED_DEVICES: usize = 8;

#[derive(Clone, Copy)]
struct CachedDevice {
    addr: [u8; 6],
    name: [u8; 32],
    name_len: u8,
    /// Class of Device as received from HCI (little-endian), if seen.
    cod: Option<[u8; 3]>,
}

static SCAN_DEVICE_CACHE: BlockingMutex<
    CriticalSectionRawMutex,
    RefCell<heapless::Vec<CachedDevice, MAX_CACHED_DEVICES>>,
> = BlockingMutex::new(RefCell::new(heapless::Vec::new()));

/// Record what an Inquiry result told us about a device.
///
/// Both fields are optional: standard Inquiry results carry a Class of Device
/// but no name, and a device may answer with an empty EIR name.
fn cache_scan_device(addr: &[u8; 6], name: Option<(&[u8; 32], u8)>, cod: Option<&[u8]>) {
    SCAN_DEVICE_CACHE.lock(|c| {
        let mut cache = c.borrow_mut();

        let idx = match cache.iter().position(|e| e.addr == *addr) {
            Some(i) => i,
            None => {
                if cache.is_full() {
                    // Evict oldest
                    cache.remove(0);
                }
                let _ = cache.push(CachedDevice {
                    addr: *addr,
                    name: [0u8; 32],
                    name_len: 0,
                    cod: None,
                });
                cache.len() - 1
            }
        };

        let entry = &mut cache[idx];
        if let Some((name, name_len)) = name {
            if name_len > 0 {
                entry.name = *name;
                entry.name_len = name_len;
            }
        }
        if let Some(cod) = cod {
            if cod.len() >= 3 {
                entry.cod = Some([cod[0], cod[1], cod[2]]);
            }
        }
    });
}

fn lookup_scan_name(addr: &[u8; 6]) -> Option<([u8; 32], u8)> {
    SCAN_DEVICE_CACHE.lock(|c| {
        c.borrow()
            .iter()
            .find(|e| e.addr == *addr && e.name_len > 0)
            .map(|e| (e.name, e.name_len))
    })
}

fn lookup_scan_cod(addr: &[u8; 6]) -> Option<[u8; 3]> {
    SCAN_DEVICE_CACHE.lock(|c| {
        c.borrow()
            .iter()
            .find(|e| e.addr == *addr)
            .and_then(|e| e.cod)
    })
}

use super::slots::{self, MAX_CLASSIC_LINKS};
use super::FlashMutex;
use crate::ble_hid::{HidReportEvent, HidReportType, HID_REPORT_CHANNEL};
use crate::ble_state::{ClassicCommand, CLASSIC_CMD_CHANNEL};
use crate::bonding;
use crate::device_profile::DeviceProfile;

// ============ Link Key Storage ============

/// In-memory link key store for Classic BT, backed by flash persistence.
/// Populated from flash at startup; new keys persisted after connect().
struct MemoryLinkKeyStore {
    keys: heapless::Vec<(bt_hci::param::BdAddr, bt_classic_host::LinkKeyInfo), 10>,
}

impl MemoryLinkKeyStore {
    fn new() -> Self {
        Self {
            keys: heapless::Vec::new(),
        }
    }

    /// Populate from loaded flash bonds.
    fn load_from_flash(&mut self, bonds: &[bonding::StoredClassicBond]) {
        for bond in bonds {
            let addr = bt_hci::param::BdAddr::new(bond.addr);
            let key_info = bt_classic_host::LinkKeyInfo {
                key: bond.link_key,
                key_type: bond.key_type,
            };
            let _ = self.keys.push((addr, key_info));
        }
    }
}

impl bt_classic_host::LinkKeyStore for MemoryLinkKeyStore {
    fn load(&self, addr: &bt_hci::param::BdAddr) -> Option<bt_classic_host::LinkKeyInfo> {
        self.keys
            .iter()
            .find(|(a, _)| a.raw() == addr.raw())
            .map(|(_, k)| k.clone())
    }

    fn store(&mut self, addr: &bt_hci::param::BdAddr, key: bt_classic_host::LinkKeyInfo) {
        // Update existing or insert new
        for (a, k) in self.keys.iter_mut() {
            if a.raw() == addr.raw() {
                *k = key;
                return;
            }
        }
        let _ = self.keys.push((*addr, key));
    }

    fn remove(&mut self, addr: &bt_hci::param::BdAddr) {
        if let Some(pos) = self.keys.iter().position(|(a, _)| a.raw() == addr.raw()) {
            self.keys.swap_remove(pos);
        }
    }
}

// ============ Helpers ============

/// Pick the profile to drive a Classic device with, for a device that has no
/// stored bond yet.
///
/// The Class of Device from Inquiry is the only thing we know before
/// connecting, and it cleanly separates keyboards from pointing devices.
/// Anything else keeps the historical default: the Magic Trackpad 2 is the
/// Classic device this bridge was built around.
fn profile_from_inquiry(addr: &[u8; 6]) -> DeviceProfile {
    match lookup_scan_cod(addr) {
        Some(cod) if cod_is_keyboard(&cod) => DeviceProfile::Keyboard,
        _ => DeviceProfile::MagicTrackpad,
    }
}

/// Report a pairing step the user has to see or act on.
///
/// Passkey Entry is the whole reason this exists: the controller picks a
/// six-digit passkey, the keyboard waits for the user to type it, and without
/// somewhere to display it the pairing simply times out. `bt2usb-cli scan
/// --classic` and `bt2usb-cli connect` print these log events as they arrive.
fn on_pairing_event(addr: &bt_hci::param::BdAddr, event: PairingEvent) {
    let mut msg: heapless::String<{ crate::rpc_log::MAX_MSG_LEN }> = heapless::String::new();
    match event {
        PairingEvent::PasskeyDisplay(passkey) => {
            info!("[classic] Passkey {} for {:02x}", passkey, addr.raw());
            // Passkeys are six digits and must be typed including leading zeros.
            let _ = core::write!(
                msg,
                "Passkey {:06}: type it on the keyboard, then press Enter",
                passkey
            );
            crate::rpc_log::info(&msg);
        }
        PairingEvent::LegacyPin(pin) => {
            info!("[classic] Legacy PIN pairing for {:02x}", addr.raw());
            let _ = core::write!(
                msg,
                "PIN {}: type it on the keyboard, then press Enter",
                pin
            );
            crate::rpc_log::info(&msg);
        }
        PairingEvent::JustWorks => {
            info!("[classic] Just Works pairing for {:02x}", addr.raw());
            crate::rpc_log::info("Pairing confirmed automatically");
        }
        PairingEvent::PasskeyEntryUnsupported => {
            warn!("[classic] Remote wants us to type a passkey; declined");
            crate::rpc_log::error("Device wants a passkey typed on the bridge, which has no keys");
        }
    }
}

/// Run the device-specific setup a profile needs once the HID channels are up.
///
/// Called at session start, and again if the user changes the profile on a
/// live connection.
async fn apply_profile_setup<C: bt_hci::controller::Controller>(
    profile: DeviceProfile,
    hid: &HidClient,
    l2cap: &L2capState<4>,
    controller: &C,
) {
    if profile.is_keyboard() {
        // Boot protocol gives us the fixed 8-byte report the USB boot keyboard
        // interface sends verbatim, with no report descriptor to parse. A
        // keyboard that refuses stays in report protocol, which the report
        // translator also understands, so a failure here is not fatal.
        match hid.set_protocol_boot(l2cap, controller).await {
            Ok(()) => info!("[classic] Requested boot protocol for keyboard"),
            Err(e) => warn!(
                "[classic] SET_PROTOCOL(Boot) failed: {:?}",
                defmt::Debug2Format(&e)
            ),
        }
        return;
    }

    // --- Activate Magic Trackpad 2 multitouch ---
    // BT Classic MT enable: SET_REPORT(Feature, report_id=0xF1, data={0x02, 0x01})
    // Matches the Linux kernel's magicmouse_bt_enable() exactly.
    if let Err(e) = hid
        .set_report(l2cap, controller, ReportType::Feature, 0xF1, &[0x02, 0x01])
        .await
    {
        warn!(
            "[classic] Failed to enable multitouch: {:?}",
            defmt::Debug2Format(&e)
        );
    } else {
        info!("[classic] Multitouch enabled!");
    }

    // --- Initial battery probe (Report ID 0x90, Input) ---
    // Real MT2 responds with 2 bytes: [flags, capacity] — see the IF0 HID
    // descriptor in notes/magic-mouse (Power Device / Battery System collection).
    // Response arrives asynchronously on the control channel and is decoded
    // in the report loop below. Subsequent polls are driven by `battery_ticker`.
    if let Err(e) = hid
        .get_report(l2cap, controller, ReportType::Input, 0x90)
        .await
    {
        warn!(
            "[classic] Battery GET_REPORT failed: {:?}",
            defmt::Debug2Format(&e)
        );
    }
}

/// How many unrecognised keyboard reports to log loudly before going quiet.
const MAX_UNKNOWN_KEY_REPORT_LOGS: u8 = 5;
static UNKNOWN_KEY_REPORT_LOGS: portable_atomic::AtomicU8 = portable_atomic::AtomicU8::new(0);

/// Forward a keyboard report to the USB keyboard interface.
///
/// A dropped mouse delta costs a pixel of movement; a dropped key release
/// leaves the host with a key held down and repeating. So back-pressure gets a
/// short wait rather than an immediate drop — bounded, so a stalled USB side
/// can never stop this task from servicing HCI events (disconnects included).
async fn forward_keyboard_report(link: usize, report: &bt_classic_host::HidReport) {
    let data = &report.data[..report.len];
    let Some(boot_report) = translate_keyboard_report(data) else {
        // Consumer/media keys and vendor reports land here. Logged rather than
        // guessed at: a misread report types characters nobody pressed.
        //
        // The first few are logged at info so `bt2usb-cli logs` shows what a
        // given keyboard sends that we skip; after that they'd only be noise,
        // since a media key held down repeats.
        let seen = UNKNOWN_KEY_REPORT_LOGS.load(Ordering::Relaxed);
        if seen < MAX_UNKNOWN_KEY_REPORT_LOGS {
            UNKNOWN_KEY_REPORT_LOGS.store(seen + 1, Ordering::Relaxed);
            info!(
                "[classic] Unrecognised keyboard report len={} data={:02x}",
                report.len,
                &data[..report.len.min(16)]
            );
        } else {
            debug!(
                "[classic] Unrecognised keyboard report len={} data={:02x}",
                report.len,
                &data[..report.len.min(16)]
            );
        }
        return;
    };

    let mut event = HidReportEvent::new();
    event.report_type = HidReportType::Keyboard;
    event.profile = DeviceProfile::Keyboard;
    event.slot_index = slots::classic_slot_index(link);
    event.report_id = 0;
    event.data[..boot_report.len()].copy_from_slice(&boot_report);
    event.len = boot_report.len();

    if HID_REPORT_CHANNEL.try_send(event.clone()).is_ok() {
        return;
    }
    match embassy_time::with_timeout(Duration::from_millis(20), HID_REPORT_CHANNEL.send(event))
        .await
    {
        Ok(()) => debug!("[classic] Keyboard report delivered after back-pressure"),
        Err(_) => warn!("[classic] HID channel blocked, dropped a keyboard report"),
    }
}

// ============ Classic BT Task ============

/// One live Classic HID link: the ACL connection plus its L2CAP and HIDP
/// state. Indexed by the runner's connection slot.
struct Link {
    addr: [u8; 6],
    handle: ConnHandle,
    profile: DeviceProfile,
    l2cap: L2capState<4>,
    hid: HidClient,
    /// HID channels are open and the profile setup has run.
    active: bool,
    /// When the link came up, for the channel-open timeout.
    since: Instant,
}

/// The connection attempt in flight. The controller pages one device at a
/// time, so there is at most one.
struct Pending {
    slot: usize,
    addr: [u8; 6],
    started: Instant,
    /// Started by a Connect command rather than auto-connect.
    manual: bool,
}

/// When to try a bonded device again after a failed attempt or a disconnect.
struct Backoff {
    addr: [u8; 6],
    next_try: Instant,
    failures: u8,
}

/// HID channels must open this soon after encryption, or the link is dropped.
const CHANNEL_OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// Give up on a connection attempt after this long. Generous because a
/// keyboard's Passkey Entry waits for a person to type six digits.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(120);

/// A manual Connect is retried this many times before it is dropped.
const MAX_MANUAL_ATTEMPTS: u8 = 3;

/// Poll MT2 battery this often (matches hid-magicmouse.c USB_BATTERY_TIMEOUT_SEC).
const BATTERY_POLL_TICKS: u32 = 60;

/// Re-read auto-connect bonds from flash this often, so bonds and
/// auto-connect flags changed over RPC take effect without a reboot.
const BOND_REFRESH_TICKS: u32 = 10;

fn retry_delay(failures: u8) -> Duration {
    if failures < 5 {
        Duration::from_secs(5)
    } else {
        Duration::from_secs(30)
    }
}

/// Note a failed attempt or a dropped link, so auto-connect waits before
/// paging the device again.
fn push_backoff(
    backoff: &mut heapless::Vec<Backoff, { bonding::MAX_CLASSIC_BONDS }>,
    addr: &[u8; 6],
    delay: Option<Duration>,
) {
    let entry = match backoff.iter_mut().position(|b| b.addr == *addr) {
        Some(i) => &mut backoff[i],
        None => {
            if backoff.is_full() {
                backoff.remove(0);
            }
            let _ = backoff.push(Backoff {
                addr: *addr,
                next_try: Instant::now(),
                failures: 0,
            });
            let last = backoff.len() - 1;
            &mut backoff[last]
        }
    };
    let delay = match delay {
        Some(d) => {
            entry.failures = 0;
            d
        }
        None => {
            entry.failures = entry.failures.saturating_add(1);
            retry_delay(entry.failures)
        }
    };
    entry.next_try = Instant::now() + delay;
}

async fn load_auto_connect_bonds(
    flash_mutex: &FlashMutex,
) -> heapless::Vec<[u8; 6], { bonding::MAX_CLASSIC_BONDS }> {
    let mut f = flash_mutex.lock().await;
    bonding::load_classic_bonds(&mut f)
        .await
        .iter()
        .filter(|b| b.auto_connect)
        .map(|b| b.addr)
        .collect()
}

/// Configure sniff mode for steady report delivery.
///
/// Without sniff, BT Classic delivers HID reports in bursts (3-5 reports per
/// burst, 32-44ms gaps). Sniff mode forces regular polling at ~91Hz (11.25ms
/// interval), matching the real MT2's native USB report rate.
async fn configure_sniff<C>(controller: &C, handle: ConnHandle)
where
    C: bt_hci::controller::ControllerCmdSync<bt_classic_host::link_policy::WriteLinkPolicySettings>
        + bt_hci::controller::ControllerCmdSync<bt_classic_host::link_policy::SniffMode>
        + bt_hci::controller::ControllerCmdSync<bt_classic_host::link_policy::SniffSubrating>,
{
    use bt_classic_host::link_policy::{
        SniffMode, SniffSubrating, WriteLinkPolicySettings, LINK_POLICY_ENABLE_SNIFF,
    };

    match controller
        .exec(&WriteLinkPolicySettings::new(handle, LINK_POLICY_ENABLE_SNIFF))
        .await
    {
        Ok(_) => info!("[classic] Link policy: sniff enabled"),
        Err(e) => warn!(
            "[classic] Failed to set link policy: {:?}",
            defmt::Debug2Format(&e)
        ),
    }

    // Request sniff mode: ~91Hz (11.25ms = 18 slots of 0.625ms)
    // sniff_attempt=4: listen for 4 slots per sniff interval
    // sniff_timeout=1: minimal extra window after receiving
    match controller.exec(&SniffMode::new(handle, 18, 18, 4, 1)).await {
        Ok(_) => info!("[classic] Sniff mode requested (interval=18 slots / 11.25ms)"),
        Err(e) => warn!(
            "[classic] Failed to request sniff mode: {:?}",
            defmt::Debug2Format(&e)
        ),
    }

    // Layer Sniff Subrating on top of the base sniff interval so the link
    // manager can stretch the effective interval during idle. max_latency=800
    // slots = 500ms: the peer may skip up to ~44 base sniff slots between
    // listens when no data is flowing, cutting peripheral radio-on time
    // substantially. Traffic collapses the subrating back to the base 11.25ms
    // interval automatically, so active-use latency is unchanged.
    match controller.exec(&SniffSubrating::new(handle, 800, 0, 0)).await {
        Ok(_) => info!("[classic] Sniff subrating enabled (max_latency=800 / 500ms)"),
        // Many HID peers (including the Magic Trackpad 2) don't implement
        // sniff subrating; the base sniff interval still applies.
        Err(e) => info!(
            "[classic] Sniff subrating not supported by peer: {:?}",
            defmt::Debug2Format(&e)
        ),
    }
}

/// Handle an Inquiry event. Returns true once the Inquiry is complete.
fn handle_inquiry_event(kind: bt_hci::event::EventKind, data: &[u8]) -> bool {
    use bt_hci::event::EventKind;

    let report = |addr: [u8; 6], name: [u8; 32], name_len: u8, rssi: i8, is_hid: bool| {
        let _ = crate::ble_state::BLE_EVENT_CHANNEL.try_send(
            crate::ble_state::BleEvent::ScanResult(crate::ble_state::ScanResultData {
                address: addr,
                addr_kind: 0,
                name,
                name_len,
                rssi,
                is_hid,
                transport_type: crate::ble_state::TransportType::Classic,
            }),
        );
    };

    match kind {
        EventKind::InquiryComplete => {
            info!("[classic] Inquiry complete");
            crate::rpc_log::info("Classic Inquiry scan complete");
            return true;
        }
        EventKind::InquiryResult => {
            // Standard: per entry = 14 bytes (addr6+psrm1+reserved2+cod3+clock2)
            if !data.is_empty() {
                let n = data[0] as usize;
                for i in 0..n {
                    let off = 1 + i * 14;
                    if off + 14 <= data.len() {
                        let mut addr = [0u8; 6];
                        addr.copy_from_slice(&data[off..off + 6]);
                        // CoD at off+9 (after addr6+psrm1+reserved2)
                        let cod = &data[off + 9..off + 12];
                        let is_hid = cod_is_peripheral(cod);
                        cache_scan_device(&addr, None, Some(cod));
                        info!("[classic] Found: {:02x} CoD={:02x} hid={}", addr, cod, is_hid);
                        report(addr, [0u8; 32], 0, -127, is_hid);
                    }
                }
            }
        }
        EventKind::InquiryResultWithRssi => {
            // With RSSI: per entry = 14 bytes (addr6+psrm1+reserved1+cod3+clock2+rssi1)
            if !data.is_empty() {
                let n = data[0] as usize;
                for i in 0..n {
                    let off = 1 + i * 14;
                    if off + 14 <= data.len() {
                        let mut addr = [0u8; 6];
                        addr.copy_from_slice(&data[off..off + 6]);
                        // CoD at off+8 (after addr6+psrm1+reserved1)
                        let cod = &data[off + 8..off + 11];
                        let is_hid = cod_is_peripheral(cod);
                        cache_scan_device(&addr, None, Some(cod));
                        let rssi = data[off + 13] as i8;
                        info!(
                            "[classic] Found: {:02x} RSSI={} CoD={:02x} hid={}",
                            addr, rssi, cod, is_hid
                        );
                        report(addr, [0u8; 32], 0, rssi, is_hid);
                    }
                }
            }
        }
        EventKind::ExtendedInquiryResult => {
            // EIR: data[0]=num, data[1..7]=addr, data[7]=psrm,
            // data[8]=reserved, data[9..12]=cod, data[12..14]=clock,
            // data[14]=rssi, data[15..]=eir_data
            if data.len() >= 15 {
                let mut addr = [0u8; 6];
                addr.copy_from_slice(&data[1..7]);
                let cod = &data[9..12];
                let is_hid = cod_is_peripheral(cod);
                let rssi = data[14] as i8;
                // Parse EIR for device name
                let mut name = [0u8; 32];
                let mut name_len = 0u8;
                if data.len() > 15 {
                    let eir = &data[15..];
                    let mut pos = 0;
                    while pos + 1 < eir.len() {
                        let len = eir[pos] as usize;
                        if len == 0 {
                            break;
                        }
                        let ad_type = eir[pos + 1];
                        if (ad_type == 0x08 || ad_type == 0x09) && len > 1 {
                            let n = (len - 1).min(name.len());
                            let end = (pos + 2 + n).min(eir.len());
                            let actual = end - (pos + 2);
                            name[..actual].copy_from_slice(&eir[pos + 2..end]);
                            name_len = actual as u8;
                        }
                        pos += 1 + len;
                    }
                }
                info!(
                    "[classic] Found: {:02x} rssi={} name_len={} CoD={:02x} hid={}",
                    addr, rssi, name_len, cod, is_hid
                );
                cache_scan_device(&addr, Some((&name, name_len)), Some(cod));
                report(addr, name, name_len, rssi, is_hid);
            }
        }
        _ => {}
    }
    false
}

/// Forward a HID report from a Magic Trackpad link to USB.
fn forward_trackpad_report(link: usize, report: &bt_classic_host::HidReport) {
    // Report ID 0x31 = BT multitouch data (4-byte header + N*9 touch points)
    // Other report IDs are status/control — log but don't forward yet.
    let report_id = if report.len > 0 { report.data[0] } else { 0 };

    if report_id == 0x31 && report.len >= 4 {
        // Touch report — forward full BT report for reclocked passthrough
        let n_fingers = (report.len - 4) / 9;
        static MT2_LOG_COUNT: portable_atomic::AtomicU8 = portable_atomic::AtomicU8::new(0);
        let log_n = MT2_LOG_COUNT.load(Ordering::Relaxed);
        if log_n < 10 {
            MT2_LOG_COUNT.store(log_n + 1, Ordering::Relaxed);
            info!(
                "[classic] MT2 report #{}: fingers={} len={}",
                log_n, n_fingers, report.len
            );
        }

        let mut event = HidReportEvent::new();
        event.report_type = HidReportType::Mouse;
        event.profile = DeviceProfile::MagicTrackpad;
        event.slot_index = slots::classic_slot_index(link);
        event.report_id = 0x31;
        let copy_len = report.len.min(event.data.len());
        event.data[..copy_len].copy_from_slice(&report.data[..copy_len]);
        event.len = copy_len;
        if HID_REPORT_CHANNEL.try_send(event).is_err() {
            debug!("[classic] HID channel full, dropping MT2 report");
        }
    } else if report_id == 0x90 && report.len >= 3 {
        // Battery report: [0x90, flags, capacity]
        // flags bits: 0=AC present, 1=charging, 2=discharging
        let flags = report.data[1];
        let capacity = report.data[2];
        info!(
            "[classic] Battery: capacity={} flags=0x{:02x}",
            capacity, flags
        );
        crate::ble_hid::update_classic_battery_level(link, capacity);
    } else {
        debug!(
            "[classic] HID report id=0x{:02x} len={} data={:02x}",
            report_id,
            report.len,
            &report.data[..report.len.min(16)]
        );
    }
}

/// Clear the status a link reported while it was up.
fn link_down(link: usize) {
    slots::set_classic_disconnected(link);
    crate::ble_hid::clear_classic_battery_level(link);
    let _ = crate::ble_state::BLE_EVENT_CHANNEL.try_send(
        crate::ble_state::BleEvent::StateChanged(crate::protocol::ConnectionState::Disconnected),
    );
}

/// Classic Bluetooth task — connects to Classic HID devices (Magic Trackpad 2
/// and keyboards), several at once.
///
/// A single loop owns the controller's Classic read side. HCI events go to the
/// `ClassicRunner`, which drives each connection through ACL → Auth → Encrypt
/// by address and handle; ACL data is demultiplexed by handle to the link's
/// own L2CAP and HIDP state. That way a keyboard can pair, passkey and all,
/// while the trackpad keeps sending touches.
///
/// Every bonded device with auto-connect set is connected and kept connected,
/// one page at a time, with backoff for devices that are asleep or away.
pub async fn classic_bt_task<C>(controller: &C, flash_mutex: &FlashMutex)
where
    C: bt_hci::controller::Controller
        + bt_hci::controller::ControllerCmdSync<bt_hci::cmd::controller_baseband::SetEventMask>
        + bt_hci::controller::ControllerCmdSync<bt_hci::cmd::link_control::CreateConnection>
        + bt_hci::controller::ControllerCmdSync<bt_hci::cmd::link_control::AuthenticationRequested>
        + bt_hci::controller::ControllerCmdSync<bt_hci::cmd::link_control::SetConnectionEncryption>
        + bt_hci::controller::ControllerCmdSync<bt_hci::cmd::link_control::LinkKeyRequestReply>
        + bt_hci::controller::ControllerCmdSync<
            bt_hci::cmd::link_control::LinkKeyRequestNegativeReply,
        > + bt_hci::controller::ControllerCmdSync<bt_hci::cmd::link_control::PinCodeRequestReply>
        + bt_hci::controller::ControllerCmdSync<bt_hci::cmd::link_control::IoCapabilityRequestReply>
        + bt_hci::controller::ControllerCmdSync<
            bt_hci::cmd::link_control::UserConfirmationRequestReply,
        > + bt_hci::controller::ControllerCmdSync<
            bt_hci::cmd::link_control::UserPasskeyRequestNegativeReply,
        > + bt_hci::controller::ControllerCmdSync<bt_classic_host::link_policy::WriteLinkPolicySettings>
        + bt_hci::controller::ControllerCmdSync<bt_classic_host::link_policy::SniffMode>
        + bt_hci::controller::ControllerCmdSync<bt_classic_host::link_policy::SniffSubrating>
        + bt_hci::controller::ControllerCmdSync<bt_classic_host::link_policy::WriteInquiryMode>
        + bt_hci::controller::ControllerCmdSync<bt_classic_host::link_policy::WriteSimplePairingMode>
        + bt_hci::controller::ControllerCmdSync<bt_hci::cmd::link_control::Inquiry>
        + bt_hci::controller::ControllerCmdSync<bt_hci::cmd::link_control::InquiryCancel>
        + bt_hci::controller::ControllerCmdSync<bt_hci::cmd::link_control::Disconnect>,
{
    info!("[classic] Classic BT task started");

    // Wait just long enough for trouble-host to finish its own init HCI
    // sequence (including its SetEventMask). We only need to cover the
    // init burst — not "hope no BLE connection lands here" — because the
    // BLE connection manager gates on CLASSIC_INIT_DONE below, so no LE
    // Create Connection can run until we've issued the merged mask.
    Timer::after_millis(300).await;

    // --- Fix event mask: trouble-host's SetEventMask disables Classic auth events
    // (LinkKeyRequest, PinCodeRequest, AuthenticationComplete). Re-send with
    // Classic events enabled so the controller generates them during pairing.
    {
        use bt_hci::cmd::controller_baseband::SetEventMask;
        use bt_hci::param::EventMask;

        let mask = EventMask::new()
            // trouble-host's events
            .enable_le_meta(true)
            .enable_conn_request(true)
            .enable_conn_complete(true)
            .enable_hardware_error(true)
            .enable_disconnection_complete(true)
            .enable_encryption_change_v1(true)
            .enable_encryption_key_refresh_complete(true)
            // Classic auth events
            .enable_authentication_complete(true)
            .enable_link_key_request(true)
            .enable_link_key_notification(true)
            .enable_pin_code_request(true)
            .enable_io_capability_request(true)
            .enable_io_capability_response(true)
            .enable_user_confirmation_request(true)
            // Passkey Entry, the association model a keyboard uses: without
            // these the controller picks a passkey we never see and the user
            // has nothing to type.
            .enable_user_passkey_request(true)
            .enable_user_passkey_notification(true)
            .enable_keypress_notification(true)
            .enable_simple_pairing_complete(true)
            .enable_mode_change(true)
            .enable_inquiry_complete(true)
            .enable_inquiry_result(true)
            // Required when WriteInquiryMode is set to 1 (RSSI) or 2 (EIR):
            // the controller still emits these events, but they're gated by
            // these mask bits. Without them inquiries return zero responses.
            .enable_inquiry_result_with_rssi(true)
            .enable_ext_inquiry_result(true)
            // Needed if we ever want to issue RemoteNameRequest as a fallback.
            .enable_remote_name_request_complete(true);

        match controller.exec(&SetEventMask::new(mask)).await {
            Ok(_) => info!("[classic] Event mask updated with Classic events"),
            Err(e) => warn!(
                "[classic] Failed to set event mask: {:?}",
                defmt::Debug2Format(&e)
            ),
        }
    }

    // --- Enable Secure Simple Pairing (required for EIR) ---
    // The CYW43439 will not emit Extended Inquiry Result events unless SSP is
    // enabled, even after WriteInquiryMode(2). This was almost certainly the
    // missing piece in the previous "modes 1 and 2 return zero results" attempt.
    {
        use bt_classic_host::link_policy::WriteSimplePairingMode;
        match controller.exec(&WriteSimplePairingMode::new(1)).await {
            Ok(_) => info!("[classic] Simple Pairing Mode enabled"),
            Err(e) => warn!(
                "[classic] WriteSimplePairingMode failed: {:?}",
                defmt::Debug2Format(&e)
            ),
        }
    }

    // --- Switch inquiry result format to Extended Inquiry Result ---
    // Mode 0 = standard (no RSSI/EIR), Mode 1 = with RSSI, Mode 2 = EIR.
    // The ExtendedInquiryResult handler parses EIR for the device name (AD
    // types 0x08/0x09), so scan results include both RSSI and the name.
    {
        use bt_classic_host::link_policy::WriteInquiryMode;
        match controller.exec(&WriteInquiryMode::new(2)).await {
            Ok(_) => info!("[classic] Inquiry mode set to 2 (EIR)"),
            Err(e) => warn!(
                "[classic] WriteInquiryMode(2) failed: {:?}",
                defmt::Debug2Format(&e)
            ),
        }
    }

    // Release the BLE manager: mask reconfiguration is done, so any LE
    // Create Connection from here on is safe. Do this unconditionally,
    // even on SetEventMask failure — otherwise BLE would deadlock waiting
    // on a gate that never opens.
    CLASSIC_INIT_DONE.signal(());

    // --- Create resources with flash-backed link key store ---
    let mut link_key_store = MemoryLinkKeyStore::new();
    {
        let mut f = flash_mutex.lock().await;
        let bonds = bonding::load_classic_bonds(&mut f).await;
        link_key_store.load_from_flash(&bonds);
    }
    info!(
        "[classic] Loaded {} link key(s) from flash",
        link_key_store.keys.len()
    );
    let link_keys = RefCell::new(link_key_store);
    let mut resources = HostResources::<MAX_CLASSIC_LINKS>::new();
    let mut runner = ClassicRunner::new(controller, &mut resources, &link_keys);
    runner.set_pairing_callback(on_pairing_event);

    let mut links: [Option<Link>; MAX_CLASSIC_LINKS] = [const { None }; MAX_CLASSIC_LINKS];
    let mut pending: Option<Pending> = None;
    // Address from a Connect command, waiting for the radio, and how many
    // times it has been tried.
    let mut requested: Option<([u8; 6], u8)> = None;
    let mut inquiry_active = false;
    let mut scan_requested = false;
    let mut auto_bonds = load_auto_connect_bonds(flash_mutex).await;
    let mut backoff: heapless::Vec<Backoff, { bonding::MAX_CLASSIC_BONDS }> = heapless::Vec::new();
    let mut ticker = Ticker::every(Duration::from_secs(1));
    let mut ticks: u32 = 0;
    let mut acl_buf = [0u8; 512];
    let mut report = bt_classic_host::HidReport::new();

    let is_linked = |links: &[Option<Link>; MAX_CLASSIC_LINKS], addr: &[u8; 6]| {
        links.iter().flatten().any(|l| l.addr == *addr)
    };

    loop {
        // --- Use the radio when it is free: Inquiry first, then connections ---
        if pending.is_none() && !inquiry_active {
            if scan_requested {
                scan_requested = false;
                info!("[classic] Starting Inquiry scan...");
                crate::rpc_log::info("Classic Inquiry scan starting (~10s)...");
                // GIAC LAP = 0x9E8B33, duration 23 (~29.4s), unlimited responses.
                // Matches CLI's default 30s scan timeout.
                match controller
                    .exec(&bt_hci::cmd::link_control::Inquiry::new(
                        [0x33, 0x8B, 0x9E],
                        23,
                        0,
                    ))
                    .await
                {
                    Ok(_) => inquiry_active = true,
                    Err(e) => {
                        warn!("[classic] Inquiry failed: {:?}", defmt::Debug2Format(&e));
                        crate::rpc_log::error("Classic Inquiry failed");
                    }
                }
            } else {
                let now = Instant::now();
                let target = match requested {
                    Some((addr, attempts)) if !is_linked(&links, &addr) => {
                        requested = Some((addr, attempts + 1));
                        Some((addr, true))
                    }
                    _ => {
                        requested = None;
                        auto_bonds
                            .iter()
                            .find(|addr| {
                                !is_linked(&links, addr)
                                    && backoff
                                        .iter()
                                        .find(|b| b.addr == **addr)
                                        .is_none_or(|b| b.next_try <= now)
                            })
                            .map(|addr| (*addr, false))
                    }
                };
                if let Some((addr, manual)) = target {
                    let bd = BdAddr::new(addr);
                    info!(
                        "[classic] Connecting to {:?} ({})",
                        bd,
                        if manual { "requested" } else { "auto-connect" }
                    );
                    let _ = crate::ble_state::BLE_EVENT_CHANNEL.try_send(
                        crate::ble_state::BleEvent::StateChanged(
                            crate::protocol::ConnectionState::Connecting,
                        ),
                    );
                    match runner.start_connect(&bd).await {
                        Ok(slot) => {
                            pending = Some(Pending {
                                slot,
                                addr,
                                started: now,
                                manual,
                            })
                        }
                        Err(e) => {
                            warn!(
                                "[classic] Could not start connection: {:?}",
                                defmt::Debug2Format(&e)
                            );
                            push_backoff(&mut backoff, &addr, None);
                            if manual {
                                requested = None;
                            }
                        }
                    }
                }
            }
        }

        let mut rx = [0u8; 259];
        match select3(
            controller.read(&mut rx),
            CLASSIC_CMD_CHANNEL.receive(),
            ticker.next(),
        )
        .await
        {
            Either3::First(Ok(bt_hci::ControllerToHostPacket::Event(evt))) => {
                use bt_hci::event::EventKind;
                match evt.kind {
                    EventKind::InquiryComplete
                    | EventKind::InquiryResult
                    | EventKind::InquiryResultWithRssi
                    | EventKind::ExtendedInquiryResult => {
                        if handle_inquiry_event(evt.kind, evt.data) {
                            inquiry_active = false;
                        }
                    }
                    // NoCP is shared with BLE via the mux's "Both" dispatch
                    // and shows up here as noise whenever a BLE link is active.
                    EventKind::NumberOfCompletedPackets => {}
                    kind => match runner.process_event(kind, evt.data).await {
                        Some(LinkEvent::Ready { slot, addr, handle }) => {
                            let addr_bytes: [u8; 6] =
                                addr.raw().try_into().unwrap_or([0u8; 6]);
                            info!(
                                "[classic] Connected and encrypted! {:?} handle={} link={}",
                                addr,
                                handle.raw(),
                                slot
                            );
                            if pending.as_ref().is_some_and(|p| p.slot == slot) {
                                if pending.as_ref().is_some_and(|p| p.manual) {
                                    requested = None;
                                }
                                pending = None;
                            }
                            backoff.retain(|b| b.addr != addr_bytes);
                            let _ = crate::ble_state::BLE_EVENT_CHANNEL
                                .try_send(crate::ble_state::BleEvent::PairingComplete);

                            // A stored bond wins: the user may have set the
                            // profile by hand. With no bond yet this is a
                            // first pairing, so fall back to what Inquiry
                            // said the device was.
                            let stored_profile_id = {
                                let mut f = flash_mutex.lock().await;
                                let bonds = bonding::load_classic_bonds(&mut f).await;
                                bonds
                                    .iter()
                                    .find(|b| b.addr == addr_bytes)
                                    .map(|b| b.profile_id)
                            };
                            let profile = match stored_profile_id {
                                Some(id) => DeviceProfile::from_id(id),
                                None => profile_from_inquiry(&addr_bytes),
                            };
                            info!("[classic] Using profile {:?}", profile);
                            slots::set_classic_connected(slot, &addr_bytes, profile.to_id());

                            // --- Persist link key to flash ---
                            let key_info = {
                                use bt_classic_host::LinkKeyStore;
                                link_keys.borrow().load(&addr)
                            };
                            if let Some(ki) = key_info {
                                let (scan_name, scan_name_len) =
                                    lookup_scan_name(&addr_bytes).unwrap_or(([0u8; 32], 0));
                                let mut f = flash_mutex.lock().await;
                                match bonding::store_classic_bond(
                                    &mut f,
                                    &addr_bytes,
                                    &ki.key,
                                    ki.key_type,
                                    profile.to_id(),
                                    true, // auto_connect on first pairing
                                    &scan_name,
                                    scan_name_len,
                                )
                                .await
                                {
                                    Ok(bond_slot) => {
                                        info!(
                                            "[classic] Bond persisted to flash slot {}",
                                            bond_slot
                                        );
                                        let _ = crate::ble_state::BLE_EVENT_CHANNEL.try_send(
                                            crate::ble_state::BleEvent::BondStored {
                                                address: addr_bytes,
                                                profile_id: profile.to_id(),
                                            },
                                        );
                                    }
                                    Err(_) => warn!("[classic] Failed to persist bond to flash"),
                                }
                                if !auto_bonds.contains(&addr_bytes) {
                                    let _ = auto_bonds.push(addr_bytes);
                                }
                            }

                            configure_sniff(controller, handle).await;

                            // --- Open L2CAP HID channels; the rest happens as ACL arrives ---
                            let mut link = Link {
                                addr: addr_bytes,
                                handle,
                                profile,
                                l2cap: L2capState::<4>::new(handle),
                                hid: HidClient::new(),
                                active: false,
                                since: Instant::now(),
                            };
                            info!("[classic] Opening HID L2CAP channels...");
                            match link.hid.open_channels(&mut link.l2cap, controller).await {
                                Ok(()) => links[slot] = Some(link),
                                Err(e) => {
                                    error!(
                                        "[classic] Failed to open HID channels: {:?}",
                                        defmt::Debug2Format(&e)
                                    );
                                    let _ = controller
                                        .exec(&bt_hci::cmd::link_control::Disconnect::new(
                                            handle,
                                            bt_hci::param::DisconnectReason::RemoteUserTerminatedConn,
                                        ))
                                        .await;
                                    runner.release(slot);
                                    link_down(slot);
                                    push_backoff(&mut backoff, &addr_bytes, None);
                                }
                            }
                        }
                        Some(LinkEvent::Failed { slot, addr, error }) => {
                            warn!(
                                "[classic] Connection to {:?} failed: {:?}",
                                addr,
                                defmt::Debug2Format(&error)
                            );
                            let addr_bytes: [u8; 6] =
                                addr.raw().try_into().unwrap_or([0u8; 6]);
                            if pending.as_ref().is_some_and(|p| p.slot == slot) {
                                let manual = pending.as_ref().is_some_and(|p| p.manual);
                                pending = None;
                                if manual
                                    && requested.is_some_and(|(_, n)| n >= MAX_MANUAL_ATTEMPTS)
                                {
                                    warn!("[classic] Giving up on requested connection");
                                    requested = None;
                                }
                            }
                            push_backoff(&mut backoff, &addr_bytes, None);
                            let _ = crate::ble_state::BLE_EVENT_CHANNEL.try_send(
                                crate::ble_state::BleEvent::StateChanged(
                                    crate::protocol::ConnectionState::Disconnected,
                                ),
                            );
                        }
                        Some(LinkEvent::Disconnected { slot, addr, .. }) => {
                            warn!("[classic] {:?} disconnected (link {})", addr, slot);
                            let addr_bytes: [u8; 6] =
                                addr.raw().try_into().unwrap_or([0u8; 6]);
                            links[slot] = None;
                            link_down(slot);
                            push_backoff(&mut backoff, &addr_bytes, Some(Duration::from_secs(2)));
                        }
                        None => {}
                    },
                }
            }
            Either3::First(Ok(bt_hci::ControllerToHostPacket::Acl(_acl))) => {
                // rx[0] = HCI type indicator (0x02); ACL header starts at rx[1]
                let handle_and_flags = u16::from_le_bytes([rx[1], rx[2]]);
                let data_len = u16::from_le_bytes([rx[3], rx[4]]) as usize;
                let acl_data = &rx[5..5 + data_len.min(rx.len() - 5)];
                let handle = handle_and_flags & 0x0FFF;

                let Some(idx) = links
                    .iter()
                    .position(|l| l.as_ref().is_some_and(|l| l.handle.raw() == handle))
                else {
                    debug!("[classic] ACL for unknown handle {}", handle);
                    continue;
                };
                let Some(link) = links[idx].as_mut() else {
                    continue;
                };

                match link
                    .l2cap
                    .process_acl(controller, handle_and_flags, acl_data, &mut acl_buf)
                    .await
                {
                    Ok(Some((channel_idx, data_len))) if link.active => {
                        // L2CAP data arrived on a HID channel
                        if link
                            .hid
                            .process_data(channel_idx, &acl_buf[..data_len], &mut report)
                        {
                            if link.profile.is_keyboard() {
                                forward_keyboard_report(idx, &report).await;
                            } else {
                                forward_trackpad_report(idx, &report);
                            }
                        }
                    }
                    Ok(_) => {} // Signaling, a fragment, or data before setup finished
                    Err(e) => {
                        warn!("[classic] L2CAP error: {:?}", defmt::Debug2Format(&e));
                    }
                }

                if !link.active && link.hid.is_ready(&link.l2cap) {
                    info!(
                        "[classic] HID channels open on link {}! Running {:?} setup...",
                        idx, link.profile
                    );
                    apply_profile_setup(link.profile, &link.hid, &link.l2cap, controller).await;
                    link.active = true;
                    info!("[classic] === CLASSIC HID SESSION ACTIVE (link {}) ===", idx);
                    let _ = crate::ble_state::BLE_EVENT_CHANNEL.try_send(
                        crate::ble_state::BleEvent::StateChanged(
                            crate::protocol::ConnectionState::Connected,
                        ),
                    );
                }
            }
            Either3::First(Ok(_)) => {}
            Either3::First(Err(_)) => {
                Timer::after_millis(1).await;
            }

            Either3::Second(cmd) => match cmd {
                ClassicCommand::Connect { address } => {
                    if is_linked(&links, &address) {
                        info!("[classic] Connect: already connected");
                    } else {
                        info!("[classic] Connect command received for {:02x}", address);
                        requested = Some((address, 0));
                    }
                }
                ClassicCommand::Scan => scan_requested = true,
                ClassicCommand::ScanStop => {
                    scan_requested = false;
                    if inquiry_active {
                        info!("[classic] Inquiry cancelled by user");
                        let _ = controller
                            .exec(&bt_hci::cmd::link_control::InquiryCancel::new())
                            .await;
                        crate::rpc_log::info("Classic Inquiry cancelled");
                        inquiry_active = false;
                    }
                }
                ClassicCommand::Disconnect { address } => {
                    for idx in 0..MAX_CLASSIC_LINKS {
                        let Some(link) = links[idx].as_ref() else {
                            continue;
                        };
                        if address.is_some_and(|a| a != link.addr) {
                            continue;
                        }
                        info!("[classic] Disconnecting link {}", idx);
                        let _ = controller
                            .exec(&bt_hci::cmd::link_control::Disconnect::new(
                                link.handle,
                                bt_hci::param::DisconnectReason::RemoteUserTerminatedConn,
                            ))
                            .await;
                        // Auto-connect brings it back, but not right away.
                        push_backoff(&mut backoff, &link.addr, Some(Duration::from_secs(30)));
                        links[idx] = None;
                        runner.release(idx);
                        link_down(idx);
                    }
                }
                ClassicCommand::ClearBond { address } => {
                    let addr = BdAddr::new(address);
                    {
                        use bt_classic_host::LinkKeyStore;
                        link_keys.borrow_mut().remove(&addr);
                    }
                    info!("[classic] ClearBond: dropped link key for {:?}", addr);
                    auto_bonds.retain(|a| *a != address);
                    backoff.retain(|b| b.addr != address);
                    if requested.is_some_and(|(a, _)| a == address) {
                        requested = None;
                    }
                    if let Some(idx) = links
                        .iter()
                        .position(|l| l.as_ref().is_some_and(|l| l.addr == address))
                    {
                        info!("[classic] ClearBond targets a connected device, disconnecting");
                        if let Some(link) = links[idx].take() {
                            let _ = controller
                                .exec(&bt_hci::cmd::link_control::Disconnect::new(
                                    link.handle,
                                    bt_hci::param::DisconnectReason::RemoteUserTerminatedConn,
                                ))
                                .await;
                        }
                        runner.release(idx);
                        link_down(idx);
                    }
                }
                ClassicCommand::UpdateProfile {
                    address,
                    profile_id,
                } => {
                    let new_profile = DeviceProfile::from_id(profile_id);
                    for idx in 0..MAX_CLASSIC_LINKS {
                        let Some(link) = links[idx].as_mut() else {
                            continue;
                        };
                        if link.addr != address || link.profile == new_profile {
                            continue;
                        }
                        info!(
                            "[classic] Profile changed {:?} -> {:?}, re-running setup",
                            link.profile, new_profile
                        );
                        link.profile = new_profile;
                        slots::set_classic_connected(idx, &address, profile_id);
                        if link.active {
                            apply_profile_setup(new_profile, &link.hid, &link.l2cap, controller)
                                .await;
                        }
                    }
                }
            },

            Either3::Third(()) => {
                ticks = ticks.wrapping_add(1);
                let now = Instant::now();

                // An attempt that never resolves would block every other
                // device from connecting.
                if let Some(p) = pending.as_ref() {
                    if now - p.started > CONNECT_TIMEOUT {
                        warn!("[classic] Connection attempt timed out");
                        if let Some(handle) = runner.handle_of(p.slot) {
                            let _ = controller
                                .exec(&bt_hci::cmd::link_control::Disconnect::new(
                                    handle,
                                    bt_hci::param::DisconnectReason::RemoteUserTerminatedConn,
                                ))
                                .await;
                        }
                        runner.release(p.slot);
                        push_backoff(&mut backoff, &p.addr, None);
                        if p.manual {
                            requested = None;
                        }
                        pending = None;
                    }
                }

                for idx in 0..MAX_CLASSIC_LINKS {
                    let Some(link) = links[idx].as_ref() else {
                        continue;
                    };
                    if !link.active && now - link.since > CHANNEL_OPEN_TIMEOUT {
                        error!("[classic] Timeout waiting for HID channels on link {}", idx);
                        let _ = controller
                            .exec(&bt_hci::cmd::link_control::Disconnect::new(
                                link.handle,
                                bt_hci::param::DisconnectReason::RemoteUserTerminatedConn,
                            ))
                            .await;
                        push_backoff(&mut backoff, &link.addr, None);
                        links[idx] = None;
                        runner.release(idx);
                        link_down(idx);
                        continue;
                    }
                    // Periodic battery poll. Report ID 0x90 is Magic Trackpad
                    // specific; a keyboard would only answer with a handshake
                    // error, so don't ask.
                    if link.active
                        && !link.profile.is_keyboard()
                        && ticks % BATTERY_POLL_TICKS == 0
                    {
                        if let Err(e) = link
                            .hid
                            .get_report(&link.l2cap, controller, ReportType::Input, 0x90)
                            .await
                        {
                            warn!(
                                "[classic] Battery poll failed: {:?}",
                                defmt::Debug2Format(&e)
                            );
                        }
                    }
                }

                if ticks % BOND_REFRESH_TICKS == 0 {
                    auto_bonds = load_auto_connect_bonds(flash_mutex).await;
                }
            }
        }
    }
}
