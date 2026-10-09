//! Classic Bluetooth host runner and event dispatch.
//!
//! The runner reads HCI events from the controller and dispatches them to
//! the connection state machine, pairing handler, and L2CAP layer.

use core::cell::RefCell;

use bt_hci::cmd::link_control::*;
use bt_hci::controller::{Controller, ControllerCmdSync};
use bt_hci::event::EventKind;
use bt_hci::param::*;
use bt_hci::ControllerToHostPacket;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;

use crate::connection::{ClassicConnection, ConnectionStorage};
use crate::error::Error;
use crate::link_key::{LinkKeyInfo, LinkKeyStore};
use crate::pairing::{self, PairingCallback, PairingContext, PairingEvent, PairingState};

/// Signal used to notify user code of connection state changes.
pub type ConnSignal = Signal<CriticalSectionRawMutex, ConnEvent>;

/// Connection events signaled to user code.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ConnEvent {
    /// ACL connection established.
    Connected(ConnHandle),
    /// Connection is authenticated and encrypted, ready for L2CAP.
    Encrypted(ConnHandle),
    /// Connection failed.
    ConnectionFailed,
    /// Disconnected.
    Disconnected,
}

/// Resources for the Classic Bluetooth host. Allocate statically.
pub struct HostResources<const CONNS: usize> {
    pub(crate) connections: [ConnectionStorage; CONNS],
    pub(crate) pairing: [PairingContext; CONNS],
    #[allow(dead_code)] // Will be used for async connection event notification
    pub(crate) conn_signals: [ConnSignal; CONNS],
}

impl<const CONNS: usize> Default for HostResources<CONNS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CONNS: usize> HostResources<CONNS> {
    pub fn new() -> Self {
        Self {
            connections: [const { ConnectionStorage::new() }; CONNS],
            pairing: [const {
                PairingContext {
                    state: PairingState::Idle,
                    remote_io_cap: None,
                    peer_addr: // Safety: BdAddr is repr(transparent) over [u8; 6]
                    unsafe { core::mem::zeroed() },
                    success: false,
                    new_link_key: None,
                    link_key_type: 0,
                    passkey: None,
                }
            }; CONNS],
            conn_signals: [const { Signal::new() }; CONNS],
        }
    }

    /// Reset all connection slots to idle. Call after disconnect before reconnecting.
    pub fn reset(&mut self) {
        for slot in &mut self.connections {
            slot.active = false;
            slot.conn = ClassicConnection::new(unsafe { core::mem::zeroed() });
        }
        for ctx in &mut self.pairing {
            ctx.state = PairingState::Idle;
            ctx.success = false;
            ctx.new_link_key = None;
            ctx.passkey = None;
        }
    }
}

/// The Classic Bluetooth host runner.
///
/// Reads HCI events and drives the connection/pairing state machines.
pub struct ClassicRunner<'a, C, L, const CONNS: usize> {
    controller: &'a C,
    resources: &'a mut HostResources<CONNS>,
    link_keys: &'a RefCell<L>,
    pairing_callback: Option<PairingCallback>,
}

impl<'a, C, L, const CONNS: usize> ClassicRunner<'a, C, L, CONNS>
where
    C: Controller
        + ControllerCmdSync<CreateConnection>
        + ControllerCmdSync<AuthenticationRequested>
        + ControllerCmdSync<SetConnectionEncryption>
        + ControllerCmdSync<LinkKeyRequestReply>
        + ControllerCmdSync<LinkKeyRequestNegativeReply>
        + ControllerCmdSync<PinCodeRequestReply>
        + ControllerCmdSync<IoCapabilityRequestReply>
        + ControllerCmdSync<UserConfirmationRequestReply>
        + ControllerCmdSync<UserPasskeyRequestNegativeReply>,
    L: LinkKeyStore,
{
    /// Create a new runner.
    pub fn new(
        controller: &'a C,
        resources: &'a mut HostResources<CONNS>,
        link_keys: &'a RefCell<L>,
    ) -> Self {
        Self {
            controller,
            resources,
            link_keys,
            pairing_callback: None,
        }
    }

    /// Register a callback for pairing steps the user needs to see or act on
    /// — most importantly the passkey a keyboard expects them to type.
    ///
    /// Without one, Passkey Entry pairing stalls with nothing on screen: the
    /// controller waits for a passkey the user was never shown.
    pub fn set_pairing_callback(&mut self, callback: PairingCallback) {
        self.pairing_callback = Some(callback);
    }

    /// Report a pairing event to the registered callback, if any.
    fn notify_pairing(&self, addr: &BdAddr, event: PairingEvent) {
        if let Some(cb) = self.pairing_callback {
            cb(addr, event);
        }
    }

    /// Connect to a Classic Bluetooth device and wait until the link is ready.
    ///
    /// Initiates the ACL connection, then drives authentication and encryption
    /// by reading HCI events itself. Returns once the connection is encrypted
    /// and ready for L2CAP.
    ///
    /// This owns the controller's read side while it runs, so it only suits a
    /// single link: ACL data and events for any other connection are consumed
    /// and lost. With several links, call [`start_connect`](Self::start_connect)
    /// and feed every event to [`process_event`](Self::process_event) from one
    /// read loop instead.
    pub async fn connect(&mut self, addr: &BdAddr) -> Result<ConnHandle, Error<C::Error>> {
        let target_slot = self.start_connect(addr).await?;

        const MAX_HCI_PACKET_LEN: usize = 259;
        let mut rx = [0u8; MAX_HCI_PACKET_LEN];

        loop {
            let packet = self.controller.read(&mut rx).await.map_err(Error::Hci)?;
            let ControllerToHostPacket::Event(event) = packet else {
                #[cfg(feature = "defmt")]
                defmt::debug!("[classic] ACL data during connection setup (ignored)");
                continue;
            };
            match self.process_event(event.kind, event.data).await {
                Some(LinkEvent::Ready { slot, handle, .. }) if slot == target_slot => {
                    return Ok(handle)
                }
                Some(LinkEvent::Failed { slot, error, .. }) if slot == target_slot => {
                    return Err(error)
                }
                _ => {}
            }
        }
    }

    /// Start connecting to a Classic Bluetooth device without waiting for it.
    ///
    /// Allocates a connection slot and sends CreateConnection. The rest of the
    /// setup (authentication, pairing, encryption) is driven by
    /// [`process_event`](Self::process_event), which reports
    /// [`LinkEvent::Ready`] or [`LinkEvent::Failed`] for the returned slot.
    ///
    /// The controller pages one device at a time, so start the next connection
    /// only once this one has resolved.
    pub async fn start_connect(&mut self, addr: &BdAddr) -> Result<usize, Error<C::Error>> {
        let slot = self
            .resources
            .connections
            .iter()
            .position(|s| !s.active)
            .ok_or(Error::NoFreeSlots)?;

        let conn = &mut self.resources.connections[slot];
        conn.active = true;
        conn.conn = ClassicConnection::new(*addr);
        conn.conn.has_link_key = self.link_keys.borrow().load(addr).is_some();

        self.resources.pairing[slot] = PairingContext::new(*addr);

        // Enable all standard ACL packet types for best throughput.
        let mut pkt_type = PacketType::default();
        pkt_type = pkt_type
            .set_dh1_may_be_used(true)
            .set_dm3_may_be_used(true)
            .set_dh3_may_be_used(true)
            .set_dm5_may_be_used(true)
            .set_dh5_may_be_used(true);

        conn.conn.set_connecting();
        let sent = self
            .controller
            .exec(&CreateConnection::new(
                *addr,
                pkt_type,
                PageScanRepetitionMode::R1,
                0, // reserved
                ClockOffset::default(),
                AllowRoleSwitch::NotAllowed,
            ))
            .await;
        if let Err(e) = sent {
            self.release(slot);
            return Err(Error::Command(e));
        }
        Ok(slot)
    }

    /// Free a connection slot without touching the controller.
    ///
    /// For links the caller has given up on, e.g. after sending HCI
    /// Disconnect itself. A DisconnectionComplete that arrives later for the
    /// old handle no longer matches any slot and is ignored.
    pub fn release(&mut self, slot: usize) {
        if let Some(s) = self.resources.connections.get_mut(slot) {
            s.active = false;
            s.conn.on_disconnected();
        }
        if let Some(p) = self.resources.pairing.get_mut(slot) {
            p.state = PairingState::Idle;
            p.success = false;
            p.new_link_key = None;
            p.passkey = None;
        }
    }

    /// Slot of the active connection to `addr`, if any.
    pub fn slot_for_addr(&self, addr: &BdAddr) -> Option<usize> {
        self.resources
            .connections
            .iter()
            .position(|s| s.active && s.conn.peer_addr.raw() == addr.raw())
    }

    /// Slot of the active connection with ACL `handle`, if any.
    pub fn slot_for_handle(&self, handle: ConnHandle) -> Option<usize> {
        self.resources
            .connections
            .iter()
            .position(|s| s.active && s.conn.handle.map(|h| h.raw()) == Some(handle.raw()))
    }

    /// ACL handle of the connection in `slot`, once ConnectionComplete has
    /// assigned one.
    pub fn handle_of(&self, slot: usize) -> Option<ConnHandle> {
        self.resources
            .connections
            .get(slot)
            .filter(|s| s.active)
            .and_then(|s| s.conn.handle)
    }

    /// Mark a slot failed: free it and build the event that reports it.
    fn fail(&mut self, slot: usize, error: Error<C::Error>) -> Option<LinkEvent<C::Error>> {
        let addr = self.resources.connections[slot].conn.peer_addr;
        self.release(slot);
        Some(LinkEvent::Failed { slot, addr, error })
    }

    /// Feed one HCI event to the connection and pairing state machines.
    ///
    /// Events are matched to their connection by address or handle, so any
    /// number of links can be set up and kept alive from a single read loop.
    /// Returns what happened to a link, if the event decided anything.
    ///
    /// Pairing requests are answered even when no slot matches, so the
    /// controller is never left waiting on a reply.
    pub async fn process_event(
        &mut self,
        kind: EventKind,
        data: &[u8],
    ) -> Option<LinkEvent<C::Error>> {
        match kind {
            EventKind::ConnectionComplete => {
                // [status(1), handle(2), bdaddr(6), link_type(1), encryption(1)]
                if data.len() < 11 {
                    return None;
                }
                let status = Status::new(data[0]);
                let handle_raw = u16::from_le_bytes([data[1], data[2]]) & 0x0FFF;
                let handle = ConnHandle::new(handle_raw);
                let addr = addr_at(data, 3);
                let link_type = data[9];
                let encryption = data[10];

                let slot = self.slot_for_addr(&addr)?;
                let conn = &mut self.resources.connections[slot];
                match conn
                    .conn
                    .on_connection_complete(status, handle, link_type, encryption)
                {
                    Ok(_) => {
                        #[cfg(feature = "defmt")]
                        defmt::info!("[classic] Connected, handle={}", handle_raw);

                        conn.conn.set_authenticating();
                        if let Err(e) = self
                            .controller
                            .exec(&AuthenticationRequested::new(handle))
                            .await
                        {
                            return self.fail(slot, Error::Command(e));
                        }
                        None
                    }
                    Err(_status) => {
                        #[cfg(feature = "defmt")]
                        defmt::warn!("[classic] Connection failed");
                        self.fail(slot, Error::ConnectionFailed)
                    }
                }
            }

            EventKind::LinkKeyRequest => {
                // [bdaddr(6)]
                if data.len() < 6 {
                    return None;
                }
                let addr = addr_at(data, 0);
                let stored_key = self.link_keys.borrow().load(&addr).map(|k| k.key);
                let slot = self.slot_for_addr(&addr);

                let sent = if let Some(key) = stored_key {
                    #[cfg(feature = "defmt")]
                    defmt::info!("[classic] Replying with stored link key");
                    self.controller
                        .exec(&LinkKeyRequestReply::new(addr, key))
                        .await
                } else {
                    #[cfg(feature = "defmt")]
                    defmt::info!(
                        "[classic] No stored link key, negative reply (will trigger pairing)"
                    );
                    if let Some(slot) = slot {
                        // SSP pairing will follow
                        self.resources.pairing[slot].start();
                    }
                    self.controller
                        .exec(&LinkKeyRequestNegativeReply::new(addr))
                        .await
                };
                match (sent, slot) {
                    (Err(e), Some(slot)) => self.fail(slot, Error::Command(e)),
                    _ => None,
                }
            }

            EventKind::PinCodeRequest => {
                // [bdaddr(6)]
                // Legacy (pre-SSP) pairing. We answer with a fixed PIN and tell
                // the user what it is: on a keyboard they have to type it and
                // press Enter, so a PIN sent silently is a pairing that never
                // completes.
                if data.len() < 6 {
                    return None;
                }
                let addr = addr_at(data, 0);
                #[cfg(feature = "defmt")]
                defmt::info!(
                    "[classic] PinCodeRequest, replying with PIN '{}'",
                    pairing::DEFAULT_LEGACY_PIN
                );
                let pin_bytes = pairing::DEFAULT_LEGACY_PIN.as_bytes();
                let pin_len = pin_bytes.len().min(16);
                let mut pin = [0u8; 16];
                pin[..pin_len].copy_from_slice(&pin_bytes[..pin_len]);
                let sent = self
                    .controller
                    .exec(&PinCodeRequestReply::new(addr, pin_len as u8, pin))
                    .await;
                if let Err(e) = sent {
                    let slot = self.slot_for_addr(&addr)?;
                    return self.fail(slot, Error::Command(e));
                }
                self.notify_pairing(&addr, PairingEvent::LegacyPin(pairing::DEFAULT_LEGACY_PIN));
                None
            }

            EventKind::IoCapabilityRequest => {
                // [bdaddr(6)]
                if data.len() < 6 {
                    return None;
                }
                let addr = addr_at(data, 0);
                #[cfg(feature = "defmt")]
                defmt::info!(
                    "[classic] IoCapabilityRequest, replying {:?}",
                    pairing::OUR_IO_CAPABILITY
                );
                // General bonding: the link stays up and carries HID traffic
                // after pairing. MITM is left to the remote to require —
                // demanding it ourselves would lock out NoInputNoOutput peers
                // like the Magic Trackpad 2.
                let sent = self
                    .controller
                    .exec(&IoCapabilityRequestReply::new(
                        addr,
                        pairing::OUR_IO_CAPABILITY,
                        OobDataPresent::NotPresent,
                        AuthenticationRequirements::MitmNotRequiredGeneralBonding,
                    ))
                    .await;
                if let Err(e) = sent {
                    let slot = self.slot_for_addr(&addr)?;
                    return self.fail(slot, Error::Command(e));
                }
                None
            }

            EventKind::IoCapabilityResponse => {
                // [bdaddr(6), io_cap(1), oob(1), auth_req(1)]
                if data.len() < 9 {
                    return None;
                }
                let io_cap = match data[6] {
                    0x00 => IoCapability::DisplayOnly,
                    0x01 => IoCapability::DisplayYesNo,
                    0x02 => IoCapability::KeyboardOnly,
                    _ => IoCapability::NoInputNoOutput,
                };
                #[cfg(feature = "defmt")]
                defmt::info!("[classic] Remote IO capability: {:?}", io_cap);
                let slot = self.slot_for_addr(&addr_at(data, 0))?;
                self.resources.pairing[slot].on_io_capability_response(io_cap);
                None
            }

            EventKind::UserConfirmationRequest => {
                // [bdaddr(6), numeric_value(4)]
                if data.len() < 6 {
                    return None;
                }
                let addr = addr_at(data, 0);
                #[cfg(feature = "defmt")]
                defmt::info!("[classic] Auto-accepting user confirmation (Just Works)");
                let sent = self
                    .controller
                    .exec(&UserConfirmationRequestReply::new(addr))
                    .await;
                if let Err(e) = sent {
                    let slot = self.slot_for_addr(&addr)?;
                    return self.fail(slot, Error::Command(e));
                }
                self.notify_pairing(&addr, PairingEvent::JustWorks);
                None
            }

            EventKind::UserPasskeyNotification => {
                // [bdaddr(6), passkey(4)]
                //
                // Passkey Entry: the controller picked a six-digit passkey and
                // the remote is waiting for the user to type it. Nothing to
                // reply to — we hand it up for display and keep processing
                // events until SimplePairingComplete arrives, however long the
                // user takes. Other links keep running meanwhile.
                if data.len() < 10 {
                    return None;
                }
                let addr = addr_at(data, 0);
                let passkey = u32::from_le_bytes([data[6], data[7], data[8], data[9]]);
                if let Some(slot) = self.slot_for_addr(&addr) {
                    self.resources.pairing[slot].on_user_passkey_notification(passkey);
                }
                #[cfg(feature = "defmt")]
                defmt::info!("[classic] Passkey for remote entry: {}", passkey);
                self.notify_pairing(&addr, PairingEvent::PasskeyDisplay(passkey));
                None
            }

            EventKind::UserPasskeyRequest => {
                // [bdaddr(6)]
                //
                // The remote is displaying a passkey and wants us to type it.
                // We have no input device, so decline rather than leave the
                // controller waiting — the user gets a clear failure instead
                // of a hang.
                if data.len() < 6 {
                    return None;
                }
                let addr = addr_at(data, 0);
                #[cfg(feature = "defmt")]
                defmt::warn!("[classic] UserPasskeyRequest: no input device, declining");
                let sent = self
                    .controller
                    .exec(&UserPasskeyRequestNegativeReply::new(addr))
                    .await;
                self.notify_pairing(&addr, PairingEvent::PasskeyEntryUnsupported);
                if let Err(e) = sent {
                    let slot = self.slot_for_addr(&addr)?;
                    return self.fail(slot, Error::Command(e));
                }
                None
            }

            EventKind::KeypressNotification => {
                // [bdaddr(6), notification_type(1)]
                // The remote reports passkey typing progress. Purely
                // informational, but it confirms the user is typing on the
                // right keyboard.
                #[cfg(feature = "defmt")]
                if data.len() >= 7 {
                    defmt::debug!("[classic] Keypress notification: type={}", data[6]);
                }
                None
            }

            EventKind::SimplePairingComplete => {
                // [status(1), bdaddr(6)]
                if data.len() < 7 {
                    return None;
                }
                let success = data[0] == 0x00;
                #[cfg(feature = "defmt")]
                defmt::info!("[classic] SimplePairingComplete, success={}", success);
                let slot = self.slot_for_addr(&addr_at(data, 1))?;
                self.resources.pairing[slot].on_simple_pairing_complete(success);
                None
            }

            EventKind::LinkKeyNotification => {
                // [bdaddr(6), link_key(16), key_type(1)]
                if data.len() < 23 {
                    return None;
                }
                let addr = addr_at(data, 0);
                let mut key = [0u8; 16];
                key.copy_from_slice(&data[6..22]);
                let key_type = data[22];

                if let Some(slot) = self.slot_for_addr(&addr) {
                    self.resources.pairing[slot].on_link_key_notification(key, key_type);
                }
                self.link_keys
                    .borrow_mut()
                    .store(&addr, LinkKeyInfo { key, key_type });
                #[cfg(feature = "defmt")]
                defmt::info!("[classic] New link key stored, type={}", key_type);
                None
            }

            EventKind::AuthenticationComplete => {
                // [status(1), handle(2)]
                if data.len() < 3 {
                    return None;
                }
                let status = Status::new(data[0]);
                let slot = self.slot_for_handle(handle_at(data, 1))?;
                let conn = &mut self.resources.connections[slot];
                if conn.conn.is_ready() {
                    // Re-authentication on an established link; nothing to drive.
                    return None;
                }
                match conn.conn.on_authentication_complete(status) {
                    Ok(()) => {
                        #[cfg(feature = "defmt")]
                        defmt::info!("[classic] Authentication complete, enabling encryption");
                        let handle = conn.conn.handle?;
                        conn.conn.set_encrypting();
                        if let Err(e) = self
                            .controller
                            .exec(&SetConnectionEncryption::new(handle, true))
                            .await
                        {
                            return self.fail(slot, Error::Command(e));
                        }
                        None
                    }
                    Err(_status) => {
                        #[cfg(feature = "defmt")]
                        defmt::warn!("[classic] Authentication failed");
                        self.fail(slot, Error::AuthenticationFailed)
                    }
                }
            }

            EventKind::EncryptionChangeV1 | EventKind::EncryptionChangeV2 => {
                // [status(1), handle(2), encryption_enabled(1)]
                if data.len() < 4 {
                    return None;
                }
                let status = Status::new(data[0]);
                let encryption_enabled = data[3];
                let slot = self.slot_for_handle(handle_at(data, 1))?;
                let conn = &mut self.resources.connections[slot];
                if conn.conn.is_ready() {
                    // A key refresh or similar on a link that is already up.
                    return None;
                }
                match conn.conn.on_encryption_change(status, encryption_enabled) {
                    Ok(()) if conn.conn.is_ready() => {
                        #[cfg(feature = "defmt")]
                        defmt::info!("[classic] Encryption enabled! Connection ready.");
                        let handle = conn.conn.handle?;
                        let addr = conn.conn.peer_addr;
                        Some(LinkEvent::Ready { slot, addr, handle })
                    }
                    Ok(()) => {
                        #[cfg(feature = "defmt")]
                        defmt::warn!("[classic] EncryptionChange but not encrypted");
                        self.fail(slot, Error::EncryptionFailed)
                    }
                    Err(_status) => {
                        #[cfg(feature = "defmt")]
                        defmt::warn!("[classic] Encryption failed");
                        self.fail(slot, Error::EncryptionFailed)
                    }
                }
            }

            EventKind::DisconnectionComplete => {
                // [status(1), handle(2), reason(1)]
                if data.len() < 3 {
                    return None;
                }
                let handle = handle_at(data, 1);
                let slot = self.slot_for_handle(handle)?;
                let conn = &self.resources.connections[slot].conn;
                if conn.is_ready() {
                    let addr = conn.peer_addr;
                    self.release(slot);
                    Some(LinkEvent::Disconnected { slot, addr, handle })
                } else {
                    // Connection lost during setup
                    self.fail(slot, Error::Disconnected)
                }
            }

            _ => None,
        }
    }
}

/// What a processed HCI event did to a connection slot.
#[derive(Debug)]
pub enum LinkEvent<E> {
    /// The link is authenticated and encrypted, ready for L2CAP.
    Ready {
        slot: usize,
        addr: BdAddr,
        handle: ConnHandle,
    },
    /// Setting up the link failed. The slot is free again.
    Failed {
        slot: usize,
        addr: BdAddr,
        error: Error<E>,
    },
    /// A ready link went down. The slot is free again.
    Disconnected {
        slot: usize,
        addr: BdAddr,
        handle: ConnHandle,
    },
}

/// Read a BD address from event parameters at `offset`.
fn addr_at(data: &[u8], offset: usize) -> BdAddr {
    let mut raw = [0u8; 6];
    raw.copy_from_slice(&data[offset..offset + 6]);
    BdAddr::new(raw)
}

/// Read a 12-bit connection handle from event parameters at `offset`.
fn handle_at(data: &[u8], offset: usize) -> ConnHandle {
    ConnHandle::new(u16::from_le_bytes([data[offset], data[offset + 1]]) & 0x0FFF)
}
