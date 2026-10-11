//! Bluetooth Classic helpers: Class of Device decoding and HID keyboard
//! report translation.
//!
//! These are pure functions so they can be unit tested on the host, away
//! from the firmware's async/HCI machinery.

/// Major Device Class for "Peripheral" — keyboards, mice, trackpads, gamepads.
pub const MAJOR_CLASS_PERIPHERAL: u8 = 0x05;

/// Extract the Major Device Class (bits 12:8) from a 3-byte Class of Device.
///
/// CoD arrives from HCI little-endian:
///   cod[0] = bits 7:0   (format type + minor device class)
///   cod[1] = bits 15:8  (major device class + low major service bits)
///   cod[2] = bits 23:16 (major service class)
pub fn cod_major_device_class(cod: &[u8]) -> Option<u8> {
    if cod.len() < 3 {
        return None;
    }
    Some(cod[1] & 0x1F)
}

/// Whether a Class of Device identifies a Peripheral (HID) device.
pub fn cod_is_peripheral(cod: &[u8]) -> bool {
    cod_major_device_class(cod) == Some(MAJOR_CLASS_PERIPHERAL)
}

/// Whether a Class of Device identifies a keyboard.
///
/// For the Peripheral major class the top two bits of the Minor Device Class
/// (bits 7:6 of the CoD, i.e. the top of `cod[0]`) select the device kind:
///   00 = uncategorized, 01 = keyboard, 10 = pointing device,
///   11 = combo keyboard/pointing device.
///
/// Combos count as keyboards: their keystrokes are what we can forward.
pub fn cod_is_keyboard(cod: &[u8]) -> bool {
    if !cod_is_peripheral(cod) {
        return false;
    }
    matches!((cod[0] >> 6) & 0x03, 0b01 | 0b11)
}

/// Whether a Class of Device identifies a pointing device (mouse, trackpad).
pub fn cod_is_pointing(cod: &[u8]) -> bool {
    if !cod_is_peripheral(cod) {
        return false;
    }
    matches!((cod[0] >> 6) & 0x03, 0b10 | 0b11)
}

/// Length of a USB/Bluetooth boot-protocol keyboard report.
pub const BOOT_KEYBOARD_REPORT_LEN: usize = 8;

/// Report ID used by the keyboard input report of virtually every Classic
/// keyboard that runs in report protocol rather than boot protocol.
pub const KEYBOARD_REPORT_ID: u8 = 0x01;

/// Translate a HIDP input report from a Classic keyboard into the 8-byte boot
/// keyboard report the USB side sends: `[modifiers, 0, key1..key6]`.
///
/// Two shapes are accepted, covering what keyboards emit in practice:
///
/// - 8 bytes — boot protocol, already `[modifiers, reserved, key1..key6]`.
///   This is what a keyboard sends once `SET_PROTOCOL(Boot)` is accepted.
/// - 9 bytes starting with report ID `0x01` — report protocol with the same
///   payload behind a report ID, for keyboards that refuse boot protocol.
///
/// Anything else returns `None` rather than guessing: a misread report types
/// characters the user never pressed, while a dropped one is merely silent.
///
/// The reserved byte is forced to zero — some keyboards put OEM data there,
/// and hosts expect it clear.
pub fn translate_keyboard_report(data: &[u8]) -> Option<[u8; BOOT_KEYBOARD_REPORT_LEN]> {
    let body = match data.len() {
        BOOT_KEYBOARD_REPORT_LEN => data,
        len if len == BOOT_KEYBOARD_REPORT_LEN + 1 && data[0] == KEYBOARD_REPORT_ID => &data[1..],
        _ => return None,
    };

    let mut out = [0u8; BOOT_KEYBOARD_REPORT_LEN];
    out[0] = body[0];
    out[1] = 0;
    out[2..].copy_from_slice(&body[2..BOOT_KEYBOARD_REPORT_LEN]);
    Some(out)
}

/// Whether a Bluetooth device name is an Apple keyboard's. Apple keyboards
/// keep "Magic Keyboard" (or the older "Apple Wireless Keyboard") in their
/// name even after a user renames them in macOS ("Olof's Magic Keyboard").
pub fn name_is_apple_keyboard(name: &[u8]) -> bool {
    fn contains_ci(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle))
    }
    contains_ci(name, b"Magic Keyboard") || contains_ci(name, b"Apple Wireless Keyboard")
}

/// Boot keyboard modifier bits: Alt and GUI, left and right.
const MOD_LALT: u8 = 0x04;
const MOD_LGUI: u8 = 0x08;
const MOD_RALT: u8 = 0x40;
const MOD_RGUI: u8 = 0x80;

/// The ISO keys an Apple keyboard reports the other way round: the key left
/// of 1 (§ on a Swedish keyboard) and the one right of left Shift (<).
const KEY_GRAVE: u8 = 0x35;
const KEY_NON_US_BACKSLASH: u8 = 0x64;

/// Rewrite a boot report from an Apple keyboard into PC conventions, what
/// Linux's hid_apple does for one plugged in directly (`swap_opt_cmd`,
/// `iso_layout`) and what a host that is not a Mac expects:
///
/// - Option and Command trade places: the key next to the space bar (Cmd)
///   arrives as Alt, as on a PC keyboard, and Option as the GUI key.
/// - The ISO keys § and < arrive where a PC keyboard puts them.
pub fn apple_to_pc(report: &mut [u8; BOOT_KEYBOARD_REPORT_LEN]) {
    let m = report[0];
    let mut out = m & !(MOD_LALT | MOD_LGUI | MOD_RALT | MOD_RGUI);
    if m & MOD_LALT != 0 {
        out |= MOD_LGUI;
    }
    if m & MOD_LGUI != 0 {
        out |= MOD_LALT;
    }
    if m & MOD_RALT != 0 {
        out |= MOD_RGUI;
    }
    if m & MOD_RGUI != 0 {
        out |= MOD_RALT;
    }
    report[0] = out;
    for key in &mut report[2..] {
        *key = match *key {
            KEY_GRAVE => KEY_NON_US_BACKSLASH,
            KEY_NON_US_BACKSLASH => KEY_GRAVE,
            k => k,
        };
    }
}

#[cfg(test)]
mod apple_tests {
    use super::*;

    #[test]
    fn recognises_apple_keyboards() {
        assert!(name_is_apple_keyboard(b"Magic Keyboard"));
        assert!(name_is_apple_keyboard(b"Olof's magic keyboard"));
        assert!(name_is_apple_keyboard(b"Apple Wireless Keyboard"));
        assert!(!name_is_apple_keyboard(b"Logitech K380"));
        assert!(!name_is_apple_keyboard(b""));
    }

    #[test]
    fn swaps_option_command_and_the_iso_keys() {
        // Left Cmd + right Option held, § and a pressed.
        let mut r = [MOD_LGUI | MOD_RALT, 0, KEY_GRAVE, 0x04, 0, 0, 0, 0];
        apple_to_pc(&mut r);
        assert_eq!(r, [MOD_LALT | MOD_RGUI, 0, KEY_NON_US_BACKSLASH, 0x04, 0, 0, 0, 0]);
        // Ctrl and Shift stay where they are; < becomes §.
        let mut r = [0x01 | 0x02, 0, KEY_NON_US_BACKSLASH, 0, 0, 0, 0, 0];
        apple_to_pc(&mut r);
        assert_eq!(r, [0x01 | 0x02, 0, KEY_GRAVE, 0, 0, 0, 0, 0]);
    }
}
