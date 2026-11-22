# Vendored embassy-usb 0.5.1

Unmodified crates.io release except for `src/class/hid.rs`: `Config` has an
`interface_string: Option<StringIndex>` field, passed to the interface's
`alt_setting` as iInterface. bt2usb names its mouse and keyboard extras
interfaces after the bonded Classic devices, so a host can tell the two
batteries apart. Drop this copy once upstream can name a HID interface.
