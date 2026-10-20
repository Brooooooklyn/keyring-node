//! Shared helpers for talking to the Win32 credential APIs.

pub(crate) fn to_wstr(s: &str) -> Vec<u16> {
  s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub(crate) unsafe fn from_wstr(ws: *const u16) -> String {
  // null pointer case, return empty string
  if ws.is_null() {
    return String::new();
  }
  // this code from https://stackoverflow.com/a/48587463/558006
  let len = (0..).take_while(|&i| unsafe { *ws.offset(i) } != 0).count();
  let slice = unsafe { std::slice::from_raw_parts(ws, len) };
  String::from_utf16_lossy(slice)
}
