//! Windows local-store ACL boundary. Refuses permissive or inherited rights.
//!
//! DACLs are attached atomically at object creation. This protects against
//! other OS principals, not hostile same-user processes or administrators.
//! Native Windows test execution is required before release.

#![cfg(windows)]

use std::ffi::{c_void, OsStr};
use std::fs::File;
use std::io;
use std::mem::{size_of, MaybeUninit};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;
use std::path::Path;
use std::ptr::{self, null_mut};

const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_USER_CLASS: u32 = 1;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const CREATE_NEW: u32 = 1;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
const FILE_ALL_ACCESS: u32 = 0x001f_01ff;
const SE_FILE_OBJECT: u32 = 1;
const OWNER_SECURITY_INFORMATION: u32 = 1;
const DACL_SECURITY_INFORMATION: u32 = 4;
const SE_DACL_PRESENT: u16 = 0x0004;
const SE_DACL_PROTECTED: u16 = 0x1000;
const ACL_SIZE_INFORMATION_CLASS: u32 = 2;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const INHERITED_ACE: u8 = 0x10;
const SDDL_REVISION_1: u32 = 1;

#[repr(C)]
struct SecurityAttributes {
    length: u32,
    security_descriptor: *mut c_void,
    inherit_handle: i32,
}
#[repr(C)]
struct SidAndAttributes {
    sid: *mut c_void,
    attributes: u32,
}
#[repr(C)]
struct AceHeader {
    kind: u8,
    flags: u8,
    size: u16,
}
#[repr(C)]
struct AclSizeInformation {
    ace_count: u32,
    bytes_in_use: u32,
    bytes_free: u32,
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(process: *mut c_void, access: u32, token: *mut *mut c_void) -> i32;
    fn GetTokenInformation(
        token: *mut c_void, class: u32, data: *mut c_void, length: u32, returned: *mut u32,
    ) -> i32;
    fn ConvertSidToStringSidW(sid: *mut c_void, text: *mut *mut u16) -> i32;
    fn ConvertStringSidToSidW(text: *const u16, sid: *mut *mut c_void) -> i32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        text: *const u16, version: u32, descriptor: *mut *mut c_void, size: *mut u32,
    ) -> i32;
    fn GetNamedSecurityInfoW(
        name: *const u16, object_type: u32, information: u32,
        owner: *mut *mut c_void, group: *mut *mut c_void,
        dacl: *mut *mut c_void, sacl: *mut *mut c_void, descriptor: *mut *mut c_void,
    ) -> u32;
    fn GetSecurityDescriptorControl(descriptor: *mut c_void, control: *mut u16, revision: *mut u32) -> i32;
    fn GetAclInformation(acl: *mut c_void, info: *mut c_void, size: u32, class: u32) -> i32;
    fn GetAce(acl: *mut c_void, index: u32, ace: *mut *mut c_void) -> i32;
    fn EqualSid(left: *const c_void, right: *const c_void) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> *mut c_void;
    fn CloseHandle(handle: *mut c_void) -> i32;
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
    fn CreateDirectoryW(path: *const u16, attributes: *const SecurityAttributes) -> i32;
    fn CreateFileW(
        path: *const u16, access: u32, sharing: u32, attributes: *const SecurityAttributes,
        disposition: u32, flags: u32, template: *mut c_void,
    ) -> *mut c_void;
}

struct LocalSecurity(*mut c_void);
impl Drop for LocalSecurity {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Pointer owned by a Windows security allocation API.
            unsafe { LocalFree(self.0) };
        }
    }
}
struct Token(*mut c_void);
impl Drop for Token {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Handle returned by OpenProcessToken.
            unsafe { CloseHandle(self.0) };
        }
    }
}
fn invalid_acl() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "Windows store ACL is not private")
}
fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain(Some(0)).collect()
}
fn path_wide(path: &Path) -> io::Result<Vec<u16>> {
    let encoded = wide(path.as_os_str());
    if encoded.len() > 32767 || encoded[..encoded.len()-1].contains(&0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid Windows path"));
    }
    Ok(encoded)
}
fn to_sid_string(sid: *mut c_void) -> io::Result<String> {
    let mut text: *mut u16 = null_mut();
    // SAFETY: SID pointer from Windows token; API allocates LocalFree memory.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let guard = LocalSecurity(text.cast());
    let mut len = 0usize;
    // SAFETY: Windows guarantees zero-terminated wide SID text.
    while len < 256 && unsafe { *text.add(len) } != 0 {
        len += 1;
    }
    if len == 256 { return Err(invalid_acl()); }
    // SAFETY: The terminator was observed within 256 code units.
    let value = String::from_utf16(unsafe { std::slice::from_raw_parts(text, len) })
        .map_err(|_| invalid_acl())?;
    drop(guard);
    Ok(value)
}
fn current_sid() -> io::Result<String> {
    let mut token: *mut c_void = null_mut();
    // SAFETY: Kernel process pseudohandle; returned token is CloseHandle-owned.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let guard = Token(token);
    let mut length = 0u32;
    // SAFETY: Size discovery call intentionally supplies an empty buffer.
    unsafe { GetTokenInformation(guard.0, TOKEN_USER_CLASS, null_mut(), 0, &mut length) };
    if (length as usize) < size_of::<SidAndAttributes>() || length > 65536 {
        return Err(invalid_acl());
    }
    let mut buffer = vec![0u8; length as usize];
    // SAFETY: Windows fills the discovered bounded buffer.
    if unsafe { GetTokenInformation(
        guard.0, TOKEN_USER_CLASS, buffer.as_mut_ptr().cast(), length, &mut length,
    ) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // Vec<u8> may be unaligned for a pointer-bearing TOKEN_USER.
    let user = unsafe { ptr::read_unaligned(buffer.as_ptr().cast::<SidAndAttributes>()) };
    if user.sid.is_null() { return Err(invalid_acl()); }
    to_sid_string(user.sid)
}
fn sid_from_text(value: &str) -> io::Result<LocalSecurity> {
    let encoded = wide(OsStr::new(value));
    let mut sid: *mut c_void = null_mut();
    // SAFETY: Owned SID allocation returned by Windows and freed by guard.
    if unsafe { ConvertStringSidToSidW(encoded.as_ptr(), &mut sid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(LocalSecurity(sid))
}

struct ProtectedDescriptor(LocalSecurity);
impl ProtectedDescriptor {
    fn new(directory: bool) -> io::Result<Self> {
        let user = current_sid()?;
        let flags = if directory { "OICI" } else { "" };
        let sddl = format!(
            "O:{user}D:P(A;{flags};FA;;;{user})(A;{flags};FA;;;SY)(A;{flags};FA;;;BA)"
        );
        let text = wide(OsStr::new(&sddl));
        let mut descriptor: *mut c_void = null_mut();
        // SAFETY: Windows validates the SDDL and returns LocalFree memory.
        if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(), SDDL_REVISION_1, &mut descriptor, null_mut(),
        ) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(LocalSecurity(descriptor)))
    }
    fn attributes(&self) -> SecurityAttributes {
        SecurityAttributes {
            length: size_of::<SecurityAttributes>() as u32,
            security_descriptor: self.0.0,
            inherit_handle: 0,
        }
    }
}
pub(crate) fn create_private_directory(path: &Path) -> io::Result<()> {
    let descriptor = ProtectedDescriptor::new(true)?;
    let attrs = descriptor.attributes();
    let path = path_wide(path)?;
    // SAFETY: Both UTF-16 name and security attributes outlive the call.
    if unsafe { CreateDirectoryW(path.as_ptr(), &attrs) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
pub(crate) fn create_private_file(path: &Path) -> io::Result<File> {
    let descriptor = ProtectedDescriptor::new(false)?;
    let attrs = descriptor.attributes();
    let path = path_wide(path)?;
    // SAFETY: CREATE_NEW does not dereference existing names; returned handle
    // is owned and passed into File::from_raw_handle.
    let handle = unsafe { CreateFileW(
        path.as_ptr(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
        &attrs, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, null_mut(),
    ) };
    if handle as isize == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Valid uniquely owned Windows file handle.
    Ok(unsafe { File::from_raw_handle(handle) })
}

/// Verify a protected DACL of exactly three full-access allow ACEs:
/// current process user, local SYSTEM and built-in Administrators.
///
/// Security descriptor inspection is path-based and therefore cannot defeat
/// adversarial same-identity rename races; M1 retains that explicit boundary.
pub(crate) fn verify_private_acl(path: &Path) -> io::Result<()> {
    let path = path_wide(path)?;
    let mut owner: *mut c_void = null_mut();
    let mut acl: *mut c_void = null_mut();
    let mut security: *mut c_void = null_mut();
    // SAFETY: Windows validates the descriptor; all aliases into security
    // remain live until guard cleanup.
    let status = unsafe { GetNamedSecurityInfoW(
        path.as_ptr(), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &mut owner, null_mut(), &mut acl, null_mut(), &mut security,
    ) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let _guard = LocalSecurity(security);
    if owner.is_null() || acl.is_null() || security.is_null() {
        return Err(invalid_acl());
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: Windows-owned validated security descriptor.
    if unsafe { GetSecurityDescriptorControl(security, &mut control, &mut revision) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if (control & (SE_DACL_PRESENT | SE_DACL_PROTECTED))
        != (SE_DACL_PRESENT | SE_DACL_PROTECTED)
    {
        return Err(invalid_acl());
    }
    let current = sid_from_text(&current_sid()?)?;
    let system = sid_from_text("S-1-5-18")?;
    let admins = sid_from_text("S-1-5-32-544")?;
    // SAFETY: Both SIDs are Windows-validated and remain allocated.
    if unsafe { EqualSid(owner, current.0) } == 0 {
        return Err(invalid_acl());
    }
    let mut info = MaybeUninit::<AclSizeInformation>::zeroed();
    // SAFETY: ACL is Windows-validated and aliases the descriptor.
    if unsafe { GetAclInformation(
        acl, info.as_mut_ptr().cast(),
        size_of::<AclSizeInformation>() as u32, ACL_SIZE_INFORMATION_CLASS,
    ) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let count = unsafe { info.assume_init() }.ace_count;
    if count != 3 { return Err(invalid_acl()); }
    let expected = [current.0, system.0, admins.0];
    let mut matched = [false; 3];
    for index in 0..count {
        let mut ace: *mut c_void = null_mut();
        if unsafe { GetAce(acl, index, &mut ace) } == 0 || ace.is_null() {
            return Err(invalid_acl());
        }
        // SAFETY: GetAce returns at least the ACE header within this ACL.
        let header = unsafe { ptr::read_unaligned(ace.cast::<AceHeader>()) };
        if header.kind != ACCESS_ALLOWED_ACE_TYPE || header.flags & INHERITED_ACE != 0
            || header.size < 16
        {
            return Err(invalid_acl());
        }
        // Win32 ACCESS_ALLOWED_ACE is [ACE_HEADER:4][MASK:4][SID:variable].
        let bytes = ace.cast::<u8>();
        let mask = unsafe { ptr::read_unaligned(bytes.add(4).cast::<u32>()) };
        if mask != FILE_ALL_ACCESS { return Err(invalid_acl()); }
        let sid = unsafe { bytes.add(8) }.cast::<c_void>();
        let slot = expected.iter().position(|known| {
            // SAFETY: SID inside a Windows-validated allow ACE.
            unsafe { EqualSid(sid, *known) != 0 }
        }).ok_or_else(invalid_acl)?;
        if matched[slot] { return Err(invalid_acl()); }
        matched[slot] = true;
    }
    if matched.into_iter().all(|entry| entry) { Ok(()) }
    else { Err(invalid_acl()) }
}
