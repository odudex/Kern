#![cfg_attr(target_os = "none", no_std)]

#[cfg(target_os = "none")]
use core::alloc::{GlobalAlloc, Layout};
#[cfg(target_os = "none")]
use core::ffi::c_void;
#[cfg(target_os = "none")]
use core::panic::PanicInfo;

pub use bip_nonces_cache_ll::ffi::{
    bnc_begin_round_one, bnc_begin_round_two, bnc_begin_signing, bnc_cached_nonce,
    bnc_held_session, bnc_issue, bnc_secret_free, bnc_session_field_decode, bnc_sign_musig,
    bnc_signer_free, bnc_signer_new, bnc_two_round_session_id,
};
pub use bipqr_ll::ffi::{
    bipqr_buf_free, bipqr_request_decode, bipqr_request_free, bipqr_response_encode,
};

#[cfg(target_os = "none")]
struct CAllocator;

#[cfg(target_os = "none")]
extern "C" {
    fn malloc(size: usize) -> *mut c_void;
    fn free(ptr: *mut c_void);
    fn abort() -> !;
}

#[cfg(target_os = "none")]
unsafe impl GlobalAlloc for CAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        malloc(layout.size().max(1)).cast()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        free(ptr.cast());
    }
}

#[cfg(target_os = "none")]
#[global_allocator]
static ALLOCATOR: CAllocator = CAllocator;

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    unsafe { abort() }
}
