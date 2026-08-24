#![cfg_attr(target_os = "none", no_std)]

#[cfg(target_os = "none")]
use core::alloc::{GlobalAlloc, Layout};
#[cfg(target_os = "none")]
use core::ffi::c_void;
#[cfg(target_os = "none")]
use core::panic::PanicInfo;

pub use bip138_ll::ffi::*;
pub use bwk_qr_protocol::ffi::*;

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
