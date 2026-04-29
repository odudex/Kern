#include "v4l2_capture.h"

#import <AVFoundation/AVFoundation.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <Foundation/Foundation.h>

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct v4l2_capture {
  uint32_t width;
  uint32_t height;
  bool configured;

  pthread_mutex_t mutex;
  pthread_cond_t cond;
  bool has_frame;
  bool closed;

  uint8_t *rgb565;
  size_t rgb565_size;

  AVCaptureSession *session;
  AVCaptureVideoDataOutput *output;
  dispatch_queue_t queue;
  id delegate;
};

static uint16_t rgb888_to_rgb565(uint8_t r, uint8_t g, uint8_t b) {
  return (uint16_t)(((r & 0xF8u) << 8) | ((g & 0xFCu) << 3) | (b >> 3));
}

@interface KernVideoDelegate : NSObject <AVCaptureVideoDataOutputSampleBufferDelegate>
@property(nonatomic, assign) v4l2_capture_t *cap;
@end

@implementation KernVideoDelegate
- (void)captureOutput:(AVCaptureOutput *)output
    didOutputSampleBuffer:(CMSampleBufferRef)sampleBuffer
           fromConnection:(AVCaptureConnection *)connection {
  (void)output;
  (void)connection;
  v4l2_capture_t *cap = self.cap;
  if (!cap)
    return;

  CVPixelBufferRef pb = CMSampleBufferGetImageBuffer(sampleBuffer);
  if (!pb)
    return;

  CVPixelBufferLockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);

  const size_t width = CVPixelBufferGetWidth(pb);
  const size_t height = CVPixelBufferGetHeight(pb);
  const size_t bytes_per_row = CVPixelBufferGetBytesPerRow(pb);
  const uint8_t *base = (const uint8_t *)CVPixelBufferGetBaseAddress(pb);

  if (!base || width == 0 || height == 0) {
    CVPixelBufferUnlockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
    return;
  }

  pthread_mutex_lock(&cap->mutex);
  if (cap->closed) {
    pthread_mutex_unlock(&cap->mutex);
    CVPixelBufferUnlockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
    return;
  }

  if (!cap->configured) {
    cap->width = (uint32_t)width;
    cap->height = (uint32_t)height;
  }
  if (cap->width != (uint32_t)width || cap->height != (uint32_t)height) {
    pthread_mutex_unlock(&cap->mutex);
    CVPixelBufferUnlockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
    return;
  }
  const size_t needed = width * height * 2;
  if (!cap->configured || cap->rgb565_size != needed) {
    free(cap->rgb565);
    cap->rgb565 = (uint8_t *)malloc(needed);
    cap->rgb565_size = cap->rgb565 ? needed : 0;
  }

  if (cap->rgb565) {
    uint16_t *dst = (uint16_t *)cap->rgb565;
    for (size_t y = 0; y < height; y++) {
      const uint8_t *row = base + y * bytes_per_row;
      for (size_t x = 0; x < width; x++) {
        const uint8_t b = row[x * 4 + 0];
        const uint8_t g = row[x * 4 + 1];
        const uint8_t r = row[x * 4 + 2];
        dst[y * width + x] = rgb888_to_rgb565(r, g, b);
      }
    }
    cap->has_frame = true;
    cap->configured = true;
    pthread_cond_broadcast(&cap->cond);
  }

  pthread_mutex_unlock(&cap->mutex);
  CVPixelBufferUnlockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
}
@end

static bool parse_device_index(const char *device, int *out_index) {
  if (!device || !out_index)
    return false;
  if (strncmp(device, "/dev/video", 10) == 0) {
    device += 10;
  }
  char *end = NULL;
  long idx = strtol(device, &end, 10);
  if (end == device || *end != '\0' || idx < 0 || idx > 1000)
    return false;
  *out_index = (int)idx;
  return true;
}

static AVCaptureDevice *select_device(const char *device) {
  NSArray<AVCaptureDevice *> *devices = [AVCaptureDevice devicesWithMediaType:AVMediaTypeVideo];
  if (devices.count == 0)
    return nil;

  if (!device || device[0] == '\0')
    return devices.firstObject;

  int idx = 0;
  if (parse_device_index(device, &idx)) {
    if (idx >= 0 && idx < (int)devices.count) {
      return devices[(NSUInteger)idx];
    }
    return devices.firstObject;
  }

  NSString *needle = [NSString stringWithUTF8String:device];
  for (AVCaptureDevice *d in devices) {
    if ([d.localizedName rangeOfString:needle options:NSCaseInsensitiveSearch].location != NSNotFound) {
      return d;
    }
    if ([d.uniqueID rangeOfString:needle options:NSCaseInsensitiveSearch].location != NSNotFound) {
      return d;
    }
  }
  return devices.firstObject;
}

extern "C" {

v4l2_capture_t *v4l2_capture_open(const char *device, uint32_t desired_width,
                                  uint32_t desired_height) {
  @autoreleasepool {
    v4l2_capture_t *cap = (v4l2_capture_t *)calloc(1, sizeof(*cap));
    if (!cap)
      return NULL;

    pthread_mutex_init(&cap->mutex, NULL);
    pthread_cond_init(&cap->cond, NULL);
    cap->queue = dispatch_queue_create("kern.sim.webcam", DISPATCH_QUEUE_SERIAL);

    AVCaptureDevice *dev = select_device(device);
    if (!dev) {
      v4l2_capture_close(cap);
      return NULL;
    }

    NSError *err = nil;
    AVCaptureDeviceInput *input = [AVCaptureDeviceInput deviceInputWithDevice:dev error:&err];
    if (!input || err) {
      v4l2_capture_close(cap);
      return NULL;
    }

    cap->session = [[AVCaptureSession alloc] init];

    if (desired_width >= 1280 || desired_height >= 720) {
      if ([cap->session canSetSessionPreset:AVCaptureSessionPreset1280x720]) {
        cap->session.sessionPreset = AVCaptureSessionPreset1280x720;
      }
    } else if ([cap->session canSetSessionPreset:AVCaptureSessionPreset640x480]) {
      cap->session.sessionPreset = AVCaptureSessionPreset640x480;
    }

    if (![cap->session canAddInput:input]) {
      v4l2_capture_close(cap);
      return NULL;
    }
    [cap->session addInput:input];

    cap->output = [[AVCaptureVideoDataOutput alloc] init];
    cap->output.videoSettings = @{
      (id)kCVPixelBufferPixelFormatTypeKey : @(kCVPixelFormatType_32BGRA),
    };
    cap->output.alwaysDiscardsLateVideoFrames = YES;

    KernVideoDelegate *delegate = [[KernVideoDelegate alloc] init];
    delegate.cap = cap;
    cap->delegate = delegate;
    [cap->output setSampleBufferDelegate:delegate queue:cap->queue];

    if (![cap->session canAddOutput:cap->output]) {
      v4l2_capture_close(cap);
      return NULL;
    }
    [cap->session addOutput:cap->output];

    [cap->session startRunning];

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 2;
    pthread_mutex_lock(&cap->mutex);
    while (!cap->configured && !cap->closed) {
      int ret = pthread_cond_timedwait(&cap->cond, &cap->mutex, &ts);
      if (ret != 0) {
        break;
      }
    }
    pthread_mutex_unlock(&cap->mutex);

    if (!cap->configured) {
      v4l2_capture_close(cap);
      return NULL;
    }

    return cap;
  }
}

void v4l2_capture_get_resolution(const v4l2_capture_t *cap, uint32_t *width,
                                 uint32_t *height) {
  if (!cap)
    return;
  if (width)
    *width = cap->width;
  if (height)
    *height = cap->height;
}

size_t v4l2_capture_read_rgb565(v4l2_capture_t *cap, uint8_t *rgb565_buf,
                                size_t buf_size) {
  if (!cap || !rgb565_buf)
    return 0;

  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  ts.tv_sec += 1;

  pthread_mutex_lock(&cap->mutex);
  while (!cap->has_frame && !cap->closed) {
    int ret = pthread_cond_timedwait(&cap->cond, &cap->mutex, &ts);
    if (ret != 0)
      break;
  }

  if (!cap->has_frame || cap->closed || !cap->rgb565) {
    pthread_mutex_unlock(&cap->mutex);
    return 0;
  }

  const size_t needed = cap->rgb565_size;
  if (buf_size < needed) {
    pthread_mutex_unlock(&cap->mutex);
    return 0;
  }

  memcpy(rgb565_buf, cap->rgb565, needed);
  cap->has_frame = false;
  pthread_mutex_unlock(&cap->mutex);
  return needed;
}

void v4l2_capture_close(v4l2_capture_t *cap) {
  if (!cap)
    return;

  @autoreleasepool {
    pthread_mutex_lock(&cap->mutex);
    cap->closed = true;
    pthread_cond_broadcast(&cap->cond);
    pthread_mutex_unlock(&cap->mutex);

    if (cap->session) {
      [cap->session stopRunning];
      cap->session = nil;
    }
    cap->output = nil;
    cap->delegate = nil;
    cap->queue = nil;

    free(cap->rgb565);
    cap->rgb565 = NULL;
    cap->rgb565_size = 0;

    pthread_cond_destroy(&cap->cond);
    pthread_mutex_destroy(&cap->mutex);

    free(cap);
  }
}

} // extern "C"
