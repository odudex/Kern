/**
 * V4L2 webcam capture for Kern Desktop Simulator.
 *
 * Opens a V4L2 device, negotiates YUYV (preferred) or MJPEG format,
 * and provides frames converted to RGB565.
 */

#include "v4l2_capture.h"
#include "stb_image.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/videodev2.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define V4L2_NUM_BUFS 4

typedef enum {
    CAP_FMT_YUYV,
    CAP_FMT_MJPEG,
    CAP_FMT_RGB24,
    CAP_FMT_NV12,
} cap_pixel_fmt_t;

typedef struct {
    void *start;
    size_t length;
} mmap_buf_t;

struct v4l2_capture {
    int fd;
    uint32_t width;
    uint32_t height;
    cap_pixel_fmt_t fmt;
    mmap_buf_t bufs[V4L2_NUM_BUFS];
    uint32_t buf_count;
};

/* ---- helpers ---- */

static int xioctl(int fd, unsigned long request, void *arg) {
    int r;
    do {
        r = ioctl(fd, request, arg);
    } while (r == -1 && errno == EINTR);
    return r;
}

static inline int clamp_byte(int v) {
    return v < 0 ? 0 : (v > 255 ? 255 : v);
}

static inline uint16_t yuv_to_rgb565(uint8_t y, uint8_t u, uint8_t v) {
    int c = y - 16;
    int d = u - 128;
    int e = v - 128;
    int r = clamp_byte((298 * c + 409 * e + 128) >> 8);
    int g = clamp_byte((298 * c - 100 * d - 208 * e + 128) >> 8);
    int b = clamp_byte((298 * c + 516 * d + 128) >> 8);
    return (uint16_t)(((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3));
}

static void yuyv_to_rgb565(const uint8_t *yuyv, uint16_t *rgb565,
                            uint32_t width, uint32_t height) {
    size_t npixels = (size_t)width * height;
    for (size_t i = 0; i < npixels; i += 2) {
        uint8_t y0 = yuyv[i * 2 + 0];
        uint8_t u  = yuyv[i * 2 + 1];
        uint8_t y1 = yuyv[i * 2 + 2];
        uint8_t v  = yuyv[i * 2 + 3];
        rgb565[i]     = yuv_to_rgb565(y0, u, v);
        rgb565[i + 1] = yuv_to_rgb565(y1, u, v);
    }
}

static bool try_format(int fd, uint32_t pixfmt, uint32_t w, uint32_t h,
                       uint32_t *out_w, uint32_t *out_h) {
    struct v4l2_format fmt = {0};
    fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    fmt.fmt.pix.width = w;
    fmt.fmt.pix.height = h;
    fmt.fmt.pix.pixelformat = pixfmt;
    fmt.fmt.pix.field = V4L2_FIELD_NONE;

    if (xioctl(fd, VIDIOC_S_FMT, &fmt) < 0)
        return false;

    if (fmt.fmt.pix.pixelformat != pixfmt)
        return false;

    *out_w = fmt.fmt.pix.width;
    *out_h = fmt.fmt.pix.height;
    return true;
}

static bool setup_mmap(v4l2_capture_t *cap) {
    struct v4l2_requestbuffers req = {0};
    req.count = V4L2_NUM_BUFS;
    req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    req.memory = V4L2_MEMORY_MMAP;

    if (xioctl(cap->fd, VIDIOC_REQBUFS, &req) < 0) {
        perror("VIDIOC_REQBUFS");
        return false;
    }

    cap->buf_count = req.count;
    if (cap->buf_count < 2) {
        fprintf(stderr, "v4l2_capture: insufficient buffers (%u)\n", cap->buf_count);
        return false;
    }
    if (cap->buf_count > V4L2_NUM_BUFS)
        cap->buf_count = V4L2_NUM_BUFS;

    for (uint32_t i = 0; i < cap->buf_count; i++) {
        struct v4l2_buffer buf = {0};
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;
        buf.index = i;

        if (xioctl(cap->fd, VIDIOC_QUERYBUF, &buf) < 0) {
            perror("VIDIOC_QUERYBUF");
            goto unmap;
        }

        cap->bufs[i].length = buf.length;
        cap->bufs[i].start = mmap(NULL, buf.length,
                                   PROT_READ | PROT_WRITE, MAP_SHARED,
                                   cap->fd, buf.m.offset);
        if (cap->bufs[i].start == MAP_FAILED) {
            perror("mmap");
            goto unmap;
        }
    }

    goto queue; /* success — skip cleanup */
unmap:
    for (uint32_t j = 0; j < cap->buf_count; j++) {
        if (cap->bufs[j].start && cap->bufs[j].start != MAP_FAILED)
            munmap(cap->bufs[j].start, cap->bufs[j].length);
        cap->bufs[j].start = NULL;
    }
    return false;

queue:
    /* Queue all buffers */
    for (uint32_t i = 0; i < cap->buf_count; i++) {
        struct v4l2_buffer buf = {0};
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;
        buf.index = i;
        if (xioctl(cap->fd, VIDIOC_QBUF, &buf) < 0) {
            perror("VIDIOC_QBUF");
            return false;
        }
    }

    /* Start streaming */
    enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    if (xioctl(cap->fd, VIDIOC_STREAMON, &type) < 0) {
        perror("VIDIOC_STREAMON");
        return false;
    }

    return true;
}

/* ---- public API ---- */

v4l2_capture_t *v4l2_capture_open(const char *device,
                                   uint32_t desired_width,
                                   uint32_t desired_height) {
    if (!device)
        device = "/dev/video0";

    int fd = open(device, O_RDWR | O_NONBLOCK);
    if (fd < 0) {
        fprintf(stderr, "v4l2_capture: cannot open %s: %s\n", device, strerror(errno));
        return NULL;
    }

    /* Verify it's a capture device */
    struct v4l2_capability cap_info = {0};
    if (xioctl(fd, VIDIOC_QUERYCAP, &cap_info) < 0 ||
        !(cap_info.capabilities & V4L2_CAP_VIDEO_CAPTURE)) {
        fprintf(stderr, "v4l2_capture: %s is not a capture device\n", device);
        close(fd);
        return NULL;
    }

    if (!(cap_info.capabilities & V4L2_CAP_STREAMING)) {
        fprintf(stderr, "v4l2_capture: %s does not support streaming\n", device);
        close(fd);
        return NULL;
    }

    /* Negotiate pixel format and resolution.
     *
     * Try the caller's desired resolution first, then common fallbacks.
     * If that fails (common with IPU6 / v4l2-loopback devices that have
     * a fixed pipeline format), query the device's current format and
     * accept it if we can convert from it. */
    const struct { uint32_t w, h; } res_prefs[] = {
        {desired_width, desired_height}, {1280, 720}, {800, 600}, {640, 480},
    };
    static const struct { uint32_t fourcc; cap_pixel_fmt_t fmt; } fmt_prefs[] = {
        { V4L2_PIX_FMT_YUYV,  CAP_FMT_YUYV  },
        { V4L2_PIX_FMT_MJPEG, CAP_FMT_MJPEG },
        { V4L2_PIX_FMT_RGB24, CAP_FMT_RGB24 },
        { V4L2_PIX_FMT_NV12,  CAP_FMT_NV12  },
    };
    #define N_FMT_PREFS (sizeof(fmt_prefs) / sizeof(fmt_prefs[0]))
    #define N_RES_PREFS (sizeof(res_prefs) / sizeof(res_prefs[0]))

    uint32_t actual_w = 0, actual_h = 0;
    cap_pixel_fmt_t pixel_fmt = CAP_FMT_YUYV;
    bool negotiated = false;

    /* Try each format at each preferred resolution */
    for (size_t f = 0; f < N_FMT_PREFS && !negotiated; f++) {
        for (size_t r = 0; r < N_RES_PREFS && !negotiated; r++) {
            if (try_format(fd, fmt_prefs[f].fourcc,
                           res_prefs[r].w, res_prefs[r].h,
                           &actual_w, &actual_h)) {
                pixel_fmt = fmt_prefs[f].fmt;
                negotiated = true;
            }
        }
    }

    /* Last resort: query the device's current format and accept it if we
     * can handle it (works for v4l2-loopback / IPU6 pipeline devices). */
    if (!negotiated) {
        struct v4l2_format cur = {0};
        cur.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        if (xioctl(fd, VIDIOC_G_FMT, &cur) == 0 &&
            cur.fmt.pix.width > 0 && cur.fmt.pix.height > 0) {
            actual_w = cur.fmt.pix.width;
            actual_h = cur.fmt.pix.height;
            uint32_t pf = cur.fmt.pix.pixelformat;
            for (size_t f = 0; f < N_FMT_PREFS; f++) {
                if (pf == fmt_prefs[f].fourcc) {
                    pixel_fmt = fmt_prefs[f].fmt;
                    negotiated = true;
                    break;
                }
            }
            if (!negotiated) {
                char fcc[5] = {(char)(pf), (char)(pf >> 8),
                               (char)(pf >> 16), (char)(pf >> 24), 0};
                fprintf(stderr, "v4l2_capture: device format %.4s not supported\n", fcc);
            }
        }
    }

    if (!negotiated) {
        fprintf(stderr, "v4l2_capture: no supported format on %s\n", device);
        close(fd);
        return NULL;
    }

    v4l2_capture_t *cap = calloc(1, sizeof(*cap));
    if (!cap) {
        close(fd);
        return NULL;
    }
    cap->fd = fd;
    cap->width = actual_w;
    cap->height = actual_h;
    cap->fmt = pixel_fmt;

    if (!setup_mmap(cap)) {
        close(fd);
        free(cap);
        return NULL;
    }

    static const char *fmt_names[] = { "YUYV", "MJPEG", "RGB24", "NV12" };
    printf("v4l2_capture: opened %s — %ux%u %s\n",
           device, actual_w, actual_h, fmt_names[pixel_fmt]);

    return cap;
}

void v4l2_capture_get_resolution(const v4l2_capture_t *cap,
                                  uint32_t *width, uint32_t *height) {
    if (!cap) return;
    if (width)  *width  = cap->width;
    if (height) *height = cap->height;
}

size_t v4l2_capture_read_rgb565(v4l2_capture_t *cap,
                                 uint8_t *rgb565_buf,
                                 size_t buf_size) {
    if (!cap || !rgb565_buf)
        return 0;

    size_t needed = (size_t)cap->width * cap->height * 2;
    if (buf_size < needed)
        return 0;

    /* Wait for a frame with 1-second timeout */
    struct pollfd pfd = {.fd = cap->fd, .events = POLLIN};
    int ret = poll(&pfd, 1, 1000);
    if (ret <= 0)
        return 0; /* timeout or error */

    struct v4l2_buffer buf = {0};
    buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buf.memory = V4L2_MEMORY_MMAP;

    if (xioctl(cap->fd, VIDIOC_DQBUF, &buf) < 0)
        return 0;

    size_t written = 0;
    const uint8_t *src = cap->bufs[buf.index].start;

    if (cap->fmt == CAP_FMT_NV12) {
        /* NV12: Y plane (w*h) + interleaved UV plane (w*h/2) at half res */
        const uint8_t *y_plane = src;
        const uint8_t *uv_plane = src + (size_t)cap->width * cap->height;
        uint16_t *dst = (uint16_t *)rgb565_buf;
        for (uint32_t row = 0; row < cap->height; row++) {
            for (uint32_t col = 0; col < cap->width; col++) {
                uint8_t y = y_plane[row * cap->width + col];
                size_t uv_off = (row / 2) * cap->width + (col & ~1u);
                uint8_t u = uv_plane[uv_off];
                uint8_t v = uv_plane[uv_off + 1];
                dst[row * cap->width + col] = yuv_to_rgb565(y, u, v);
            }
        }
        written = needed;
    } else if (cap->fmt == CAP_FMT_YUYV) {
        yuyv_to_rgb565(src, (uint16_t *)rgb565_buf, cap->width, cap->height);
        written = needed;
    } else if (cap->fmt == CAP_FMT_RGB24) {
        size_t npixels = (size_t)cap->width * cap->height;
        uint16_t *dst = (uint16_t *)rgb565_buf;
        for (size_t i = 0; i < npixels; i++) {
            uint16_t r = (src[i * 3 + 0] >> 3) & 0x1F;
            uint16_t g = (src[i * 3 + 1] >> 2) & 0x3F;
            uint16_t b = (src[i * 3 + 2] >> 3) & 0x1F;
            dst[i] = (r << 11) | (g << 5) | b;
        }
        written = needed;
    } else {
        /* MJPEG: decode with stb_image */
        int w, h, channels;
        unsigned char *rgb = stbi_load_from_memory(src, buf.bytesused,
                                                    &w, &h, &channels, 3);
        if (rgb) {
            /* Use negotiated resolution; ignore decoded size if it differs
             * to avoid mutating cap dimensions and overflowing the caller's
             * buffer. */
            size_t npixels = (size_t)cap->width * cap->height;
            size_t decoded_pixels = (size_t)w * h;
            if (decoded_pixels < npixels)
                npixels = decoded_pixels;
            uint16_t *dst = (uint16_t *)rgb565_buf;
            for (size_t i = 0; i < npixels; i++) {
                uint16_t r = (rgb[i * 3 + 0] >> 3) & 0x1F;
                uint16_t g = (rgb[i * 3 + 1] >> 2) & 0x3F;
                uint16_t b = (rgb[i * 3 + 2] >> 3) & 0x1F;
                dst[i] = (r << 11) | (g << 5) | b;
            }
            stbi_image_free(rgb);
            written = npixels * 2;
        }
    }

    /* Re-queue the buffer */
    xioctl(cap->fd, VIDIOC_QBUF, &buf);

    return written;
}

void v4l2_capture_close(v4l2_capture_t *cap) {
    if (!cap) return;

    enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    xioctl(cap->fd, VIDIOC_STREAMOFF, &type);

    for (uint32_t i = 0; i < cap->buf_count; i++) {
        if (cap->bufs[i].start && cap->bufs[i].start != MAP_FAILED)
            munmap(cap->bufs[i].start, cap->bufs[i].length);
    }

    close(cap->fd);
    free(cap);
}
