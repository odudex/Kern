#pragma once
#include <stdint.h>

/* V4L2 pixel format constants used by components/video/video.h */
#define V4L2_PIX_FMT_SBGGR8  0x42474752U
#define V4L2_PIX_FMT_SBGGR10 0x30424752U
#define V4L2_PIX_FMT_GREY    0x59455247U
#define V4L2_PIX_FMT_RGB565  0x50424752U
#define V4L2_PIX_FMT_RGB24   0x33424752U
#define V4L2_PIX_FMT_YUV422P 0x50323234U
#define V4L2_PIX_FMT_YUV420  0x32315559U

/* V4L2 ioctl constants for video.c */
#define VIDIOC_QUERYCAP          0xC0685600U
#define VIDIOC_G_FMT             0xC0D05604U
#define VIDIOC_S_FMT             0xC0D05605U
#define VIDIOC_REQBUFS           0xC0145608U
#define VIDIOC_QUERYBUF          0xC0585609U
#define VIDIOC_QBUF              0xC058560FU
#define VIDIOC_DQBUF             0xC0585611U
#define VIDIOC_STREAMON          0x40045612U
#define VIDIOC_STREAMOFF         0x40045613U
#define VIDIOC_G_CTRL            0xC008561BU
#define VIDIOC_S_CTRL            0xC008561CU
#define VIDIOC_G_EXT_CTRLS       0xC0185647U
#define VIDIOC_S_EXT_CTRLS       0xC0185648U
#define VIDIOC_EXPBUF            0xC0185610U

#define V4L2_CAP_VIDEO_CAPTURE   0x00000001U
#define V4L2_BUF_TYPE_VIDEO_CAPTURE 1
#define V4L2_MEMORY_MMAP        1
#define V4L2_MEMORY_USERPTR     2
#define V4L2_FIELD_NONE         1

#define V4L2_CID_BASE            (0x00980900U)
#define V4L2_CID_FOCUS_ABSOLUTE  (V4L2_CID_BASE + 28)
#define V4L2_CTRL_CLASS_CAMERA   0x009A0000U
#define V4L2_CID_CAMERA_CLASS_BASE (V4L2_CTRL_CLASS_CAMERA | 0x900)

struct v4l2_capability {
    uint8_t  driver[16];
    uint8_t  card[32];
    uint8_t  bus_info[32];
    uint32_t version;
    uint32_t capabilities;
    uint32_t device_caps;
    uint32_t reserved[3];
};

struct v4l2_pix_format {
    uint32_t width;
    uint32_t height;
    uint32_t pixelformat;
    uint32_t field;
    uint32_t bytesperline;
    uint32_t sizeimage;
    uint32_t colorspace;
    uint32_t priv;
    uint32_t flags;
    uint32_t ycbcr_enc;
    uint32_t quantization;
    uint32_t xfer_func;
};

struct v4l2_format {
    uint32_t type;
    union {
        struct v4l2_pix_format pix;
        uint8_t raw_data[200];
    } fmt;
};

struct v4l2_requestbuffers {
    uint32_t count;
    uint32_t type;
    uint32_t memory;
    uint32_t capabilities;
    uint32_t reserved[1];
};

struct v4l2_timecode {
    uint32_t type, flags;
    uint8_t frames, seconds, minutes, hours, userbits[4];
};

struct v4l2_buffer {
    uint32_t index;
    uint32_t type;
    uint32_t bytesused;
    uint32_t flags;
    uint32_t field;
    struct { long tv_sec; long tv_usec; } timestamp;
    struct v4l2_timecode timecode;
    uint32_t sequence;
    uint32_t memory;
    union { uint32_t offset; unsigned long userptr; } m;
    uint32_t length;
    uint32_t reserved2;
    uint32_t request_fd;
};

struct v4l2_control {
    uint32_t id;
    int32_t  value;
};

struct v4l2_ext_control {
    uint32_t id;
    uint32_t size;
    uint32_t reserved2[1];
    union { int32_t value; int64_t value64; char *string; } ;
};

struct v4l2_ext_controls {
    union { uint32_t ctrl_class; uint32_t which; };
    uint32_t count;
    uint32_t error_idx;
    int32_t  request_fd;
    uint32_t reserved[1];
    struct v4l2_ext_control *controls;
};

struct v4l2_exportbuffer {
    uint32_t type;
    uint32_t index;
    uint32_t plane;
    uint32_t flags;
    int32_t  fd;
    uint32_t reserved[11];
};
