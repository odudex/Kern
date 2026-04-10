#pragma once
#include "esp_err.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef void *ppa_client_handle_t;

typedef enum {
    PPA_SRM_ROTATION_ANGLE_0   = 0,
    PPA_SRM_ROTATION_ANGLE_90  = 1,
    PPA_SRM_ROTATION_ANGLE_180 = 2,
    PPA_SRM_ROTATION_ANGLE_270 = 3,
} ppa_srm_rotation_angle_t;

typedef enum { PPA_SRM_COLOR_MODE_RGB565 = 0 } ppa_srm_color_mode_t;
typedef enum { PPA_OPERATION_SRM = 0 }         ppa_operation_t;
typedef enum { PPA_TRANS_MODE_BLOCKING = 0 }   ppa_trans_mode_t;

typedef struct {
    struct {
        const void           *buffer;
        size_t                buffer_size;
        uint32_t              pic_w, pic_h;
        uint32_t              block_w, block_h;
        uint32_t              block_offset_x, block_offset_y;
        ppa_srm_color_mode_t  srm_cm;
    } in;
    struct {
        void                 *buffer;
        size_t                buffer_size;
        uint32_t              pic_w, pic_h;
        uint32_t              block_offset_x, block_offset_y;
        ppa_srm_color_mode_t  srm_cm;
    } out;
    ppa_srm_rotation_angle_t  rotation_angle;
    float                     scale_x, scale_y;
    bool                      mirror_x, mirror_y;
    ppa_trans_mode_t          mode;
} ppa_srm_oper_config_t;

typedef struct {
    ppa_operation_t oper_type;
} ppa_client_config_t;

esp_err_t ppa_register_client(const ppa_client_config_t *config,
                              ppa_client_handle_t *ret_client);
esp_err_t ppa_unregister_client(ppa_client_handle_t ppa_client);
esp_err_t ppa_do_scale_rotate_mirror(ppa_client_handle_t ppa_client,
                                     const ppa_srm_oper_config_t *config);
