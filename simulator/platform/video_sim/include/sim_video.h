#pragma once

/**
 * Set the QR image path for the video simulator.
 * Call before app_video_open(). If NULL or not called, a blank frame is used.
 * Called from CLI argument parsing in main_sim.c.
 */
void sim_video_set_qr_image(const char *path);

/**
 * Set a directory of QR images to cycle through.
 * Call before app_video_open(). If NULL or not called, uses single image or blank.
 */
void sim_video_set_qr_dir(const char *dir_path);

/**
 * Enable webcam capture via V4L2.
 * Call before app_video_open(). If device is NULL, defaults to /dev/video0.
 * Requires SIM_WEBCAM build option; otherwise prints a warning and is a no-op.
 */
void sim_video_set_webcam(const char *device);
