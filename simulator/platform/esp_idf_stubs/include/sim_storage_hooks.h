#pragma once

/*
 * Simulator-only hooks for compiling production storage.c unchanged.
 *
 * This file is force-included only for main/core/storage.c in the simulator
 * CMake target. It includes the system headers first, then remaps the POSIX
 * file APIs that storage.c uses for /spiffs so the calls land in sim_flash.
 */

#include <dirent.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

FILE *sim_storage_fopen(const char *path, const char *mode);
DIR *sim_storage_opendir(const char *path);
int sim_storage_unlink(const char *path);
int sim_storage_stat(const char *path, struct stat *st);

#define fopen(path, mode) sim_storage_fopen((path), (mode))
#define opendir(path) sim_storage_opendir((path))
#define unlink(path) sim_storage_unlink((path))
#define stat(path, st) sim_storage_stat((path), (st))
