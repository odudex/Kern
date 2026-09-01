/*
 * Force-included when compiling core/storage.c for the host tests. storage.c
 * hardcodes /spiffs and /sdcard; these hooks let the test rebase both under a
 * temporary directory without touching the production source.
 */
#pragma once
#include <dirent.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

FILE *host_storage_fopen(const char *path, const char *mode);
DIR *host_storage_opendir(const char *path);
int host_storage_unlink(const char *path);
int host_storage_stat(const char *path, struct stat *st);
int host_storage_mkdir(const char *path, mode_t mode);

#define fopen(path, mode) host_storage_fopen((path), (mode))
#define opendir(path) host_storage_opendir((path))
#define unlink(path) host_storage_unlink((path))
#define stat(path, st) host_storage_stat((path), (st))
#define mkdir(path, mode) host_storage_mkdir((path), (mode))
