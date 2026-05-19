#include "sim_storage_hooks.h"

#undef fopen
#undef opendir
#undef unlink
#undef stat

#include "sim_flash.h"

static const char *resolve_if_flash(const char *path, char *buf,
                                    size_t buf_size) {
  if (!path)
    return NULL;

  if (sim_flash_is_path(path))
    return sim_flash_resolve_path(path, buf, buf_size);

  return path;
}

FILE *sim_storage_fopen(const char *path, const char *mode) {
  char host_path[512];
  const char *resolved = resolve_if_flash(path, host_path, sizeof(host_path));
  if (!resolved)
    return NULL;
  return fopen(resolved, mode);
}

DIR *sim_storage_opendir(const char *path) {
  char host_path[512];
  const char *resolved = resolve_if_flash(path, host_path, sizeof(host_path));
  if (!resolved)
    return NULL;
  return opendir(resolved);
}

int sim_storage_unlink(const char *path) {
  char host_path[512];
  const char *resolved = resolve_if_flash(path, host_path, sizeof(host_path));
  if (!resolved)
    return -1;
  return unlink(resolved);
}

int sim_storage_stat(const char *path, struct stat *st) {
  char host_path[512];
  const char *resolved = resolve_if_flash(path, host_path, sizeof(host_path));
  if (!resolved)
    return -1;
  return stat(resolved, st);
}
