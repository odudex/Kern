#pragma once
#define ESP_LOGE(tag, fmt, ...)                                                \
  do {                                                                         \
    (void)(tag);                                                               \
    (void)(fmt);                                                               \
  } while (0)
#define ESP_LOGW(tag, fmt, ...)                                                \
  do {                                                                         \
    (void)(tag);                                                               \
    (void)(fmt);                                                               \
  } while (0)
#define ESP_LOGI(tag, fmt, ...)                                                \
  do {                                                                         \
    (void)(tag);                                                               \
    (void)(fmt);                                                               \
  } while (0)
#define ESP_LOGD(tag, fmt, ...)                                                \
  do {                                                                         \
    (void)(tag);                                                               \
    (void)(fmt);                                                               \
  } while (0)
