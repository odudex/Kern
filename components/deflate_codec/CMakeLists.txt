idf_component_register(
    SRCS
        "src/deflate_codec.c"
    INCLUDE_DIRS
        "src"
    PRIV_REQUIRES
        espressif__zlib
)
