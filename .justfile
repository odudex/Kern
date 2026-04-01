export IDF_PATH := env_var("HOME") + "/esp/esp-idf"
export IDF_PATH_FORCE := "1"

build:
    . $IDF_PATH/export.sh && idf.py build
    cp ./build/compile_commands.json ./compile_commands.json

flash:
    . $IDF_PATH/export.sh && idf.py flash

format:
    ./format.sh

test:
    ./test.sh

clean:
    rm -fRd build/
    rm -fRd compile_commands.json
    rm -fRd .cache/
    make -C components/bbqr/test clean
    make -C main/core/test clean
