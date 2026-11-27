# Shared board metadata loader reading boards.json at the repository root.
# Used by main/CMakeLists.txt, components/video/CMakeLists.txt,
# components/bsp_common/CMakeLists.txt, and simulator/CMakeLists.txt.

set(KERN_BOARDS_JSON "${CMAKE_CURRENT_LIST_DIR}/../boards.json")
file(READ "${KERN_BOARDS_JSON}" _kern_boards_json_text)
string(JSON _kern_boards_count LENGTH "${_kern_boards_json_text}" boards)

# Populate KERN_ALL_BOARDS with every board name in manifest order.
set(KERN_ALL_BOARDS "")
math(EXPR _kern_boards_last "${_kern_boards_count} - 1")
foreach(_i RANGE 0 ${_kern_boards_last})
    string(JSON _bname GET "${_kern_boards_json_text}" boards ${_i} name)
    list(APPEND KERN_ALL_BOARDS "${_bname}")
endforeach()

# Populate KERN_ACTIVE_BOARD, KERN_BOARD_KCONFIG, KERN_BOARD_WIDTH,
# KERN_BOARD_HEIGHT, KERN_BOARD_TOUCH, KERN_BOARD_PMIC,
# KERN_BOARD_CAN_POWER_OFF, and KERN_BOARD_REQUIRES from Kconfig.
# During ESP-IDF's script-mode discovery pass (before sdkconfig is loaded),
# KERN_ACTIVE_BOARD is unset and KERN_BOARD_REQUIRES lists every board so all
# board components and their idf_component.yml manifests are discovered.
macro(kern_board_detect_from_kconfig)
    unset(KERN_ACTIVE_BOARD)
    unset(KERN_BOARD_KCONFIG)
    unset(KERN_BOARD_WIDTH)
    unset(KERN_BOARD_HEIGHT)
    unset(KERN_BOARD_TOUCH)
    unset(KERN_BOARD_PMIC)
    unset(KERN_BOARD_CAN_POWER_OFF)

    foreach(_i RANGE 0 ${_kern_boards_last})
        string(JSON _bkcfg GET "${_kern_boards_json_text}" boards ${_i} kconfig)
        if(${_bkcfg})
            string(JSON KERN_ACTIVE_BOARD GET "${_kern_boards_json_text}" boards ${_i} name)
            set(KERN_BOARD_KCONFIG "${_bkcfg}")
            string(JSON KERN_BOARD_WIDTH GET "${_kern_boards_json_text}" boards ${_i} width)
            string(JSON KERN_BOARD_HEIGHT GET "${_kern_boards_json_text}" boards ${_i} height)
            string(JSON KERN_BOARD_TOUCH GET "${_kern_boards_json_text}" boards ${_i} touch)
            string(JSON KERN_BOARD_PMIC GET "${_kern_boards_json_text}" boards ${_i} pmic)
            string(JSON KERN_BOARD_CAN_POWER_OFF GET "${_kern_boards_json_text}" boards ${_i} can_power_off)
            break()
        endif()
    endforeach()

    if(DEFINED KERN_ACTIVE_BOARD)
        set(KERN_BOARD_REQUIRES ${KERN_ACTIVE_BOARD})
    else()
        set(KERN_BOARD_REQUIRES ${KERN_ALL_BOARDS})
    endif()
endmacro()

# Populate KERN_BOARD_* variables for an explicit board name (used by simulator).
macro(kern_board_load_by_name BOARD_NAME)
    unset(KERN_ACTIVE_BOARD)
    foreach(_i RANGE 0 ${_kern_boards_last})
        string(JSON _bname GET "${_kern_boards_json_text}" boards ${_i} name)
        if(_bname STREQUAL "${BOARD_NAME}")
            set(KERN_ACTIVE_BOARD "${_bname}")
            string(JSON KERN_BOARD_KCONFIG GET "${_kern_boards_json_text}" boards ${_i} kconfig)
            string(JSON KERN_BOARD_WIDTH GET "${_kern_boards_json_text}" boards ${_i} width)
            string(JSON KERN_BOARD_HEIGHT GET "${_kern_boards_json_text}" boards ${_i} height)
            string(JSON KERN_BOARD_TOUCH GET "${_kern_boards_json_text}" boards ${_i} touch)
            string(JSON KERN_BOARD_PMIC GET "${_kern_boards_json_text}" boards ${_i} pmic)
            string(JSON KERN_BOARD_CAN_POWER_OFF GET "${_kern_boards_json_text}" boards ${_i} can_power_off)
            break()
        endif()
    endforeach()
    if(NOT DEFINED KERN_ACTIVE_BOARD)
        message(FATAL_ERROR "Unknown board '${BOARD_NAME}' (not found in ${KERN_BOARDS_JSON})")
    endif()
endmacro()
