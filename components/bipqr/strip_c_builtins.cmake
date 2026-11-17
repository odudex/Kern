# Drops every non-Rust object (compiler_builtins' C intrinsics) from ${LIB}.
execute_process(COMMAND ${AR} t ${LIB} OUTPUT_VARIABLE members
                COMMAND_ERROR_IS_FATAL ANY)
string(REPLACE "\n" ";" members "${members}")
set(c_objects)
foreach(member IN LISTS members)
  if(member MATCHES "\\.o$" AND NOT member MATCHES "\\.rcgu\\.o$")
    list(APPEND c_objects ${member})
  endif()
endforeach()
if(c_objects)
  execute_process(COMMAND ${AR} d ${LIB} ${c_objects} COMMAND_ERROR_IS_FATAL ANY)
endif()
