import qbs

CppApplication {
    name: "storage_test"
    type: "application"

    cpp.dynamicLibraries: ["ssl", "crypto", "sqlite3"]

    files: ["storage_data_key_api.c", "data_types.h", "tee_memory.h", "tee_memory.c", "storage_data_key_api.h"]
}
