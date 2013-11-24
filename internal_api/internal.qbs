import qbs

DynamicLibrary {
    name: "internal"
    Depends { name: "cpp" }

    Export {
        Depends { name: "cpp" }
        cpp.includePaths: ["../include", "."]
    }

    files: ["../include/tee_internal_api.h", "data_types.h", "tee_ta_interface.h",
        "tee_memory.h", "tee_memory.c"
    ]
}

