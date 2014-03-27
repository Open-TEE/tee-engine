import qbs

DynamicLibrary {
    name: "InternalApi"
    Depends { name: "cpp" }

    Export {
        Depends { name: "cpp" }
        cpp.includePaths: ["../include", "."]
    }

    cpp.dynamicLibraries: ["ssl", "crypto"]

    files: ["../include/tee_internal_api.h", "data_types.h", "tee_ta_interface.h",
        "tee_memory.h", "tee_memory.c", "time_api.h", "time_api.c", "storage_data_key_api.h",
        "storage_data_key_api.c", "storage_key_apis_external_funcs.c", "tee_panic.h", "tee_panic.c",
        "tee_storage_common.h", "storage_key_apis_external_funcs.h", "tee_crypto_api.h",
        "tee_crypto_api.c", "tee_object_handle.h"
    ]
}

