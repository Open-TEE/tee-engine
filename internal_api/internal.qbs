import qbs

DynamicLibrary {
    name: "InternalApi"
    Depends { name: "cpp" }
    Depends { name: "OpenSSL" }

    Export {
        Depends { name: "cpp" }
        cpp.includePaths: ["../include", "."]
    }

    destinationDirectory: '.'

    files: ["../include/tee_internal_api.h", "tee_data_types.h", "tee_ta_interface.h",
        "tee_memory.h", "tee_memory.c", "tee_time_api.h", "tee_time_api.c", "tee_storage_api.h",
        "tee_storage_api.c", "storage_key_apis_external_funcs.c", "tee_panic.h", "tee_panic.c",
        "tee_storage_common.h", "storage_key_apis_external_funcs.h", "tee_crypto_api.h",
        "tee_crypto_api.c", "tee_object_handle.h", "openssl_1_0_2_beta_rsa_oaep.h",
        "openssl_1_0_2_beta_rsa_oaep.c", "../include/tee_shared_data_types.h"
    ]
}

