import qbs

DynamicLibrary {
    name: "ManagerApi"
    Group {
        name: "project-install"
        fileTagsFilter: "dynamiclibrary"
        qbs.install: false
        qbs.installDir: "lib"
    }

    Depends { name: "cpp" }
    Depends { name: "CommonApi" }

    destinationDirectory: '.'

    cpp.dynamicLibraries: [
        "dl",
        "pthread",
        "rt",
    ]

    cpp.includePaths: [
        "../core",
        "../include",
        "../internal_api",
    ]

    cpp.defines: ["OT_LOGGING", "_FORTIFY_SOURCE=2"]

    files: [
        "../include/core_control_resources.h",
        "../include/ta_exit_states.h",
        "../common/tee_list.c",
        "extern_resources.h",
        "io_thread.h",
        "io_thread.c",
        "logic_thread.h",
        "logic_thread.c",
        "mainloop.c",
        "opentee_manager_storage_api.h",
        "opentee_manager_storage_api.c",
        "ext_storage_stream_api.h",
        "ext_storage_stream_api_posix.c",
        "../internal_api/opentee_storage_common.h",
        "../internal_api/opentee_storage_common.c",
        "shm_mem.h",
        "shm_mem.c",
        "ta_dir_watch.h",
        "ta_dir_watch.c",
        "tee_ta_properties.h",
    ]
}
