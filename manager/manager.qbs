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
        "uuid",
        "crypt",
        "rt",
    ]

    cpp.includePaths: [
        "../core",
        "../include",
        "../internal_api",
    ]

    files: [
        "../include/core_control_resources.h",
        "../include/ta_exit_states.h",
        "extern_resources.h",
        "io_thread.h",
        "io_thread.c",
        "logic_thread.h",
        "logic_thread.c",
        "mainloop.c",
        "opentee_manager_storage_api.h",
        "opentee_manager_storage_api.c",
        "../internal_api/opentee_storage_common.h",
        "../internal_api/opentee_storage_common.c",
        "shm_mem.h",
        "shm_mem.c",
        "ta_dir_watch.h",
        "ta_dir_watch.c",
        "tee_ta_properties.h",
    ]
}
