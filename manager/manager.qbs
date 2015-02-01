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
        "shm_mem.h",
        "shm_mem.c",
        "ta_dir_watch.h",
        "ta_dir_watch.c",
        "tee_ta_properties.h",
    ]
}
