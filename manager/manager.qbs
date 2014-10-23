import qbs

DynamicLibrary {
    name: "ManagerApi"
    Depends { name: "cpp" }
    Depends { name: "CommonApi" }

    destinationDirectory: '.'

    cpp.dynamicLibraries: [
        "dl",
        "pthread"
    ]

    cpp.includePaths: [
        "../core",
        "../include",
    ]

    files: [
        "../core/core_extern_resources.h",
        "../core/main.c",
        "mainloop.c",
        "process_definition.h",
        "process_manager.h",
        "process_manager.c",
        "ta_dir_watch.h",
        "ta_dir_watch.c",
        "tee_ta_propertie.h",
    ]
}
