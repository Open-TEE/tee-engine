import qbs

DynamicLibrary {
    name: "ManagerApi"
    Depends { name: "cpp" }
    Depends { name: "CommonApi" }

    destinationDirectory: '.'

    cpp.dynamicLibraries: ["dl", "pthread"]
    cpp.includePaths: ["../include", "../core"]

    files: ["mainloop.c", "process_definition.h", "process_manager.c", "process_manager.h",
        "../core/core_extern_resources.h", "../core/main.c"
    ]
}
