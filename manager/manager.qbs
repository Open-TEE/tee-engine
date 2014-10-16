import qbs

DynamicLibrary {
    name: "ManagerApi"
    Depends { name: "cpp" }
    Depends { name: "CommonApi" }

    destinationDirectory: '.'

    cpp.dynamicLibraries: ["dl", "pthread"]
    cpp.includePaths: ["../include"]

    files: ["mainloop.c",
        "process_definition.h",  "process_manager.c", "process_manager.h",
        "../core/main_shared_var.h", "../core/main.c"
    ]
}
