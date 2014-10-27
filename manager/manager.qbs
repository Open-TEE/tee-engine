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
        "extern_resources.h",
        "mainloop.c",
    ]
}
