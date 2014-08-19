import qbs

DynamicLibrary {
    name: "LauncherApi"
    Depends { name: "cpp" }
    Depends { name: "CommonApi" }
    Depends { name: "InternalApi" }

    Export {
        Depends { name: "cpp" }
        cpp.includePaths: ["../include"]
    }

    destinationDirectory: '.'

    cpp.dynamicLibraries: ["dl"]

    files: ["launcher_mainloop.c", "dynamic_loader.c", "dynamic_loader.h",
            "ta_process.h", "ta_process.c"]
}
