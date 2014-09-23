import qbs

DynamicLibrary {
    name: "LauncherApi"
    Depends { name: "cpp" }
    Depends { name: "CommonApi" }
    Depends { name: "InternalApi" }

    destinationDirectory: '.'

    Export {
        Depends { name: "cpp" }
        cpp.includePaths: ["../include"]
    }

    cpp.dynamicLibraries: ["dl", "pthread", "rt"]
    cpp.warningLevel: "none"

    files: ["launcher_mainloop.c", "dynamic_loader.c", "dynamic_loader.h",
            "ta_process.h", "ta_process.c", "utils.h", "utils.c",
            "../include/trusted_app_properties.h"
    ]
}
