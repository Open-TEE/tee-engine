import qbs

DynamicLibrary {
    name: "ManagerApi"
    Depends { name: "cpp" }
    Depends { name: "CommonApi" }

    cpp.includePaths: ["../include"]

    files: ["mainloop.c",
            "process_definition.h", "process_manager.c", "process_manager.h"
    ]
}
