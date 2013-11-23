import qbs

CppApplication {
    type: "application"
    Depends { name: "internal" }

    cpp.dynamicLibraries: ["dl"]

    files: ["main.c", "context_child.c", "context_child.h"
    ]
}
