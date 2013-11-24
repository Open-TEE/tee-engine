import qbs

CppApplication {
    type: "application"
    Depends { name: "InternalApi" }

    cpp.dynamicLibraries: ["dl"]

    files: ["main.c", "context_child.c", "context_child.h", "dynamic_loader.h", "dynamic_loader.c"
    ]
}
