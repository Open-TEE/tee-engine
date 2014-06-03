import qbs

CppApplication {
    name: "TEE_Core_Process"
    type: "application"
    Depends { name: "CommonApi" }

    cpp.dynamicLibraries: ["dl"]
    cpp.includePaths: ["../include"]

    files: ["main.c"]
}
