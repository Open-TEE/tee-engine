import qbs

CppApplication {
    name: "TEE_Core_Process"
    type: "application"
    Depends { name: "CommonApi" }

    destinationDirectory: '.'

    cpp.dynamicLibraries: ["dl"]
    cpp.includePaths: ["../include"]

    files: ["main.c"]
}
