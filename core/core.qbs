import qbs

CppApplication {
    name: "TEE_Core_Process"
    type: "application"
    Depends { name: "CommonApi" }

    destinationDirectory: '.'

    Export {
        Depends { name: "cpp" }
        cpp.includePaths: ["../include", "."]
    }

    cpp.dynamicLibraries: ["dl", "pthread"]
    cpp.includePaths: ["../include"]
    cpp.linkerFlags: "-rdynamic"

    files: ["main.c", "core_extern_resources.h"]
}
