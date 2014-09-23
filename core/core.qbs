import qbs

CppApplication {
    name: "TEE_Core_Process"
    type: "application"
    Depends { name: "CommonApi" }

    destinationDirectory: '.'

    cpp.dynamicLibraries: ["dl", "pthread"]
    cpp.includePaths: ["../include"]
    cpp.linkerFlags: "-rdynamic"

    files: ["main.c", "main_shared_var.h"]
}
