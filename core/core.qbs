import qbs

CppApplication {
    name: "TEE_Core_Process"
    type: "application"
    Depends { name: "CommonApi" }

    cpp.dynamicLibraries: ["dl"]
    cpp.includePaths: ["../include"]

    Group {
        name: 'Common'
        prefix: '../include/'
        files: ["subprocess.h", "conf_parser.h"]
    }

    files: ["main.c"]
}
