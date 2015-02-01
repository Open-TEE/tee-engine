import qbs

CppApplication {
    name: "opentee-engine"
    type: "application"
    Depends { name: "CommonApi" }

    destinationDirectory: '.'

    Export {
        Depends { name: "cpp" }
        cpp.includePaths: ["../include", "."]
    }

    cpp.dynamicLibraries: [
        "dl",
        "pthread"
    ]

    cpp.includePaths: [
        "../include"
    ]

    cpp.linkerFlags: "-rdynamic"

    files: [
        "../include/core_control_resources.h",
        "../include/conf_parser.h",
        "args.c",
        "args.h",
        "conf_parser.c",
        "ini.c",
        "ini.h",
        "main.c",
    ]
}
