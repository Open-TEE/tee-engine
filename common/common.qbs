import qbs

DynamicLibrary {
    name: "CommonApi"
    Depends { name: "cpp" }

    Export {
        Depends { name: "cpp" }
        cpp.includePaths: ["../include", "."]
    }

    cpp.includePaths: ["../include"]

    files: ["../include/tee_list.h", "../include/conf_parser.h", "conf_parser.c", "tee_list.c",
            "socket_help.c", "../include/socket_help.h"
    ]
}

