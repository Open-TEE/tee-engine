import qbs

DynamicLibrary {
    name: "CommonApi"
    Depends { name: "cpp" }

    Export {
        Depends { name: "cpp" }
        cpp.includePaths: ["../include", "."]
    }

    destinationDirectory: '.'

    cpp.includePaths: ["../include"]
    cpp.dynamicLibraries: ["z"]

    files: ["../include/tee_list.h", "../include/conf_parser.h", "conf_parser.c", "tee_list.c",
        "socket_help.c", "../include/socket_help.h", "../include/tee_logging.h",
        "../include/h_table.h", "h_table.c", "com_protocol.c", "../include/com_protocol.h" ]
    ]
}

