import qbs

DynamicLibrary {
    name: "CommonApi"
    Depends { name: "cpp" }

    Export {
        Depends { name: "cpp" }
        cpp.includePaths: ["../include", "."]
    }

    destinationDirectory: '.'

    cpp.dynamicLibraries: [
        "elf",
        "z"
    ]

    cpp.includePaths: [
        "../include"
    ]

    files: [
        "../include/com_protocol.h",
        "../include/conf_parser.h",
        "../include/elf_read.h",
        "../include/epoll_wrapper.h",
        "../include/h_table.h",
        "../include/ini.h",
        "../include/socket_help.h",
        "../include/tee_list.h",
        "../include/tee_logging.h",
        "com_protocol.c",
        "conf_parser.c",
        "elf_read.c",
        "epoll_wrapper.c",
        "h_table.c",
        "ini.c",
        "socket_help.c",
        "tee_list.c",
    ]
}
