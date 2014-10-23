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
        "../include/com_protocol.h", "com_protocol.c",
        "../include/conf_parser.h", "conf_parser.c",
        "../include/elf_read.h", "elf_read.c",
        "../include/epoll_wrapper.h", "epoll_wrapper.c",
        "../include/h_table.h", "h_table.c",
        "../include/socket_help.h", "socket_help.c",
        "../include/tee_list.h", "tee_list.c",
        "../include/tee_logging.h",
    ]
}
