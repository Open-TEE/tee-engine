import qbs

DynamicLibrary {
    name: "CommonApi"
    Depends { name: "cpp" }

    Export {
        Depends { name: "cpp" }
        cpp.includePaths: ["../include", "."]
    }

    destinationDirectory: '.'
    cpp.dynamicLibraries: ["elf", "z"]
    cpp.includePaths: ["../include"]

    files: ["../include/tee_list.h", "../include/conf_parser.h", "conf_parser.c", "tee_list.c",
        "socket_help.c", "../include/socket_help.h", "../include/tee_logging.h",
        "../include/h_table.h", "h_table.c", "elf_read.c", "../include/elf_read.h",
        "com_protocol.c", "../include/com_protocol.h",
        "../include/epoll_wrapper.h", "epoll_wrapper.c"
	]
}

