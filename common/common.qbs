import qbs

DynamicLibrary {
    name: "CommonApi"
    Depends { name: "cpp" }

    Export {
        Depends { name: "cpp" }
        cpp.includePaths: ["../include", "."]
    }

    cpp.dynamicLibraries: ["elf", "pthread"]

    destinationDirectory: '.'

    cpp.includePaths: ["../include"]

    files: ["../include/tee_list.h", "../include/conf_parser.h", "conf_parser.c", "tee_list.c",
            "socket_help.c", "../include/socket_help.h",
        "../include/h_table.h", "h_table.c",
        "../include/elf_read.h", "elf_read.c", "../include/trusted_app_properties.h",
        "trusted_app_properties.c", "../manager/epoll_wrapper.h", "../manager/epoll_wrapper.c"
    ]
}

