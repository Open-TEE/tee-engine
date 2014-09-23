import qbs

DynamicLibrary {
    name: "CommonApi"
    Depends { name: "cpp" }

    Export {
        Depends { name: "cpp" }
        cpp.includePaths: ["../include/", ".", "../internal_api/"]
    }

    cpp.dynamicLibraries: ["z", "pthread"]
    cpp.includePaths: ["../include/", "../internal_api/"]

    files: ["../include/tee_list.h", "../include/conf_parser.h", "conf_parser.c", "tee_list.c",
            "socket_help.c", "../include/socket_help.h", "../include/h_table.h", "h_table.c",
        "../include/com_protocol.h", "com_protocol.c", "../include/epoll_wrapper.h",
        "epoll_wrapper.c", "../include/general_data_types.h",
        "../include/intermediate_data_types.h", "../include/trusted_app_properties.h",
        "trusted_app_properties.c", "../include/subprocess.h"
    ]
}

