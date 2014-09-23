import qbs

DynamicLibrary {
    name: "ManagerApi"
    Depends { name: "cpp" }
    Depends { name: "CommonApi" }

    destinationDirectory: '.'

    cpp.includePaths: ["../include"]
    cpp.dynamicLibraries: ["dl", "pthread", "rt"]
    cpp.warningLevel: "none"

    files: ["mainloop.c",
        "process_definition.h", "../include/epoll_wrapper.h",
        "manager_io_thread.c", "manager_io_thread.h", "../include/com_protocol.h",
        "manager_shared_variables.h", "manager_logic_thread.h", "manager_logic_thread.c",
        "../include/trusted_app_properties.h", "../core/main.c"
    ]
}
