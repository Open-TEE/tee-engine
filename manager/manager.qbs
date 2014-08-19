import qbs

DynamicLibrary {
    name: "ManagerApi"
    Depends { name: "cpp" }
    Depends { name: "CommonApi" }

    destinationDirectory: '.'

    cpp.includePaths: ["../include"]

    files: ["mainloop.c",
            "process_definition.h", "epoll_wrapper.c", "epoll_wrapper.h",
            "process_manager.c", "process_manager.h"
    ]
}
