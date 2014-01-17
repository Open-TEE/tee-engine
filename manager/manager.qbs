import qbs

DynamicLibrary {
    name: "ManagerApi"
    Depends { name: "cpp" }
    Depends { name: "CommonApi" }

    cpp.includePaths: ["../include"]

    files: ["../include/subprocess.h", "mainloop.c", "context_child.c", "context_child.h",
            "process_definition.h", "epoll_wrapper.c", "epoll_wrapper.h",
            "process_manager.c", "process_manager.h"
    ]
}
