import qbs

CppApplication {
    type: "application"
    Depends { name: "InternalApi" }

    cpp.dynamicLibraries: ["dl"]

    files: ["main.c", "context_child.c", "context_child.h", "dynamic_loader.h", "dynamic_loader.c",
            "conf_parser.c", "conf_parser.h", "process_definition.h", "tee_list.h", "tee_list.c",
            "io_thread.c", "io_thread.h", "epoll_wrapper.c", "epoll_wrapper.h", "process_manager.c",
            "process_manager.h"
    ]
}
