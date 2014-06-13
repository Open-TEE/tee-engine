import qbs

DynamicLibrary {
    name: "ManagerApi"
    Depends { name: "cpp" }
    Depends { name: "CommonApi" }

    cpp.includePaths: ["../include", "../internal_api"]
	cpp.dynamicLibraries: ["elf"]

    files: ["mainloop.c",
            "process_definition.h", "epoll_wrapper.c", "epoll_wrapper.h",
            "process_manager.c", "process_manager.h", "elf_reader.c", "elf_reader.h"
    ]
}
