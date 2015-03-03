import qbs

DynamicLibrary {
    name: "CommonApi"
    Group {
        name: "project-install"
        fileTagsFilter: "dynamiclibrary"
        qbs.install: false
        qbs.installDir: "lib"
    }

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

    cpp.defines: ["OT_LOGGING"]

    files: [
        "../include/com_protocol.h",
        "../include/elf_read.h",
        "../include/epoll_wrapper.h",
        "../include/tee_list.h",
        "../include/tee_logging.h",
        "com_protocol.c",
        "elf_read.c",
        "epoll_wrapper.c",
        "tee_list.c",
    ]
}
