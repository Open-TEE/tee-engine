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
        //"seccomp",
        "z"
    ]

    cpp.includePaths: [
        "../include"
    ]

    cpp.defines: [
        "OT_LOGGING",
        //"HAVE_SECCOMP"
    ]

    files: [
        "../include/com_protocol.h",
        "../include/elf_read.h",
        "../include/epoll_wrapper.h",
        "../include/socket_help.h",
        "../include/tee_list.h",
        "../include/tee_logging.h",
        "../include/tee_seccomp.h",
        "com_protocol.c",
        "elf_read.c",
        "epoll_wrapper.c",
        "socket_help.c",
        "tee_list.c",
        "tee_seccomp.c"
    ]
}
