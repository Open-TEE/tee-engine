import qbs

DynamicLibrary {
    name: "LauncherApi"
    Group {
        name: "project-install"
        fileTagsFilter: "dynamiclibrary"
        qbs.install: false
        qbs.installDir: "lib"
    }

    Depends { name: "cpp" }
    Depends { name: "CommonApi" }
    Depends { name: "InternalApi" }

    Export {
        Depends { name: "cpp" }
        cpp.includePaths: ["../include"]
    }

    destinationDirectory: '.'

    cpp.dynamicLibraries: ["dl", "pthread", "rt"]

    cpp.includePaths: [
        "../core",
        "../include",
    ]

    cpp.defines: ["OT_LOGGING"]

    files: [
        "../include/core_control_resources.h",
        "../include/ta_exit_states.h",
        "../internal_api/callbacks.h",
        "dynamic_loader.h",
        "dynamic_loader.c",
        "launcher_mainloop.c",
        "ta_ctl_resources.h",
        "ta_internal_thread.h",
        "ta_internal_thread.c",
        "ta_io_thread.h",
        "ta_io_thread.c",
        "ta_process.h",
        "ta_process.c",
        "ta_signal_handler.h",
        "ta_signal_handler.c",
    ]
}
