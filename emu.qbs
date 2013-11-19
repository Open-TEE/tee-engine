import qbs

CppApplication {
    type: "application"
    files: ["core/main.c", "core/context_child.c", "core/context_child.h",
        "core/session_child.c", "core/session_child.h", "include/tee_internal_api.h"
    ]
}
