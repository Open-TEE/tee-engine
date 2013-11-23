import qbs

CppApplication {
    type: "application"
    Depends { name: "internal" }

    files: ["main.c", "context_child.c", "context_child.h"
    ]
}
