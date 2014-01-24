import qbs

CppApplication {
    name: "storage_test"
    type: "application"

    Depends { name: "InternalApi" }

    cpp.dynamicLibraries: ["ssl", "crypto"]

    files: ["storage_test.c"]
}
