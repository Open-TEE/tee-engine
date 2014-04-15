import qbs

CppApplication {
    name: "storage_test"
    type: "application"

    Depends { name: "InternalApi" }
    cpp.dynamicLibraries: ["ssl", "crypto", "sqlite3"]

    files: ["storage_test.c"]
}
