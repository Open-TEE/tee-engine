import qbs

CppApplication {
    name: "storage_test"
    type: "application"

    Depends { name: "InternalApi" }
    Depends { name: "OpenSSL" }

    files: ["storage_test.c"]
}
