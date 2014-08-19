import qbs

CppApplication {
    name: "storage_test"
    type: "application"

    Depends { name: "InternalApi" }
    Depends { name: "OpenSSL" }

    destinationDirectory: '.'

    files: ["storage_test.c"]
}
