import qbs

CppApplication {
    name: "crypto_test"
    type: "application"

    cpp.debugInformation: true
    Depends { name: "InternalApi" }

    files: ["crypto_test.c"]
}
