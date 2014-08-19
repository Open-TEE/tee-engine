import qbs

CppApplication {
    name: "crypto_test"
    type: "application"

    destinationDirectory: '.'

    cpp.debugInformation: true
    Depends { name: "InternalApi" }
    Depends { name: "OpenSSL" }

    files: ["crypto_test.c"]
}
