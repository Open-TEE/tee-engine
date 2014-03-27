import qbs

CppApplication {
    name: "crypto_test"
    type: "application"

    cpp.libraryPaths: ["/home/dettenbo/project-build/qtc_Desktop-release/"]
    cpp.dynamicLibraries: ["InternalApi", "ssl", "crypto" ]

    files: ["crypto_test.c"]
}
