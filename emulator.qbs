import qbs

Project {
    name: "emulator"	
    references: [
        "core/core.qbs",
        "internal_api/internal.qbs",
        "TAs/TrustedApplications.qbs"
    ]
}
