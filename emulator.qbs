import qbs

Project {
    name: "emulator"
    references: [
        "internal_api/internal.qbs",
        "core/core.qbs",
        "common/common.qbs",
        "manager/manager.qbs",
        "launcher/launcher.qbs",
        "TAs/TrustedApplications.qbs",
        "tests/storage_test.qbs",
    ]
}
