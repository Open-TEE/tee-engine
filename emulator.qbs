import qbs

Project {
    name: "emulator"
    references: [
        "core/core.qbs",
        "common/common.qbs",
        "manager/manager.qbs",
        "launcher/launcher.qbs",
        "internal_api/internal.qbs",
        "TAs/TrustedApplications.qbs",
    ]
}
