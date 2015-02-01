import qbs

Project {
    name: "emulator"
    references: [
        "internal_api/internal.qbs",
        "opentee-main/opentee.qbs",
        "common/common.qbs",
        "manager/manager.qbs",
        "launcher/launcher.qbs",
    ]
}
