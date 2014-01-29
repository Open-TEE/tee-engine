import qbs
import qbs.Probes

DynamicLibrary {
    name: "InternalApi"
    Depends { name: "cpp" }

    Export {
        Depends { name: "cpp" }
        cpp.includePaths: ["../include", "."]
    }

    Probes.PkgConfigProbe {
	id: opensslConfig
	name: "openssl"
    }

    files: ["../include/tee_internal_api.h", "data_types.h", "tee_ta_interface.h",
        "tee_memory.h", "tee_memory.c", "time_api.h", "time_api.c"
    ]

    cpp.cxxFlags: opensslConfig.cflags
    cpp.linkerFlags: opensslConfig.libs
}
