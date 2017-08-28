COPTS = [
    "-g",
    "-Wall",
    "-Wextra",
]

cc_binary(
    name = "runtests",
    srcs = [
        "src/nugget_core_tests.cc",
        "src/runtests.cc",
        "src/gtest_with_gflags_main.cc",
    ],
    deps = [
        ":util",
        "@nugget//:driver",
        "@com_github_gflags_gflags//:gflags",
        "@gtest//:gtest",
    ],
)

cc_library(
    name = "util",
    srcs = [
        "src/util.cc",
    ],
    hdrs = [
        "src/util.h",
    ],
    deps = [
        ":control_cc_proto",
        ":testing_api_cc_proto",
        "@ahdlc//:ahdlc",
    ],
)

################################################################################
# proto cc libraries
################################################################################

cc_proto_library(
    name = "control_cc_proto",
    deps = [":control_proto"],
)

cc_proto_library(
    name = "diagnostics_api_cc_proto",
    deps = [":diagnostics_api_proto"],
)

cc_proto_library(
    name = "testing_api_cc_proto",
    deps = [":testing_api_proto"],
)

################################################################################
# proto libraries
################################################################################

proto_library(
    name = "control_proto",
    srcs = ["proto/control.proto"],
    deps = [
        ":header_proto",
    ],
)

proto_library(
    name = "diagnostics_api_proto",
    srcs = ["proto/diagnostics_api.proto"],
    deps = [
        ":gchips_types_proto",
        ":header_proto",
    ],
)

proto_library(
    name = "gchips_types_proto",
    srcs = ["proto/gchips_types.proto"],
)

proto_library(
    name = "header_proto",
    srcs = ["proto/header.proto"],
)

proto_library(
    name = "testing_api_proto",
    srcs = ["proto/testing_api.proto"],
    deps = [
        ":header_proto",
    ],
)
