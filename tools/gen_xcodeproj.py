#!/usr/bin/env python3
"""
tools/gen_xcodeproj.py — Sinh file ios/JVHD.xcodeproj/project.pbxproj.

Lý do có script này: dự án được tạo/kiểm tra trên Linux (CI), không bấm nút
"New Project" trong Xcode được. Script sinh ra file .pbxproj chuẩn (objectVersion
56, tương thích Xcode 14/15/16) với UUID cố định để mỗi lần chạy cho cùng kết
quả -> diff trên git luôn sạch.

Cách dùng:  python3 tools/gen_xcodeproj.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PROJECT_DIR = os.path.join(ROOT, "ios", "JVHD.xcodeproj")

SOURCE_FILES = [
    "AppDelegate.swift",
    "LaunchViewController.swift",
    "MainViewController.swift",
    "NativePlayer.swift",
    "LocalServer.swift",
    "HTTPRequest.swift",
    "MediaProxy.swift",
    "DeviceKey.swift",
    "Crypto.swift",
    "Config.swift",
]

RESOURCE_FILES = ["Assets.xcassets"]
FOLDER_REFERENCES = [("www", "../www")]

BUNDLE_ID = "vn.jvhd.ios"
DEPLOYMENT_TARGET = "16.0"
MARKETING_VERSION = "1.0"
PROJECT_VERSION = "1"


def uid(index):
    """UUID 24 ký tự hex, cố định theo chỉ số."""
    return "1A2B3C4E%016X" % index


class Builder:
    def __init__(self):
        self.counter = 0
        self.lines = []

    def new_id(self):
        self.counter += 1
        return uid(self.counter)

    def add(self, text):
        self.lines.append(text)


def build():
    b = Builder()

    project_id = b.new_id()
    main_group = b.new_id()
    products_group = b.new_id()
    jvhd_group = b.new_id()
    target_id = b.new_id()
    product_ref = b.new_id()
    sources_phase = b.new_id()
    resources_phase = b.new_id()
    frameworks_phase = b.new_id()
    project_config_list = b.new_id()
    project_debug = b.new_id()
    project_release = b.new_id()
    target_config_list = b.new_id()
    target_debug = b.new_id()
    target_release = b.new_id()

    info_plist_ref = b.new_id()

    # fileRef + buildFile cho từng file nguồn
    sources = []
    for name in SOURCE_FILES:
        file_ref = b.new_id()
        build_file = b.new_id()
        sources.append((name, file_ref, build_file))

    resources = []
    for name in RESOURCE_FILES:
        file_ref = b.new_id()
        build_file = b.new_id()
        resources.append((name, file_ref, build_file))

    folders = []
    for name, path in FOLDER_REFERENCES:
        file_ref = b.new_id()
        build_file = b.new_id()
        folders.append((name, path, file_ref, build_file))

    b.add("// !$*UTF8*$!")
    b.add("{")
    b.add("\tarchiveVersion = 1;")
    b.add("\tclasses = {")
    b.add("\t};")
    b.add("\tobjectVersion = 56;")
    b.add("\tobjects = {")
    b.add("")

    # ---------------- PBXBuildFile ----------------
    b.add("/* Begin PBXBuildFile section */")
    for name, _ref, build_file in sources:
        b.add("\t\t%s /* %s in Sources */ = {isa = PBXBuildFile; fileRef = %s /* %s */; };"
              % (build_file, name, _ref, name))
    for name, _ref, build_file in resources:
        b.add("\t\t%s /* %s in Resources */ = {isa = PBXBuildFile; fileRef = %s /* %s */; };"
              % (build_file, name, _ref, name))
    for name, _path, _ref, build_file in folders:
        b.add("\t\t%s /* %s in Resources */ = {isa = PBXBuildFile; fileRef = %s /* %s */; };"
              % (build_file, name, _ref, name))
    b.add("/* End PBXBuildFile section */")
    b.add("")

    # ---------------- PBXFileReference ----------------
    b.add("/* Begin PBXFileReference section */")
    b.add("\t\t%s /* JVHD.app */ = {isa = PBXFileReference; explicitFileType = wrapper.application; "
          "includeInIndex = 0; path = JVHD.app; sourceTree = BUILT_PRODUCTS_DIR; };" % product_ref)
    b.add("\t\t%s /* Info.plist */ = {isa = PBXFileReference; lastKnownFileType = text.plist.xml; "
          "name = Info.plist; path = JVHD/Info.plist; sourceTree = \"<group>\"; };" % info_plist_ref)
    for name, file_ref, _build in sources:
        b.add("\t\t%s /* %s */ = {isa = PBXFileReference; lastKnownFileType = sourcecode.swift; "
              "name = %s; path = JVHD/%s; sourceTree = \"<group>\"; };" % (file_ref, name, name, name))
    for name, file_ref, _build in resources:
        b.add("\t\t%s /* %s */ = {isa = PBXFileReference; lastKnownFileType = folder.assetcatalog; "
              "name = %s; path = JVHD/%s; sourceTree = \"<group>\"; };" % (file_ref, name, name, name))
    for name, path, file_ref, _build in folders:
        b.add("\t\t%s /* %s */ = {isa = PBXFileReference; lastKnownFileType = folder; "
              "name = %s; path = %s; sourceTree = \"<group>\"; };" % (file_ref, name, name, path))
    b.add("/* End PBXFileReference section */")
    b.add("")

    # ---------------- PBXFrameworksBuildPhase ----------------
    b.add("/* Begin PBXFrameworksBuildPhase section */")
    b.add("\t\t%s /* Frameworks */ = {" % frameworks_phase)
    b.add("\t\t\tisa = PBXFrameworksBuildPhase;")
    b.add("\t\t\tbuildActionMask = 2147483647;")
    b.add("\t\t\tfiles = (")
    b.add("\t\t\t);")
    b.add("\t\t\trunOnlyForDeploymentPostprocessing = 0;")
    b.add("\t\t};")
    b.add("/* End PBXFrameworksBuildPhase section */")
    b.add("")

    # ---------------- PBXGroup ----------------
    b.add("/* Begin PBXGroup section */")
    b.add("\t\t%s = {" % main_group)
    b.add("\t\t\tisa = PBXGroup;")
    b.add("\t\t\tchildren = (")
    b.add("\t\t\t\t%s /* Info.plist */," % info_plist_ref)
    for name, path, file_ref, _build in folders:
        b.add("\t\t\t\t%s /* %s */," % (file_ref, name))
    b.add("\t\t\t\t%s /* JVHD */," % jvhd_group)
    b.add("\t\t\t\t%s /* Products */," % products_group)
    b.add("\t\t\t);")
    b.add("\t\t\tsourceTree = \"<group>\";")
    b.add("\t\t};")
    b.add("\t\t%s /* JVHD */ = {" % jvhd_group)
    b.add("\t\t\tisa = PBXGroup;")
    b.add("\t\t\tchildren = (")
    for name, file_ref, _build in sources:
        b.add("\t\t\t\t%s /* %s */," % (file_ref, name))
    for name, file_ref, _build in resources:
        b.add("\t\t\t\t%s /* %s */," % (file_ref, name))
    b.add("\t\t\t);")
    b.add("\t\t\tname = JVHD;")
    b.add("\t\t\tpath = JVHD;")
    b.add("\t\t\tsourceTree = \"<group>\";")
    b.add("\t\t};")
    b.add("\t\t%s /* Products */ = {" % products_group)
    b.add("\t\t\tisa = PBXGroup;")
    b.add("\t\t\tchildren = (")
    b.add("\t\t\t\t%s /* JVHD.app */," % product_ref)
    b.add("\t\t\t);")
    b.add("\t\t\tname = Products;")
    b.add("\t\t\tsourceTree = \"<group>\";")
    b.add("\t\t};")
    b.add("/* End PBXGroup section */")
    b.add("")

    # ---------------- PBXNativeTarget ----------------
    b.add("/* Begin PBXNativeTarget section */")
    b.add("\t\t%s /* JVHD */ = {" % target_id)
    b.add("\t\t\tisa = PBXNativeTarget;")
    b.add("\t\t\tbuildConfigurationList = %s /* Build configuration list for PBXNativeTarget \"JVHD\" */;" % target_config_list)
    b.add("\t\t\tbuildPhases = (")
    b.add("\t\t\t\t%s /* Sources */," % sources_phase)
    b.add("\t\t\t\t%s /* Frameworks */," % frameworks_phase)
    b.add("\t\t\t\t%s /* Resources */," % resources_phase)
    b.add("\t\t\t);")
    b.add("\t\t\tbuildRules = (")
    b.add("\t\t\t);")
    b.add("\t\t\tdependencies = (")
    b.add("\t\t\t);")
    b.add("\t\t\tname = JVHD;")
    b.add("\t\t\tproductName = JVHD;")
    b.add("\t\t\tproductReference = %s /* JVHD.app */;" % product_ref)
    b.add("\t\t\tproductType = \"com.apple.product-type.application\";")
    b.add("\t\t};")
    b.add("/* End PBXNativeTarget section */")
    b.add("")

    # ---------------- PBXProject ----------------
    b.add("/* Begin PBXProject section */")
    b.add("\t\t%s /* Project object */ = {" % project_id)
    b.add("\t\t\tisa = PBXProject;")
    b.add("\t\t\tattributes = {")
    b.add("\t\t\t\tBuildIndependentTargetsInParallel = 1;")
    b.add("\t\t\t\tLastSwiftUpdateCheck = 1500;")
    b.add("\t\t\t\tLastUpgradeCheck = 1500;")
    b.add("\t\t\t\tTargetAttributes = {")
    b.add("\t\t\t\t\t%s = {" % target_id)
    b.add("\t\t\t\t\t\tCreatedOnToolsVersion = 15.0;")
    b.add("\t\t\t\t\t};")
    b.add("\t\t\t\t};")
    b.add("\t\t\t};")
    b.add("\t\t\tbuildConfigurationList = %s /* Build configuration list for PBXProject \"JVHD\" */;" % project_config_list)
    b.add("\t\t\tcompatibilityVersion = \"Xcode 14.0\";")
    b.add("\t\tdevelopmentRegion = vi;")
    b.add("\t\thasScannedForEncodings = 0;")
    b.add("\t\tknownRegions = (")
    b.add("\t\t\ten,")
    b.add("\t\t\tBase,")
    b.add("\t\t\tvi,")
    b.add("\t\t);")
    b.add("\t\tmainGroup = %s;" % main_group)
    b.add("\t\tproductRefGroup = %s /* Products */;" % products_group)
    b.add("\t\tprojectDirPath = \"\";")
    b.add("\t\tprojectRoot = \"\";")
    b.add("\t\ttargets = (")
    b.add("\t\t\t%s /* JVHD */," % target_id)
    b.add("\t\t);")
    b.add("\t\t};")
    b.add("/* End PBXProject section */")
    b.add("")

    # ---------------- PBXResourcesBuildPhase ----------------
    b.add("/* Begin PBXResourcesBuildPhase section */")
    b.add("\t\t%s /* Resources */ = {" % resources_phase)
    b.add("\t\t\tisa = PBXResourcesBuildPhase;")
    b.add("\t\t\tbuildActionMask = 2147483647;")
    b.add("\t\t\tfiles = (")
    for name, _path, _ref, build_file in folders:
        b.add("\t\t\t\t%s /* %s in Resources */," % (build_file, name))
    for name, _ref, build_file in resources:
        b.add("\t\t\t\t%s /* %s in Resources */," % (build_file, name))
    b.add("\t\t\t);")
    b.add("\t\t\trunOnlyForDeploymentPostprocessing = 0;")
    b.add("\t\t};")
    b.add("/* End PBXResourcesBuildPhase section */")
    b.add("")

    # ---------------- PBXSourcesBuildPhase ----------------
    b.add("/* Begin PBXSourcesBuildPhase section */")
    b.add("\t\t%s /* Sources */ = {" % sources_phase)
    b.add("\t\t\tisa = PBXSourcesBuildPhase;")
    b.add("\t\t\tbuildActionMask = 2147483647;")
    b.add("\t\t\tfiles = (")
    for name, _ref, build_file in sources:
        b.add("\t\t\t\t%s /* %s in Sources */," % (build_file, name))
    b.add("\t\t\t);")
    b.add("\t\t\trunOnlyForDeploymentPostprocessing = 0;")
    b.add("\t\t};")
    b.add("/* End PBXSourcesBuildPhase section */")
    b.add("")

    # ---------------- XCBuildConfiguration ----------------
    common_project = [
        ("ALWAYS_SEARCH_USER_PATHS", "NO"),
        ("CLANG_ANALYZER_NONNULL", "YES"),
        ("CLANG_ENABLE_MODULES", "YES"),
        ("CLANG_ENABLE_OBJC_ARC", "YES"),
        ("CLANG_WARN_DOCUMENTATION_COMMENTS", "YES"),
        ("CLANG_WARN_UNGUARDED_AVAILABILITY", "YES_AGGRESSIVE"),
        ("COPY_PHASE_STRIP", "NO"),
        ("ENABLE_STRICT_OBJC_MSGSEND", "YES"),
        ("GCC_C_LANGUAGE_STANDARD", "gnu17"),
        ("GCC_NO_COMMON_BLOCKS", "YES"),
        ("GCC_WARN_ABOUT_RETURN_TYPE", "YES_ERROR"),
        ("GCC_WARN_UNDECLARED_SELECTOR", "YES"),
        ("GCC_WARN_UNINITIALIZED_AUTOS", "YES_AGGRESSIVE"),
        ("GCC_WARN_UNUSED_FUNCTION", "YES"),
        ("GCC_WARN_UNUSED_VARIABLE", "YES"),
        ("IPHONEOS_DEPLOYMENT_TARGET", DEPLOYMENT_TARGET),
        ("SDKROOT", "iphoneos"),
        ("SWIFT_VERSION", "5.0"),
    ]
    debug_project = common_project + [
        ("DEBUG_INFORMATION_FORMAT", "dwarf"),
        ("ENABLE_TESTABILITY", "YES"),
        ("GCC_DYNAMIC_NO_PIC", "NO"),
        ("GCC_OPTIMIZATION_LEVEL", "0"),
        ("GCC_PREPROCESSOR_DEFINITIONS", "(\n\t\t\t\t\t\"DEBUG=1\",\n\t\t\t\t\t\"$(inherited)\",\n\t\t\t\t)"),
        ("MTL_ENABLE_DEBUG_INFO", "INCLUDE_SOURCE"),
        ("ONLY_ACTIVE_ARCH", "YES"),
        ("SWIFT_ACTIVE_COMPILATION_CONDITIONS", "DEBUG"),
        ("SWIFT_OPTIMIZATION_LEVEL", "\"-Onone\""),
    ]
    release_project = common_project + [
        ("DEBUG_INFORMATION_FORMAT", "\"dwarf-with-dsym\""),
        ("ENABLE_NS_ASSERTIONS", "NO"),
        ("MTL_ENABLE_DEBUG_INFO", "NO"),
        ("SWIFT_COMPILATION_MODE", "wholemodule"),
        ("SWIFT_OPTIMIZATION_LEVEL", "\"-O\""),
        ("VALIDATE_PRODUCT", "YES"),
    ]

    common_target = [
        ("ASSETCATALOG_COMPILER_APPICON_NAME", "AppIcon"),
        ("ASSETCATALOG_COMPILER_GLOBAL_ACCENT_COLOR_NAME", "AccentColor"),
        ("CODE_SIGN_STYLE", "Automatic"),
        ("CURRENT_PROJECT_VERSION", PROJECT_VERSION),
        ("GENERATE_INFOPLIST_FILE", "NO"),
        ("INFOPLIST_FILE", "JVHD/Info.plist"),
        ("IPHONEOS_DEPLOYMENT_TARGET", DEPLOYMENT_TARGET),
        ("LD_RUNPATH_SEARCH_PATHS", "(\n\t\t\t\t\t\"@executable_path/Frameworks\",\n\t\t\t\t\t\"$(inherited)\",\n\t\t\t\t)"),
        ("MARKETING_VERSION", MARKETING_VERSION),
        ("PRODUCT_BUNDLE_IDENTIFIER", BUNDLE_ID),
        ("PRODUCT_NAME", "JVHD"),
        ("SKIP_INSTALL", "NO"),
        ("SWIFT_EMIT_LOC_STRINGS", "YES"),
        ("SWIFT_STRICT_CONCURRENCY", "minimal"),
        ("TARGETED_DEVICE_FAMILY", "\"1,2\""),
    ]

    b.add("/* Begin XCBuildConfiguration section */")
    for config_id, name, settings in [
        (project_debug, "Debug", debug_project),
        (project_release, "Release", release_project),
        (target_debug, "Debug", common_target),
        (target_release, "Release", common_target),
    ]:
        b.add("\t\t%s /* %s */ = {" % (config_id, name))
        b.add("\t\t\tisa = XCBuildConfiguration;")
        b.add("\t\t\tbuildSettings = {")
        for key, value in settings:
            b.add("\t\t\t\t%s = %s;" % (key, value))
        b.add("\t\t\t};")
        b.add("\t\t\tname = %s;" % name)
        b.add("\t\t};")
    b.add("/* End XCBuildConfiguration section */")
    b.add("")

    # ---------------- XCConfigurationList ----------------
    b.add("/* Begin XCConfigurationList section */")
    b.add("\t\t%s /* Build configuration list for PBXProject \"JVHD\" */ = {" % project_config_list)
    b.add("\t\t\tisa = XCConfigurationList;")
    b.add("\t\t\tbuildConfigurations = (")
    b.add("\t\t\t\t%s /* Debug */," % project_debug)
    b.add("\t\t\t\t%s /* Release */," % project_release)
    b.add("\t\t\t);")
    b.add("\t\t\tdefaultConfigurationIsVisible = 0;")
    b.add("\t\t\tdefaultConfigurationName = Release;")
    b.add("\t\t};")
    b.add("\t\t%s /* Build configuration list for PBXNativeTarget \"JVHD\" */ = {" % target_config_list)
    b.add("\t\t\tisa = XCConfigurationList;")
    b.add("\t\t\tbuildConfigurations = (")
    b.add("\t\t\t\t%s /* Debug */," % target_debug)
    b.add("\t\t\t\t%s /* Release */," % target_release)
    b.add("\t\t\t);")
    b.add("\t\t\tdefaultConfigurationIsVisible = 0;")
    b.add("\t\t\tdefaultConfigurationName = Release;")
    b.add("\t\t};")
    b.add("/* End XCConfigurationList section */")
    b.add("\t};")
    b.add("\trootObject = %s /* Project object */;" % project_id)
    b.add("}")

    return "\n".join(b.lines) + "\n"


def main():
    content = build()
    os.makedirs(PROJECT_DIR, exist_ok=True)
    target = os.path.join(PROJECT_DIR, "project.pbxproj")
    with open(target, "w", encoding="utf-8") as handle:
        handle.write(content)
    print("Đã sinh %s (%d dòng)" % (target, content.count("\n")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
