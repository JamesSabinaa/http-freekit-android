# Project-authored research build configuration; upstream source is unchanged.
APP_OPTIM := release
APP_PLATFORM := android-26
APP_ABI := arm64-v8a x86_64
APP_CFLAGS := -O3 -DPKGNAME=com/httpfreekit/engineprobe -DCLSNAME=NativeEngine
APP_SUPPORT_FLEXIBLE_PAGE_SIZES := true
NDK_TOOLCHAIN_VERSION := clang
