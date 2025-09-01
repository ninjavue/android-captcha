cmake_minimum_required(VERSION 3.22.1)
project("captcha")


set(CMAKE_SYSTEM_NAME Android)
set(CMAKE_SYSTEM_VERSION 24)
set(ANDROID_NDK "/home/ubuntu/Android/Sdk/ndk/27.0.12077973")

set(OpenCV_DIR "D:/OpenCV-android-sdk/sdk/native/jni")

find_package(OpenCV REQUIRED)


add_library(${CMAKE_PROJECT_NAME} SHARED
        native/main.cpp
)


add_library(curl STATIC IMPORTED)
add_library(ssl STATIC IMPORTED)
add_library(crypto STATIC IMPORTED)
add_library(libz STATIC IMPORTED)

set(CURL_LIB_DIR "${CMAKE_SOURCE_DIR}/jniLibs/${CMAKE_ANDROID_ARCH_ABI}")


#set_target_properties(curl PROPERTIES IMPORTED_LOCATION "${CURL_LIB_DIR}/libcurl.a")
set_target_properties(ssl PROPERTIES IMPORTED_LOCATION "${CURL_LIB_DIR}/libssl.a")
set_target_properties(crypto PROPERTIES IMPORTED_LOCATION "${CURL_LIB_DIR}/libcrypto.a")
#set_target_properties(libz PROPERTIES IMPORTED_LOCATION "${CURL_LIB_DIR}/libz.a")


target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include
        ${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include/android
        ${OpenCV_INCLUDE_DIRS}
)


target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE -fexceptions -frtti)


target_link_libraries(${CMAKE_PROJECT_NAME}
#        curl
        ssl
        crypto
#        libz
        log
        android
        ${OpenCV_LIBS}
)
