cmake_minimum_required(VERSION 3.22.1)
project(haseeb_vm LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(HASEEB_BUILD_HOST_TESTS "Build host unit and integration tests" OFF)
option(HASEEB_BUILD_GUEST_TEST "Build standalone VM integration test binary" OFF)

add_library(
    haseeb_vm_core
    STATIC
    src/boot_image.cpp
    src/fdt_builder.cpp
    src/guest_ram.cpp
    src/pl011_uart.cpp
    src/mmu_tlb.cpp
    src/dbt_cache.cpp
    src/cpu_sysregs.cpp
    src/cpu_neon.cpp
    src/cpu_mem_atomics.cpp
    src/cpu_core.cpp
    src/machine.cpp
    src/ext4_reader.cpp
    src/elf64_loader.cpp
    src/prop_area.cpp
    src/property_service.cpp
    src/pl031_rtc.cpp
    src/sp805_wdt.cpp
    src/gicv3.cpp
    src/psci.cpp
    src/virtio_mmio.cpp
    src/virtio_devices.cpp
    src/virtio_gpu.cpp
    src/virtio_input.cpp
    src/virtio_snd_net.cpp
    src/phone_hardware.cpp
    src/magisk_patcher.cpp
    src/soft_gles.cpp
    src/guest_vfs_bridge.cpp
    src/compression.cpp
    src/cpio_reader.cpp
    src/kernel_boot.cpp
    src/engine_rom_builder.cpp
)

target_include_directories(
    haseeb_vm_core
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_options(
    haseeb_vm_core
    PRIVATE
    -Wall
    -Wextra
    -Werror=return-type
    -O2
)

find_package(Threads REQUIRED)
target_link_libraries(haseeb_vm_core PUBLIC Threads::Threads)

if(ANDROID)
    add_library(
        haseeb_vm
        SHARED
        haseeb_vm_jni.cpp
        src/engine_runtime.cpp
    )

    target_include_directories(
        haseeb_vm
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )

    target_compile_options(
        haseeb_vm
        PRIVATE
        -Wall
        -Wextra
        -Werror=return-type
        -O2
    )

    # Android 15+ 16 KiB ELF segment page alignment
    target_link_options(
        haseeb_vm
        PRIVATE
        -Wl,-z,max-page-size=16384
    )

    find_library(log-lib log)
    find_library(android-lib android)

    target_link_libraries(
        haseeb_vm
        PRIVATE
        haseeb_vm_core
        ${android-lib}
        ${log-lib}
    )
endif()

if(HASEEB_BUILD_HOST_TESTS OR HASEEB_BUILD_GUEST_TEST)
    enable_testing()

    set(HASEEB_TEST_TARGETS
        haseeb_m1_vm_tests:tests/m1_boot_machine_test.cpp
        haseeb_m1_property_tests:tests/m1_property_area_test.cpp
        haseeb_guest_prop_integration_tests:tests/guest_prop_integration_test.cpp
        haseeb_m2_cpu_mmu_tests:tests/m2_cpu_mmu_test.cpp
        haseeb_m3_devices_tests:tests/m3_devices_test.cpp
        haseeb_m4_kernel_init_tests:tests/m4_kernel_init_test.cpp
        haseeb_m5_display_gpu_tests:tests/m5_display_gpu_test.cpp
        haseeb_m6_input_tests:tests/m6_input_test.cpp
        haseeb_m7_magisk_phone_tests:tests/m7_magisk_phone_test.cpp
        haseeb_m8_softgles_snd_net_tests:tests/m8_softgles_snd_net_test.cpp
        haseeb_m9_engine_rom_framework_tests:tests/m9_engine_rom_framework_test.cpp
    )

    foreach(entry IN LISTS HASEEB_TEST_TARGETS)
        string(REPLACE ":" ";" pair "${entry}")
        list(GET pair 0 tgt_name)
        list(GET pair 1 src_path)
        add_executable(${tgt_name} ${src_path})
        target_include_directories(${tgt_name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
        target_compile_options(${tgt_name} PRIVATE -Wall -Wextra -O2)
        target_link_libraries(${tgt_name} PRIVATE haseeb_vm_core)
        if(ANDROID)
            target_link_options(${tgt_name} PRIVATE -Wl,-z,max-page-size=16384)
        endif()
        add_test(NAME ${tgt_name} COMMAND ${tgt_name})
    endforeach()
endif()
