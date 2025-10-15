project(boot-it C CXX)

cmake_minimum_required(VERSION 3.15)

include(GNUInstallDirs)

add_executable(
    boot-it
    
    src/boot-it.cc
    src/bootpd.cc
    src/tftpd.cc
)

install(TARGETS boot-it)