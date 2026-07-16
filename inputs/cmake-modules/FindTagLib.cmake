# CMake module for Ubuntu TagLib packages that ship pkg-config but no TagLibConfig.cmake.
find_package(PkgConfig REQUIRED)
pkg_check_modules(TAGLIB REQUIRED IMPORTED_TARGET taglib)
if(NOT TARGET TagLib::tag)
  add_library(TagLib::tag ALIAS PkgConfig::TAGLIB)
endif()
set(TagLib_FOUND TRUE)
