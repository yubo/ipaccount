cmake_minimum_required(VERSION 2.6)

ADD_DEFINITIONS(-g -O2  -Wall)

IF (NOT DEFINED LIBNL_LIBS)
  FIND_LIBRARY(libnl NAMES libnl-3 libnl nl-3 nl)
  SET(LIBNL_LIBS ${libnl})
ENDIF()

SET(LIBS ${LIBS} ${LIBNL_LIBS})

ADD_DEFINITIONS(-D_GNU_SOURCE)

# Build of the program
ADD_LIBRARY(account SHARED libipaccount.c )
TARGET_LINK_LIBRARIES(account  ${LIBS})
ADD_EXECUTABLE(ipaccount ipaccount.c)
TARGET_LINK_LIBRARIES(ipaccount account ${LIBS})


# Build the module
IF (NOT  DEFINED KERNEL_DIR)
EXECUTE_PROCESS(COMMAND uname -r
                OUTPUT_VARIABLE os_release
                OUTPUT_STRIP_TRAILING_WHITESPACE)
SET(module_path /lib/modules/${os_release})
SET(KERNEL_DIR ${module_path}/build)
ENDIF()

ADD_CUSTOM_COMMAND(OUTPUT ip_account.ko
                   COMMAND make -C ${KERNEL_DIR} M=`pwd`
                   DEPENDS ip_account.c
                   COMMENT "Building ip_account.ko"
                  )

ADD_CUSTOM_TARGET(ip_account ALL DEPENDS ip_account.ko)

# Installation of the module
SET(module_install_path ${module_path}/kernel)
INSTALL(FILES ip_account.ko
        DESTINATION ${module_install_path}
        PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

# Installation of the program
INSTALL(TARGETS ipaccount
        RUNTIME DESTINATION "sbin")

INSTALL(TARGETS account
        DESTINATION "lib")