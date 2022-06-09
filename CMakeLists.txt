cmake_minimum_required(VERSION 3.5)

project(ubd_library C)

set(CMAKE_C_FLAGS "-g -D_GNU_SOURCE -DDEBUG -MMD -fPIC -Wall")

############################################################
# Create a library
############################################################

find_library(PTHREAD pthread)

#Generate the shared library from the library sources
add_library(ubd_library SHARED 
    libubd.c
)
add_library(ubd::library ALIAS ubd_library)

target_include_directories(ubd_library
    PRIVATE 
        ${PROJECT_SOURCE_DIR}/include
    PRIVATE 
    ${PROJECT_SOURCE_DIR}/include/ccan
)

############################################################
# Create an executable
############################################################

# Add an executable with the above sources
add_executable(ubd_aio_test_binary
    ubd_aio_test.c
    ubd_aio.c
)

# link the new ubd_library target with the ubd_runner_binary target
target_link_libraries(ubd_aio_test_binary
    PRIVATE 
    ${PTHREAD}
)

target_include_directories(ubd_aio_test_binary
    PRIVATE 
        ${PROJECT_SOURCE_DIR}/include
    PRIVATE 
    ${PROJECT_SOURCE_DIR}/include/ccan
)


############################################################
# Create an executable
############################################################

# Add an executable with the above sources
add_executable(ubd_test_binary
    ubd_test.c
)

# link the new ubd_library target with the ubd_runner_binary target
target_link_libraries(ubd_test_binary
    PRIVATE 
    ubd::library
    ${PTHREAD}
)

target_include_directories(ubd_test_binary
    PRIVATE 
        ${PROJECT_SOURCE_DIR}/include
    PRIVATE 
    ${PROJECT_SOURCE_DIR}/include/ccan
)


############################################################
# Create an executable
############################################################

# Add an executable with the above sources
add_executable(ubd_noob_binary
    ubd_noob.c
)

# link the new ubd_library target with the ubd_runner_binary target
target_link_libraries(ubd_noob_binary
    PRIVATE 
    ubd::library
    ${PTHREAD}
)

target_include_directories(ubd_noob_binary
    PRIVATE 
        ${PROJECT_SOURCE_DIR}/include
    PRIVATE 
    ${PROJECT_SOURCE_DIR}/include/ccan
)

############################################################
# Create an executable
############################################################

# Add an executable with the above sources
add_executable(ubd_runner_binary
    ubd_aio.c
    ubd_runner.c
)

# link the new ubd_library target with the ubd_runner_binary target
target_link_libraries(ubd_runner_binary
    PRIVATE 
    ubd::library
    ${PTHREAD}
)

target_include_directories(ubd_runner_binary
    PRIVATE 
        ${PROJECT_SOURCE_DIR}/include
    PRIVATE 
    ${PROJECT_SOURCE_DIR}/include/ccan
)

