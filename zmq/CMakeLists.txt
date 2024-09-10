cmake_minimum_required(VERSION 3.10)
project(ZMQExample)

# Найти библиотеку libzmq
find_library(LIBZMQ_LIBRARY zmq)
find_path(LIBZMQ_INCLUDE_DIR zmq.h)

# Проверка, что библиотека найдена
if (NOT LIBZMQ_LIBRARY OR NOT LIBZMQ_INCLUDE_DIR)
    message(FATAL_ERROR "libzmq not found")
endif()

# Добавить пути к заголовочным файлам и библиотекам
include_directories(${LIBZMQ_INCLUDE_DIR})

# Добавить исходные файлы из папки tests
set(SERVER_SOURCES tests/server.c)
set(CLIENT_SOURCES tests/client.c)

# Добавить исполняемые файлы
add_executable(server ${SERVER_SOURCES})
add_executable(client ${CLIENT_SOURCES})

# Линковка с библиотекой libzmq
target_link_libraries(server ${LIBZMQ_LIBRARY})
target_link_libraries(client ${LIBZMQ_LIBRARY})
