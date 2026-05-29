
# Минимальная версия CMake, необходимая для сборки проекта.
# Версия 3.16 требуется для корректной поддержки генераторных
# выражений ($<TARGET_FILE_DIR:...>) и find_package с REQUIRED.
cmake_minimum_required(VERSION 3.16)

# Имя проекта и язык программирования
project(messenger CXX)


# Стандарт C++17 обязателен: используются std::thread,
# std::string_view, структурированные привязки и другие
# возможности, появившиеся в C++17.
# REQUIRED означает, что компилятор обязан поддерживать C++17,
# иначе сборка прервётся с ошибкой.

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


# Тип сборки по умолчанию — Release.
# Если при вызове cmake не передан -DCMAKE_BUILD_TYPE=Debug,
# проект соберётся в режиме Release с оптимизацией -O2.
# Debug-сборка отключает оптимизации и добавляет отладочные
# символы для работы с gdb/lldb.

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_CXX_FLAGS_RELEASE "-O2")


# Поиск зависимостей
# REQUIRED означает, что если библиотека не найдена —
# сборка немедленно прерывается с понятным сообщением об ошибке.


# OpenSSL используется в двух местах:
#   1. SHA-1 при WebSocket-рукопожатии (RFC 6455)
#   2. SHA-256 при хэшировании паролей перед сохранением в БД
find_package(OpenSSL REQUIRED)

# Threads подключает поддержку многопоточности.
# На Linux это pthreads, на Windows — нативные потоки.
# Нужен для std::thread, std::mutex в серверном коде.
find_package(Threads REQUIRED)

# SQLite3 не имеет стандартного CMake-модуля, поэтому
# библиотека и заголовочный файл ищутся вручную.
# find_library ищет libsqlite3.so / sqlite3.lib в системных путях.
# find_path ищет директорию, содержащую sqlite3.h.
find_library(SQLITE3_LIB sqlite3 REQUIRED)
find_path(SQLITE3_INCLUDE sqlite3.h REQUIRED)


# Определение исполняемого файла сервера.
# Весь проект собирается в один бинарник: сервер самостоятельно
# принимает соединения, обрабатывает WebSocket и раздаёт
# клиентское веб-приложение по HTTP.

add_executable(server
    server/main.cpp   # единственный .cpp файл — точка входа и вся серверная логика
)


# Пути поиска заголовочных файлов.
# PRIVATE означает, что пути нужны только самому серверу,
# а не другим таргетам (если они появятся).
#   ${OPENSSL_INCLUDE_DIR} — заголовки OpenSSL (openssl/sha.h и др.)
#   ${SQLITE3_INCLUDE}     — заголовок sqlite3.h
#   common                 — директория с logger.h и protocol.h,
#                            общими для всех частей проекта

target_include_directories(server PRIVATE
    ${OPENSSL_INCLUDE_DIR}
    ${SQLITE3_INCLUDE}
    common
)


# Линковка с внешними библиотеками.
#   OpenSSL::SSL    — основная библиотека SSL/TLS
#   OpenSSL::Crypto — криптографические примитивы (SHA-1, SHA-256)
#   ${SQLITE3_LIB}  — встраиваемая СУБД SQLite3
#   Threads::Threads — поддержка std::thread / pthreads

target_link_libraries(server PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    ${SQLITE3_LIB}
    Threads::Threads
)


# Пост-сборочная команда: копирование клиентского приложения.
# Выполняется автоматически после каждой успешной сборки.
#
# Шаг 1: создаёт папку client/ рядом с бинарником сервера.
#         $<TARGET_FILE_DIR:server> — генераторное выражение,
#         раскрывается в реальный путь к собранному бинарнику
#         (например, build/client/).
#
# Шаг 2: копирует index.html из исходников в папку рядом
#         с бинарником. Сервер при старте ищет HTML именно
#         по пути ./client/index.html относительно себя.
#
# Это гарантирует, что после сборки клиент всегда актуален
# и находится там, где сервер ожидает его найти.

add_custom_command(TARGET server POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory
        $<TARGET_FILE_DIR:server>/client
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_SOURCE_DIR}/client/index.html
        $<TARGET_FILE_DIR:server>/client/index.html
    COMMENT "Copying client HTML"
)

# Информационные сообщения при конфигурации проекта.
# Выводятся в терминал при запуске cmake ..
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "OpenSSL: ${OPENSSL_VERSION}")