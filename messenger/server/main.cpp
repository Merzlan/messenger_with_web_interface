// ─────────────────────────────────────────────────────────
//  main.cpp — точка входа сервера мессенджера
//
//  Архитектура:
//    • Один поток принимает TCP-соединения (accept-loop)
//    • Каждый клиент обрабатывается в отдельном std::thread
//    • Все соединения хранятся в g_clients (fd → Client)
//    • Обмен данными — JSON поверх WebSocket (RFC 6455)
//    • Персистентность — SQLite3 через класс Database (db.h)
//
//  Зависимости: OpenSSL (SHA-256, WebSocket-handshake), SQLite3
// ─────────────────────────────────────────────────────────

#include <iostream>
#include <string>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <csignal>
#include <ctime>
#include <cstring>

#include <unistd.h>        // close(), read()
#include <sys/socket.h>    // socket(), bind(), listen(), accept()
#include <netinet/in.h>    // sockaddr_in
#include <arpa/inet.h>     // inet_ntop(), htons()

#include "../common/protocol.h"  // DEFAULT_PORT, MAX_USERNAME_LEN, MAX_PASSWORD_LEN
#include "../common/logger.h"    // Logger
#include "db.h"                  // Database, Message, Group
#include "websocket.h"           // ws_handshake(), ws_recv_frame(), ws_send_frame()
#include "json_helper.h"         // json_get_str(), json_get_int(), namespace json::

// ─────────────────────────────────────────────────────────
//  Глобальное состояние
//
//  g_log     — логгер: пишет в stdout и в файл server.log
//  g_db      — указатель на объект базы данных (инициализируется в main)
//  g_clients — таблица активных WebSocket-соединений: fd → Client
//  g_clients_mtx — мьютекс для g_clients
//
//  ВАЖНО: ws_send_frame() блокируется на send() и никогда не должна
//  вызываться под g_clients_mtx — иначе возможен дедлок (поток держит
//  мьютекс и ждёт сокет, другой поток ждёт мьютекс).
// ─────────────────────────────────────────────────────────

Logger    g_log("server.log");
Database* g_db = nullptr;

// Описание одного подключённого клиента.
// username пустой, пока клиент не прошёл login/register.
struct Client {
    int         fd;        // файловый дескриптор сокета
    std::string username;  // имя пользователя после авторизации (или "")
};

std::mutex                      g_clients_mtx;
std::unordered_map<int, Client> g_clients;

// ─────────────────────────────────────────────────────────
//  Вспомогательные функции
// ─────────────────────────────────────────────────────────

// Возвращает fd авторизованного пользователя или -1, если он офлайн.
static int fd_of_user(const std::string& username) {
    std::lock_guard<std::mutex> lock(g_clients_mtx);
    for (auto& [fd, client] : g_clients)
        if (client.username == username) return fd;
    return -1;
}

// Отправляет JSON-сообщение конкретному пользователю (если онлайн).
static void send_to_user(const std::string& username, const std::string& msg) {
    int fd = fd_of_user(username);
    if (fd != -1) ws_send_frame(fd, msg);
}

// Возвращает список fd всех авторизованных клиентов.
// Снимает копию под мьютексом, чтобы не держать блокировку во время send.
static std::vector<int> all_authed_fds() {
    std::lock_guard<std::mutex> lock(g_clients_mtx);
    std::vector<int> result;
    for (auto& [fd, client] : g_clients)
        if (!client.username.empty()) result.push_back(fd);
    return result;
}

// Возвращает список имён всех авторизованных пользователей (онлайн).
static std::vector<std::string> online_users() {
    std::lock_guard<std::mutex> lock(g_clients_mtx);
    std::vector<std::string> result;
    for (auto& [fd, client] : g_clients)
        if (!client.username.empty()) result.push_back(client.username);
    return result;
}

// Рассылает сообщение всем авторизованным клиентам.
static void broadcast(const std::string& msg) {
    for (int fd : all_authed_fds()) ws_send_frame(fd, msg);
}

// Рассылает всем обновлённый список пользователей (все зарегистрированные
// + пометка онлайн/офлайн). Вызывается при входе/выходе любого пользователя.
static void broadcast_user_list() {
    auto all = g_db->get_all_users();
    broadcast(json::all_users_list(all, online_users()));
}

// Рассылает сообщение всем онлайн-участникам группы.
// exclude_fd — fd отправителя, которому эхо уже отправлено отдельно (или -1).
static void broadcast_to_group(const Group& g, const std::string& msg,
                                int exclude_fd = -1)
{
    for (auto& member : g.members) {
        int mfd = fd_of_user(member);
        if (mfd != -1 && mfd != exclude_fd)
            ws_send_frame(mfd, msg);
    }
}

// ─────────────────────────────────────────────────────────
//  SHA-256
//
//  Используется для хэширования паролей перед сохранением в БД.
//  Пароль никогда не хранится в открытом виде — только хэш.
//
//  Примечание: SHA-256 без соли уязвим к атакам по радужным таблицам.
//  Для production рекомендуется bcrypt / Argon2.
// ─────────────────────────────────────────────────────────

#include <openssl/evp.h>

// Возвращает hex-строку SHA-256 от входных данных.
static std::string sha256(const std::string& input) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int  hash_len = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, input.c_str(), input.size());
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);

    const char* hex = "0123456789abcdef";
    std::string result;
    result.reserve(hash_len * 2);
    for (unsigned i = 0; i < hash_len; ++i) {
        result += hex[(hash[i] >> 4) & 0xF];
        result += hex[hash[i] & 0xF];
    }
    return result;
}

// ─────────────────────────────────────────────────────────
//  handle_client — обработчик одного WebSocket-соединения
//
//  Запускается в отдельном потоке для каждого клиента.
//  Жизненный цикл:
//    1. HTTP-запрос → WebSocket upgrade handshake
//    2. Цикл чтения фреймов: разбор JSON, диспетчеризация команд
//    3. Разрыв соединения → очистка, уведомление остальных
// ─────────────────────────────────────────────────────────

// Объявление глобальной переменной с HTML-страницей клиента
// (определена в main, здесь нужна для ws_handshake).
extern std::string g_html;

static void handle_client(int fd) {
    // ── Шаг 1: HTTP-запрос и WebSocket upgrade ────────────
    // Если клиент прислал обычный HTTP GET (без Upgrade: websocket),
    // ws_handshake отдаёт index.html и возвращает false — закрываем соединение.
    std::string http_req = recv_http_request(fd);
    if (http_req.empty()) { close(fd); return; }
    if (!ws_handshake(fd, http_req, g_html)) { close(fd); return; }

    // Регистрируем новое соединение в глобальной таблице (username пока пустой).
    {
        std::lock_guard<std::mutex> lock(g_clients_mtx);
        g_clients[fd] = { fd, "" };
    }
    g_log.info("WS connection: fd=" + std::to_string(fd));

    // ── Шаг 2: Основной цикл обработки команд ────────────
    // Читаем WebSocket-фреймы один за другим. Пустой фрейм означает
    // закрытие соединения (opcode 0x8 или ошибку чтения).
    while (true) {
        std::string raw = ws_recv_frame(fd);
        if (raw.empty()) break;  // клиент отключился

        std::string cmd = json_get_str(raw, "cmd");

        // ── login / register ───────────────────────────────
        // Обе команды используют одну и ту же логику валидации.
        // register дополнительно создаёт пользователя, затем оба пути
        // проверяют пароль через check_password.
        if (cmd == "login" || cmd == "register") {
            std::string username = json_get_str(raw, "username");
            std::string password = json_get_str(raw, "password");

            // Базовая валидация: поля не пустые, длина в пределах лимитов
            if (username.empty() || password.empty() ||
                username.size() > MAX_USERNAME_LEN ||
                password.size() > MAX_PASSWORD_LEN)
            {
                ws_send_frame(fd, json::auth_fail("Неверные данные"));
                continue;
            }
            // Допустимые символы в имени: буквы, цифры и подчёркивание
            bool bad_chars = false;
            for (char c : username)
                if (!isalnum(c) && c != '_') { bad_chars = true; break; }
            if (bad_chars) {
                ws_send_frame(fd, json::auth_fail("Только буквы, цифры и _"));
                continue;
            }

            std::string hash = sha256(password);

            if (cmd == "register") {
                // Проверяем уникальность имени перед регистрацией
                if (g_db->user_exists(username)) {
                    ws_send_frame(fd, json::auth_fail("Имя уже занято"));
                    continue;
                }
                g_db->register_user(username, hash);
                g_db->log_event("register", username);
                g_log.info("Registered: " + username);
                // После register сразу переходим к проверке пароля ниже
            }

            // Проверяем пароль (работает и для login, и после register)
            if (!g_db->check_password(username, hash)) {
                ws_send_frame(fd, json::auth_fail("Неверный логин или пароль"));
                continue;
            }

            // Сохраняем имя пользователя в таблице соединений
            {
                std::lock_guard<std::mutex> lock(g_clients_mtx);
                g_clients[fd].username = username;
            }
            g_db->log_event("login", username);
            g_log.info("Login: " + username);

            // Отправляем подтверждение авторизации
            ws_send_frame(fd, json::auth_ok(username));

            // Отправляем счётчики непрочитанных личных сообщений
            ws_send_frame(fd, json::unread_counts(g_db->get_unread_counts(username)));

            // Отправляем список групп пользователя
            auto groups = g_db->get_user_groups(username);
            ws_send_frame(fd, json::group_list(groups));

            // Отправляем счётчики непрочитанных в группах
            ws_send_frame(fd, json::group_unread_counts(g_db->get_group_unread_counts(username)));

            // Рассылаем обновлённый список пользователей всем онлайн
            broadcast_user_list();

            // Уведомляем остальных пользователей о входе нового участника.
            // Собираем fd под мьютексом, отправляем вне его (см. ВАЖНО выше).
            {
                std::string notice_msg = json::notice(username + " вошёл в чат");
                std::vector<int> fds;
                {
                    std::lock_guard<std::mutex> lock(g_clients_mtx);
                    for (auto& [cfd, client] : g_clients)
                        if (!client.username.empty() && cfd != fd)
                            fds.push_back(cfd);
                }
                for (int cfd : fds) ws_send_frame(cfd, notice_msg);
            }
        }

        // ── send_msg (личное сообщение) ────────────────────
        // Сохраняет сообщение в БД и доставляет получателю (если онлайн).
        // Эхо также отправляется отправителю — чтобы он видел своё сообщение.
        else if (cmd == "send_msg") {
            std::string my_name;
            {
                std::lock_guard<std::mutex> lock(g_clients_mtx);
                my_name = g_clients[fd].username;
            }
            if (my_name.empty()) { ws_send_frame(fd, json::error("Войдите")); continue; }

            std::string to   = json_get_str(raw, "to");
            std::string text = json_get_str(raw, "text");
            // Ограничение длины сообщения — 4096 символов
            if (to.empty() || text.empty() || text.size() > 4096) {
                ws_send_frame(fd, json::error("Неверные данные")); continue;
            }

            int64_t ts = std::time(nullptr);
            g_db->save_message(my_name, to, text, ts);
            std::string msg = json::recv_msg(my_name, to, text, ts);

            // Доставляем получателю (если он сейчас онлайн)
            int to_fd = fd_of_user(to);
            if (to_fd != -1 && to_fd != fd) ws_send_frame(to_fd, msg);
            // Эхо отправителю (подтверждение + отображение в его интерфейсе)
            ws_send_frame(fd, msg);
            g_log.info("MSG " + my_name + "→" + to + ": " + text.substr(0, 40));
        }

        // ── send_group_msg (сообщение в группу) ───────────
        // Проверяет членство, сохраняет сообщение и рассылает всем
        // онлайн-участникам группы (включая самого отправителя — эхо).
        else if (cmd == "send_group_msg") {
            std::string my_name;
            {
                std::lock_guard<std::mutex> lock(g_clients_mtx);
                my_name = g_clients[fd].username;
            }
            if (my_name.empty()) { ws_send_frame(fd, json::error("Войдите")); continue; }

            int64_t group_id = json_get_int(raw, "group_id");
            std::string text = json_get_str(raw, "text");
            if (group_id < 0 || text.empty() || text.size() > 4096) {
                ws_send_frame(fd, json::error("Неверные данные")); continue;
            }

            // Защита от отправки сообщений в чужую группу
            if (!g_db->is_member(group_id, my_name)) {
                ws_send_frame(fd, json::error("Вы не в этой группе")); continue;
            }

            int64_t ts = std::time(nullptr);
            g_db->save_group_message(my_name, group_id, text, ts);

            // Получаем актуальный список участников для рассылки
            Group g = g_db->get_group(group_id);
            if (g.id == -1) continue;  // группа удалена — игнорируем

            std::string msg = json::recv_group_msg(my_name, group_id, text, ts);
            // Рассылаем всем онлайн-участникам (включая отправителя — эхо)
            for (auto& member : g.members) {
                int mfd = fd_of_user(member);
                if (mfd != -1) ws_send_frame(mfd, msg);
            }
            g_log.info("GROUP_MSG " + my_name + "→group" +
                       std::to_string(group_id) + ": " + text.substr(0, 40));
        }

        // ── create_group ───────────────────────────────────
        // Создаёт новую группу и уведомляет всех указанных участников
        // (только тех, кто сейчас онлайн). Создатель автоматически
        // добавляется в группу на уровне БД (db.h).
        else if (cmd == "create_group") {
            std::string my_name;
            {
                std::lock_guard<std::mutex> lock(g_clients_mtx);
                my_name = g_clients[fd].username;
            }
            if (my_name.empty()) { ws_send_frame(fd, json::error("Войдите")); continue; }

            std::string name    = json_get_str(raw, "name");
            auto        members = json_get_str_array(raw, "members");

            // Валидация: имя группы не пустое и не длиннее 64 символов
            if (name.empty() || name.size() > 64) {
                ws_send_frame(fd, json::error("Неверное имя группы")); continue;
            }
            // Нельзя создать группу без участников
            if (members.empty()) {
                ws_send_frame(fd, json::error("Добавьте участников")); continue;
            }

            int64_t gid = g_db->create_group(name, my_name, members);
            if (gid < 0) {
                ws_send_frame(fd, json::error("Ошибка создания группы")); continue;
            }

            // Получаем полные данные созданной группы (с членами) из БД
            Group g = g_db->get_group(gid);
            std::string msg = json::group_created(g);

            // Уведомляем всех участников (включая создателя)
            for (auto& member : g.members) {
                int mfd = fd_of_user(member);
                if (mfd != -1) ws_send_frame(mfd, msg);
            }
            g_log.info("GROUP_CREATED id=" + std::to_string(gid) +
                       " name=" + name + " by=" + my_name);
        }

        // ── group_history ──────────────────────────────────
        // Отправляет клиенту последние 50 сообщений группы.
        // Доступ проверяется: запрашивать историю может только участник группы.
        else if (cmd == "group_history") {
            std::string my_name;
            {
                std::lock_guard<std::mutex> lock(g_clients_mtx);
                my_name = g_clients[fd].username;
            }
            if (my_name.empty()) continue;

            int64_t group_id = json_get_int(raw, "group_id");
            if (group_id < 0) continue;
            // Защита: не участник группы не может читать её историю
            if (!g_db->is_member(group_id, my_name)) continue;

            auto msgs = g_db->get_group_history(group_id);
            ws_send_frame(fd, json::group_history(group_id, msgs));
        }

        // ── mark_read (личные сообщения) ───────────────────
        // Клиент сообщает, что прочитал все сообщения от конкретного
        // пользователя. Сервер обновляет read_state в БД.
        else if (cmd == "mark_read") {
            std::string my_name;
            {
                std::lock_guard<std::mutex> lock(g_clients_mtx);
                my_name = g_clients[fd].username;
            }
            if (my_name.empty()) continue;
            std::string peer = json_get_str(raw, "peer");
            if (!peer.empty()) g_db->mark_read(my_name, peer);
        }

        // ── mark_group_read (групповые сообщения) ─────────
        // Аналогично mark_read, но для конкретной группы.
        else if (cmd == "mark_group_read") {
            std::string my_name;
            {
                std::lock_guard<std::mutex> lock(g_clients_mtx);
                my_name = g_clients[fd].username;
            }
            if (my_name.empty()) continue;
            int64_t group_id = json_get_int(raw, "group_id");
            if (group_id >= 0) g_db->mark_group_read(my_name, group_id);
        }

        // ── list_users ─────────────────────────────────────
        // По запросу возвращает полный список пользователей с пометкой онлайн.
        // Обычно клиент получает этот список автоматически при входе/выходе
        // других пользователей, но может запросить вручную (например, при
        // первом открытии).
        else if (cmd == "list_users") {
            auto all = g_db->get_all_users();
            ws_send_frame(fd, json::all_users_list(all, online_users()));
        }

        // ── history (личная переписка) ─────────────────────
        // Возвращает последние 50 сообщений в диалоге между текущим
        // пользователем и указанным собеседником (параметр "with").
        else if (cmd == "history") {
            std::string my_name;
            {
                std::lock_guard<std::mutex> lock(g_clients_mtx);
                my_name = g_clients[fd].username;
            }
            if (my_name.empty()) continue;
            std::string with = json_get_str(raw, "with");
            if (with.empty()) continue;
            auto msgs = g_db->get_history(my_name, with);
            ws_send_frame(fd, json::history(with, msgs));
        }
    }

    // ── Шаг 3: Обработка отключения клиента ──────────────
    // Удаляем клиента из таблицы, уведомляем остальных.
    std::string username;
    {
        std::lock_guard<std::mutex> lock(g_clients_mtx);
        username = g_clients[fd].username;
        g_clients.erase(fd);
    }
    close(fd);

    if (!username.empty()) {
        // Пользователь был авторизован — логируем выход и уведомляем чат
        g_db->log_event("logout", username);
        g_log.info("Disconnected: " + username);
        std::string notice_msg = json::notice(username + " покинул чат");
        // Рассылаем уведомление и обновлённый список онлайн-пользователей
        // (используем user_list вместо all_users_list — только онлайн)
        std::string ul = json::user_list(online_users());
        for (int cfd : all_authed_fds()) {
            ws_send_frame(cfd, notice_msg);
            ws_send_frame(cfd, ul);
        }
    } else {
        // Клиент отключился до авторизации — просто логируем
        g_log.info("WS disconnect: fd=" + std::to_string(fd));
    }
}

// ─────────────────────────────────────────────────────────
//  main — инициализация и accept-loop
//
//  Аргументы командной строки:
//    --port <N>   — порт (по умолчанию DEFAULT_PORT = 8080)
//    --db   <path> — путь к файлу SQLite БД (по умолчанию messenger.db)
//    --html <path> — путь к index.html (по умолчанию client/index.html)
// ─────────────────────────────────────────────────────────

// Глобальный буфер с содержимым index.html.
// Загружается один раз при старте, отдаётся при каждом HTTP GET.
std::string g_html;

int main(int argc, char* argv[]) {
    // Значения по умолчанию
    uint16_t    port      = DEFAULT_PORT;
    std::string db_path   = "messenger.db";
    std::string html_path = "client/index.html";

    // Разбор аргументов командной строки (формат: --ключ значение)
    for (int i = 1; i < argc - 1; ++i) {
        if (std::string(argv[i]) == "--port") port      = atoi(argv[i+1]);
        if (std::string(argv[i]) == "--db")   db_path   = argv[i+1];
        if (std::string(argv[i]) == "--html") html_path = argv[i+1];
    }

    // Загружаем HTML-клиент в память (читается один раз при старте)
    {
        FILE* f = fopen(html_path.c_str(), "r");
        if (!f) { g_log.error("Cannot open HTML: " + html_path); return 1; }
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        fseek(f, 0, SEEK_SET);
        g_html.resize(sz);
        fread(g_html.data(), 1, sz, f);
        fclose(f);
    }

    // Инициализируем базу данных (создаёт таблицы, если их нет)
    Database db(db_path, g_log);
    g_db = &db;

    db.log_event("server_start", "system", "port=" + std::to_string(port));
    g_log.info("Server starting on port " + std::to_string(port));

    // Игнорируем SIGPIPE: без этого запись в закрытый сокет убивает процесс.
    // Вместо этого send() вернёт -1, который обработает ws_send_frame.
    signal(SIGPIPE, SIG_IGN);

    // Создаём TCP-сокет сервера
    int srv_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (srv_fd < 0) { g_log.error("socket() failed"); return 1; }

    // SO_REUSEADDR позволяет немедленно перезапустить сервер на том же порту
    // после остановки (без ожидания TIME_WAIT состояния)
    int opt = 1;
    setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Привязываем сокет к порту на всех интерфейсах (0.0.0.0)
    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(srv_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        g_log.error("bind() failed on port " + std::to_string(port)); return 1;
    }
    // Очередь ожидающих соединений — до 128 штук
    if (listen(srv_fd, 128) < 0) { g_log.error("listen() failed"); return 1; }
    g_log.info("Listening on http://0.0.0.0:" + std::to_string(port));

    // ── Accept-loop ────────────────────────────────────────
    // Бесконечно принимаем входящие соединения. Каждое передаётся в
    // отдельный поток (detach), чтобы не блокировать приём новых клиентов.
    // Недостаток: нет ограничения на количество потоков — при DDoS
    // возможно исчерпание ресурсов. Для production нужен thread pool.
    while (true) {
        sockaddr_in client_addr{};
        socklen_t   client_len = sizeof(client_addr);
        int client_fd = accept(srv_fd, (sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) { g_log.warn("accept() failed"); continue; }

        // Логируем IP нового подключения
        char ip_buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, ip_buf, sizeof(ip_buf));
        g_log.info("New connection from " + std::string(ip_buf));

        // Запускаем обработчик клиента в отдельном потоке
        std::thread(handle_client, client_fd).detach();
    }

   
    db.log_event("server_stop", "system", "");
    close(srv_fd);
    return 0;
}