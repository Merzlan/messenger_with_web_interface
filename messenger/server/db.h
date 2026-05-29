#pragma once
#include <string>
#include <vector>
#include <algorithm>
#include <mutex>
#include <ctime>
#include <sqlite3.h>
#include "logger.h"

// Структура одного сообщения — используется и для личных, и для групповых.
// В групповых сообщениях поле to не заполняется (group_id передаётся отдельно).
struct Message {
    int64_t     id;    // первичный ключ из БД
    std::string from;  // имя отправителя
    std::string to;    // имя получателя (личные) или пусто (групповые)
    std::string text;  // тело сообщения
    int64_t     ts;    // Unix-время отправки в секундах
};

// Структура группового чата.
struct Group {
    int64_t     id;          // первичный ключ из таблицы groups
    std::string name;        // отображаемое имя группы
    std::string created_by;  // имя пользователя, создавшего группу
    std::vector<std::string> members; // список имён всех участников
};

// Обёртка над SQLite3: все публичные методы потокобезопасны (внутренний мьютекс).
// Используется SQLITE_OPEN_FULLMUTEX — SQLite тоже работает в многопоточном режиме,
// но мьютекс на уровне C++ нужен для атомарности составных операций (create_group и др.)
class Database {
public:
    // Открывает (или создаёт) файл БД по указанному пути.
    // Настраивает WAL-режим, таймаут блокировки и создаёт схему при первом запуске.
    explicit Database(const std::string& path, Logger& log)
        : log_(log)
    {
        int rc = sqlite3_open_v2(path.c_str(), &db_,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
            nullptr);
        if (rc != SQLITE_OK) {
            log_.error("DB open failed: " + std::string(sqlite3_errmsg(db_)));
            db_ = nullptr;
            return;
        }
        // WAL (Write-Ahead Log) позволяет читателям не блокировать писателей
        exec("PRAGMA journal_mode=WAL;");
        // NORMAL — сброс на диск при контрольных точках, не при каждой транзакции
        exec("PRAGMA synchronous=NORMAL;");
        // При конкурентной записи ждём до 5 секунд вместо немедленной ошибки SQLITE_BUSY
        exec("PRAGMA busy_timeout=5000;");
        create_tables();
        log_.info("Database opened: " + path);
    }

    // Закрывает соединение с БД при уничтожении объекта
    ~Database() { if (db_) sqlite3_close(db_); }

    // ── Пользователи ──────────────────────────────────────

    // Регистрирует нового пользователя. password_hash — SHA-256 от пароля.
    // INSERT OR IGNORE гарантирует отсутствие дубликатов без исключений.
    // Возвращает false, если имя уже занято (sqlite3_changes == 0).
    bool register_user(const std::string& username, const std::string& password_hash) {
        std::lock_guard<std::mutex> lock(mtx_);
        const char* sql =
            "INSERT OR IGNORE INTO users(username, password_hash, created_at) VALUES(?,?,?);";
        sqlite3_stmt* stmt = prepare(sql);
        if (!stmt) return false;
        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, password_hash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 3, std::time(nullptr));
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        // sqlite3_changes > 0 означает, что строка реально вставлена (не проигнорирована)
        return rc == SQLITE_DONE && sqlite3_changes(db_) > 0;
    }

    // Проверяет пару username + password_hash.
    // Возвращает true, если в таблице users есть строка с такими значениями.
    bool check_password(const std::string& username, const std::string& password_hash) {
        std::lock_guard<std::mutex> lock(mtx_);
        const char* sql = "SELECT 1 FROM users WHERE username=? AND password_hash=? LIMIT 1;";
        sqlite3_stmt* stmt = prepare(sql);
        if (!stmt) return false;
        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, password_hash.c_str(), -1, SQLITE_TRANSIENT);
        bool ok = (sqlite3_step(stmt) == SQLITE_ROW); // SQLITE_ROW — хотя бы одна строка найдена
        sqlite3_finalize(stmt);
        return ok;
    }

    // Проверяет, зарегистрировано ли имя пользователя (используется при регистрации).
    bool user_exists(const std::string& username) {
        std::lock_guard<std::mutex> lock(mtx_);
        const char* sql = "SELECT 1 FROM users WHERE username=? LIMIT 1;";
        sqlite3_stmt* stmt = prepare(sql);
        if (!stmt) return false;
        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
        bool ok = (sqlite3_step(stmt) == SQLITE_ROW);
        sqlite3_finalize(stmt);
        return ok;
    }

    // Возвращает список имён всех зарегистрированных пользователей в алфавитном порядке.
    // Используется для отображения глобального списка с онлайн-статусами.
    std::vector<std::string> get_all_users() {
        std::lock_guard<std::mutex> lock(mtx_);
        const char* sql = "SELECT username FROM users ORDER BY username;";
        sqlite3_stmt* stmt = prepare(sql);
        std::vector<std::string> result;
        if (!stmt) return result;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* u = (const char*)sqlite3_column_text(stmt, 0);
            if (u) result.emplace_back(u);
        }
        sqlite3_finalize(stmt);
        return result;
    }

    // ── Личные сообщения ──────────────────────────────────

    // Сохраняет личное сообщение от from пользователю to.
    // ts — Unix-время, выставляется сервером в момент получения.
    bool save_message(const std::string& from, const std::string& to,
                      const std::string& text, int64_t ts)
    {
        std::lock_guard<std::mutex> lock(mtx_);
        const char* sql =
            "INSERT INTO messages(from_user, to_user, body, sent_at) VALUES(?,?,?,?);";
        sqlite3_stmt* stmt = prepare(sql);
        if (!stmt) return false;
        sqlite3_bind_text(stmt, 1, from.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, to.c_str(),   -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, text.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 4, ts);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return rc == SQLITE_DONE;
    }

    // Возвращает последние limit сообщений между user_a и user_b в хронологическом порядке.
    // Запрос выбирает оба направления переписки (A→B и B→A) через OR.
    // БД возвращает строки в порядке убывания времени (DESC), затем std::reverse
    // переворачивает их в хронологический порядок для отображения в чате.
    std::vector<Message> get_history(const std::string& user_a,
                                     const std::string& user_b,
                                     int limit = 50)
    {
        std::lock_guard<std::mutex> lock(mtx_);
        const char* sql =
            "SELECT id, from_user, to_user, body, sent_at FROM messages "
            "WHERE (from_user=? AND to_user=?) OR (from_user=? AND to_user=?) "
            "ORDER BY sent_at DESC LIMIT ?;";
        sqlite3_stmt* stmt = prepare(sql);
        if (!stmt) return {};
        // Параметры дублируются: 1=user_a, 2=user_b (направление A→B)
        //                         3=user_b, 4=user_a (направление B→A)
        sqlite3_bind_text(stmt, 1, user_a.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, user_b.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, user_b.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, user_a.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt,  5, limit);
        std::vector<Message> result;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            Message m;
            m.id   = sqlite3_column_int64(stmt, 0);
            m.from = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            m.to   = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            m.text = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
            m.ts   = sqlite3_column_int64(stmt, 4);
            result.push_back(m);
        }
        sqlite3_finalize(stmt);
        std::reverse(result.begin(), result.end()); // DESC → ASC для отображения
        return result;
    }

    // ── Прочитанные (личные) ──────────────────────────────

    // Отмечает все сообщения от peer к reader как прочитанные,
    // сохраняя id последнего сообщения в таблице read_state.
    // ON CONFLICT обновляет запись, принимая максимальный id (защита от регрессии
    // при одновременном открытии чата на нескольких вкладках).
    void mark_read(const std::string& reader, const std::string& peer) {
        std::lock_guard<std::mutex> lock(mtx_);
        const char* sql =
            "INSERT INTO read_state(reader, sender, last_read_id) "
            "SELECT ?, ?, MAX(id) FROM messages WHERE from_user=? AND to_user=? "
            "ON CONFLICT(reader, sender) DO UPDATE SET "
            "last_read_id = MAX(last_read_id, excluded.last_read_id);";
        sqlite3_stmt* stmt = prepare(sql);
        if (!stmt) return;
        sqlite3_bind_text(stmt, 1, reader.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, peer.c_str(),   -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, peer.c_str(),   -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, reader.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    // Возвращает количество непрочитанных личных сообщений для username, сгруппированных по отправителю.
    // LEFT JOIN с read_state: если записи нет (IS NULL) — все сообщения считаются непрочитанными.
    std::vector<std::pair<std::string, int>> get_unread_counts(const std::string& username) {
        std::lock_guard<std::mutex> lock(mtx_);
        const char* sql =
            "SELECT m.from_user, COUNT(*) FROM messages m "
            "LEFT JOIN read_state rs ON rs.reader=? AND rs.sender=m.from_user "
            "WHERE m.to_user=? AND (rs.last_read_id IS NULL OR m.id > rs.last_read_id) "
            "GROUP BY m.from_user;";
        sqlite3_stmt* stmt = prepare(sql);
        if (!stmt) return {};
        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_TRANSIENT);
        std::vector<std::pair<std::string, int>> result;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::string sender = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            int count = sqlite3_column_int(stmt, 1);
            result.push_back({ sender, count });
        }
        sqlite3_finalize(stmt);
        return result;
    }

    // ── Группы ────────────────────────────────────────────

    // Создаёт группу и добавляет всех переданных участников + создателя.
    // Операция НЕ атомарна на уровне SQL (несколько INSERT), поэтому защищена мьютексом целиком.
    // Возвращает id новой группы или -1 при ошибке вставки.
    int64_t create_group(const std::string& name, const std::string& created_by,
                         const std::vector<std::string>& members)
    {
        std::lock_guard<std::mutex> lock(mtx_);
        // Шаг 1: вставляем запись о группе
        {
            const char* sql =
                "INSERT INTO groups(name, created_by, created_at) VALUES(?,?,?);";
            sqlite3_stmt* stmt = prepare(sql);
            if (!stmt) return -1;
            sqlite3_bind_text(stmt, 1, name.c_str(),       -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, created_by.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(stmt, 3, std::time(nullptr));
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
        int64_t gid = sqlite3_last_insert_rowid(db_); // id только что созданной группы

        // Шаг 2: добавляем переданных участников (INSERT OR IGNORE избегает дублей)
        const char* sql2 = "INSERT OR IGNORE INTO group_members(group_id, username) VALUES(?,?);";
        for (auto& m : members) {
            sqlite3_stmt* stmt = prepare(sql2);
            if (!stmt) continue;
            sqlite3_bind_int64(stmt, 1, gid);
            sqlite3_bind_text(stmt, 2, m.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
        // Шаг 3: добавляем создателя (он мог быть уже в списке members, OR IGNORE защитит от дубля)
        {
            sqlite3_stmt* stmt = prepare(sql2);
            if (stmt) {
                sqlite3_bind_int64(stmt, 1, gid);
                sqlite3_bind_text(stmt, 2, created_by.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
        }
        return gid;
    }

    // Загружает группу по id: сначала базовые поля, затем отдельным запросом — список участников.
    // Возвращает Group с id == -1, если группа не найдена.
    Group get_group(int64_t gid) {
        std::lock_guard<std::mutex> lock(mtx_);
        Group g;
        g.id = -1;
        // Запрос 1: получаем имя и создателя группы
        {
            const char* sql = "SELECT name, created_by FROM groups WHERE id=?;";
            sqlite3_stmt* stmt = prepare(sql);
            if (!stmt) return g;
            sqlite3_bind_int64(stmt, 1, gid);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                g.id         = gid;
                g.name       = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                g.created_by = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            }
            sqlite3_finalize(stmt);
        }
        if (g.id == -1) return g; // группа не существует
        // Запрос 2: получаем список участников
        {
            const char* sql = "SELECT username FROM group_members WHERE group_id=?;";
            sqlite3_stmt* stmt = prepare(sql);
            if (!stmt) return g;
            sqlite3_bind_int64(stmt, 1, gid);
            while (sqlite3_step(stmt) == SQLITE_ROW)
                g.members.push_back(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
            sqlite3_finalize(stmt);
        }
        return g;
    }

    // Возвращает все группы, в которых состоит пользователь, с заполненными списками участников.
    // Для каждой группы делается отдельный запрос за участниками — N+1, но групп обычно мало.
    std::vector<Group> get_user_groups(const std::string& username) {
        std::lock_guard<std::mutex> lock(mtx_);
        const char* sql =
            "SELECT g.id, g.name, g.created_by FROM groups g "
            "JOIN group_members gm ON gm.group_id=g.id "
            "WHERE gm.username=? ORDER BY g.id;";
        sqlite3_stmt* stmt = prepare(sql);
        if (!stmt) return {};
        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
        std::vector<Group> result;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            Group g;
            g.id         = sqlite3_column_int64(stmt, 0);
            g.name       = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            g.created_by = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            result.push_back(g);
        }
        sqlite3_finalize(stmt);
        // Отдельно догружаем участников каждой группы
        for (auto& g : result) {
            const char* sql2 = "SELECT username FROM group_members WHERE group_id=?;";
            sqlite3_stmt* s2 = prepare(sql2);
            if (!s2) continue;
            sqlite3_bind_int64(s2, 1, g.id);
            while (sqlite3_step(s2) == SQLITE_ROW)
                g.members.push_back(reinterpret_cast<const char*>(sqlite3_column_text(s2, 0)));
            sqlite3_finalize(s2);
        }
        return result;
    }

    // Проверяет, является ли username участником группы group_id.
    // Используется перед каждой отправкой сообщения в группу.
    bool is_member(int64_t group_id, const std::string& username) {
        std::lock_guard<std::mutex> lock(mtx_);
        const char* sql = "SELECT 1 FROM group_members WHERE group_id=? AND username=? LIMIT 1;";
        sqlite3_stmt* stmt = prepare(sql);
        if (!stmt) return false;
        sqlite3_bind_int64(stmt, 1, group_id);
        sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_TRANSIENT);
        bool ok = (sqlite3_step(stmt) == SQLITE_ROW);
        sqlite3_finalize(stmt);
        return ok;
    }

    // ── Групповые сообщения ───────────────────────────────

    // Сохраняет сообщение в групповой чат. group_id хранится явно,
    // в отличие от личных сообщений, где получатель — конкретный пользователь.
    bool save_group_message(const std::string& from, int64_t group_id,
                            const std::string& text, int64_t ts)
    {
        std::lock_guard<std::mutex> lock(mtx_);
        const char* sql =
            "INSERT INTO group_messages(from_user, group_id, body, sent_at) VALUES(?,?,?,?);";
        sqlite3_stmt* stmt = prepare(sql);
        if (!stmt) return false;
        sqlite3_bind_text(stmt, 1, from.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, group_id);
        sqlite3_bind_text(stmt, 3, text.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 4, ts);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return rc == SQLITE_DONE;
    }

    // Возвращает последние limit сообщений группы в хронологическом порядке.
    // Аналогично get_history: БД даёт DESC, std::reverse переводит в ASC.
    std::vector<Message> get_group_history(int64_t group_id, int limit = 50) {
        std::lock_guard<std::mutex> lock(mtx_);
        const char* sql =
            "SELECT id, from_user, body, sent_at FROM group_messages "
            "WHERE group_id=? ORDER BY sent_at DESC LIMIT ?;";
        sqlite3_stmt* stmt = prepare(sql);
        if (!stmt) return {};
        sqlite3_bind_int64(stmt, 1, group_id);
        sqlite3_bind_int(stmt,  2, limit);
        std::vector<Message> result;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            Message m;
            m.id   = sqlite3_column_int64(stmt, 0);
            m.from = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            m.text = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            m.ts   = sqlite3_column_int64(stmt, 3);
            result.push_back(m);
        }
        sqlite3_finalize(stmt);
        std::reverse(result.begin(), result.end()); // DESC → ASC для отображения
        return result;
    }

    // Отмечает все сообщения группы group_id как прочитанные для username.
    // Логика та же, что у mark_read: хранится id последнего прочитанного сообщения.
    // ON CONFLICT берёт MAX, чтобы не откатить прочтение при гонке нескольких вкладок.
    void mark_group_read(const std::string& username, int64_t group_id) {
        std::lock_guard<std::mutex> lock(mtx_);
        const char* sql =
            "INSERT INTO group_read_state(username, group_id, last_read_id) "
            "SELECT ?, ?, MAX(id) FROM group_messages WHERE group_id=? "
            "ON CONFLICT(username, group_id) DO UPDATE SET "
            "last_read_id = MAX(last_read_id, excluded.last_read_id);";
        sqlite3_stmt* stmt = prepare(sql);
        if (!stmt) return;
        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, group_id);
        sqlite3_bind_int64(stmt, 3, group_id);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    // Возвращает количество непрочитанных сообщений по каждой группе для username.
    // JOIN с group_members — учитываем только группы, где состоит пользователь.
    // Условие from_user != username исключает собственные сообщения из счётчика.
    std::vector<std::pair<int64_t, int>> get_group_unread_counts(const std::string& username) {
        std::lock_guard<std::mutex> lock(mtx_);
        const char* sql =
            "SELECT gm_msg.group_id, COUNT(*) FROM group_messages gm_msg "
            "JOIN group_members gm ON gm.group_id=gm_msg.group_id AND gm.username=? "
            "LEFT JOIN group_read_state grs ON grs.username=? AND grs.group_id=gm_msg.group_id "
            "WHERE gm_msg.from_user != ? "
            "  AND (grs.last_read_id IS NULL OR gm_msg.id > grs.last_read_id) "
            "GROUP BY gm_msg.group_id;";
        sqlite3_stmt* stmt = prepare(sql);
        if (!stmt) return {};
        // username передаётся трижды: для JOIN участников, JOIN состояния прочтения и фильтра автора
        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, username.c_str(), -1, SQLITE_TRANSIENT);
        std::vector<std::pair<int64_t, int>> result;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            int64_t gid   = sqlite3_column_int64(stmt, 0);
            int     count = sqlite3_column_int(stmt, 1);
            result.push_back({ gid, count });
        }
        sqlite3_finalize(stmt);
        return result;
    }

    // ── Лог событий ──────────────────────────────────────

    // Записывает событие в таблицу events_log (login, logout, register, server_start и т.д.).
    // detail — опциональная дополнительная информация (например, «port=8080»).
    void log_event(const std::string& event_type, const std::string& username,
                   const std::string& detail = "")
    {
        std::lock_guard<std::mutex> lock(mtx_);
        const char* sql =
            "INSERT INTO events_log(event_type, username, detail, occurred_at) VALUES(?,?,?,?);";
        sqlite3_stmt* stmt = prepare(sql);
        if (!stmt) return;
        sqlite3_bind_text(stmt, 1, event_type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, username.c_str(),   -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, detail.c_str(),     -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 4, std::time(nullptr));
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

private:
    sqlite3*   db_  = nullptr; // дескриптор соединения с SQLite
    Logger&    log_;            // ссылка на логгер (владелец — main)
    std::mutex mtx_;            // защищает все операции с db_ от гонок

    // Создаёт все таблицы и индексы при первом запуске (IF NOT EXISTS — идемпотентно).
    // Схема:
    //   users            — аккаунты (username уникален)
    //   messages         — личные сообщения; индекс idx_msg_pair ускоряет выборку переписки
    //   read_state       — last_read_id для каждой пары (reader, sender)
    //   groups           — группы
    //   group_members    — N:M между groups и users
    //   group_messages   — сообщения в группах; индекс idx_gmsg_group ускоряет историю
    //   group_read_state — last_read_id для каждой пары (username, group_id)
    //   events_log       — аудит событий сервера
    void create_tables() {
        exec(R"(
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT    UNIQUE NOT NULL,
                password_hash TEXT    NOT NULL,
                created_at    INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS messages (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                from_user TEXT    NOT NULL,
                to_user   TEXT    NOT NULL,
                body      TEXT    NOT NULL,
                sent_at   INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_msg_pair
                ON messages(from_user, to_user, sent_at);
            CREATE TABLE IF NOT EXISTS read_state (
                reader       TEXT    NOT NULL,
                sender       TEXT    NOT NULL,
                last_read_id INTEGER NOT NULL,
                PRIMARY KEY (reader, sender)
            );
            CREATE TABLE IF NOT EXISTS groups (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                name       TEXT    NOT NULL,
                created_by TEXT    NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS group_members (
                group_id INTEGER NOT NULL,
                username TEXT    NOT NULL,
                PRIMARY KEY (group_id, username),
                FOREIGN KEY (group_id) REFERENCES groups(id)
            );
            CREATE TABLE IF NOT EXISTS group_messages (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id  INTEGER NOT NULL,
                from_user TEXT    NOT NULL,
                body      TEXT    NOT NULL,
                sent_at   INTEGER NOT NULL,
                FOREIGN KEY (group_id) REFERENCES groups(id)
            );
            CREATE INDEX IF NOT EXISTS idx_gmsg_group
                ON group_messages(group_id, sent_at);
            CREATE TABLE IF NOT EXISTS group_read_state (
                username     TEXT    NOT NULL,
                group_id     INTEGER NOT NULL,
                last_read_id INTEGER NOT NULL,
                PRIMARY KEY (username, group_id)
            );
            CREATE TABLE IF NOT EXISTS events_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type  TEXT    NOT NULL,
                username    TEXT    NOT NULL,
                detail      TEXT,
                occurred_at INTEGER NOT NULL
            );
        )");
    }

    // Выполняет SQL-выражение без возвращаемых строк (DDL, PRAGMA).
    // При ошибке пишет в лог и освобождает сообщение об ошибке SQLite.
    void exec(const char* sql) {
        char* err = nullptr;
        if (sqlite3_exec(db_, sql, nullptr, nullptr, &err) != SQLITE_OK) {
            log_.error("SQL error: " + std::string(err));
            sqlite3_free(err); // SQLite выделяет строку ошибки через свой аллокатор
        }
    }

    // Компилирует SQL-запрос в подготовленное выражение (prepared statement).
    // Использование prepared statements защищает от SQL-инъекций и ускоряет повторное выполнение.
    // Возвращает nullptr при ошибке компиляции (подробности в логе).
    sqlite3_stmt* prepare(const char* sql) {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            log_.error("Prepare failed: " + std::string(sqlite3_errmsg(db_)));
            return nullptr;
        }
        return stmt;
    }
};