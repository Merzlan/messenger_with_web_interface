#pragma once
#include <string>
#include <sstream>
#include <vector>

// Минималистичный JSON-парсер и билдер без внешних зависимостей.
// Парсер намеренно упрощён: не поддерживает вложенные объекты и
// рассчитан на плоские команды протокола мессенджера.

// ─────────────────────────────────────────────────────────
//  Парсер: чтение значений из JSON-строки
// ─────────────────────────────────────────────────────────

// Экранирует спецсимволы строки для безопасной вставки в JSON-значение.
// Обрабатывает: кавычку, обратный слеш, \n, \r, \t.
static std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 4); // небольшой запас на случай нескольких escape-символов
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;      break;
        }
    }
    return out;
}

// Извлекает строковое значение поля key из плоского JSON-объекта.
// Пример: json_get_str({"cmd":"login","username":"alice"}, "username") → "alice"
// Поддерживает escape-последовательности внутри значения.
// Возвращает пустую строку, если ключ не найден или значение не строка.
static std::string json_get_str(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "";
    pos += search.size();
    // Пропускаем пробелы и двоеточие между ключом и значением
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':')) ++pos;
    if (pos >= json.size() || json[pos] != '"') return ""; // значение не строка
    ++pos; // пропускаем открывающую кавычку
    std::string result;
    while (pos < json.size() && json[pos] != '"') {
        if (json[pos] == '\\' && pos + 1 < json.size()) {
            // Обрабатываем escape-последовательность
            ++pos;
            switch (json[pos]) {
                case '"':  result += '"';  break;
                case '\\': result += '\\'; break;
                case 'n':  result += '\n'; break;
                case 'r':  result += '\r'; break;
                case 't':  result += '\t'; break;
                default:   result += json[pos]; break;
            }
        } else {
            result += json[pos];
        }
        ++pos;
    }
    return result;
}

// Извлекает целочисленное значение поля key из JSON-объекта.
// Пример: json_get_int({"group_id":42}, "group_id") → 42
// Возвращает -1, если ключ не найден.
static int64_t json_get_int(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return -1;
    pos += search.size();
    // Пропускаем пробелы и двоеточие между ключом и значением
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':')) ++pos;
    if (pos >= json.size()) return -1;
    return std::stoll(json.substr(pos)); // stoll останавливается на первом нецифровом символе
}

// Извлекает массив строк по ключу key из JSON-объекта.
// Пример: json_get_str_array({"members":["alice","bob"]}, "members") → {"alice","bob"}
// Упрощённый парсер: не поддерживает вложенные массивы и escape внутри элементов.
// Возвращает пустой вектор, если ключ не найден или значение не массив.
static std::vector<std::string> json_get_str_array(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return {};
    pos += search.size();
    // Пропускаем пробелы и двоеточие, ищем открывающую скобку массива
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':')) ++pos;
    if (pos >= json.size() || json[pos] != '[') return {};
    ++pos; // пропускаем '['
    std::vector<std::string> result;
    while (pos < json.size() && json[pos] != ']') {
        // Ищем начало следующей строки-элемента
        while (pos < json.size() && json[pos] != '"' && json[pos] != ']') ++pos;
        if (pos >= json.size() || json[pos] == ']') break;
        ++pos; // пропускаем открывающую кавычку элемента
        std::string s;
        while (pos < json.size() && json[pos] != '"') {
            if (json[pos] == '\\' && pos + 1 < json.size()) { ++pos; } // пропускаем escape
            s += json[pos++];
        }
        ++pos; // пропускаем закрывающую кавычку элемента
        result.push_back(s);
    }
    return result;
}

// ─────────────────────────────────────────────────────────
//  Билдер: формирование JSON-ответов сервера
// ─────────────────────────────────────────────────────────

namespace json {

// Успешная аутентификация: сообщает клиенту его имя пользователя
inline std::string auth_ok(const std::string& username) {
    return "{\"cmd\":\"auth_ok\",\"username\":\"" + json_escape(username) + "\"}";
}

// Ошибка аутентификации с текстовой причиной отказа
inline std::string auth_fail(const std::string& reason) {
    return "{\"cmd\":\"auth_fail\",\"reason\":\"" + json_escape(reason) + "\"}";
}

// Доставка личного сообщения: отправляется и отправителю (эхо), и получателю.
// ts — Unix-время отправки в секундах, используется клиентом для сортировки и отображения.
inline std::string recv_msg(const std::string& from, const std::string& to,
                             const std::string& text, int64_t ts)
{
    std::ostringstream ss;
    ss << "{\"cmd\":\"recv_msg\","
       << "\"from\":\"" << json_escape(from) << "\","
       << "\"to\":\""   << json_escape(to)   << "\","
       << "\"text\":\"" << json_escape(text) << "\","
       << "\"ts\":"     << ts << "}";
    return ss.str();
}

// Доставка сообщения в групповой чат: рассылается всем онлайн-участникам группы
inline std::string recv_group_msg(const std::string& from, int64_t group_id,
                                   const std::string& text, int64_t ts)
{
    std::ostringstream ss;
    ss << "{\"cmd\":\"recv_group_msg\","
       << "\"from\":\"" << json_escape(from) << "\","
       << "\"group_id\":" << group_id << ","
       << "\"text\":\"" << json_escape(text) << "\","
       << "\"ts\":"     << ts << "}";
    return ss.str();
}

// Системное уведомление (например, «Alice вошла в чат»): рассылается всем онлайн
inline std::string notice(const std::string& text) {
    return "{\"cmd\":\"notice\",\"text\":\"" + json_escape(text) + "\"}";
}

// Сообщение об ошибке протокола (например, «Вы не в этой группе»)
inline std::string error(const std::string& text) {
    return "{\"cmd\":\"error\",\"text\":\"" + json_escape(text) + "\"}";
}

// Список текущих онлайн-пользователей (только имена, без статуса)
inline std::string user_list(const std::vector<std::string>& users) {
    std::ostringstream ss;
    ss << "{\"cmd\":\"user_list\",\"users\":[";
    for (size_t i = 0; i < users.size(); ++i) {
        if (i > 0) ss << ",";
        ss << "\"" << json_escape(users[i]) << "\"";
    }
    ss << "]}";
    return ss.str();
}

// Полный список зарегистрированных пользователей с флагом онлайн для каждого.
// Отправляется всем при входе/выходе любого пользователя.
// Онлайн-статус определяется линейным поиском по списку online_users.
inline std::string all_users_list(const std::vector<std::string>& all_users,
                                   const std::vector<std::string>& online_users)
{
    std::ostringstream ss;
    ss << "{\"cmd\":\"all_users_list\",\"users\":[";
    for (size_t i = 0; i < all_users.size(); ++i) {
        if (i > 0) ss << ",";
        bool is_online = false;
        for (const auto& u : online_users)
            if (u == all_users[i]) { is_online = true; break; }
        ss << "{\"name\":\"" << json_escape(all_users[i]) << "\","
           << "\"online\":" << (is_online ? "true" : "false") << "}";
    }
    ss << "]}";
    return ss.str();
}

// История личной переписки с пользователем with.
// Сообщения передаются в хронологическом порядке (БД возвращает их уже отсортированными).
inline std::string history(const std::string& with, const std::vector<Message>& messages) {
    std::ostringstream ss;
    ss << "{\"cmd\":\"history\","
       << "\"with\":\"" << json_escape(with) << "\","
       << "\"messages\":[";
    for (size_t i = 0; i < messages.size(); ++i) {
        if (i > 0) ss << ",";
        ss << "{\"from\":\"" << json_escape(messages[i].from) << "\","
           << "\"text\":\"" << json_escape(messages[i].text) << "\","
           << "\"ts\":"     << messages[i].ts << "}";
    }
    ss << "]}";
    return ss.str();
}

// История сообщений группового чата по его идентификатору
inline std::string group_history(int64_t group_id, const std::vector<Message>& messages) {
    std::ostringstream ss;
    ss << "{\"cmd\":\"group_history\","
       << "\"group_id\":" << group_id << ","
       << "\"messages\":[";
    for (size_t i = 0; i < messages.size(); ++i) {
        if (i > 0) ss << ",";
        ss << "{\"from\":\"" << json_escape(messages[i].from) << "\","
           << "\"text\":\"" << json_escape(messages[i].text) << "\","
           << "\"ts\":"     << messages[i].ts << "}";
    }
    ss << "]}";
    return ss.str();
}

// Счётчики непрочитанных личных сообщений: отправляется сразу после входа.
// Формат: {"cmd":"unread_counts","counts":{"alice":3,"bob":1}}
inline std::string unread_counts(const std::vector<std::pair<std::string,int>>& counts) {
    std::ostringstream ss;
    ss << "{\"cmd\":\"unread_counts\",\"counts\":{";
    bool first = true;
    for (auto& [sender, count] : counts) {
        if (!first) ss << ",";
        ss << "\"" << json_escape(sender) << "\":" << count;
        first = false;
    }
    ss << "}}";
    return ss.str();
}

// Счётчики непрочитанных сообщений по группам: отправляется сразу после входа.
// Формат: {"cmd":"group_unread_counts","counts":{"1":5,"3":2}}
inline std::string group_unread_counts(const std::vector<std::pair<int64_t,int>>& counts) {
    std::ostringstream ss;
    ss << "{\"cmd\":\"group_unread_counts\",\"counts\":{";
    bool first = true;
    for (auto& [gid, count] : counts) {
        if (!first) ss << ",";
        ss << "\"" << gid << "\":" << count;
        first = false;
    }
    ss << "}}";
    return ss.str();
}

// Список групп, в которых состоит пользователь (с участниками каждой).
// Отправляется сразу после успешного входа.
inline std::string group_list(const std::vector<Group>& groups) {
    std::ostringstream ss;
    ss << "{\"cmd\":\"group_list\",\"groups\":[";
    for (size_t i = 0; i < groups.size(); ++i) {
        if (i > 0) ss << ",";
        ss << "{\"id\":" << groups[i].id
           << ",\"name\":\"" << json_escape(groups[i].name) << "\""
           << ",\"created_by\":\"" << json_escape(groups[i].created_by) << "\""
           << ",\"members\":[";
        for (size_t j = 0; j < groups[i].members.size(); ++j) {
            if (j > 0) ss << ",";
            ss << "\"" << json_escape(groups[i].members[j]) << "\"";
        }
        ss << "]}";
    }
    ss << "]}";
    return ss.str();
}

// Уведомление о создании новой группы: рассылается всем её участникам,
// включая создателя, с полным списком членов группы.
inline std::string group_created(const Group& g) {
    std::ostringstream ss;
    ss << "{\"cmd\":\"group_created\","
       << "\"id\":" << g.id << ","
       << "\"name\":\"" << json_escape(g.name) << "\","
       << "\"created_by\":\"" << json_escape(g.created_by) << "\","
       << "\"members\":[";
    for (size_t i = 0; i < g.members.size(); ++i) {
        if (i > 0) ss << ",";
        ss << "\"" << json_escape(g.members[i]) << "\"";
    }
    ss << "]}";
    return ss.str();
}

} // namespace json