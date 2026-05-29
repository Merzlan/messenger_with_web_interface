#pragma once
#include <string>
#include <vector>
#include <stdexcept>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

// ─────────────────────────────────────────────────────────
//  Вспомогательные функции: Base64, SHA-1
// ─────────────────────────────────────────────────────────

// Кодирует бинарные данные в строку Base64 (без переносов строк).
// Используется при формировании ответного ключа WebSocket-рукопожатия.
static std::string base64_encode(const unsigned char* data, size_t len) {
    BIO* b64  = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // без символа переноса строки
    BIO_write(b64, data, (int)len);
    BIO_flush(b64);

    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);
    std::string result(bptr->data, bptr->length);
    BIO_free_all(b64);
    return result;
}

// Вычисляет значение заголовка Sec-WebSocket-Accept по алгоритму RFC 6455:
//   1. Конкатенирует клиентский ключ с фиксированным GUID
//   2. Хеширует результат SHA-1
//   3. Кодирует хеш в Base64
static std::string ws_accept_key(const std::string& client_key) {
    const std::string magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"; // GUID из RFC 6455
    std::string combined = client_key + magic;

    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(combined.c_str()),
         combined.size(), hash);

    return base64_encode(hash, SHA_DIGEST_LENGTH);
}

// ─────────────────────────────────────────────────────────
//  HTTP-заголовки: читаем до \r\n\r\n
// ─────────────────────────────────────────────────────────

// Читает HTTP-запрос из сокета побайтово до маркера конца заголовков \r\n\r\n.
// Возвращает пустую строку при разрыве соединения.
static std::string recv_http_request(int fd) {
    std::string buf;
    buf.reserve(1024);
    char c;
    while (true) {
        ssize_t n = recv(fd, &c, 1, 0);
        if (n <= 0) return ""; // соединение закрыто или ошибка
        buf += c;
        if (buf.size() >= 4 &&
            buf.substr(buf.size() - 4) == "\r\n\r\n") // конец HTTP-заголовков
            break;
    }
    return buf;
}

// Извлекает значение HTTP-заголовка по имени (без учёта регистра).
// Например: extract_header(req, "Sec-WebSocket-Key") → "dGhlIHNhbXBsZQ=="
static std::string extract_header(const std::string& req, const std::string& name) {
    // Приводим и запрос, и имя к нижнему регистру для регистронезависимого поиска
    std::string lower_req = req;
    std::string lower_name = name;
    for (auto& ch : lower_req)  ch = tolower(ch);
    for (auto& ch : lower_name) ch = tolower(ch);

    size_t pos = lower_req.find(lower_name + ":");
    if (pos == std::string::npos) return "";
    pos += lower_name.size() + 1;
    while (pos < req.size() && req[pos] == ' ') ++pos; // пропускаем пробелы после двоеточия
    size_t end = req.find("\r\n", pos);
    return req.substr(pos, end - pos);
}

// ─────────────────────────────────────────────────────────
//  WebSocket handshake
//  Возвращает true если клиент хочет WS и всё прошло успешно.
//  Если GET / без Upgrade — отдаём HTTP-ответ с index.html.
// ─────────────────────────────────────────────────────────

// Обрабатывает входящий HTTP-запрос:
//   — Если запрос без заголовка «Upgrade: websocket» — отдаёт статический HTML и возвращает false.
//   — Если запрос на апгрейд WebSocket — выполняет рукопожатие и возвращает true.
static bool ws_handshake(int fd, const std::string& http_request,
                          const std::string& static_html)
{
    // Обычный браузерный GET — отдаём HTML-страницу клиента
    if (http_request.find("Upgrade: websocket") == std::string::npos &&
        http_request.find("upgrade: websocket") == std::string::npos)
    {
        std::string body   = static_html;
        std::string header =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "Content-Length: " + std::to_string(body.size()) + "\r\n"
            "Connection: close\r\n\r\n";
        std::string response = header + body;
        send(fd, response.c_str(), response.size(), 0);
        return false;
    }

    // WebSocket upgrade: извлекаем ключ клиента и формируем ответный заголовок
    std::string key    = extract_header(http_request, "Sec-WebSocket-Key");
    std::string accept = ws_accept_key(key);

    std::string response =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: " + accept + "\r\n\r\n";

    send(fd, response.c_str(), response.size(), 0);
    return true;
}

// ─────────────────────────────────────────────────────────
//  WebSocket фреймы
// ─────────────────────────────────────────────────────────

// Читает один WebSocket-фрейм из сокета согласно RFC 6455.
// Поддерживает 7-битную, 16-битную и 64-битную длину payload.
// Снимает маску клиента (клиент → сервер всегда маскируется).
// Автоматически отвечает на Ping фреймом Pong.
// Возвращает текстовый payload или пустую строку при ошибке/закрытии.
static std::string ws_recv_frame(int fd) {
    // Лямбда для надёжного чтения ровно n байт из сокета
    auto read_bytes = [&](void* buf, size_t n) -> bool {
        size_t got = 0;
        while (got < n) {
            ssize_t r = recv(fd, (char*)buf + got, n - got, 0);
            if (r <= 0) return false;
            got += r;
        }
        return true;
    };

    // Первый байт: FIN-бит (7) + RSV (6-4) + opcode (3-0)
    uint8_t b0;
    if (!read_bytes(&b0, 1)) return "";
    uint8_t opcode = b0 & 0x0F;

    // Опкоды: 0x1 = текстовый фрейм, 0x8 = закрытие соединения,
    //         0x9 = ping,            0xA = pong
    if (opcode == 0x8) return "";  // клиент инициировал закрытие

    // Второй байт: MASK-бит (7) + базовая длина payload (6-0)
    uint8_t b1;
    if (!read_bytes(&b1, 1)) return "";
    bool    masked      = (b1 & 0x80) != 0;
    uint64_t payload_len = b1 & 0x7F;

    // Расширенная длина: 126 → следующие 2 байта, 127 → следующие 8 байт
    if (payload_len == 126) {
        uint16_t ext;
        if (!read_bytes(&ext, 2)) return "";
        payload_len = ntohs(ext);
    } else if (payload_len == 127) {
        uint64_t ext;
        if (!read_bytes(&ext, 8)) return "";
        payload_len = be64toh(ext);
    }

    // Читаем 4-байтовую маску (присутствует только в направлении клиент → сервер)
    uint8_t mask[4] = {};
    if (masked) {
        if (!read_bytes(mask, 4)) return "";
    }

    // Защита от огромных фреймов (> 1 МБ)
    if (payload_len > 1024 * 1024) return "";
    std::vector<uint8_t> payload(payload_len);
    if (payload_len > 0 && !read_bytes(payload.data(), payload_len)) return "";

    // Демаскирование: каждый байт XOR-ится с соответствующим байтом маски
    if (masked) {
        for (size_t i = 0; i < payload_len; ++i)
            payload[i] ^= mask[i % 4];
    }

    // Ping → отвечаем Pong и рекурсивно читаем следующий фрейм
    if (opcode == 0x9) {
        uint8_t pong[2] = { 0x8A, 0x00 }; // FIN + opcode 0xA (pong), длина 0
        send(fd, pong, 2, 0);
        return ws_recv_frame(fd);
    }

    return std::string(payload.begin(), payload.end());
}

// Отправляет текстовый WebSocket-фрейм (сервер → клиент).
// Сервер НЕ маскирует исходящие фреймы (RFC 6455 §5.1).
// Поддерживает payload любой длины: до 125 байт, до 65535 байт, и более.
static bool ws_send_frame(int fd, const std::string& text) {
    size_t len = text.size();
    std::vector<uint8_t> frame;
    frame.reserve(len + 10); // максимальный overhead заголовка — 10 байт

    frame.push_back(0x81); // FIN=1, opcode=0x1 (текстовый фрейм)

    // Кодируем длину payload в соответствии с RFC 6455
    if (len <= 125) {
        frame.push_back((uint8_t)len);          // 7-битная длина
    } else if (len <= 65535) {
        frame.push_back(126);                   // признак 16-битной длины
        frame.push_back((len >> 8) & 0xFF);
        frame.push_back(len & 0xFF);
    } else {
        frame.push_back(127);                   // признак 64-битной длины
        for (int i = 7; i >= 0; --i)
            frame.push_back((len >> (i * 8)) & 0xFF);
    }

    // Добавляем payload без маскирования
    for (char c : text) frame.push_back((uint8_t)c);

    ssize_t sent = send(fd, frame.data(), frame.size(), MSG_NOSIGNAL);
    return sent == (ssize_t)frame.size();
}