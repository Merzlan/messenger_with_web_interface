#pragma once
#include <string>
#include <fstream>
#include <mutex>
#include <ctime>
#include <iostream>

// Уровни логирования: INFO — обычные события, WARN — предупреждения, ERR — ошибки
enum class LogLevel { INFO, WARN, ERR };

// Потокобезопасный логгер: пишет в stdout и опционально в файл
class Logger {
public:
    // path — путь к файлу лога; если пустой, запись идёт только в stdout
    explicit Logger(const std::string& path = "") {
        if (!path.empty()) {
            file_.open(path, std::ios::app); // открываем в режиме дозаписи
            if (!file_.is_open())
                std::cerr << "[Logger] Cannot open: " << path << "\n";
        }
    }

    // Удобные обёртки для каждого уровня
    void info (const std::string& msg) { write(LogLevel::INFO, msg); }
    void warn (const std::string& msg) { write(LogLevel::WARN, msg); }
    void error(const std::string& msg) { write(LogLevel::ERR,  msg); }

    // Основной метод: форматирует строку «TIMESTAMP [LEVEL] msg» и выводит её
    void write(LogLevel lvl, const std::string& msg) {
        std::lock_guard<std::mutex> lock(mtx_); // защита от гонок при многопоточной записи
        std::string line = timestamp() + " [" + level_str(lvl) + "] " + msg;
        std::cout << line << "\n" << std::flush;
        if (file_.is_open())
            file_ << line << "\n" << std::flush; // дублируем в файл, если он открыт
    }

private:
    std::ofstream file_; // файловый поток лога
    std::mutex    mtx_;  // мьютекс для потокобезопасности

    // Возвращает текущее время в формате «YYYY-MM-DD HH:MM:SS»
    static std::string timestamp() {
        std::time_t t = std::time(nullptr);
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&t));
        return buf;
    }

    // Преобразует уровень в строковую метку для вывода
    static const char* level_str(LogLevel l) {
        switch (l) {
            case LogLevel::INFO: return "INFO";
            case LogLevel::WARN: return "WARN";
            case LogLevel::ERR:  return "ERROR";
        }
        return "?";
    }
};