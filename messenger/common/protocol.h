#pragma once
#include <cstdint>
#include <string>

constexpr uint16_t DEFAULT_PORT     = 8080;
constexpr size_t   MAX_USERNAME_LEN = 32;
constexpr size_t   MAX_PASSWORD_LEN = 64;

// ─────────────────────────────────────────────────────────
//  Протокол: все сообщения — JSON через WebSocket
//
//  client → server:
//    { "cmd": "login",     "username": "...", "password": "..." }
//    { "cmd": "register",  "username": "...", "password": "..." }
//    { "cmd": "send_msg",  "to": "...",       "text": "..."    }
//    { "cmd": "list_users"                                      }
//    { "cmd": "history",   "with": "..."                       }
//
//  server → client:
//    { "cmd": "auth_ok",   "username": "..."                        }
//    { "cmd": "auth_fail", "reason":   "..."                        }
//    { "cmd": "recv_msg",  "from": "...", "text": "...", "ts": 0    }
//    { "cmd": "user_list", "users": ["alice","bob",...]             }
//    { "cmd": "history",   "with": "...", "messages": [...]         }
//    { "cmd": "notice",    "text": "..."                            }
//    { "cmd": "error",     "text": "..."                            }
// ─────────────────────────────────────────────────────────
