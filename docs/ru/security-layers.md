# Слои безопасности

Этот документ описывает стратегию глубокоэшелонированной защиты, реализованную в angie-modsecurity-docker, и как каждый слой взаимодействует с другими.

## Обзор

Безопасность в angie-modsecurity-docker реализована через множественные перекрывающиеся слои. Каждый слой служит определенной цели и ловит разные типы угроз.

```
┌─────────────────────────────────────────────────────────┐
│ Слой 4: Аутентификация (OAuth2-Proxy)                   │
│ Цель: Идентификация и авторизация                       │
│ Защищает: Чувствительные ресурсы                        │
└─────────────────────────────────────────────────────────┘
                          ↑
┌─────────────────────────────────────────────────────────┐
│ Слой 3: Баны IP (Fail2Ban)                              │
│ Цель: Блокировка на основе паттернов                    │
│ Защищает: От настойчивых атакующих                      │
└─────────────────────────────────────────────────────────┘
                          ↑
┌─────────────────────────────────────────────────────────┐
│ Слой 2: WAF (ModSecurity + CRS)                         │
│ Цель: Обнаружение атак на уровне приложения             │
│ Защищает: От SQLi, XSS, RCE и т.д.                      │
└─────────────────────────────────────────────────────────┘
                          ↑
┌─────────────────────────────────────────────────────────┐
│ Слой 1: Rate Limiting (Angie)                           │
│ Цель: Защита ресурсов                                   │
│ Защищает: От DDoS, brute force                          │
└─────────────────────────────────────────────────────────┘
                          ↑
                    Интернет трафик
```

## Слой 1: Rate Limiting (Angie)

### Цель

Защита ресурсов сервера от исчерпания путем ограничения скорости запросов до начала дорогостоящей обработки.

### Конфигурация

```nginx
# Из includes/security/rate-limiting.conf

# Определение зон
limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=static:10m rate=50r/s;
limit_req_zone $binary_remote_addr zone=api:10m rate=5r/s;
limit_req_zone $binary_remote_addr zone=forms:10m rate=2r/s;

# Глобальные настройки
limit_req_status 429;
limit_req_log_level warn;
```

### Применение

```nginx
# В виртуальном хосте
location / {
    limit_req zone=general burst=20 nodelay;
    # ... остальная конфигурация
}

location ~* \.(jpg|jpeg|png|css|js)$ {
    limit_req zone=static burst=100 nodelay;
    # ... остальная конфигурация
}
```

### Что ловит

1. **DDoS атаки**: 100+ запросов/секунду с одного IP
2. **Brute Force**: Быстрые попытки входа
3. **Исчерпание ресурсов**: Слишком много одновременных соединений
4. **Скрейпинг**: Автоматическое извлечение контента

### Интеграция с другими слоями

**С ModSecurity**:
- Rate limiting выполняется ПЕРВЫМ (более дешевая операция)
- Предотвращает перегрузку ModSecurity запросами
- ModSecurity видит только запросы в пределах лимита

**С Fail2Ban**:
- Fail2Ban может отслеживать 429 ответы (опционально)
- Постоянные превышения rate limit → бан IP
- Двухуровневая защита: rate limit + ban

## Слой 2: Web Application Firewall (ModSecurity)

### Цель

Обнаружение и блокировка атак на уровне приложения путем анализа HTTP запросов и ответов по правилам безопасности.

### Конфигурация

```nginx
# Из angie.conf
load_module modules/ngx_http_modsecurity_module.so;

# Из виртуального хоста
modsecurity on;
modsecurity_rules_file /etc/angie/modsecurity/rules.conf;
```

```
# Из modsec/rules.conf
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off

# OWASP CRS
Include /var/lib/angie/modsecurity/coreruleset/crs-setup.conf
Include /var/lib/angie/modsecurity/coreruleset/rules/*.conf

# Пользовательские исключения
Include /etc/angie/modsecurity/exclusions.conf
```

### Что ловит

1. **SQL Injection (SQLi)**: `' OR 1=1--`, `UNION SELECT` и т.д.
2. **Cross-Site Scripting (XSS)**: `<script>`, `onerror=`, `javascript:`
3. **Remote Code Execution (RCE)**: Shell команды, eval() и т.д.
4. **Local File Inclusion (LFI)**: `../../etc/passwd`
5. **Command Injection**: `; rm -rf /`, `| cat /etc/passwd`
6. **Нарушения протокола**: Неправильный HTTP, отсутствующие заголовки
7. **Плохие боты**: Известные вредоносные user agents

### Как работает

**Фаза запроса**:
```
Запрос: GET /admin?id=1' OR '1'='1

Обработка ModSecurity:
    ↓
Парсинг запроса
    ↓
Применение цепочки правил (931+ правил)
    ↓
Правило 942100: SQL Injection обнаружено → Score: +5 ⚠
  Паттерн: ' OR '.*?'
  Переменная: ARGS:id
    ↓
Правило 942190: SQL comment sequence → Score: +5 ⚠
    ↓
Итоговый Anomaly Score: 10
Порог: 5
    ↓
Решение: БЛОКИРОВАТЬ 🛑
    ↓
Запись в error.log
    ↓
Возврат: 403 Forbidden
```

### Интеграция с Fail2Ban

```ini
# fail2ban/jail.d/angie.conf
[angie-modsecurity]
enabled = true
filter = angie-modsecurity
logpath = /var/log/angie/error.log
maxretry = 3      # 3 блокировки ModSecurity
findtime = 300    # за 5 минут
bantime = 7200    # бан на 2 часа
```

**Сценарий атаки**:
```
Попытка 1: SQL injection → ModSecurity: БЛОК (403)
  → Fail2Ban счетчик: 1

Попытка 2: UNION SELECT → ModSecurity: БЛОК (403)
  → Fail2Ban счетчик: 2

Попытка 3: admin' -- → ModSecurity: БЛОК (403)
  → Fail2Ban счетчик: 3 → ПОРОГ ПРЕВЫШЕН
  → Fail2Ban: БАН IP на 2 часа

Попытка 4: (любой запрос)
  → iptables: DROP (пакет не достигает Angie)
```

## Слой 3: Баны IP (Fail2Ban)

### Цель

Автоматически банить IP-адреса, демонстрирующие вредоносные паттерны, путем анализа логов и применения правил firewall.

### Архитектура

```
Angie пишет логи
    ↓
/var/log/angie/access.log (все запросы)
/var/log/angie/error.log  (блокировки ModSecurity)
    ↓
Fail2Ban читает логи в реальном времени
    ↓
Применение regex фильтров
    ↓
Извлечение IP адресов
    ↓
Подсчет нарушений по IP
    ↓
Если порог превышен:
  └─> бан через iptables
```

### Конфигурация

```ini
# fail2ban/jail.d/angie.conf

[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 172.18.0.0/16

# Jail 1: Плохие HTTP запросы (400 ошибки)
[angie-bad-request]
enabled = true
filter = angie-bad-request
logpath = /var/log/angie/access.log
maxretry = 5
findtime = 300
bantime = 3600

# Jail 2: Нарушения ModSecurity
[angie-modsecurity]
enabled = true
filter = angie-modsecurity
logpath = /var/log/angie/error.log
maxretry = 3
findtime = 300
bantime = 7200

# Jail 3: Обнаружение сканера (404 сканирование)
[angie-scan]
enabled = true
filter = angie-scan
logpath = /var/log/angie/access.log
maxretry = 10
findtime = 600
bantime = 86400

# Jail 4: DDoS защита
[angie-ddos]
enabled = true
filter = angie-ddos
logpath = /var/log/angie/access.log
maxretry = 100
findtime = 60
bantime = 600
```

### Как работает

**Пример: Атакующий сканирует на наличие уязвимостей**

```
Время 15:00:00 - GET /admin.php → 404
  Fail2Ban: счетчик angie-scan[203.0.113.100] = 1

Время 15:00:05 - GET /wp-admin/ → 404
  Fail2Ban: счетчик angie-scan[203.0.113.100] = 2

... (продолжается)

Время 15:05:00 - GET /config.php → 404
  Fail2Ban: счетчик angie-scan[203.0.113.100] = 10
  Порог: maxretry=10, findtime=600s (10 мин)
  Решение: БАН 🔒

  Выполнение:
    iptables -I f2b-angie-scan 1 \
             -s 203.0.113.100 \
             -j DROP

  Длительность бана: 86400s (24 часа)

Время 15:05:01 - Любой запрос от 203.0.113.100
  iptables: DROP (пакет отброшен до достижения Angie)
```

## Слой 4: Аутентификация (OAuth2-Proxy)

### Цель

Обеспечить аутентификацию и авторизацию для защищенных ресурсов с использованием Keycloak (или других OIDC провайдеров).

### Конфигурация

```nginx
# Из includes/auth/keycloak-auth.conf

# Внутренний auth endpoint
location = /oauth2/auth {
    internal;
    proxy_pass http://oauth2-proxy:4180/oauth2/auth;
    # ... настройки прокси
}

# OAuth2 endpoints (callback, sign-in/out)
location /oauth2/ {
    proxy_pass http://oauth2-proxy:4180;
    # ... настройки прокси
}
```

### Использование в защищенном location

```nginx
location /admin {
    auth_request /oauth2/auth;
    error_page 401 = @oauth2_signin;

    # Извлечение информации о пользователе
    auth_request_set $user $upstream_http_x_auth_request_user;
    auth_request_set $email $upstream_http_x_auth_request_email;

    # Передача бэкенду
    proxy_set_header X-User $user;
    proxy_set_header X-Email $email;
    proxy_pass http://backend:8080;
}
```

## Сводка взаимодействия слоев

### Сценарии глубокоэшелонированной защиты

**Сценарий 1: DDoS атака**

```
Слой 1 (Rate Limiting): ✓ БЛОКИРУЕТ большую часть трафика (429)
Слой 2 (ModSecurity): Не достигнут (сэкономлен CPU)
Слой 3 (Fail2Ban): Банит IP после превышения порога
Слой 4 (OAuth2): Не достигнут
```

**Сценарий 2: SQL Injection**

```
Слой 1 (Rate Limiting): ✓ ПРОПУСКАЕТ (в пределах лимита)
Слой 2 (ModSecurity): ✓ БЛОКИРУЕТ (обнаруживает SQLi, возвращает 403)
Слой 3 (Fail2Ban): Отслеживает нарушения, банит после 3 попыток
Слой 4 (OAuth2): Не достигнут
```

**Сценарий 3: Неавторизованный доступ**

```
Слой 1 (Rate Limiting): ✓ ПРОПУСКАЕТ
Слой 2 (ModSecurity): ✓ ПРОПУСКАЕТ (легитимная структура запроса)
Слой 3 (Fail2Ban): Не сработал
Слой 4 (OAuth2): ✓ БЛОКИРУЕТ (нет валидной сессии, редирект на логин)
```

**Сценарий 4: Легитимный пользователь**

```
Слой 1 (Rate Limiting): ✓ ПРОПУСКАЕТ (нормальная скорость)
Слой 2 (ModSecurity): ✓ ПРОПУСКАЕТ (нет вредоносных паттернов)
Слой 3 (Fail2Ban): Не сработал
Слой 4 (OAuth2): ✓ ПРОПУСКАЕТ (валидная сессия) → Бэкенд
```

### Порядок обработки

```
Интернет запрос
    ↓
[0] iptables (если IP забанен Fail2Ban) → DROP
    ↓
[1] Angie получает запрос
    ↓
[2] Rate Limiting → 429 или PASS
    ↓
[3] ModSecurity WAF → 403 или PASS
    ↓
[4] OAuth2 (если требуется) → 401/redirect или PASS
    ↓
[5] Бэкенд/Статический контент
    ↓
[6] ModSecurity фаза ответа
    ↓
[7] Отправка ответа
    ↓
[8] Логирование (асинхронное)
    ↓
[9] Fail2Ban читает логи (offline)
    ↓
[10] Fail2Ban обновляет iptables (при необходимости)
```

## Следующие шаги

- Настройка безопасности: [Руководство по конфигурации](configuration.md)
- Понимание потока запросов: [Путь запроса](request-flow.md)
- Мониторинг логов: [Система логирования](logging.md)
- Отладка проблем: [Устранение неполадок](troubleshooting.md)
