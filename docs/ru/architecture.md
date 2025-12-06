# Архитектура системы

Этот документ описывает, как компоненты в angie-modsecurity-docker связаны и как они взаимодействуют друг с другом.

## Диаграмма компонентов

```
┌─────────────────────────────────────────────────────────────────┐
│                         Docker Host                              │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                    angie_network (bridge)                   │ │
│  │                                                              │ │
│  │  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐ │ │
│  │  │    Angie     │───▶│ OAuth2-Proxy │    │   Vector     │ │ │
│  │  │  Port 80/443 │    │  Port 4180   │    │              │ │ │
│  │  │              │    │              │    │              │ │ │
│  │  │ + ModSecurity│    │ (Keycloak)   │    │ (Обогащение) │ │ │
│  │  └──────┬───────┘    └──────────────┘    └──────┬───────┘ │ │
│  │         │                                        │         │ │
│  └─────────┼────────────────────────────────────────┼─────────┘ │
│            │                                        │           │
│            │         ┌──────────────────┐           │           │
│            │         │ Директория логов │           │           │
│            └────────▶│ /var/log/angie/  │◀──────────┘           │
│                      │                  │                       │
│                      │ • access.log     │                       │
│                      │ • error.log      │                       │
│                      │ • access_enri... │                       │
│                      └────────┬─────────┘                       │
│                               │                                 │
│                               │ (только чтение)                 │
│                               │                                 │
│                      ┌────────▼─────────┐                       │
│                      │    Fail2Ban      │                       │
│                      │  (network: host) │                       │
│                      │                  │                       │
│                      │  • Читает логи   │                       │
│                      │  • Банит IP      │                       │
│                      └──────────────────┘                       │
│                               │                                 │
└───────────────────────────────┼─────────────────────────────────┘
                                │
                                ▼
                        Host iptables
                        (блокировка IP)
```

## Ответственность компонентов

### 1. Angie (Веб-сервер + ModSecurity)

**Контейнер**: `angie`
**Сеть**: `angie_network` + открытые порты 80, 443
**Образ**: Собственная сборка с модулем ModSecurity

**Основные функции**:
- Обработка HTTP/HTTPS/HTTP3 запросов
- Терминация SSL/TLS
- Rate limiting (до ModSecurity)
- Обратное проксирование к бэкенд-сервисам
- Выполнение ModSecurity WAF
- Обогащение логов (GeoIP, анализ User-Agent)
- Запросы OAuth2 аутентификации

**Ключевая конфигурация**:
```yaml
# Из compose.yml
ports:
  - "80:80"
  - "443:443/tcp"
  - "443:443/udp"  # HTTP/3 (QUIC)

volumes:
  - ./angie/angie.conf:/etc/angie/angie.conf:ro
  - ./angie/includes:/etc/angie/includes:ro
  - ./logs:/var/log/angie
  - ./modsec:/etc/angie/modsecurity:ro
```

**Точки интеграции**:
- Пишет логи в общую директорию `/var/log/angie`
- Проксирует запросы аутентификации к контейнеру OAuth2-Proxy
- Встраивает ModSecurity как динамический модуль
- Использует общую Docker-сеть для разрешения имен контейнеров

См. [Путь запроса](request-flow.md) для деталей обработки запросов.

### 2. ModSecurity (Web Application Firewall)

**Расположение**: Загружается как модуль Angie
**Не отдельный контейнер**

**Основные функции**:
- Анализ HTTP запросов и ответов
- Применение OWASP Core Rule Set (CRS)
- Блокировка вредоносных паттернов (SQLi, XSS и т.д.)
- Запись событий блокировки в error log

**Ключевая конфигурация**:
```nginx
# Из angie.conf
load_module modules/ngx_http_modsecurity_module.so;

# Из конфига виртуального хоста
modsecurity on;
modsecurity_rules_file /etc/angie/modsecurity/rules.conf;
```

**Точки интеграции**:
- Встроен в процесс Angie (не отдельный)
- Логирует нарушения в `/var/log/angie/error.log`
- Блокировки происходят до отправки ответа
- Работает с rate limiting Angie

См. [Слои безопасности](security-layers.md#modsecurity-layer) для деталей WAF.

### 3. OAuth2-Proxy (Аутентификация)

**Контейнер**: `oauth2-proxy`
**Сеть**: `angie_network` (только внутренняя)
**Порт**: 4180 (не открыт наружу)

**Основные функции**:
- OIDC аутентификация с Keycloak
- Управление cookie сессиями
- Извлечение информации о пользователе
- Обработка auth subrequest

**Ключевая конфигурация**:
```yaml
# Из compose.yml
environment:
  - OAUTH2_PROXY_PROVIDER=keycloak-oidc
  - OAUTH2_PROXY_CLIENT_ID=${KEYCLOAK_CLIENT_ID}
  - OAUTH2_PROXY_HTTP_ADDRESS=0.0.0.0:4180
  - OAUTH2_PROXY_REVERSE_PROXY=true
```

**Точки интеграции**:
- Получает auth subrequest от Angie
- Возвращает заголовки пользователя (X-Auth-Request-User, X-Auth-Request-Email)
- Обрабатывает OAuth2 callback и редиректы
- Недоступен напрямую из интернета

**Интеграция с Angie**:
```nginx
# Из keycloak-auth.conf
location = /oauth2/auth {
    internal;
    proxy_pass http://oauth2-proxy:4180/oauth2/auth;
    # ... настройки прокси
}

# В защищенных location
auth_request /oauth2/auth;
error_page 401 = @oauth2_signin;
```

См. [Руководство по конфигурации](configuration.md#oauth2-authentication) для деталей настройки.

### 4. Vector (Обогащение логов)

**Контейнер**: `vector`
**Сеть**: `angie_network`
**Нет открытых портов**

**Основные функции**:
- Чтение JSON логов Angie
- Парсинг и обогащение данных логов
- Вычисление security score
- Запись обогащенных логов

**Ключевая конфигурация**:
```toml
# Из vector.toml
[sources.angie_logs]
type = "file"
include = ["/var/log/angie/access.log"]

[transforms.parse_json]
type = "remap"
# Вычисляет security_score
# Добавляет классификацию threat_level

[sinks.enriched_logs]
type = "file"
path = "/var/log/angie/access_enriched.log"
```

**Точки интеграции**:
- Читает из общей директории логов
- Пишет обратно в ту же директорию
- Независимая обработка (не блокирует запросы)
- Добавляет слой интеллекта для анализа

См. [Система логирования](logging.md#vector-enrichment) для деталей пайплайна.

### 5. Fail2Ban (Баны IP)

**Контейнер**: `fail2ban`
**Сеть**: `host` (необходим доступ к iptables хоста)
**Привилегированный**: Да (нужен доступ к iptables)

**Основные функции**:
- Мониторинг логов Angie на наличие паттернов
- Обнаружение повторяющихся нарушений
- Бан IP через iptables
- Автоматический разбан после таймаута

**Ключевая конфигурация**:
```yaml
# Из compose.yml
network_mode: "host"  # Необходимо для iptables
volumes:
  - ./logs:/var/log/angie:ro
  - ./fail2ban:/data
```

**Конфигурация Jail**:
```ini
# Из jail.d/angie.conf
[angie-modsecurity]
enabled = true
filter = angie-modsecurity
logpath = /var/log/angie/error.log
maxretry = 3
findtime = 300
bantime = 7200
action = iptables-allports[name=angie-modsec]
```

**Точки интеграции**:
- Читает логи через read-only монтирование
- Использует host network для модификации iptables
- Множественные фильтры для разных типов атак
- Независим от обработки запросов

См. [Слои безопасности](security-layers.md#fail2ban-layer) для логики банов.

## Паттерны потока данных

### Общая директория логов

Директория `/var/log/angie` является центральным коммуникационным хабом:

```
/var/log/angie/
├── access.log              (Пишет: Angie)
│                          (Читают: Fail2Ban, Vector)
├── error.log               (Пишут: Angie + ModSecurity)
│                          (Читает: Fail2Ban)
└── access_enriched.log     (Пишет: Vector)
```

**Точки монтирования**:
```yaml
# Angie: Чтение-запись
- ./logs:/var/log/angie

# Fail2Ban: Только чтение
- ./logs:/var/log/angie:ro

# Vector: Чтение-запись
- ./logs:/var/log/angie
```

## Следующие шаги

- Понимание обработки запросов: [Путь запроса](request-flow.md)
- Изучение реализации безопасности: [Слои безопасности](security-layers.md)
- Настройка стека: [Руководство по конфигурации](configuration.md)
- Мониторинг операций: [Система логирования](logging.md)
