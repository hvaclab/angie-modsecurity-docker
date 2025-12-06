# Руководство по конфигурации

Этот документ описывает, как настроить интегрированный стек angie-modsecurity-docker для ваших конкретных нужд.

## Быстрый старт

### 1. Переменные окружения

Создайте `.env` файл из примера:

```bash
cp .env.example .env
```

Отредактируйте `.env`:

```bash
# Часовой пояс
TZ=Europe/Moscow

# Конфигурация Keycloak (если используется OAuth2)
KEYCLOAK_URL=https://keycloak.example.com
KEYCLOAK_REALM=myrealm
KEYCLOAK_CLIENT_ID=angie-client
KEYCLOAK_CLIENT_SECRET=your-secret-here
KEYCLOAK_REDIRECT_URI=https://example.com/oauth2/callback
KEYCLOAK_COOKIE_SECRET=generate-random-32-chars
KEYCLOAK_COOKIE_NAME=_oauth2_proxy
```

Сгенерируйте cookie secret:
```bash
python3 -c 'import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())'
```

### 2. Конфигурация виртуального хоста

Создайте ваш виртуальный хост в `angie/conf.d/yourdomain.com.conf`:

```nginx
server {
    listen 443 ssl;
    listen 443 quic reuseport;
    http2 on;

    server_name yourdomain.com;

    # ACME для Let's Encrypt
    acme letsencrypt;
    ssl_certificate     $acme_cert_letsencrypt;
    ssl_certificate_key $acme_cert_key_letsencrypt;

    # Анонс HTTP/3
    add_header Alt-Svc 'h3=":443"; ma=86400' always;

    # Заголовки безопасности
    include /etc/angie/includes/security/security-headers.conf;

    # ModSecurity
    modsecurity on;
    modsecurity_rules_file /etc/angie/modsecurity/rules.conf;

    root /var/www/html;

    location / {
        limit_req zone=general burst=20 nodelay;
        try_files $uri $uri/ =404;
    }

    location ~* \.(jpg|jpeg|png|gif|css|js)$ {
        limit_req zone=static burst=100 nodelay;
        expires 30d;
    }
}

server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$host$request_uri;
}
```

### 3. Запуск стека

```bash
docker compose up -d
```

## Конфигурация компонентов

### Angie веб-сервер

#### Rate Limiting зоны

Файл: `angie/includes/security/rate-limiting.conf`

Настройте rate limits под ваш трафик:

```nginx
# Общий трафик (настройте rate под ваши нужды)
limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;

# Статические файлы (браузеры загружают много параллельно)
limit_req_zone $binary_remote_addr zone=static:10m rate=50r/s;

# API endpoints (более строго)
limit_req_zone $binary_remote_addr zone=api:10m rate=5r/s;

# Формы (предотвращение спама)
limit_req_zone $binary_remote_addr zone=forms:10m rate=2r/s;
```

Использование в locations:
```nginx
location /api/ {
    limit_req zone=api burst=10 nodelay;
    # ... остальная конфигурация
}

location /contact-form {
    limit_req zone=forms burst=3 nodelay;
    # ... остальная конфигурация
}
```

### ModSecurity WAF

#### Базовая конфигурация

Файл: `modsec/rules.conf`

```
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off

# Временные директории
SecDataDir /tmp/
SecTmpDir /tmp/

# OWASP CRS
Include /var/lib/angie/modsecurity/coreruleset/crs-setup.conf
Include /var/lib/angie/modsecurity/coreruleset/rules/*.conf

# Пользовательские исключения
Include /etc/angie/modsecurity/exclusions.conf
```

#### Пользовательские исключения

Файл: `modsec/exclusions.conf`

```
# Пример: Отключить конкретное правило для endpoint загрузки
SecRule REQUEST_URI "@beginsWith /api/upload" \
    "id:1001,phase:1,pass,nolog,ctl:ruleRemoveById=920420"

# Пример: Увеличить лимит тела для конкретного API
SecRule REQUEST_URI "@beginsWith /api/data/bulk" \
    "id:1002,phase:1,pass,nolog,ctl:requestBodyLimit=10485760"

# Пример: Полностью отключить WAF для health checks
SecRule REQUEST_URI "@streq /health" \
    "id:1003,phase:1,pass,nolog,ctl:ruleEngine=Off"
```

### Fail2Ban

#### Конфигурация Jail

Файл: `fail2ban/jail.d/angie.conf`

Настройте пороги под ваше окружение:

```ini
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 172.18.0.0/16
# Добавьте ваши доверенные IP:
# ignoreip = 127.0.0.1/8 203.0.113.50

# Нарушения ModSecurity
[angie-modsecurity]
enabled = true
filter = angie-modsecurity
logpath = /var/log/angie/error.log
maxretry = 3       # Настройте: сколько нарушений до бана
findtime = 300     # Настройте: временное окно (5 минут)
bantime = 7200     # Настройте: длительность бана (2 часа)
action = iptables-allports[name=angie-modsec]

# Обнаружение сканера
[angie-scan]
enabled = true
filter = angie-scan
logpath = /var/log/angie/access.log
maxretry = 10      # Настройте: подозрительные 404
findtime = 600     # Настройте: временное окно (10 минут)
bantime = 86400    # Настройте: длительность бана (24 часа)
action = iptables-allports[name=angie-scan]

# DDoS защита
[angie-ddos]
enabled = true
filter = angie-ddos
logpath = /var/log/angie/access.log
maxretry = 100     # Настройте: на основе легитимного трафика
findtime = 60      # Настройте: временное окно (1 минута)
bantime = 600      # Настройте: длительность бана (10 минут)
action = iptables-allports[name=angie-ddos]
```

### OAuth2-Proxy аутентификация

#### Конфигурация окружения

В `.env`:

```bash
# Настройки Keycloak OIDC
KEYCLOAK_URL=https://keycloak.example.com
KEYCLOAK_REALM=production
KEYCLOAK_CLIENT_ID=angie-webapp
KEYCLOAK_CLIENT_SECRET=your-client-secret
KEYCLOAK_REDIRECT_URI=https://example.com/oauth2/callback

# Безопасность сессий
KEYCLOAK_COOKIE_SECRET=random-32-byte-string-base64
KEYCLOAK_COOKIE_NAME=_oauth2_proxy
```

#### Интеграция с Angie

Использование в виртуальном хосте:

```nginx
server {
    # ... SSL и другие настройки ...

    # Включить OAuth2-Proxy endpoints
    include /etc/angie/includes/auth/keycloak-auth.conf;

    # Защитить конкретные пути
    location /admin {
        # Требовать аутентификацию
        auth_request /oauth2/auth;
        error_page 401 = @oauth2_signin;

        # Извлечь информацию о пользователе
        auth_request_set $user $upstream_http_x_auth_request_user;
        auth_request_set $email $upstream_http_x_auth_request_email;

        # Передать бэкенду
        proxy_set_header X-User $user;
        proxy_set_header X-Email $email;

        proxy_pass http://admin-backend:8080;
    }

    # Публичные пути (без аутентификации)
    location / {
        root /var/www/html;
    }
}
```

### Vector лог пайплайн

#### Базовая конфигурация

Файл: `vector/vector.toml`

```toml
[sources.angie_logs]
type = "file"
include = ["/var/log/angie/access.log"]
read_from = "end"  # Измените на "beginning" для обработки существующих логов

[transforms.parse_json]
type = "remap"
inputs = ["angie_logs"]
source = '''
  . = parse_json!(.message)

  # Добавить метаданные
  .meta_enriched_by = "vector"
  .meta_enriched_at = now()

  # Вычислить security score
  score = 0
  if .security_suspicious_ua == "1" { score = score + 5 }
  if .security_suspicious_pattern == "1" { score = score + 7 }
  .security_score = score

  # Классифицировать threat level
  .security_threat_level = if score >= 10 { "high" }
                           else if score >= 5 { "medium" }
                           else { "safe" }
'''

[sinks.enriched_logs]
type = "file"
inputs = ["parse_json"]
path = "/var/log/angie/access_enriched.log"
encoding.codec = "json"
```

## Типичные сценарии

### Сценарий 1: Высоконагруженный сайт

Настройте rate limits:

```nginx
# Увеличить общий лимит
limit_req_zone $binary_remote_addr zone=general:20m rate=50r/s;
limit_req zone=general burst=100 nodelay;

# Увеличить лимит статических файлов
limit_req_zone $binary_remote_addr zone=static:20m rate=200r/s;
limit_req zone=static burst=300 nodelay;
```

### Сценарий 2: API сервер

Создайте специфичный для API rate limit:

```nginx
# Строгий API rate limiting
limit_req_zone $binary_remote_addr zone=api_public:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=api_authenticated:10m rate=100r/s;

location /api/ {
    limit_req zone=api_public burst=20 nodelay;

    modsecurity on;
    modsecurity_rules_file /etc/angie/modsecurity/rules.conf;

    proxy_pass http://api-backend:8080;
}
```

## Тестирование конфигурации

### Тест конфигурации Angie

```bash
docker exec angie angie -t
```

### Перезагрузка Angie

```bash
docker exec angie angie -s reload
```

### Тест ModSecurity

```bash
# Должен быть заблокирован (SQLi)
curl -X GET "https://example.com/?id=1' OR '1'='1"

# Проверка логов
docker exec angie tail /var/log/angie/error.log | grep ModSecurity
```

### Тест Rate Limiting

```bash
# Отправить быстрые запросы
for i in {1..50}; do
    curl -w "%{http_code}\n" https://example.com/
done

# Должны увидеть 200s, затем 429s
```

### Тест Fail2Ban

```bash
# Проверка статуса
docker exec fail2ban fail2ban-client status

# Проверка конкретного jail
docker exec fail2ban fail2ban-client status angie-modsecurity

# Проверка забаненных IP
docker exec fail2ban fail2ban-client status angie-modsecurity | grep "Banned IP"
```

## Следующие шаги

- Понимание архитектуры: [Архитектура](architecture.md)
- Мониторинг логов: [Система логирования](logging.md)
- Отладка проблем: [Устранение неполадок](troubleshooting.md)
- Обзор безопасности: [Слои безопасности](security-layers.md)
