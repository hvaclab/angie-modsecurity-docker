# Angie Configuration Includes

Эта директория содержит общие конфигурационные файлы, которые подключаются в основной конфигурации и виртуальных хостах.

## Структура

```
includes/
├── auth/           # Аутентификация и авторизация
│   ├── keycloak-auth.conf
│   └── keycloak-protected-paths.conf
├── security/       # Настройки безопасности
│   ├── security-headers.conf
│   ├── rate-limiting.conf
│   └── ssl-params.conf
└── logs/          # Логирование
    ├── log-formats.conf
    └── enrichment.conf
```

## Описание категорий

### auth/ - Аутентификация

- **keycloak-auth.conf** - базовая настройка OAuth2-proxy для Keycloak
  - Internal endpoints для проверки авторизации
  - OAuth2 callback и sign-in/out
  - Error pages для редиректа на страницу входа

- **keycloak-protected-paths.conf** - список путей, защищённых OAuth авторизацией
  - Добавляйте сюда location блоки для защищённых ресурсов
  - Примеры использования приведены в самом файле

### security/ - Безопасность

- **security-headers.conf** - заголовки безопасности
  - HSTS, CSP, X-Frame-Options, X-Content-Type-Options
  - Permissions-Policy
  - Referrer-Policy

- **rate-limiting.conf** - защита от DDoS и перегрузок
  - Зоны rate limiting для разных типов запросов
  - Настройки лимитов для general, static, api

- **ssl-params.conf** - параметры SSL/TLS
  - Протоколы и cipher suites
  - Session cache и tickets
  - OCSP stapling

### logs/ - Логирование

- **log-formats.conf** - форматы логов
  - JSON формат для структурированного логирования
  - Обогащённые форматы с дополнительными полями

- **enrichment.conf** - обогащение логов
  - GeoIP данные (страна, город)
  - User-Agent парсинг
  - Security метрики
  - Performance метрики

## Использование

### В главном конфиге (angie.conf)

```nginx
http {
    # Безопасность
    include /etc/angie/includes/security/rate-limiting.conf;
    include /etc/angie/includes/security/ssl-params.conf;

    # Логирование
    include /etc/angie/includes/logs/enrichment.conf;
    include /etc/angie/includes/logs/log-formats.conf;
}
```

### В виртуальном хосте (conf.d/*.conf)

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    # Security headers
    include /etc/angie/includes/security/security-headers.conf;

    # Keycloak authentication
    include /etc/angie/includes/auth/keycloak-auth.conf;
    include /etc/angie/includes/auth/keycloak-protected-paths.conf;

    # ... остальная конфигурация
}
```

## Добавление нового защищённого пути

Чтобы защитить путь OAuth авторизацией:

1. Убедитесь, что в server блоке подключен `keycloak-auth.conf`
2. Откройте `auth/keycloak-protected-paths.conf`
3. Добавьте новый location блок:

```nginx
location /admin {
    auth_request /oauth2/auth;
    error_page 401 = @oauth2_signin;

    auth_request_set $user $upstream_http_x_auth_request_user;
    auth_request_set $email $upstream_http_x_auth_request_email;

    # Ваша конфигурация...
}
```

## Примечания

- Все файлы монтируются в Docker контейнер как read-only (`:ro`)
- После изменений необходимо перезапустить контейнер: `docker compose restart angie`
- Для проверки конфигурации: `docker compose exec angie angie -t`
