# Руководство по устранению неполадок

Этот документ помогает диагностировать и решать типичные проблемы в интегрированном стеке angie-modsecurity-docker.

## Подход к диагностике

При устранении неполадок следуйте этому систематическому подходу:

```
1. Определите симптом
2. Определите затронутый слой
3. Проверьте релевантные логи
4. Проверьте конфигурацию
5. Тестируйте изолированно
6. Примените исправление
7. Проверьте решение
```

## Быстрая диагностика

### Проверка статуса всех контейнеров

```bash
docker compose ps
```

Ожидаемый вывод:
```
NAME            STATUS          PORTS
angie           Up 5 minutes    0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp
oauth2-proxy    Up 5 minutes
vector          Up 5 minutes
fail2ban        Up 5 minutes
```

### Проверка логов всех сервисов

```bash
# Angie access log
docker exec angie tail -20 /var/log/angie/access.log

# Angie error log
docker exec angie tail -20 /var/log/angie/error.log

# OAuth2-Proxy
docker logs --tail 20 oauth2-proxy

# Vector
docker logs --tail 20 vector

# Fail2Ban
docker logs --tail 20 fail2ban
```

## Категории проблем

### 1. Проблемы подключения

#### Симптом: Невозможно подключиться к порту 80/443

**Проверка 1: Контейнер запущен**
```bash
docker compose ps angie
```

**Проверка 2: Привязка порта**
```bash
docker compose ps | grep angie
# Должно показать: 0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp
```

**Проверка 3: Firewall**
```bash
# Проверка firewall хоста
sudo iptables -L -n | grep -E '80|443'

# Проверка Docker iptables
sudo iptables -t nat -L -n
```

**Решение**:
- Если контейнер не запущен: `docker compose up -d angie`
- Если порты не привязаны: Проверьте конфликты портов с `sudo netstat -tlnp | grep -E ':80|:443'`
- Если firewall блокирует: `sudo ufw allow 80/tcp && sudo ufw allow 443/tcp`

#### Симптом: SSL/TLS ошибки

**Проверка 1: Статус сертификата**
```bash
# Тест SSL соединения
openssl s_client -connect example.com:443 -servername example.com

# Проверка сертификата в Angie
docker exec angie openssl x509 -in /etc/ssl/certs/default-selfsigned.crt -text -noout
```

**Проверка 2: Статус ACME (если используется Let's Encrypt)**
```bash
# Проверка ACME логов
docker exec angie tail -50 /var/log/angie/error.log | grep -i acme

# Проверка файлов сертификатов
docker exec angie ls -la /var/lib/angie/acme/
```

### 2. Проблемы Rate Limiting

#### Симптом: Легитимный трафик получает 429 ошибки

**Проверка 1: Логи rate limit**
```bash
docker exec angie tail -50 /var/log/angie/error.log | grep "limiting requests"
```

**Проверка 2: Текущие лимиты**
```bash
docker exec angie grep -A 5 "limit_req_zone" /etc/angie/includes/security/rate-limiting.conf
```

**Решение**: Настройте rate limits

```nginx
# В rate-limiting.conf
# Увеличить rate с 10r/s до 50r/s
limit_req_zone $binary_remote_addr zone=general:10m rate=50r/s;

# Увеличить burst с 20 до 100
# В виртуальном хосте
limit_req zone=general burst=100 nodelay;
```

**Перезагрузка Angie**:
```bash
docker exec angie angie -t && docker exec angie angie -s reload
```

### 3. Проблемы ModSecurity

#### Симптом: Ложные срабатывания (легитимные запросы блокируются)

**Проверка 1: Найдите заблокированный запрос в логах**
```bash
docker exec angie grep "ModSecurity: Access denied" /var/log/angie/error.log | tail -5
```

Пример:
```
ModSecurity: Access denied with code 403 (phase 2). Matched ... [id "942100"] [msg "SQL Injection Attack"] ... request: "GET /search?q=what's+new"
```

**Решение**: Добавьте исключение

```
# В modsec/exclusions.conf

# Отключить правило 942100 для поисковых запросов
SecRule REQUEST_URI "@beginsWith /search" \
    "id:1000,phase:1,pass,nolog,ctl:ruleRemoveById=942100"
```

**Перезагрузка Angie**:
```bash
docker exec angie angie -s reload
```

### 4. Проблемы Fail2Ban

#### Симптом: IP не банятся

**Проверка 1: Статус Fail2Ban**
```bash
docker exec fail2ban fail2ban-client status
```

Должен показать активные jails:
```
Status
|- Number of jail:      4
`- Jail list:   angie-modsecurity, angie-scan, angie-ddos, angie-bad-request
```

**Проверка 2: Проверка конкретного jail**
```bash
docker exec fail2ban fail2ban-client status angie-modsecurity
```

**Проверка 3: Тест фильтра**
```bash
docker exec fail2ban fail2ban-regex /var/log/angie/error.log /data/filter.d/angie-modsecurity.conf
```

**Решение**: Типичные исправления

```ini
# В jail.d/angie.conf

# Проверьте путь к логу правильный
logpath = /var/log/angie/error.log  # Внутри контейнера

# Снизьте порог для тестирования
maxretry = 1
findtime = 60
bantime = 300
```

**Перезапуск Fail2Ban**:
```bash
docker compose restart fail2ban
```

#### Симптом: Легитимные IP банятся

**Решение**: Добавьте IP в whitelist

```ini
# В jail.d/angie.conf
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 172.18.0.0/16 203.0.113.50
```

**Разбан и перезапуск**:
```bash
docker exec fail2ban fail2ban-client set angie-scan unbanip 203.0.113.50
docker compose restart fail2ban
```

### 5. Проблемы OAuth2-Proxy

#### Симптом: Цикл аутентификации (redirect loop)

**Проверка 1: Логи OAuth2-Proxy**
```bash
docker logs oauth2-proxy | tail -50
```

**Проверка 2: Настройки cookie**
```bash
docker exec oauth2-proxy env | grep COOKIE
```

**Решение**:

```yaml
# В compose.yml
environment:
  - OAUTH2_PROXY_COOKIE_SECURE=true  # Требует HTTPS
  - OAUTH2_PROXY_COOKIE_DOMAINS=.example.com  # Соответствует вашему домену
  - OAUTH2_PROXY_COOKIE_SAMESITE=lax  # Разрешает редиректы
```

#### Симптом: 401 Unauthorized на защищенных путях

**Проверка 1: Тест OAuth2 endpoint**
```bash
# Должен редиректить на логин
curl -v https://example.com/admin
```

**Проверка 2: Проверка доступности OAuth2-Proxy**
```bash
docker exec angie curl -v http://oauth2-proxy:4180/ping
```

**Решение**: Обеспечьте правильную конфигурацию

```nginx
# Включите OAuth2 config
include /etc/angie/includes/auth/keycloak-auth.conf;

location /admin {
    auth_request /oauth2/auth;
    error_page 401 = @oauth2_signin;

    # ... остальная конфигурация
}
```

### 6. Проблемы логирования

#### Симптом: Логи не записываются

**Проверка 1: Права на директорию логов**
```bash
ls -la logs/
```

Должна быть доступна для записи контейнером.

**Проверка 2: Место на диске**
```bash
df -h logs/
```

**Решение**:
```bash
# Исправление прав
chmod 755 logs/

# Создание файлов логов если отсутствуют
touch logs/access.log logs/error.log
chmod 644 logs/*.log
```

#### Симптом: Vector не обогащает логи

**Проверка 1: Статус Vector**
```bash
docker logs vector | tail -20
```

**Проверка 2: Проверка чтения логов Vector**
```bash
docker exec vector ls -la /var/log/angie/access.log
```

**Решение**: Перезапуск Vector

```bash
docker compose restart vector

# Отслеживание обработки
docker logs -f vector
```

### 7. Проблемы производительности

#### Симптом: Высокая загрузка CPU

**Проверка 1: Определите контейнер**
```bash
docker stats --no-stream
```

**Если Angie высокая CPU**:
- Проверьте на DDoS: `docker exec angie tail -100 /var/log/angie/access.log | jq -r '.client_ip' | sort | uniq -c | sort -rn`
- Проверьте нагрузку ModSecurity: Попробуйте отключить временно
- Проверьте время ответа upstream: `docker exec angie cat /var/log/angie/access.log | jq -r '.perf_upstream_time'`

**Решение**: Оптимизация конфигурации

```nginx
# Отключить ModSecurity для статических файлов
location ~* \.(jpg|png|css|js)$ {
    modsecurity off;
    # ... остальное
}

# Уменьшить уровень логирования
error_log /var/log/angie/error.log error;  # Только ошибки, не warnings
```

## Экстренные процедуры

### Полный отказ стека

```bash
# Остановка всех контейнеров
docker compose down

# Проверка Docker daemon
sudo systemctl status docker

# Проверка системных ресурсов
df -h
free -h

# Перезапуск стека
docker compose up -d

# Мониторинг запуска
docker compose logs -f
```

### Подозрение на взлом

```bash
# 1. Временно заблокировать весь трафик (если нужно)
docker compose stop angie

# 2. Проверить логи на подозрительную активность
docker exec angie cat /var/log/angie/access.log | \
  jq 'select(.security_score > 10)'

# 3. Проверить все забаненные IP
docker exec fail2ban fail2ban-client status | grep "Jail list"

# 4. Проверить блокировки ModSecurity
docker exec angie grep "ModSecurity" /var/log/angie/error.log | tail -100

# 5. Экспорт логов для анализа
docker cp angie:/var/log/angie /tmp/incident-logs-$(date +%Y%m%d)
```

## Полезные команды

```bash
# Управление контейнерами
docker compose up -d                    # Запуск стека
docker compose down                     # Остановка стека
docker compose restart angie            # Перезапуск конкретного сервиса
docker compose logs -f angie            # Отслеживание логов

# Angie
docker exec angie angie -t              # Тест конфигурации
docker exec angie angie -s reload       # Перезагрузка конфигурации
docker exec angie angie -V              # Показать версию

# Fail2Ban
docker exec fail2ban fail2ban-client status                    # Показать все jails
docker exec fail2ban fail2ban-client status angie-modsecurity  # Детали jail
docker exec fail2ban fail2ban-client set JAIL unbanip IP       # Разбан IP
docker exec fail2ban fail2ban-client reload                    # Перезагрузка config

# Логи
docker exec angie tail -f /var/log/angie/access.log            # Отслеживание access log
docker exec angie grep "403" /var/log/angie/access.log         # Поиск 403
cat logs/access.log | jq '.' | less                            # Красивый вывод JSON
cat logs/access.log | jq 'select(.security_score > 10)'        # Фильтр высоких scores
```

## Следующие шаги

- Понимание архитектуры: [Архитектура](architecture.md)
- Обзор безопасности: [Слои безопасности](security-layers.md)
- Настройка стека: [Руководство по конфигурации](configuration.md)
- Мониторинг логов: [Система логирования](logging.md)
