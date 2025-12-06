# Система логирования

Этот документ описывает многоуровневый пайплайн обогащения логов и как использовать логи для мониторинга и отладки.

## Обзор

Система логирования в angie-modsecurity-docker работает на двух уровнях:

```
Уровень 1: Нативное обогащение Angie
  ├─ GeoIP данные (страна, город, координаты)
  ├─ Парсинг User-Agent (браузер, ОС, тип устройства)
  ├─ Флаги безопасности (подозрительные паттерны)
  ├─ Метрики производительности (время запроса, размер)
  └─ Бизнес метрики (события конверсии, A/B группы)
      ↓
  Пишет: /var/log/angie/access.log (JSON формат)
      ↓
Уровень 2: Обработка Vector
  ├─ Читает логи Уровня 1
  ├─ Парсит JSON
  ├─ Вычисляет security_score
  ├─ Классифицирует threat_level
  └─ Добавляет метаданные
      ↓
  Пишет: /var/log/angie/access_enriched.log
```

## Файлы логов

### Расположение

Все логи хранятся в `/var/log/angie/` (общий volume):

```
/var/log/angie/
├── access.log              # Уровень 1: Обогащены Angie
├── access_enriched.log     # Уровень 2: Улучшены Vector
└── error.log               # Ошибки + нарушения ModSecurity
```

### Паттерн доступа

```yaml
# Из compose.yml

angie:
  volumes:
    - ./logs:/var/log/angie  # Чтение-запись

fail2ban:
  volumes:
    - ./logs:/var/log/angie:ro  # Только чтение

vector:
  volumes:
    - ./logs:/var/log/angie  # Чтение-запись
```

## Уровень 1: Обогащение Angie

### Конфигурация

Файл: `angie/includes/logs/enrichment.conf`

#### GeoIP Lookup

```nginx
geoip2 /etc/angie/geoip/GeoLite2-City.mmdb {
    auto_reload 5m;
    $geoip2_country_code country iso_code;
    $geoip2_country_name country names en;
    $geoip2_city_name city names en;
    $geoip2_latitude location latitude;
    $geoip2_longitude location longitude;
}
```

#### Анализ User-Agent

```nginx
# Определение типа устройства
map $http_user_agent $device_type {
    default "desktop";
    ~*mobile "mobile";
    ~*tablet "tablet";
    ~*bot "bot";
}

# Определение браузера
map $http_user_agent $browser {
    default "other";
    ~*chrome "chrome";
    ~*firefox "firefox";
    ~*safari "safari";
}
```

#### Флаги безопасности

```nginx
# Подозрительный User-Agent
map $http_user_agent $suspicious_ua {
    default 0;
    ~*(sqlmap|nikto|nmap|burp|acunetix) 1;
}

# Подозрительные паттерны URL
map $request_uri $suspicious_pattern {
    default 0;
    ~*(union.*select|insert.*into|\.\./) 1;
}
```

### JSON формат лога

```nginx
log_format json_enriched escape=json '{'
    '"timestamp":"$time_iso8601",'
    '"client_ip":"$remote_addr",'
    '"geo_country_code":"$geoip2_country_code",'
    '"ua_browser":"$browser",'
    '"request_uri":"$request_uri",'
    '"response_status":"$status",'
    '"security_suspicious_ua":"$suspicious_ua",'
    '"security_suspicious_pattern":"$suspicious_pattern"'
'}';
```

### Пример записи лога

```json
{
  "timestamp": "2025-12-06T15:30:45+03:00",
  "client_ip": "203.0.113.45",
  "geo_country_code": "US",
  "geo_city": "New York",
  "ua_browser": "chrome",
  "ua_os": "windows",
  "request_uri": "/api/users?page=2",
  "response_status": "200",
  "perf_request_time": "0.245",
  "security_suspicious_ua": "0",
  "security_suspicious_pattern": "0"
}
```

## Уровень 2: Обогащение Vector

### Конфигурация

Файл: `vector/vector.toml`

```toml
# Источник: Чтение логов Angie
[sources.angie_logs]
type = "file"
include = ["/var/log/angie/access.log"]
read_from = "end"

# Трансформация: Парсинг и обогащение
[transforms.parse_json]
type = "remap"
inputs = ["angie_logs"]
source = '''
  . = parse_json!(.message)

  # Вычислить security score
  score = 0
  if .security_suspicious_ua == "1" { score = score + 5 }
  if .security_suspicious_pattern == "1" { score = score + 7 }
  .security_score = score

  # Классифицировать threat level
  .security_threat_level = if score == 0 { "safe" }
                           else if score < 5 { "low" }
                           else if score < 10 { "medium" }
                           else { "high" }
'''

# Sink: Запись обогащенных логов
[sinks.enriched_logs]
type = "file"
inputs = ["parse_json"]
path = "/var/log/angie/access_enriched.log"
encoding.codec = "json"
```

### Вычисление Security Score

```
Базовый Score: 0

Добавление баллов за подозрительные индикаторы:
  + 5 баллов: Подозрительный User-Agent (sqlmap, nikto и т.д.)
  + 7 баллов: Подозрительный паттерн URL (SQLi, path traversal)
  + 3 балла: Подозрительный X-Forwarded-For (длинная proxy цепочка)

Примеры:
  Нормальный запрос:     0 баллов → "safe"
  Бот скрейпинг:        5 баллов → "medium"
  SQL injection:       12 баллов → "high"
  Комбинированная атака: 15 баллов → "high"
```

## Error логи

### Нарушения ModSecurity

ModSecurity пишет в `error.log`:

```
2025/12/06 15:35:22 [error] 42#42: *156 ModSecurity: Access denied with code 403 (phase 2). Matched "Operator `Rx' with parameter `(?i:(\s|;|'|")or(\s|;|'|").*?=.*?)` against variable `ARGS:id' (Value: `1' OR '1'='1' ), client: 203.0.113.100, server: example.com
```

## Анализ логов

### Использование jq для парсинга JSON

```bash
# Подсчет запросов по странам
cat access.log | jq -r '.geo_country_code' | sort | uniq -c | sort -rn

# Поиск высокоугрожающих запросов
cat access_enriched.log | jq 'select(.security_threat_level == "high")'

# Среднее время ответа
cat access.log | jq -r '.perf_request_time' | awk '{sum+=$1; count++} END {print sum/count}'

# Топ 10 IP
cat access.log | jq -r '.client_ip' | sort | uniq -c | sort -rn | head -10

# Запросы с подозрительными паттернами
cat access.log | jq 'select(.security_suspicious_pattern == "1")'
```

### Использование grep для error логов

```bash
# Найти все блокировки ModSecurity
grep "ModSecurity: Access denied" error.log

# Извлечь заблокированные IP
grep "ModSecurity: Access denied" error.log | grep -oP 'client: \K[0-9.]+'

# Подсчет блокировок по ID правил
grep "ModSecurity" error.log | grep -oP '\[id "\K[0-9]+' | sort | uniq -c

# Найти события rate limiting
grep "limiting requests" error.log
```

### Мониторинг в реальном времени

```bash
# Хвост access логов (красивый вывод)
tail -f access.log | jq '.'

# Отслеживание высокоугрожающих запросов
tail -f access_enriched.log | jq 'select(.security_threat_level == "high")'

# Мониторинг блокировок ModSecurity
tail -f error.log | grep "ModSecurity"

# Отслеживание конкретного IP
tail -f access.log | jq 'select(.client_ip == "203.0.113.100")'
```

## Интеграция с Fail2Ban

### Как Fail2Ban использует логи

```
Fail2Ban непрерывно читает логи:
  - /var/log/angie/access.log (для паттернов доступа)
  - /var/log/angie/error.log (для ModSecurity)

Процесс:
  1. Чтение новых строк лога
  2. Применение regex фильтров
  3. Извлечение IP адресов
  4. Увеличение счетчиков
  5. Проверка порогов
  6. Бан при превышении
```

## Отладка с помощью логов

### Отслеживание конкретного запроса

```bash
# Используя request_id
request_id="a3f2b1c9d8e7f6a5"

# Поиск в access log
cat access.log | jq "select(.request_id == \"$request_id\")"

# Поиск в error log
grep "$request_id" error.log
```

### Исследование неудачных запросов

```bash
# Поиск 5xx ошибок
cat access.log | jq 'select(.response_status | tonumber >= 500)'

# Проверка проблем upstream
cat access.log | jq 'select(.perf_upstream_time == "" or .perf_upstream_time == null)'
```

### Исследование инцидента безопасности

```bash
# Найти все запросы от подозрительного IP
ip="203.0.113.100"
cat access.log | jq "select(.client_ip == \"$ip\")"

# Проверить threat level
cat access_enriched.log | jq "select(.client_ip == \"$ip\") | .security_threat_level"

# Найти блокировки ModSecurity для этого IP
grep "client: $ip" error.log | grep "ModSecurity"
```

## Следующие шаги

- Понимание потока логов: [Путь запроса](request-flow.md)
- Отладка проблем: [Устранение неполадок](troubleshooting.md)
- Настройка пайплайна: [Руководство по конфигурации](configuration.md)
- Обзор безопасности: [Слои безопасности](security-layers.md)
