#!/bin/bash
# Скрипт для ротации логов Angie
# Запускать через cron: 0 2 * * * /path/to/project/scripts/rotate-logs.sh

set -e

# Настройте путь к вашему проекту
LOG_DIR="./logs"
KEEP_DAYS=30

cd "$LOG_DIR"

# Функция ротации лога
rotate_log() {
    local logfile="$1"
    local date_suffix=$(date +%Y%m%d-%H%M%S)

    if [ -f "$logfile" ] && [ -s "$logfile" ]; then
        # Копируем лог с датой
        cp "$logfile" "${logfile}.${date_suffix}"

        # Очищаем текущий лог
        truncate -s 0 "$logfile"

        # Сжимаем старый лог
        gzip "${logfile}.${date_suffix}"

        echo "Rotated: $logfile -> ${logfile}.${date_suffix}.gz"
    fi
}

# Ротация access.log
rotate_log "access.log"

# Ротация error.log
rotate_log "error.log"

# Ротация modsec_audit.log (если существует)
[ -f "modsec_audit.log" ] && rotate_log "modsec_audit.log"

# Отправляем сигнал Angie для переоткрытия логов
docker exec angie angie -s reopen 2>/dev/null || echo "Warning: Could not reopen logs"

# Удаляем логи старше KEEP_DAYS дней
find "$LOG_DIR" -name "*.log.*.gz" -mtime +"${KEEP_DAYS}" -delete
echo "Deleted logs older than ${KEEP_DAYS} days"

# Статистика
echo "Current log sizes:"
ls -lh "$LOG_DIR"/*.log 2>/dev/null || echo "No active logs"
echo ""
echo "Archived logs count: $(find "$LOG_DIR" -name "*.log.*.gz" | wc -l)"
