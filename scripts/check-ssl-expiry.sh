#!/bin/bash
# ==============================================================================
# Скрипт проверки срока действия SSL сертификата
# ==============================================================================
# Использование:
#   ./scripts/check-ssl-expiry.sh
#   или добавить в crontab для ежедневной проверки:
#   0 9 * * * /path/to/project/scripts/check-ssl-expiry.sh
# ==============================================================================

# Настройте под ваш домен
DOMAIN="example.com"
ALERT_DAYS=14  # Предупреждать за 14 дней до истечения
EMAIL="admin@example.com"  # Замените на ваш email

# Получить дату истечения сертификата
EXPIRY_DATE=$(docker exec angie openssl x509 -in /var/lib/angie/acme/certificates/$DOMAIN.crt -noout -enddate 2>/dev/null | cut -d= -f2)

if [ -z "$EXPIRY_DATE" ]; then
    echo "ОШИБКА: Не удалось получить дату истечения сертификата для $DOMAIN"
    exit 1
fi

# Конвертировать в timestamp
EXPIRY_TIMESTAMP=$(date -d "$EXPIRY_DATE" +%s)
CURRENT_TIMESTAMP=$(date +%s)

# Вычислить оставшиеся дни
DAYS_LEFT=$(( ($EXPIRY_TIMESTAMP - $CURRENT_TIMESTAMP) / 86400 ))

echo "=================================================="
echo "SSL Certificate Check for $DOMAIN"
echo "=================================================="
echo "Истекает: $EXPIRY_DATE"
echo "Осталось дней: $DAYS_LEFT"
echo ""

if [ $DAYS_LEFT -lt 0 ]; then
    echo "КРИТИЧНО: Сертификат УЖЕ истёк!"
    echo "Требуется срочное обновление!"

    # Отправить alert (если настроен mail)
    if command -v mail &> /dev/null; then
        echo "КРИТИЧНО: SSL сертификат $DOMAIN истёк $DAYS_LEFT дней назад!" | mail -s "SSL ALERT: $DOMAIN" $EMAIL
    fi

    exit 2

elif [ $DAYS_LEFT -lt $ALERT_DAYS ]; then
    echo "ВНИМАНИЕ: Сертификат истекает через $DAYS_LEFT дней!"
    echo "ACME должен обновить автоматически, но проверьте логи:"
    echo "  docker logs angie --tail 50"

    # Отправить warning (если настроен mail)
    if command -v mail &> /dev/null; then
        echo "ВНИМАНИЕ: SSL сертификат $DOMAIN истекает через $DAYS_LEFT дней" | mail -s "SSL WARNING: $DOMAIN" $EMAIL
    fi

    exit 1

else
    echo "Сертификат валиден, всё в порядке"
    exit 0
fi
