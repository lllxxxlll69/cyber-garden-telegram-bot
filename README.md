# Cyber Garden — Telegram-бот и сервер

Telegram-бот для доставки PDF-отчётов Cyber Garden и общий сервер Android-приложения. Node.js 22+, PDFKit, файловое хранилище, аккаунты и сессии, одноразовая привязка Telegram, очередь отправки с повторными попытками. Бот использует long polling.

## Запуск

```powershell
cd server
npm ci
Copy-Item .env.example .env
# Укажите TELEGRAM_BOT_TOKEN от @BotFather в .env
npm start
```

Откройте http://127.0.0.1:8787, зарегистрируйтесь, получите код привязки и отправьте `/login КОД` боту. Без токена доступны аккаунты, загрузка отчётов и скачивание PDF через браузер.

Команды: `/start`, `/help`, `/login КОД`, `/reports`, `/report [ID]`, `/sessions`, `/logout`.

## Проверка

```powershell
cd server
npm test
cd ..
node --test garden/test.cjs garden/github.test.cjs
```

## Структура

- `server/` — бот, HTTP API, сессии, PDF, очередь и тесты.
- `garden/` — общие анализаторы, сценарии, импорт GitHub и интеграция LLM, необходимые серверу.
- `mobile/.../assets/` — браузерная версия интерфейса Android, доступная по `/mobile/`.
- `assets/fonts/` — JetBrains Mono и лицензия OFL для PDF.

Исходники и сборка APK: [cyber-garden-mobile](https://github.com/lllxxxlll69/cyber-garden-mobile).
Для скачивания APK через `/mobile/app.apk` самостоятельно соберите приложение и поместите APK в `mobile/output/CyberGarden-debug.apk` этого репозитория.

Для телефона по Wi-Fi задайте в `server/.env` HOST=0.0.0.0 и ALLOWED_HOSTS с IPv4 компьютера. Через USB используйте `adb reverse tcp:8787 tcp:8787` с loopback-адресом. Сервер должен оставаться запущенным.

[Подробная документация, API и настройки](server/README.md).
Токены, локальные аккаунты, отчёты и каталоги зависимостей в публикацию не входят. Эвристические анализаторы предназначены для учебных проектов; встроенные находки и справочник синтетические.
