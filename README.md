# svo-govno / PoisonProto

Реализация протокола PoisonProto для Poison VPN по ТЗ (см. `ROADMAP.md` —
что сделано и что осталось по фазам 1–5).

## Структура

```
pkg/poisonproto/
  config/      L — конфиг подписки (ТЗ §14)
  frame/       L3/L4 — формат кадра (ТЗ §10)
  fingerprint/ L1 — профиль yandex-android для uTLS (ТЗ §5)
  auth/        L1 — токен в session_id, верификация (ТЗ §6)
  crypto/      L2 — Noise IK поверх TLS (ТЗ §7)
  session/     L3/L4 — сессия, стримы (ТЗ §8–9)
  transport/   L0 — TCP+TLS, разбор ClientHello, fallback-сплайсинг (ТЗ §6.2–6.3, §12)
cmd/
  poisonproto-server/  демо-сервер
  poisonproto-client/  демо-клиент
```

## Сборка и тесты

```sh
go build ./...
go test ./... -race
```

## Запуск демо

Сервер (генерирует статический ключ при первом запуске и печатает
публичный ключ для конфига подписки):

```sh
go run ./cmd/poisonproto-server --listen :8443 --fallback example.com:443
```

Клиент (подписка — JSON по схеме ТЗ §14; `server_pubkey` — то, что вывел
сервер):

```sh
go run ./cmd/poisonproto-client --config subscription.json --listen 127.0.0.1:1080 --target example.com:443
```

После этого любое TCP-соединение на `127.0.0.1:1080` идёт через туннель
на `--target`.

## Важно

Фазы 1–2 готовы: маскировка, токен с откатом на fallback, L2-шифрование,
и — главное — пул соединений с адаптивным бюджетом, ACK/переотправкой и
миграцией (устойчивость к заморозке на ТСПУ). Перед продуктивным
использованием см. список нереализованного в `ROADMAP.md`: PSK-резюмирование,
шейпинг трафика, альтернативные транспорты, control plane и интеграция в
sing-box/Remnawave (фазы 3–5) всё ещё впереди.
