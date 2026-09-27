# XHTTP через Yandex CDN: скрыть содержимое VLESS от CDN (черновик)

Схема: VLESS + XHTTP `packet-up` (`uplinkHTTPMethod=GET`) через Yandex Cloud CDN, TLS
терминируется **на CDN**, xray 26.7.28 (3x-ui), клиент Shadowrocket 2.2.92.

**Проблема.** После снятия TLS на CDN внутри HTTP-запросов идёт открытый VLESS. CDN видит
UUID, адрес назначения (домен или IP) и всё содержимое туннеля, включая SNI в TLS ClientHello
сайтов, которые ты открываешь. Известен случай, когда Selectel CDN заблокировал клиента за
«VPN-трафик к заблокированным ресурсам».

**Цель.** Сквозное шифрование от клиента до xray, чтобы CDN видел только случайные байты.

> Статус: черновик. Проверено только локально (xray 26.7.28, loopback, без TLS и без CDN).
> С Shadowrocket и через реальный CDN не проверялось.

---

## Что видит посредник: замер

Стенд: клиент xray → TCP-перехватчик (он играет роль CDN после снятия TLS) → сервер xray.
Транспорт XHTTP `packet-up` + `GET`, как у тебя. В туннеле идёт запрос к
`marker-dest.internal` с маркером в содержимом (аналог SNI и данных сайта). Ищем в
перехваченных байтах адрес назначения, маркер, UUID и хеш пароля Trojan.

| Вариант поверх XHTTP | Адрес назначения | Содержимое / SNI | UUID / хеш пароля |
|---|---|---|---|
| VLESS, `encryption: none` (как сейчас) | **виден** | **виден** | **UUID виден** |
| **VLESS Encryption** (`mlkem768x25519plus`) | скрыт | скрыт | скрыт |
| VMess (`aes-128-gcm`) | скрыт | скрыт | скрыт |
| Trojan | **виден** | **виден** | **хеш SHA-224 пароля виден** |
| Shadowsocks 2022 (`2022-blake3-aes-128-gcm`) | скрыт | скрыт | — |

Отдельно проверен именно черновой вариант (VLESS Encryption `xorpub` с аутентификацией X25519,
а также VMess): три запроса подряд, все 200, первый ~35 мс, следующие ~3 мс (срабатывает
0-RTT по тикету), маркеры не видны.

**Trojan проблему не решает.** Своего шифрования у него нет, он рассчитан на внешний TLS.
Когда TLS снимает CDN, Trojan для него такой же открытый, как VLESS.

---

## 1. VLESS Encryption в xray

Появилась в **v25.8.29** (PR #5067). Код: `proxy/vless/encryption/`, разбор параметров в
`infra/conf/vless.go`.

### Как включается

Ключи генерирует `xray vlessenc` (или кнопка генерации ключей в 3x-ui у поля decryption).
Команда выдаёт две пары, **смешивать их нельзя**:

- `Authentication: X25519` — короткие ключи;
- `Authentication: ML-KEM-768` — клиентский ключ длиной ~1580 символов.

Эфемерный обмен ключами в обоих вариантах гибридный постквантовый (ML-KEM-768 + X25519).
Отличается только долговременный ключ аутентификации сервера.

- **Сервер (inbound):** `settings.decryption` вместо `"none"`. В `clients` поле
  `encryption` указывать **нельзя** (ошибка конфига).
- **Клиент (outbound):** `encryption` у пользователя вместо `"none"`. В ссылке это параметр
  `encryption=...`.
- **С `fallbacks` несовместимо** (`"fallbacks" can not be used together with "decryption"`).
  Это ещё одна причина делать отдельный inbound.

### Формат строки

```
сервер: mlkem768x25519plus.<mode>.<ticket>.[padding.]<ключ сервера>
клиент: mlkem768x25519plus.<mode>.<rtt>.[padding.]<ключ клиента>
```

| Поле | Значения |
|---|---|
| `mode` | `native`: записи с 5-байтовым заголовком как у TLS (`17 03 03 len`). `xorpub`: публичные ключи рукопожатия XOR-маскируются. `random`: весь поток выглядит случайным. **На сервере и клиенте должно совпадать** |
| сервер: `<ticket>` | время жизни 0-RTT-тикета: `600s` или диапазон `300-600s`; `0s` отключает 0-RTT |
| клиент: `<rtt>` | `0rtt` (переиспользует тикет сервера) или `1rtt` |
| `padding` (необязательно) | блоки `вероятность-мин-макс`, например `100-111-1111.75-0-111.50-0-3333`. Первый блок: длина не меньше 35 |
| ключ сервера | X25519 private key (32 байта) **или** seed ML-KEM-768 (64 байта), base64url |
| ключ клиента | X25519 public key («password», 32 байта) **или** ML-KEM-768 encapsulation key (1184 байта) |

### Что видит посредник после включения

Рукопожатие шифрования выполняется **на сыром потоке до VLESS-заголовка**
(`inbound.go: h.decryption.Handshake(connection)` идёт до чтения запроса). Поэтому шифруется
всё: UUID, команда, адрес назначения и порт, данные.

CDN по-прежнему видит:
- IP клиента;
- объём и тайминг трафика;
- HTTP-обёртку XHTTP: path, session и seq в пути, частые GET-запросы, `Referer` с `x_padding`.

То есть **факт туннеля** остаётся заметен, а **куда и что** идёт — нет. Размер первого
запроса растёт (ключи рукопожатия + padding, в замере ~16–19 КБ за соединение против ~3,4 КБ
без шифрования). Повторные соединения в пределах времени жизни тикета идут по 0-RTT.

---

## 2. Поддерживает ли Shadowrocket VLESS Encryption

**Частично, по сторонним данным. Официального changelog с этой функцией я не нашёл**
(App Store и Telegram-канал Shadowrocket отсюда недоступны).

- charmingyi/vless-encryption-reality: вариант с аутентификацией **ML-KEM-768**
  (`mlkem768x25519plus.xorpub.0rtt.<X25519>.<700+ символов ML-KEM>`) «в Shadowrocket не
  подключается (v2rayN / v2rayNG нормально)». Автор форка оставил только **X25519**
  и пометил это как «совместимо с Shadowrocket». Проверялось поверх REALITY, не XHTTP.
  Версия Shadowrocket не указана.
- В поисковой выдаче встречается строка changelog Shadowrocket «display VLESS encryption in
  plain text», то есть поле encryption у VLESS в Shadowrocket, по всей видимости, есть.
  Первоисточник проверить не смог.
- Xboard (панель) в ссылке для Shadowrocket поле `encryption` у VLESS **не передаёт**.
  В XrayRP PR #235 сбой Shadowrocket объяснён «legacy VLESS URI serialization» Xboard,
  а не самим шифрованием. Значит, импортировать нужно стандартную ссылку `vless://...`
  с `encryption=...` (как экспортирует 3x-ui), а не подписку Xboard.
- Shadowrocket/config issue #4 (Shadowrocket 2.2.92, iOS 27) про **X25519MLKEM768 в TLS
  ClientHello для REALITY**. Это другая вещь, к VLESS Encryption отношения не имеет.
  В поиске их часто путают.

Вывод: **пробовать X25519-вариант**. Работает ли он поверх XHTTP в Shadowrocket 2.2.92,
покажет только тест.

---

## 3. Альтернативы: Shadowsocks 2022 и Trojan поверх XHTTP

- **xray сам по себе** умеет любой из них поверх XHTTP: транспорт от протокола не зависит.
  Все пять вариантов из таблицы выше собраны и прогнаны на xray 26.7.28.
- **Shadowrocket.** По генератору ссылок Xboard (`app/Protocols/Shadowrocket.php`)
  `obfs=xhttp` выставляется для **VLESS, VMess и Trojan**. У **Shadowsocks** там только
  плагины (`obfs-local`, `v2ray-plugin` и т.п.), XHTTP нет. Значит:
  - **SS-2022 поверх XHTTP в Shadowrocket, скорее всего, не заведётся.** Отпадает.
  - **Trojan поверх XHTTP** Shadowrocket поддерживает, но он **не шифрует** (см. замер).
    Отпадает.
  - **VMess поверх XHTTP**, судя по тому же генератору, Shadowrocket поддерживает, и VMess
    AEAD шифрует адрес и содержимое. **Это запасной вариант.** Минусы: протокол старше и хуже
    изучен против активного зондирования. Для скрытия содержимого от CDN его достаточно.

---

## 4. Итог и черновики

| Вариант | Скрывает от CDN | Shadowrocket | Решение |
|---|---|---|---|
| VLESS Encryption, аутентификация X25519, `xorpub` | да | вероятно (сторонний отчёт, поверх REALITY) | **основной тест** |
| VLESS Encryption, аутентификация ML-KEM-768 | да | не работает (сторонний отчёт) | не использовать |
| VMess `aes-128-gcm` поверх XHTTP | да | вероятно (Xboard генерирует такие ссылки) | **запасной** |
| Trojan поверх XHTTP | **нет** | да | не решает задачу |
| SS-2022 поверх XHTTP | да | нет XHTTP для SS | не подходит |

### Файлы

- [`inbound-vlessenc.server.json`](inbound-vlessenc.server.json): VLESS + VLESS Encryption
  (X25519, `xorpub`) + XHTTP `packet-up` + `GET`.
- [`inbound-vmess.server.json`](inbound-vmess.server.json): запасной VMess + XHTTP.

Оба с подставленными тестовыми ключами прошли `xray run -test` на 26.7.28. В репозитории
только плейсхолдеры `CHANGE-ME`, **реальные ключи не коммить**.

### Сервер (3x-ui), основной inbound не трогаем

1. Сгенерируй ключи: `xray vlessenc` → пара **«Authentication: X25519»**. В обеих строках
   замени `.native.` на `.xorpub.` (так сделано в отчёте, где Shadowrocket работал).
   Или кнопкой в 3x-ui выбери X25519 / xorpub.
2. Новый inbound VLESS, транспорт XHTTP: `mode = packet-up`, `uplinkHTTPMethod = GET`,
   **свой path** (`/CHANGE-ME-enc`), `decryption = mlkem768x25519plus.xorpub.600s.<private>`,
   `flow` пустой, `fallbacks` нет.
3. Порт, listen и TLS — по той же схеме, что основной inbound:
   - nginx за CDN: `127.0.0.1:<порт>` + `location /CHANGE-ME-enc`;
   - или отдельный порт и правило location в Yandex CDN.
4. В Yandex CDN новый path настроить как основной (без кэширования).

### Клиент (Shadowrocket)

Импортируй ссылку (подставь свои значения; `encryption` — клиентская строка с **public**-ключом):

```
vless://CHANGE-ME-UUID@cdn.example.ru:443?encryption=mlkem768x25519plus.xorpub.0rtt.CHANGE-ME-X25519-PUBLIC&security=tls&sni=cdn.example.ru&type=xhttp&host=cdn.example.ru&path=%2FCHANGE-ME-enc&mode=packet-up&extra=%7B%22uplinkHTTPMethod%22%3A%22GET%22%7D#xhttp-enc
```

После импорта открой узел и проверь, что поле encryption заполнилось, а не сбросилось в `none`.

### План проверки

1. Сначала на **рабочей** точке CDN. Если не подключается, по логу xray с `loglevel: info`
   видно, есть ли `ML-KEM-768 handshake failed`: это значит, что Shadowrocket игнорирует или
   искажает `encryption`.
2. Если подключается, сделай контрольную проверку: временно поставь клиенту `encryption=none`.
   Подключение **должно сломаться**, так как сервер ждёт рукопожатие. Это доказывает, что
   шифрование реально используется, а не игнорируется.
3. Если VLESS Encryption в Shadowrocket не заводится, пробуй запасной VMess
   (`inbound-vmess.server.json`, в клиенте алгоритм `aes-128-gcm` или `chacha20-poly1305`,
   **не `none`/`zero`**).
4. Совмещать с черновиком uplink-в-заголовках (`../README.md`) только после того, как каждый
   вариант заработал по отдельности.

## Что проверено

- Исходники Xray-core на теге `v26.7.28`: `infra/conf/vless.go`,
  `proxy/vless/encryption/{common,client,server,xor}.go`, `proxy/vless/inbound/inbound.go`,
  `proxy/vless/outbound/outbound.go`, `main/commands/all/vlessenc.go`.
- Локальный стенд: xray 26.7.28, собранный из исходников. Пять вариантов поверх XHTTP
  `packet-up` + `GET` с перехватом трафика между клиентом и сервером (результат в таблице
  выше).
- Генератор ссылок Shadowrocket в Xboard (`app/Protocols/Shadowrocket.php`).
- К реальному серверу и CDN не подключался. Shadowrocket не запускал.

## Источники

- Xray-core PR #5067 (VLESS Encryption): https://github.com/XTLS/Xray-core/pull/5067
- Xray-core v26.7.28: https://github.com/XTLS/Xray-core/tree/v26.7.28/proxy/vless/encryption
- Документация VLESS: https://xtls.github.io/en/config/outbounds/vless.html
- Отчёт о совместимости с Shadowrocket (X25519 работает, ML-KEM нет): https://github.com/charmingyi/vless-encryption-reality
- XrayRP PR #235 (Shadowrocket и сериализация Xboard): https://github.com/Mtoly/XrayRP/pull/235
- Xboard, генератор ссылок Shadowrocket: https://github.com/cedar2025/Xboard/blob/master/app/Protocols/Shadowrocket.php
- Shadowrocket/config #4 (X25519MLKEM768 в REALITY, не путать): https://github.com/Shadowrocket/config/issues/4
- 3x-ui, VLESS Encryption в панели: https://github.com/MHSanaei/3x-ui/issues/6332
