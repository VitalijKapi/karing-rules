# XHTTP через Yandex Cloud CDN: uplink в заголовках (черновик)

Ситуация: VLESS + XHTTP `packet-up` за Yandex Cloud CDN, xray 26.7.28 (3x-ui 3.6.0),
клиент Shadowrocket 2.2.92. Сейчас `uplinkHTTPMethod=GET`, `uplinkDataPlacement=body`.
На одной точке присутствия (абоненты Билайна) каждый uplink-запрос получает **413**, на других
тот же IP работает. `POST` этот CDN отвечает **405**.

Идея: убрать тело из GET-запросов совсем и возить uplink-данные в заголовках `X-Data-0..N`.
Это **отдельный** inbound с отдельным path, основной inbound не трогаем.

> Статус: черновик. Проверено только локально (xray 26.7.28 на loopback, см. «Что проверено»).
> Через реальный CDN и с Shadowrocket не проверялось.

---

## 1. Что умеет Xray-core (transport/internet/splithttp, тег v26.7.28)

### Допустимые значения `uplinkDataPlacement`

Из `infra/conf/transport_method.go` (`SplitHTTPConfig.Build`):

| Значение | Где данные | Ограничение |
|---|---|---|
| `auto` (значение по умолчанию после разбора конфига) | Клиент кладёт в **тело**. Сервер принимает всё сразу: header + cookie + body, склеивая по порядку | — |
| `body` | тело запроса | — |
| `header` | заголовки `<uplinkDataKey>-0`, `-1`, … | **только `mode: packet-up`**, иначе ошибка конфига |
| `cookie` | cookie `<uplinkDataKey>_0`, `_1`, … | **только `mode: packet-up`** |

**`query` и `path` для uplink-данных не поддерживаются.** Любое другое значение даёт ошибку
`unsupported uplink data placement`. `query` и `path` есть только у `sessionIDPlacement` и
`seqPlacement` (там допустимы `path|cookie|header|query`) и у `xPaddingPlacement`
(`queryInHeader|header|query|cookie`).

Опции `uplinkHTTPMethod`, `uplinkDataPlacement`, `uplinkDataKey` и `uplinkChunkSize` появились
в v26.1.31 (PR #5414 «New options for bypassing CDN's detection»), `serverMaxHeaderBytes` —
в v26.3.23 (PR #5720). Между v26.7.28 и v26.9.9 логика размещения не менялась.

`uplinkHTTPMethod: GET` тоже разрешён **только в `packet-up`**.

### Кодирование

- Весь пакет кодируется как **base64url без паддинга** (`base64.RawURLEncoding`, алфавит
  `A–Z a–z 0–9 - _`). Размер вырастает в **4/3** раза.
- Закодированная строка режется на куски размером `uplinkChunkSize` **символов** (не байт
  исходных данных).
- Header: `X-Data-0: …`, `X-Data-1: …`, … Сервер читает `X-Data-i` подряд до первого пустого,
  склеивает и декодирует. Имя по умолчанию `X-Data`.
- Cookie: `x_data_0=…; x_data_1=…`, имя по умолчанию `x_data`.
- Session ID и seq по-прежнему в path (`/path/<session>/<seq>`), если не менять
  `sessionIDPlacement` и `seqPlacement`.

### Размеры: главная ловушка

1. **`uplinkChunkSize` задаёт размер одного заголовка, а не всего запроса.** Сколько данных
   уходит в одном запросе, определяет **`scMaxEachPostBytes`** (по умолчанию 1 000 000 байт).
   Клиент режет поток на пакеты этого размера (`buf.SplitSize(..., maxUploadSize)` в
   `dialer.go`), и **весь пакет** уходит в заголовки. Если `scMaxEachPostBytes` не уменьшить,
   запрос может нести сотни килобайт заголовков. Локально без этого параметра я получил
   152 КБ заголовков на запрос, соединение не поднялось.
2. `uplinkChunkSize` по умолчанию: для `header` 3000–4000, для `cookie` 2048–3072, для `body`
   равен `scMaxEachPostBytes`. Минимум 64.
3. Сервер: `serverMaxHeaderBytes` по умолчанию **8192** (это `http.Server.MaxHeaderBytes`
   в Go, у HTTP/1.1 есть небольшой запас сверху). Для header-режима его стоит поднять.
4. Сервер отвечает 413 сам, если `len(payload) > scMaxEachPostBytes` **сервера**. У тебя 413
   только на одной PoP, значит, отвечает CDN, а не Xray. Проверить можно по заголовкам
   ответа или в логах CDN.
5. `xPaddingBytes` сервер **проверяет**: длина padding должна попасть в его диапазон. Поэтому
   значение должно совпадать у сервера и клиента. В черновике на обеих сторонах `100-400`,
   чтобы padding меньше съедал из бюджета заголовков.

### Почему `header`, а не `cookie`

- В HTTP/1.1 все cookie уходят **одной строкой** `Cookie:`, то есть весь пакет оказывается
  в одной строке заголовка. У nginx-подобных прокси лимит на одну строку обычно 8 КБ
  (`large_client_header_buffers 4 8k`). С `header` каждый кусок идёт отдельной строкой.
- CDN может трогать cookie (кэш-ключ, игнорирование cookie). С произвольными заголовками
  такое бывает реже.
- В `uplinkDataKey` не используй подчёркивания: nginx по умолчанию отбрасывает заголовки
  с `_` (`underscores_in_headers off`). `X-Data` подходит.

### Бюджет заголовков в черновике

Цель: весь запрос меньше **8 КБ**, одна строка меньше **4 КБ**.

| Параметр (клиент) | Значение | Эффект |
|---|---|---|
| `scMaxEachPostBytes` | `2560-3072` | не больше 3072 байт данных на запрос, то есть не больше 4096 символов base64 |
| `uplinkChunkSize` | `1800-2400` | 2–3 заголовка `X-Data-N`, каждый не больше 2400 символов |
| `xPaddingBytes` | `100-400` | padding в `Referer` не больше 400 символов |
| `scMinPostsIntervalMs` | `10-20` | больше запросов в секунду, чтобы компенсировать маленькие пакеты |

Замер на loopback: максимум **4,8 КБ** заголовков на запрос, самая длинная строка
**2409 байт**, тела нет. Upload через loopback примерно **180 КБ/с (~1,4 Мбит/с)**. Скорость
отдачи в этом режиме ограничена числом запросов в секунду, download не затронут.

Если консервативный вариант заработает, можно попробовать бюджет ~16 КБ:
`scMaxEachPostBytes: "6144-8192"`, `uplinkChunkSize: "3000-3800"`. Это 3–4 заголовка,
~11–12 КБ. Проверять только после того, как 8-КБ вариант заработал на проблемной PoP.

---

## 2. Поддерживает ли Shadowrocket `header` / `cookie`

**Прямых подтверждений не нашёл.** Shadowrocket закрытый, публичного changelog 2.2.92 с этими
полями нет. Что удалось найти:

- `uplinkHTTPMethod: GET` Shadowrocket, по всей видимости, понимает: у тебя GET работает
  на других PoP. Руководство ServerTechnologies/proxy-via-russian-cdn называет Shadowrocket
  среди клиентов для схемы с GET через российские CDN, но оговаривает, что «не все клиенты
  поддерживают новые параметры даже после обновления».
- Issue «XHTTP Supporting» в Shadowrocket/config (апрель 2025) без ответа мейнтейнеров.
- В mihomo (Clash Meta) есть поля `uplink-data-placement` и `uplink-http-method`, но GET там
  нестабилен (discussion #3025, июль 2026). К Shadowrocket это отношения не имеет.
- Упоминаний `uplinkDataPlacement`, `uplinkChunkSize` или `X-Data` рядом с Shadowrocket
  в issues, changelog и обсуждениях не нашёл.

Проверить можно этим же черновиком, см. «План проверки».

---

## 3. Черновик второго inbound

Файлы:
- [`inbound-hdr.server.json`](inbound-hdr.server.json): inbound для сервера (формат Xray).
- [`client-hdr.extra.json`](client-hdr.extra.json): клиентский блок `extra` для XHTTP.

Оба прогнаны через `xray run -test` на v26.7.28: `Configuration OK`.

### Сервер (3x-ui)

Создай **новый** inbound (VLESS, транспорт XHTTP), основной не трогай.

- **Порт, listen и security** возьми по схеме основного inbound:
  - если перед xray стоит nginx или другой прокси, который принимает TLS от CDN: inbound
    на `127.0.0.1:<новый порт>`, `security: none`, в nginx добавь `location /CHANGE-ME-hdr`
    с проксированием на этот порт. Там же подними `large_client_header_buffers`
    (например, `4 16k`);
  - если CDN ходит прямо в xray с TLS: скопируй `tlsSettings` из основного inbound и дай
    новый порт. В Yandex CDN правилом для location (`/CHANGE-ME-hdr`) направь запросы на
    origin с этим портом (правила для location со своим origin есть с Q1 2026).
- **XHTTP**: `mode = packet-up`, `path = /CHANGE-ME-hdr` (случайный, не совпадающий
  с основным), `uplinkHTTPMethod = GET`, `uplinkDataPlacement = header`,
  `uplinkDataKey = X-Data`, `xPaddingBytes = 100-400`, `serverMaxHeaderBytes = 32768`,
  `scMaxBufferedPosts = 60`. Маленьких пакетов в полёте больше, поэтому буфер
  переупорядочивания увеличен с 30.
- **Server-side `header`, а не `auto` — сознательно.** С `auto` сервер принял бы и старый
  body-вариант, и при тесте нельзя было бы отличить, понял ли Shadowrocket новую опцию.
  С `header` клиент, который её не понимает, не подключится нигде. Это однозначный сигнал.
  Когда всё заработает, можно переключить на `auto`.
- **В Yandex CDN** новый path должен вести себя как основной: кэширование выключено,
  заголовки и query передаются на origin.

### Клиент (Shadowrocket)

В XHTTP-узле: тот же host и SNI, что у основного, `path = /CHANGE-ME-hdr`,
`mode = packet-up`, в поле Extra (если оно есть) вставь содержимое
`client-hdr.extra.json`. Или импортируй ссылку (подставь свои значения):

```
vless://CHANGE-ME-UUID@cdn.example.ru:443?encryption=none&security=tls&sni=cdn.example.ru&type=xhttp&host=cdn.example.ru&path=%2FCHANGE-ME-hdr&mode=packet-up&extra=%7B%22uplinkHTTPMethod%22%3A%22GET%22%2C%22uplinkDataPlacement%22%3A%22header%22%2C%22uplinkDataKey%22%3A%22X-Data%22%2C%22uplinkChunkSize%22%3A%221800-2400%22%2C%22scMaxEachPostBytes%22%3A%222560-3072%22%2C%22scMinPostsIntervalMs%22%3A%2210-20%22%2C%22xPaddingBytes%22%3A%22100-400%22%7D#xhttp-hdr
```

Что именно 3x-ui 3.6.0 кладёт в `extra` при экспорте ссылки, не проверял. Сверь экспорт
с этим JSON вручную.

---

## План проверки

Сначала на **рабочей** PoP (не Билайн), потом на Билайне:

| Результат на рабочей PoP | Вывод |
|---|---|
| Подключается | Shadowrocket понимает `header` и `scMaxEachPostBytes`, переходи к Билайну |
| Не подключается, запросы с телом, сервер пишет пустые payload или таймаут | Shadowrocket игнорирует `uplinkDataPlacement` (шлёт GET с телом, сервер в `header`-режиме его не читает) |
| Не подключается, CDN или сервер отвечает 400/431 | Shadowrocket понимает `header`, но игнорирует `scMaxEachPostBytes` (пакеты по 1 МБ уходят в заголовки) |

Оба отрицательных сценария я воспроизвёл локально на xray-клиенте (так они выглядят
со стороны сервера): в обоих случаях соединение не устанавливается.

Если Shadowrocket не поддерживает `header`:
- попросить поддержку Yandex Cloud включить `POST` для ресурса. В документации: «By
  default, the POST, PUT, PATCH, and DELETE methods are not available… contact support»;
- на iPhone взять клиент на xray-core (Happ, v2RayTun, Streisand): у них эти опции
  поддерживаются ядром.

## Что проверено

- Исходники Xray-core на теге `v26.7.28`: `transport/internet/splithttp/{common,config,hub,dialer,client}.go`,
  `infra/conf/transport_method.go`.
- Локальный стенд: xray 26.7.28, собранный из исходников. Сервер и клиент на 127.0.0.1,
  между ними TCP-перехватчик, который меряет заголовки, без TLS и без CDN. Загрузка 1 МБ
  и скачивание 2 МБ через туннель прошли. Все uplink-запросы — `GET` без тела, 2–3
  заголовка `X-Data-N`, максимум 4790 байт заголовков.
- К реальному серверу и CDN не подключался.

## Источники

- Xray-core: https://github.com/XTLS/Xray-core/tree/v26.7.28/transport/internet/splithttp
- Xray-core PR #5414 (опции uplink*), #5720 (`serverMaxHeaderBytes`)
- 3x-ui, поля XHTTP в UI: https://github.com/MHSanaei/3x-ui/commit/a973fa6d6886b7f6af14d7848b31964c46ee151d
- Yandex Cloud CDN, методы и release notes: https://github.com/yandex-cloud/docs (`en/_includes/cdn/http-post-method.md`, `en/cdn/release-notes.md`)
- https://github.com/ServerTechnologies/proxy-via-russian-cdn
- https://github.com/Shadowrocket/config/issues/2
- https://github.com/MetaCubeX/mihomo/discussions/3025
