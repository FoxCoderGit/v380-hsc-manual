# 2. Облачный API, подписи и ключи

[Оглавление](../README.md) · [Границы проверки](08-validation.md)

| Назначение | Адрес по умолчанию | Путь |
|---|---|---|
| Dispatch | `http://dispatch.av380.net:8001` | `/api/v1/get_stream_server` |
| Аккаунт | `https://mapi.av380.net` | `/user/login` |
| Устройства | тот же API | `/device/list` |
| Обновление публичного ключа | тот же API | `/device/renew-public-key` |
| Обмен ключами | `http://secret.av380.net` | `/v1/app/exch` |
| Канал | `http://<relay>:<call_port>` | `/v1/app/call` |

Название `https_key_exchange` в исходном клиенте историческое: его адрес обмена ключами
действительно использует **HTTP**. Не утверждайте, что все служебные обращения
защищены TLS. AES медиапотока не заменяет защиту HTTP-токенов на пути к облаку.
Поддержка безопасной замены схемы на стороне производителя здесь не проверена.

Все `timestamp` ниже — Unix seconds. JSON перед подписью сериализуется компактно,
UTF-8, `ensure_ascii=False`, separators `(',', ':')`; порядок полей важен там,
где подписывается весь JSON. Hex-хеши — строчные. Соли ниже — общие константы
протокола из приложения, не персональные пароли.

**Dispatch**:

```text
body = {dev_id, platform:20001, timestamp, sign}
sign = SHA1("dev_id=<id>&platform=20001&timestamp=<ts>hsdata2022")
```

Читаются `data[].domain` / `ip`, `tp.call_port`, `tp.trans_port`.
Порты транспортного соединения берутся из ответа выделения канала;
не подменяйте их произвольно портом dispatch.

**Вход аккаунта**:

```text
p = HEX(AES-128-ECB(key="1234567890123456", PKCS7(UTF8(password))))
sign = MD5("password=<p>&phonetoken=100&timestamp=<ts>&username=<name>hsshop2016")
body = {username, password:p, phonetoken:"100", sign, timestamp}
```

Сохраняется `data.access_token` при успешном ответе. Константа AES — только
преобразование поля пароля для API, не ключ расшифрования камеры.

**Список устройств** подписывает строку:

```text
accesstoken=<token>&from_app=V380Pro&get_sub_server=20&language=en&registrationid=&timestamp=<ts>&type=all&ver=1008hsshop2016
```

`sign=MD5(строка)`, остальные поля передаются JSON. Клиент ищет нужный `device_id`
в ответе и `public_key` / `pKey` / `p_key`. Дополнительное получение текущего ключа:

```text
sign = MD5("accesstoken=<token>&deviceid=<id>&timestamp=<ts>hsshop2016")
POST /device/renew-public-key
{accesstoken, deviceid, timestamp, sign}
```

**Общая Signature** для рассмотренных запросов `/call` и `/exch`:

```text
inner = MD5(compact_json(body) + decimal(timestamp))
Signature = MD5(inner + "2021Mr")
```

Signature передаётся HTTP-заголовком. Нельзя подписывать красиво
отформатированный JSON и отправлять компактный либо менять порядок полей.

## X25519 и AES-сессия

1. Base64 публичного ключа камеры декодируется в 32 байта.
2. Генерируются 32 случайных байта приватного материала клиента.
3. X25519 даёт публичный ключ клиента `cKM` и 32-байтный shared secret.
4. `dS = MD5(client_public) XOR MD5(device_public)`, оба поля кодируются Base64.
5. Выполняется `/v1/app/exch` с общей Signature.

```json
{
  "mr": {"params": {"access_token": "TOKEN", "device_id": 123456789}},
  "tr": {
    "id": 12345,
    "method_id": 196866,
    "chn": 1,
    "ts": 1790000000,
    "params": {"cKM": "BASE64_CLIENT_PUBLIC", "dS": "BASE64_VERIFY"}
  },
  "timestamp": 1790000000
}
```

Нужны внешний `code=1000` и `tr.result.code=1000`; из `tr.data` берутся `sid`,
`exp`. Shared secret не приходит готовым от сервера — клиент вычисляет его.
Первые 16 байт shared secret — AES-128 key, следующие 16 — CBC IV.
Проверяйте длину публичного ключа и не сохраняйте shared secret в журнал.

## Точный состав device/list

Подписанная строка выше и JSON имеют разные представления. Наблюдавшееся тело:

```json
{
  "accesstoken": "TOKEN",
  "from_app": "V380Pro",
  "get_sub_server": 20,
  "language": "en",
  "registrationid": "",
  "sign": "MD5_HEX",
  "timestamp": 1790000000,
  "type": "all",
  "ver": 1008
}
```

Не заменяйте `accesstoken` на `access_token` во всех запросах сразу:
написания различаются между API аккаунта и обёрткой `mr.params`.
В login `phonetoken` передаётся строкой `"100"`, а `ver` в device/list — числом.
Выбирайте устройство по ID, а не первый элемент ответа. Структура списка
может содержать вложенные объекты; нужный ключ ищется у найденного устройства.

## Локальный пример построения Signature

Это самостоятельный вычислительный фрагмент: он не делает сетевых запросов.

```python
import hashlib
import json

def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

def signature(body, timestamp):
    inner = hashlib.md5((compact(body) + str(timestamp)).encode("utf-8")).hexdigest()
    return hashlib.md5((inner + "2021Mr").encode("utf-8")).hexdigest()

timestamp = 1790000000  # Только фиксированный пример, не время живого запроса.
body = {
    "mr": {"params": {"access_token": "TOKEN", "device_id": 123456789, "call": 2}},
    "timestamp": timestamp,
}
header_signature = signature(body, timestamp)
payload_bytes = compact(body).encode("utf-8")
```

В реальном запросе используйте текущее время и отправляйте именно подписанные байты.
Не включайте `sort_keys=True`: это меняет порядок. Для подписи используется
строчное hex-представление MD5, а в `dS` — XOR **бинарных** 16-байтных MD5-значений.

## Проверки сессии

Публичный ключ должен декодироваться из Base64 в ровно 32 байта.
Для X25519 используйте библиотечную реализацию, а не обычное умножение чисел.
Base64 `cKM` содержит публичный ключ клиента, а `dS` — результат XOR хешей,
не shared secret. Закрытый материал генерируется заново для обмена.

`sid` и `exp` берутся из ответа, не вычисляются из device ID. Единица и точная
семантика `exp` здесь не объявляются универсальными. Обновляйте сессию по
признакам истечения и фактическим ответам. Сам токен аккаунта, channel token,
sid и shared secret выполняют разные роли — их нельзя подставлять друг вместо друга.
