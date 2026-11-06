# ProxyPanel — как конфигурировать панель

## Быстрый старт

Вся настройка — один файл `~/main/.config/proxypanel/proxies.yaml`: правите его в панели (раздел «Конфиг») или в редакторе, затем «Применить». Панель слушает только http://127.0.0.1:8800 и пароля не имеет.

1. Установка (Ubuntu 24.04+ / Debian 12+, от обычного пользователя, не root):

   ```bash
   git clone https://github.com/ezyhook/proxypanel.git && cd proxypanel
   ./install.sh
   ```

   Скрипт ставит пакеты, venv, `pp-run`, включает linger и качает недостающие бинарники в `~/main/bin`. На свежей установке кладёт пример `proxies.yaml` и образцы конфигов клиентов.
2. Откройте http://127.0.0.1:8800 → «Конфиг». Все туннели примера выключены (`autostart: false`).
3. Положите конфиги клиентов (wireproxy `.conf`, hysteria `.yaml`, экспорт AmneziaWG…) в `~/main/.config/proxypanel/`.
4. Опишите туннели, впишите свои серверы и ключи, уберите `autostart: false`.
5. «Сохранить и применить». Панель проверит конфиг, создаст systemd-units `pp-<имя>.service` и запустит туннели.

«Сохранить» только записывает файл (с бэкапом `proxies.yaml.bak`); «Применить» генерирует units и конфиги и перезапускает изменённое. Пока не применено, в панели висит плашка «сохранён, но не применён». То же из терминала:

```bash
~/main/.local/share/proxypanel/venv/bin/python ~/main/.local/share/proxypanel/app.py apply
```

## Структура proxies.yaml

Обязателен только раздел `tunnels`; всё остальное имеет разумные значения по умолчанию и пишется, только если нужно изменить.

| Раздел | Что задаёт |
| --- | --- |
| `tunnels` | туннели: каждый — свой процесс, порт и systemd-unit |
| `apps` | ярлыки в меню: программа через туннель (pp-run) |
| `singbox` + `groups` | опциональный комбинатор: единый вход и автовыбор |
| `health` | проверки туннелей: задержка, exit IP |
| `notify` | уведомления на рабочий стол |
| `updates` | обновления бинарников с GitHub |
| `panel` | адрес и порт самой панели |

Минимальный рабочий конфиг — один туннель:

```yaml
tunnels:
  vps1-ssh:
    port: 1081
    cmd: autossh -M 0 -N -D 127.0.0.1:{port} -o BatchMode=yes user@vps1.example.com
```

**Где что лежит.** Корень `~/main` меняется переменной `PP_MAIN` при установке.

| Путь | Что | Кто пишет |
| --- | --- | --- |
| `~/main/.config/proxypanel/proxies.yaml` | ваш конфиг | вы |
| `~/main/.config/proxypanel/*.conf, *.yaml, *.json` | конфиги клиентов | вы |
| `~/main/.config/proxypanel/run/` | скрипты запуска и копии конфигов с подстановками | панель, не править |
| `~/main/bin/` | sing-box, hysteria, wireproxy, wireproxy-awg, wg-obfuscator, pp-run | панель («Компоненты») |
| `~/.config/systemd/user/pp-*.service` | units туннелей | панель, не править |

Относительные пути в `cmd` и `config` считаются от `~/main/.config/proxypanel`. Ваши исходные файлы панель не меняет: она кладёт копии в `run/`, а лишние оттуда удаляет при каждом «Применить». Каталог конфигов — права 700, файлы с ключами — 600.

## Общие поля туннеля

У каждого туннеля есть имя, тип (`kind`), способ запуска (`cmd` и/или `config`) и локальный SOCKS-порт. Имя: `a-z 0-9 - _`, до 40 символов, без суффиксов `-obfs`/`-http` и не `select`, `direct`, `singbox`, `panel`, `in`, `local`.

| Поле | По умолчанию | Зачем |
| --- | --- | --- |
| `kind` | по программе в `cmd` | `ssh`, `hysteria2`, `wireproxy`, `amneziawg` (`awg`), `sing-box`, `wg-obfuscator` |
| `port` | из файла клиента | локальный SOCKS5 на 127.0.0.1 |
| `http_port` | нет | ещё и HTTP-прокси |
| `cmd` | для `config` — по `kind` | команда на переднем плане, без демонизации |
| `config` | нет | файл клиента; панель делает копию с подстановками |
| `description` | нет | подпись в карточке и unit |
| `autostart` | `true` | запускать при «Применить» и загрузке |
| `restart_sec` | `3` | пауза перед рестартом, 0…3600 с; при падениях подряд растёт до 60 с |
| `requires` | `[]` | туннели, которые должны работать раньше |
| `env` | `{}` | переменные окружения процесса |
| `socks` | `true`, если есть `port` | `false` — туннель не SOCKS (например, проброс порта) |
| `via` | нет | цепочка: идти через другой туннель |
| `obfuscator` | нет | обёртка wg-obfuscator для WireGuard |

**Порты — в одном месте.** Лучше задавать их в `proxies.yaml`: панель сама допишет их в копию файла клиента и проверит на конфликты. Нет `port` в `proxies.yaml` — берётся из файла клиента. Задан в обоих местах и разный — главный `proxies.yaml`, панель предупредит.

**Подстановки** работают в `cmd` и в файле клиента:

- `{port}`, `{http_port}`, `{name}`, `{config}` (путь к копии в `run/`);
- `{obfs}` — адрес локального обфускатора;
- `{via}`, `{via_host}`, `{via_port}`, `{via_url}` — SOCKS верхнего туннеля цепочки;
- `{confdir}`, `{bin}`, `{main}`, `{home}` — каталоги.

## Туннели по типам

Для внешних клиентов (ssh, hysteria, wireproxy, AmneziaWG) достаточно `kind` + `config`, а sing-box можно описать прямо в YAML.

### ssh / autossh

```yaml
vps1-ssh:
  kind: ssh
  port: 1081
  env: { AUTOSSH_GATETIME: "0" }
  cmd: >-
    autossh -M 0 -N -D 127.0.0.1:{port}
    -o ServerAliveInterval=15 -o ServerAliveCountMax=3
    -o ExitOnForwardFailure=yes -o BatchMode=yes
    user@vps1.example.com
```

Нужен ключ без пароля или ssh-agent, доступный user-сервисам. HTTP ssh не умеет: при `http_port` панель поднимет мост HTTP→SOCKS.

### hysteria2

```yaml
nl-hy2:
  kind: hysteria2
  port: 1082
  http_port: 1182
  config: hy2-nl.yaml      # cmd не нужен: hysteria client -c {config}
```

Панель сама выставит `socks5.listen` и `http.listen` в копии конфига.

### wireproxy (WireGuard → SOCKS)

```yaml
de-wg:
  kind: wireproxy
  port: 1083
  http_port: 1183
  config: wireproxy-de.conf
```

В `.conf` — обычные `[Interface]` и `[Peer]`; `[Socks5]` и `[http]` панель допишет сама. Можно подключить готовый wg-quick конфиг строкой `WGConfig = wg0.conf`.

### AmneziaWG

```yaml
nl-awg:
  kind: amneziawg          # или awg
  port: 1088
  http_port: 1188
  config: awg-nl.conf      # экспорт из клиента Amnezia как есть
```

- Клиент — wireproxy-awg. Он ставится по требованию: опишите туннель, «Применить», затем «Компоненты» → wireproxy-awg → «Установить».
- Экспорт «Формат AmneziaWG / awg-quick» кладётся без правок: `Jc`, `S1`…`S4`, `H1`…`H4`, `I1`…`I5` должны совпадать с сервером.
- При «Применить» конфиг проверяет сам клиент; с ошибкой туннель не перезапускается.
- AWG-конфиг с `kind: wireproxy` и `obfuscator` у AWG — ошибки.

### sing-box: три варианта

```yaml
# 1) outbound/endpoint прямо в YAML (kind можно не писать)
fi-vless:
  port: 1085
  outbound: { type: vless, server: fi.example.com, server_port: 443, uuid: ..., tls: {...} }

# 2) тот же объект из JSON-файла (экспорт из клиента, с полем "type")
nl-sb:
  port: 1087
  config: sb-nl.json

# 3) полный конфиг sing-box — запускается как есть
my-sb:
  port: 1089               # необязательно: иначе из первого mixed/socks inbound
  config: full.json
```

Варианты 1 и 2 — отдельный процесс sing-box на туннель, с ними работают `via`, `obfuscator`, `http_port`. `tag` и `detour` не пишите — их задаёт панель. В варианте 3 панель только ставит вход на `port`, добавляет HTTP-вход при `http_port` и `detour` при `via`.

### WireGuard в sing-box и поля wg-quick

```yaml
de-wg-sb:
  port: 1084
  endpoint:
    type: wireguard
    address: [10.66.0.3/32]
    private_key: ...
    peers:
      - address: vps-de.example.com
        port: 51820
        public_key: ...
        pre_shared_key: ...      # wg genpsk, 44 символа
        allowed_ips: [0.0.0.0/0]
        persistent_keepalive_interval: 25
```

Можно писать и как в wg-quick, панель переведёт: `PrivateKey`, `PublicKey`, `PresharedKey`, `AllowedIPs: "0.0.0.0/0, ::/0"`, `PersistentKeepalive`, `Endpoint: host:port`.

## Обфускатор, цепочки и HTTP-прокси

### Обёртка wg-obfuscator

Для WireGuard-туннелей (wireproxy или sing-box `endpoint: {type: wireguard}`): конфиг остаётся обычным, с реальным адресом сервера, а обфускатор описывается рядом.

```yaml
de-wg:
  kind: wireproxy
  port: 1083
  config: wireproxy-de.conf     # Endpoint = vps-de.example.com:19999
  obfuscator:
    key: мой-ключ               # как на сервере
    masking: STUN
    in-timeout: 60
```

Панель поднимает `pp-de-wg-obfs.service` на 127.0.0.1:52000 (далее 52001…), перенаправляет на него Endpoint и связывает units: старт, стоп и рестарт идут вместе.

| Параметр | Значение |
| --- | --- |
| `key` | обязателен, как на сервере |
| `target` | адрес сервера; по умолчанию из Endpoint/peer. При нескольких `[Peer]` — обязателен |
| `masking` | `STUN`, `AUTO` (по умолчанию), `NONE` |
| `listen_port` | локальный UDP-порт, по умолчанию с 52000 |
| `in-timeout`, `idle-timeout`, `resolve-interval`, `max-dummy`, `max-clients`, `verbose`, `fwmark` | передаются обфускатору как есть |

Masking STUN добавляет байты к пакетам: ставьте `MTU = 1380` или меньше и `PersistentKeepalive = 25`. Обфускатор несовместим с `via` и не нужен AmneziaWG.

### Цепочки `via`

`via: <туннель>` пускает коннект к серверу через SOCKS-порт другого туннеля; unit получает зависимость от верхнего.

| Туннель | Как строится цепочка |
| --- | --- |
| ssh / autossh | само: `ProxyCommand=nc -X 5 -x 127.0.0.1:PORT %h %p` |
| sing-box (варианты 1–3) | `detour` через SOCKS верхнего туннеля |
| остальные | вручную подстановками `{via}`, `{via_url}`, `{via_host}`, `{via_port}` |
| через группу | `via: auto` — нужен комбинатор и `port` у группы |

UDP-протоколы (hysteria2, WireGuard, AmneziaWG, tuic) через `ssh -D` не проходят: wireproxy/hysteria через `via` панель не пропустит, для sing-box выдаст предупреждение. Циклы в `via` и `requires` — ошибка конфига.

### HTTP-прокси рядом с SOCKS (`http_port`)

Для программ, не умеющих SOCKS (apt, часть Electron и Java). Кто отдаёт HTTP:

- wireproxy / AmneziaWG — сам клиент, `[http] BindAddress`;
- hysteria — сама, `http.listen`;
- sing-box — основной `port` уже понимает и SOCKS, и HTTP; `http_port` — отдельный вход;
- ssh и остальные — мост HTTP→SOCKS `pp-<имя>-http.service` на sing-box, живёт вместе с туннелем.

## Комбинатор, pp-run и ярлыки

### Комбинатор sing-box (опция)

Единый вход и автовыбор поверх портов туннелей; сами туннели продолжают работать на своих портах.

```yaml
singbox:
  enabled: true
  port: 1080                 # единый вход socks5 + http, выбор выхода — в панели
  default: auto
  rules:                     # маршрутизация по доменам (правила sing-box)
    - { domain_suffix: [".ru", ".рф"], outbound: direct }
groups:
  auto:
    type: urltest            # самый быстрый живой; selector — ручной выбор
    port: 1090               # свой вход прямо в группу (необязательно)
    members: [vps1-ssh, nl-hy2, de-wg]
```

| Ключ `singbox` | По умолчанию |
| --- | --- |
| `enabled` | `false` |
| `port` / `clash_api_port` | `1080` / `9090` |
| `default` | первая группа или туннель |
| `test_url` / `test_interval` | `https://www.gstatic.com/generate_204` / `3m` |
| `log_level` | `warn` |
| `bin` | `~/main/bin/sing-box`, затем PATH |

У группы `urltest` можно задать `url`, `interval` и `tolerance` (мс, по умолчанию 50). В `members` — туннели с SOCKS-портом, другие группы и `direct`. Выключили комбинатор — его unit удаляется.

### pp-run: программа через туннель

```bash
pp-run -l                         # туннели, порты, состояние
pp-run de-wg telegram-desktop     # Telegram через de-wg
pp-run nl-hy2 google-chrome       # Chrome с отдельным профилем
pp-run vps1-ssh curl ifconfig.co  # консольная программа
pp-run -f vps1-ssh some-app       # принудительно через proxychains4
```

Остановленный туннель pp-run запустит сам. Браузеры получают отдельный профиль на туннель в `~/main/profiles/`, Telegram — предложение включить прокси, Electron-программы — `--proxy-server`, остальные — `ALL_PROXY`/`HTTP(S)_PROXY`.

### Ярлыки в меню (`apps`)

```yaml
apps:
  telegram:  { tunnel: de-wg, cmd: telegram-desktop }
  chrome-nl: { tunnel: nl-hy2, cmd: google-chrome, title: "Chrome · Нидерланды" }
  old-app:   { tunnel: vps1-ssh, cmd: some-app, mode: proxychains }
```

При «Применить» в `~/.local/share/applications/` появятся ярлыки с иконкой исходной программы. `tunnel` — туннель, а при комбинаторе ещё `singbox` или группа с `port`. `mode`: `auto` или `proxychains`; есть `title` и `icon`. Удалили запись — ярлык исчезнет.

## Проверки, уведомления, обновления, панель

Эти разделы можно не писать вовсе: значения ниже действуют по умолчанию. Указывайте только то, что меняете.

| Ключ | По умолчанию | Что значит |
| --- | --- | --- |
| `health.interval` | `30` | проверка туннелей раз в N с (3…86400) |
| `health.ip_interval` | `300` | как часто узнавать exit IP и страну, с |
| `health.timeout` | `8` | таймаут одной проверки, с |
| `health.url` / `health.ip_url` | gstatic generate_204 / ipinfo.io/json | куда ходит проверка |
| `notify.enabled` | `true` | уведомления notify-send |
| `notify.on_crash` / `on_down` / `on_recover` / `on_update` | `true` | упал, не отвечает, снова работает, новая версия |
| `notify.on_ip_change` | `false` | сменился exit IP единого входа |
| `notify.fail_threshold` | `2` | сколько провалов подряд до «не отвечает» |
| `notify.cooldown` | `300` | не чаще раза в N с на одно событие |
| `updates.enabled` | `true` | проверять новые версии бинарников |
| `updates.check_interval_h` | `12` | как часто, ч |
| `updates.auto_install` | `false` | ставить обновления самому |
| `updates.proxy` | `auto` | `auto`: напрямую, потом через комбинатор и туннели; `direct`; `socks5h://…` |
| `updates.prerelease` | `false` | брать беты |
| `updates.github_token` | пусто | если упираетесь в лимит GitHub API (60 запросов/час) |
| `updates.disabled` | `[]` | компоненты, которые не трогать |
| `panel.listen` / `panel.port` | `127.0.0.1` / `8800` | только loopback: `127.0.0.1`, `localhost`, `::1` |

**Компоненты.** sing-box, hysteria, wireproxy и wg-obfuscator `install.sh` ставит сразу. wireproxy-awg — по требованию: только если в конфиге есть AWG-туннель или он уже установлен. Каждая установка проверяет sha256 и пробно запускает бинарник; старая версия остаётся для отката. Из терминала:

```bash
app.py check                   # проверить обновления
app.py install wireproxy-awg   # поставить один (или all / missing)
app.py rollback sing-box       # вернуть предыдущую версию
```

## Типичные ошибки

Конфиг проверяется при сохранении: с ошибкой он не запишется (есть «Сохранить всё равно»), а редактор перейдёт к строке с ошибкой. Перед запуском панель ещё проверяет программу, файлы и порты — проблемы видны в карточке туннеля.

| Сообщение | Что сделать |
| --- | --- |
| «порт N уже занят (…)» | два туннеля, группа или панель на одном порту — смените один |
| «порт N уже занят: <процесс>» в карточке | порт держит программа вне панели — остановите её или смените порт |
| «программа «X» не найдена» | «Компоненты» → «Установить», или поставьте в PATH |
| «в конфиге параметры AmneziaWG … укажите kind: amneziawg» | это AWG-конфиг, обычный wireproxy его не поймёт |
| «конфиг AmneziaWG не прошёл проверку: …» | сверьте Jc/S/H с сервером или возьмите свежий экспорт; старый процесс продолжает работать |
| «цикл в via» / «цикл в requires/via: a → b → a» | туннели зависят друг от друга по кругу — уберите одну связь |
| «via для «X» не настраивается автоматически» | UDP-клиент — опишите его как sing-box `outbound`/`endpoint`; иначе — подстановки `{via…}` |
| «obfuscator и via несовместимы» | обфускатор сам ходит к серверу по UDP — уберите одно |
| «несколько [Peer] — задайте obfuscator.target» | укажите `target: host:port` сервера явно |
| «pre_shared_key — 32 байта в base64» | PSK должен быть 44 символа, как выдаёт `wg genpsk` |
| «panel.listen: только 127.0.0.1/localhost/::1» | панель без пароля и управляет процессами — в сеть её не открывать |
| «сохранён, но не применён» | нажмите «Применить» |
| «падает в цикле» | причина — в карточке и в «Логи» (`journalctl --user -u pp-<имя>`) |

Полный пример с комментариями — [proxies.example.yaml](../proxies.example.yaml), все детали — [README](../README.md).
