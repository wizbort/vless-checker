#!/usr/bin/env python3
"""
VLESS Checker — проверяет серверы из подписок на доступность.

Требования к VLESS-ссылкам:
  • flow=xtls-rprx-vision
  • security=reality
  • sni — валидный домен (не мусор / эмодзи)

Серверы проверяются TLS-хендшейком (REALITY) к host:port.
Рабочие конфиги сохраняются в файл working_servers.txt.
"""

import base64
import os
import re
import socket
import ssl
import sys
import time
import concurrent.futures
from urllib.parse import urlparse, parse_qs, unquote
from urllib.request import urlopen, Request
from urllib.error import URLError

# Паттерн валидного домена: буквы, цифры, точки, дефисы
_DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)

# ─── Настройки ───────────────────────────────────────────────────────
TIMEOUT_CONNECT = 5        # тайм-аут TCP-подключения (сек)
MAX_WORKERS     = 50       # параллельные проверки
OUTPUT_FILE     = "working_servers.txt"
USER_AGENT      = "Mozilla/5.0"
# ─────────────────────────────────────────────────────────────────────


def read_input() -> tuple[list[str], list[str]]:
    """Читает ввод из stdin.
    Разделяет на ссылки подписок (http/https) и прямые vless:// конфиги.
    Возвращает (subscription_urls, direct_vless_configs).
    """
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║           VLESS Subscription Checker                       ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print("║  Вставьте ссылки на подписки или прямые vless:// ссылки. ║")
    print("║  Нажмите Enter на пустой строке, чтобы начать проверку.    ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()

    sub_urls: list[str] = []
    direct_configs: list[str] = []
    while True:
        try:
            line = input("Ввод> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            break
        if line.startswith("PROXY_LINK_REMOVED
            direct_configs.append(line)
        else:
            sub_urls.append(line)
    return sub_urls, direct_configs


def fetch_subscription(url: str) -> str:
    """Скачивает содержимое подписки по URL."""
    req = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(req, timeout=15) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def decode_subscription(raw: str) -> list[str]:
    """
    Пытается декодировать base64, если содержимое закодировано.
    Возвращает список строк (по одной конфигурации на строку).
    """
    lines = raw.strip().splitlines()

    # Если первая строчка уже начинается с PROXY_LINK_REMOVED значит plain-text
    for line in lines:
        if line.strip().startswith("PROXY_LINK_REMOVED
            return [l.strip() for l in lines if l.strip()]

    # Иначе пробуем base64
    try:
        decoded = base64.b64decode(raw.strip() + "==").decode("utf-8", errors="ignore")
        return [l.strip() for l in decoded.splitlines() if l.strip()]
    except Exception:
        return [l.strip() for l in lines if l.strip()]


def parse_vless(uri: str) -> dict | None:
    """
    Разбирает строку вида:
      PROXY_LINK_REMOVED
    Возвращает dict с полями или None, если формат невалидный / не vless.
    """
    if not uri.startswith("PROXY_LINK_REMOVED
        return None

    try:
        # urlparse не дружит с кастомными схемами, помогаем вручную
        without_scheme = uri[len("PROXY_LINK_REMOVED

        # Отделяем фрагмент (#...)
        fragment = ""
        if "#" in without_scheme:
            without_scheme, fragment = without_scheme.rsplit("#", 1)
            fragment = unquote(fragment)

        # Отделяем query (?...)
        query_str = ""
        if "?" in without_scheme:
            without_scheme, query_str = without_scheme.split("?", 1)

        # UUID@HOST:PORT
        if "@" not in without_scheme:
            return None
        uuid_part, hostport = without_scheme.rsplit("@", 1)

        # HOST:PORT  — поддержка IPv6 [::1]:443
        if hostport.startswith("["):
            closing = hostport.index("]")
            host = hostport[1:closing]
            port_str = hostport[closing + 1:].lstrip(":")
        else:
            parts = hostport.rsplit(":", 1)
            host = parts[0]
            port_str = parts[1] if len(parts) == 2 else "443"

        port = int(port_str) if port_str else 443
        params = parse_qs(query_str)

        return {
            "uuid": uuid_part,
            "host": host,
            "port": port,
            "params": params,
            "fragment": fragment,
            "raw": uri,
        }
    except Exception:
        return None


def is_valid_domain(value: str) -> bool:
    """Проверяет, является ли строка валидным доменным именем."""
    return bool(_DOMAIN_RE.match(value))


def passes_filter(info: dict) -> bool:
    """Проверяет, удовлетворяет ли конфиг обязательным условиям."""
    p = info["params"]

    # flow=xtls-rprx-vision
    flow = p.get("flow", [None])[0]
    if flow != "xtls-rprx-vision":
        return False

    # security=reality
    security = p.get("security", [None])[0]
    if security != "reality":
        return False

    # sni должен быть валидным доменом
    sni_raw = p.get("sni", [""])[0]
    # sni может содержать запятые (google.com,www.google.com) — берём первый
    sni = sni_raw.split(",")[0].strip()
    if not sni or not is_valid_domain(sni):
        return False

    return True


def check_server(info: dict) -> tuple[bool, float]:
    """TLS-проверка: подключаемся к host:port и делаем TLS-хендшейк с SNI.
    Это гораздо точнее для REALITY — мёртвые серверы не пройдут хендшейк.
    Возвращает (alive, ping_ms)."""
    host = info["host"]
    port = info["port"]
    sni = info["params"].get("sni", [""])[0].split(",")[0].strip()

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        t0 = time.monotonic()
        raw_sock = socket.create_connection((host, port), timeout=TIMEOUT_CONNECT)
        tls_sock = ctx.wrap_socket(raw_sock, server_hostname=sni)
        ping_ms = (time.monotonic() - t0) * 1000
        tls_sock.close()
        return True, ping_ms
    except (socket.timeout, OSError, ssl.SSLError):
        return False, -1


def load_existing_servers(filepath: str) -> list[str]:
    """Загружает существующие конфиги из файла."""
    if not os.path.exists(filepath):
        return []
    with open(filepath, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def save_servers(filepath: str, configs: list[str]):
    """Сохраняет конфиги в файл."""
    with open(filepath, "w", encoding="utf-8") as f:
        for cfg in configs:
            f.write(cfg + "\n")


def recheck_existing(filepath: str) -> list[tuple[str, float]]:
    """Перепроверяет существующие серверы в файле. Удаляет мёртвые, оставляет рабочие.
    Возвращает список (raw_config, ping_ms) рабочих серверов."""
    existing = load_existing_servers(filepath)
    if not existing:
        return []

    print(f"\n🔄 Перепроверка существующих серверов из {filepath}: {len(existing)} шт.")

    configs_to_check: list[dict] = []
    for raw in existing:
        info = parse_vless(raw)
        if info and passes_filter(info):
            configs_to_check.append(info)

    if not configs_to_check:
        print("  Нет валидных конфигов в файле.")
        return []

    alive_list: list[tuple[str, float]] = []
    dead_count = 0
    checked = 0

    def task(info):
        ok, ping = check_server(info)
        return info, ok, ping

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(task, info): info for info in configs_to_check}
        for future in concurrent.futures.as_completed(futures):
            info, alive, ping_ms = future.result()
            checked += 1
            host_str = f"{info['host']}:{info['port']}"
            if alive:
                print(f"  [{checked}/{len(configs_to_check)}] ✓  {host_str:<24} {ping_ms:>7.0f} ms — оставляем")
                alive_list.append((info["raw"], ping_ms))
            else:
                print(f"  [{checked}/{len(configs_to_check)}] ✗  {host_str:<24}   --- ms — удаляем")
                dead_count += 1

    print(f"  Рабочих: {len(alive_list)}, удалено мёртвых: {dead_count}")
    return alive_list


def main():
    # 0. Перепроверяем существующие серверы
    existing_alive = recheck_existing(OUTPUT_FILE)
    existing_raw_set = {cfg for cfg, _ in existing_alive}

    # 1. Сбор ввода
    sub_urls, direct_configs = read_input()
    if not sub_urls and not direct_configs:
        # Если ничего не введено, просто сохраняем перепроверенные
        if existing_alive:
            existing_alive.sort(key=lambda x: x[1])
            save_servers(OUTPUT_FILE, [cfg for cfg, _ in existing_alive])
            print(f"\nОбновлён {OUTPUT_FILE}: {len(existing_alive)} рабочих серверов.")
        else:
            print("Ничего не введено. Выход.")
        return

    # 2. Скачивание подписок + прямые конфиги
    all_configs: list[str] = list(direct_configs)
    if direct_configs:
        print(f"\nПрямых vless:// ссылок: {len(direct_configs)}")
    for idx, url in enumerate(sub_urls, 1):
        print(f"\n[Подписка {idx}/{len(sub_urls)}] Загружаю: {url[:80]}...")
        try:
            raw = fetch_subscription(url)
            lines = decode_subscription(raw)
            print(f"  ↳ получено строк: {len(lines)}")
            all_configs.extend(lines)
        except (URLError, Exception) as e:
            print(f"  ✗ Ошибка загрузки: {e}")

    print(f"\nВсего конфигов получено: {len(all_configs)}")

    # 3. Парсим и фильтруем VLESS
    vless_list: list[dict] = []
    skipped = 0
    for line in all_configs:
        info = parse_vless(line)
        if info is None:
            skipped += 1
            continue
        if not passes_filter(info):
            skipped += 1
            continue
        # Пропускаем дубли тех, что уже есть в файле
        key = (info["host"], info["port"])
        vless_list.append(info)

    print(f"Прошли фильтр (reality + xtls-rprx-vision + sni): {len(vless_list)}")
    print(f"Пропущено: {skipped}")

    if not vless_list:
        if existing_alive:
            existing_alive.sort(key=lambda x: x[1])
            save_servers(OUTPUT_FILE, [cfg for cfg, _ in existing_alive])
            print(f"\nОбновлён {OUTPUT_FILE}: {len(existing_alive)} рабочих серверов.")
        else:
            print("Нет подходящих конфигов для проверки.")
        return

    # Дедупликация: убираем те, что уже проверены и живы
    existing_keys = set()
    for cfg in existing_raw_set:
        info = parse_vless(cfg)
        if info:
            existing_keys.add((info["host"], info["port"]))

    new_vless: list[dict] = []
    seen = set()
    for info in vless_list:
        key = (info["host"], info["port"])
        if key in existing_keys or key in seen:
            continue
        seen.add(key)
        new_vless.append(info)

    print(f"Новых для проверки (без дублей с существующими): {len(new_vless)}")

    if not new_vless:
        if existing_alive:
            existing_alive.sort(key=lambda x: x[1])
            save_servers(OUTPUT_FILE, [cfg for cfg, _ in existing_alive])
            print(f"\nОбновлён {OUTPUT_FILE}: {len(existing_alive)} рабочих серверов.")
        return

    # 4. Проверяем доступность серверов
    print(f"\nПроверяю {len(new_vless)} серверов (до {MAX_WORKERS} потоков, таймаут {TIMEOUT_CONNECT}с)...\n")

    new_working: list[tuple[str, float]] = []
    checked = 0
    start_time = time.time()

    def task(info: dict) -> tuple[dict, bool, float]:
        alive, ping_ms = check_server(info)
        return info, alive, ping_ms

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(task, info): info for info in new_vless}
        for future in concurrent.futures.as_completed(futures):
            info, alive, ping_ms = future.result()
            checked += 1
            host_str = f"{info['host']}:{info['port']}"
            sni = info['params'].get('sni', [''])[0]
            if alive:
                status = "✓"
                ping_str = f"{ping_ms:>7.0f} ms"
                new_working.append((info["raw"], ping_ms))
            else:
                status = "✗"
                ping_str = "  --- ms"
            print(f"  [{checked}/{len(new_vless)}] {status}  {host_str:<24} {ping_str}   sni={sni}")

    elapsed = time.time() - start_time

    # 5. Объединяем: новые рабочие + существующие рабочие, сортируем по пингу
    all_working = existing_alive + new_working
    all_working.sort(key=lambda x: x[1])

    # 6. Сохраняем результаты
    print(f"\n{'═' * 60}")
    print(f"Проверка завершена за {elapsed:.1f}с")
    print(f"Новых рабочих: {len(new_working)}")
    print(f"Существующих рабочих: {len(existing_alive)}")
    print(f"Итого: {len(all_working)}")

    if all_working:
        print(f"\nТоп серверов по пингу:")
        for i, (cfg, ping_ms) in enumerate(all_working[:10], 1):
            info = parse_vless(cfg)
            if info:
                host_str = f"{info['host']}:{info['port']}"
                sni = info['params'].get('sni', [''])[0]
                print(f"  {i:>2}. {host_str:<24} {ping_ms:>7.0f} ms   sni={sni}")
        if len(all_working) > 10:
            print(f"  ... и ещё {len(all_working) - 10}")

        save_servers(OUTPUT_FILE, [cfg for cfg, _ in all_working])
        print(f"\nСохранено в: {OUTPUT_FILE} ({len(all_working)} серверов, отсортировано по пингу)")
    else:
        print("Рабочих серверов не найдено.")

    print()


if __name__ == "__main__":
    main()
