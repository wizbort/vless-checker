#!/usr/bin/env python3
"""
VLESS Finder — полный поиск vless:// по GitHub через API + известные источники.

GitHub Code Search API:
  - Авторизация через Personal Access Token (файл .github_token)
  - Лимит: 1000 результатов на запрос, но скрипт делает десятки
    разных запросов с разбивкой по размеру файла, расширению, звёздам и т.д.
  - Каждый найденный файл скачивается как raw и из него извлекаются vless://

Фильтры:
  • flow=xtls-rprx-vision  • security=reality  • sni — валидный домен

При старте перепроверяет found_working_servers.txt.
Мёртвые удаляются, новые добавляются.
"""

import base64
import json
import os
import re
import socket
import ssl
import sys
import time
import threading
import concurrent.futures
from urllib.parse import parse_qs, unquote, quote
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# ─── Настройки ───────────────────────────────────────────────────────
TIMEOUT_CONNECT  = 5
TIMEOUT_FETCH    = 10
MAX_WORKERS      = 50       # для проверки серверов
FETCH_WORKERS    = 25       # для скачивания файлов
OUTPUT_FILE      = "found_working_servers.txt"
TOKEN_FILE       = ".github_token"
USER_AGENT       = "Mozilla/5.0"

# GitHub API: 30 search req/min с токеном. Между запросами ставим паузу.
GITHUB_SEARCH_PAUSE = 2.2   # секунд между search-запросами (≈27/мин, с запасом)
GITHUB_PER_PAGE     = 100   # макс 100

_DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)
_VLESS_RE = re.compile(r'PROXY_LINK_REMOVED

# ─── Известные прямые источники (всегда проверяются первыми) ─────────
KNOWN_SOURCES = [
    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/splitted-by-protocol/vless.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/vless.txt",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/vless",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/base64/vless",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/Surfboardv2ray/Proxy-sorter/main/output/vless.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub2.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub3.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub4.txt",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
    "https://raw.githubusercontent.com/Leon406/SubCrawler/master/sub/share/vless",
    "https://raw.githubusercontent.com/LalatinaHub/Mineral/master/result/nodes",
    "https://raw.githubusercontent.com/itsyebekhe/HiN-VPN/main/subscription/normal/vless",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/vpei/Free-Node-Merge/main/o/node.txt",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/Ashkan-m/v2ray/main/Sub.txt",
]

# ─── Запросы для GitHub Code Search ──────────────────────────────────
# Каждый запрос дополнительно дробится по размеру файла (size:),
# чтобы обойти лимит в 1000 результатов.

GITHUB_QUERIES_BASE = [
    '"PROXY_LINK_REMOVED
    '"PROXY_LINK_REMOVED "reality"',
    '"PROXY_LINK_REMOVED "xtls-rprx-vision"',
    '"PROXY_LINK_REMOVED "security=reality"',
    'vless reality xtls-rprx-vision',
    '"PROXY_LINK_REMOVED "flow=xtls-rprx-vision"',
    '"PROXY_LINK_REMOVED "pbk="',
]

# Разбивка по размерам файла — позволяет обойти лимит 1000 на запрос
SIZE_RANGES = [
    "size:<500",
    "size:500..2000",
    "size:2000..5000",
    "size:5000..20000",
    "size:20000..100000",
    "size:>100000",
]

# Дополнительные фильтры по расширению
EXTENSIONS = ["txt", "md", "yaml", "json", "conf", "list", "sub", ""]


# ═════════════════════════════════════════════════════════════════════
#                        УТИЛИТЫ
# ═════════════════════════════════════════════════════════════════════

def load_token() -> str:
    """Загружает GitHub token из файла .github_token."""
    token_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), TOKEN_FILE)
    if not os.path.exists(token_path):
        print(f"❌ Файл {TOKEN_FILE} не найден!")
        print(f"   Создайте файл {token_path} с вашим GitHub Personal Access Token.")
        print(f"   GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)")
        sys.exit(1)
    with open(token_path, "r") as f:
        token = f.read().strip()
    if not token:
        print(f"❌ Файл {TOKEN_FILE} пуст!")
        sys.exit(1)
    return token


def fetch_url(url: str, headers: dict | None = None, timeout: int = TIMEOUT_FETCH) -> str:
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    req = Request(url, headers=hdrs)
    with urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def github_api(endpoint: str, token: str) -> dict:
    """Запрос к GitHub API с авторизацией."""
    url = f"https://api.github.com{endpoint}" if endpoint.startswith("/") else endpoint
    req = Request(url, headers={
        "User-Agent": USER_AGENT,
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    })
    with urlopen(req, timeout=20) as resp:
        return json.loads(resp.read())


def try_base64_decode(text: str) -> str:
    stripped = text.strip()
    if "PROXY_LINK_REMOVED in stripped[:500]:
        return stripped
    try:
        decoded = base64.b64decode(stripped + "==").decode("utf-8", errors="ignore")
        if "PROXY_LINK_REMOVED in decoded[:1000]:
            return decoded
    except Exception:
        pass
    return stripped


def extract_vless_links(text: str) -> list[str]:
    found = _VLESS_RE.findall(text)
    cleaned = []
    for link in found:
        link = link.rstrip("\"'`>)]\n\r\t ;,")
        if link.startswith("PROXY_LINK_REMOVED and "@" in link:
            cleaned.append(link)
    return cleaned


# ═════════════════════════════════════════════════════════════════════
#                   GITHUB CODE SEARCH
# ═════════════════════════════════════════════════════════════════════

def github_code_search(query: str, token: str, max_pages: int = 10) -> list[str]:
    """
    Один поисковый запрос к GitHub Code Search API.
    Возвращает список raw-URL файлов.
    Пагинация: до max_pages страниц по 100 результатов.
    """
    raw_urls = []
    for page in range(1, max_pages + 1):
        try:
            endpoint = f"/search/code?q={quote(query, safe='')}&per_page={GITHUB_PER_PAGE}&page={page}"
            data = github_api(endpoint, token)
            items = data.get("items", [])
            if not items:
                break
            for item in items:
                html_url = item.get("html_url", "")
                if "github.com" in html_url and "/blob/" in html_url:
                    raw = html_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                    raw_urls.append(raw)
            # Если получили меньше 100 — значит последняя страница
            if len(items) < GITHUB_PER_PAGE:
                break
            time.sleep(GITHUB_SEARCH_PAUSE)
        except HTTPError as e:
            if e.code == 403:
                # Rate limit — ждём
                print(f"    ⏳ Rate limit, жду 60с...")
                time.sleep(60)
            elif e.code == 422:
                # Validation error (too many results etc.) — skip
                break
            else:
                break
        except Exception:
            break
    return raw_urls


def build_search_queries() -> list[str]:
    """
    Генерирует список поисковых запросов для максимального покрытия.
    Комбинирует базовые запросы с фильтрами по размеру и расширению.
    """
    queries = []

    # Основные комбинации: запрос + размер
    for base_q in GITHUB_QUERIES_BASE:
        for size in SIZE_RANGES:
            queries.append(f"{base_q} {size}")

    # Дополнительно: запрос + расширение (для топовых запросов)
    top_queries = GITHUB_QUERIES_BASE[:3]
    for base_q in top_queries:
        for ext in EXTENSIONS:
            if ext:
                queries.append(f"{base_q} extension:{ext}")

    # Убираем дубли, сохраняя порядок
    return list(dict.fromkeys(queries))


# ═════════════════════════════════════════════════════════════════════
#                      VLESS-ЛОГИКА
# ═════════════════════════════════════════════════════════════════════

def is_valid_domain(value: str) -> bool:
    return bool(_DOMAIN_RE.match(value))


def parse_vless(uri: str) -> dict | None:
    if not uri.startswith("PROXY_LINK_REMOVED
        return None
    try:
        without_scheme = uri[len("PROXY_LINK_REMOVED
        fragment = ""
        if "#" in without_scheme:
            without_scheme, fragment = without_scheme.rsplit("#", 1)
            fragment = unquote(fragment)
        query_str = ""
        if "?" in without_scheme:
            without_scheme, query_str = without_scheme.split("?", 1)
        if "@" not in without_scheme:
            return None
        uuid_part, hostport = without_scheme.rsplit("@", 1)
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
            "uuid": uuid_part, "host": host, "port": port,
            "params": params, "fragment": fragment, "raw": uri,
        }
    except Exception:
        return None


def passes_filter(info: dict) -> bool:
    p = info["params"]
    if p.get("flow", [None])[0] != "xtls-rprx-vision":
        return False
    if p.get("security", [None])[0] != "reality":
        return False
    sni = p.get("sni", [""])[0].split(",")[0].strip()
    if not sni or not is_valid_domain(sni):
        return False
    return True


def check_server(info: dict) -> tuple[bool, float]:
    host, port = info["host"], info["port"]
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


# ═════════════════════════════════════════════════════════════════════
#                    ФАЙЛОВАЯ ЛОГИКА
# ═════════════════════════════════════════════════════════════════════

def load_existing(filepath: str) -> list[str]:
    if not os.path.exists(filepath):
        return []
    with open(filepath, "r", encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip()]


def save_servers(filepath: str, configs: list[str]):
    with open(filepath, "w", encoding="utf-8") as f:
        for cfg in configs:
            f.write(cfg + "\n")


def recheck_existing(filepath: str) -> list[tuple[str, float]]:
    existing = load_existing(filepath)
    if not existing:
        return []
    configs = []
    for raw in existing:
        info = parse_vless(raw)
        if info and passes_filter(info):
            configs.append(info)
    if not configs:
        return []

    print(f"\n🔄 Перепроверка {len(configs)} серверов из {filepath}...")
    alive_list: list[tuple[str, float]] = []
    dead = 0
    checked = 0

    def task(info):
        return info, *check_server(info)

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(task, i): i for i in configs}
        for fut in concurrent.futures.as_completed(futures):
            info, ok, ping = fut.result()
            checked += 1
            h = f"{info['host']}:{info['port']}"
            if ok:
                print(f"  [{checked}/{len(configs)}] ✓  {h:<24} {ping:>7.0f} ms")
                alive_list.append((info["raw"], ping))
            else:
                print(f"  [{checked}/{len(configs)}] ✗  {h:<24}   --- ms — удаляем")
                dead += 1
    print(f"  Рабочих: {len(alive_list)}, удалено: {dead}")
    return alive_list


# ═════════════════════════════════════════════════════════════════════
#                         MAIN
# ═════════════════════════════════════════════════════════════════════

def main():
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║     VLESS Finder — Полный поиск по GitHub + источники      ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print("║  GitHub Code Search API с токеном авторизации.             ║")
    print("║  Десятки запросов с разбивкой по размеру / расширению.     ║")
    print("║  Перепроверка существующих + mass-скачивание + проверка.   ║")
    print("╚══════════════════════════════════════════════════════════════╝")

    token = load_token()
    print(f"  ✓ GitHub токен загружен из {TOKEN_FILE}")

    # ── Этап 0: Перепроверка ──────────────────────────────────────────
    existing_alive = recheck_existing(OUTPUT_FILE)
    existing_keys = set()
    for cfg, _ in existing_alive:
        info = parse_vless(cfg)
        if info:
            existing_keys.add((info["host"], info["port"]))

    # ── Этап 1: GitHub Code Search ───────────────────────────────────
    queries = build_search_queries()
    print(f"\n\n🔍 Этап 1: GitHub Code Search ({len(queries)} запросов)")
    print("─" * 58)
    print(f"  (лимит API: ~30 запросов/мин, каждый до 1000 результатов)")
    print(f"  Это займёт ~{len(queries) * GITHUB_SEARCH_PAUSE / 60:.0f}–{len(queries) * (GITHUB_SEARCH_PAUSE + 1) / 60:.0f} мин для поиска.\n")

    all_raw_urls: set[str] = set()       # URL raw-файлов из GitHub Search
    total_api_calls = 0

    for i, query in enumerate(queries, 1):
        short_q = query[:60] + ("..." if len(query) > 60 else "")
        print(f"  [{i}/{len(queries)}] Запрос: {short_q}", end="", flush=True)
        before = len(all_raw_urls)
        try:
            urls = github_code_search(query, token, max_pages=10)
            all_raw_urls.update(urls)
            new = len(all_raw_urls) - before
            total_api_calls += 1
            print(f"  → +{new} файлов (всего уникальных: {len(all_raw_urls)})")
        except Exception as e:
            print(f"  → ошибка: {str(e)[:40]}")
        time.sleep(GITHUB_SEARCH_PAUSE)

    # Добавляем известные прямые источники
    for src in KNOWN_SOURCES:
        all_raw_urls.add(src)

    print(f"\n  GitHub Search завершён:")
    print(f"    API-запросов: {total_api_calls}")
    print(f"    Уникальных файлов: {len(all_raw_urls)}")

    # ── Этап 2: Скачивание файлов и извлечение vless:// ──────────────
    raw_url_list = list(all_raw_urls)
    total_files = len(raw_url_list)
    print(f"\n\n📥 Этап 2: Скачиваю {total_files} файлов (параллельно, {FETCH_WORKERS} потоков)")
    print("─" * 58)

    all_vless_raw: list[str] = []
    lock = threading.Lock()
    success = 0
    fail = 0
    fetched = 0

    def fetch_and_extract(url: str) -> tuple[str, list[str]]:
        try:
            raw = fetch_url(url, timeout=8)
            text = try_base64_decode(raw)
            return url, extract_vless_links(text)
        except Exception:
            return url, []

    with concurrent.futures.ThreadPoolExecutor(max_workers=FETCH_WORKERS) as pool:
        futures = {pool.submit(fetch_and_extract, url): url for url in raw_url_list}
        for fut in concurrent.futures.as_completed(futures):
            url, links = fut.result()
            fetched += 1
            if links:
                success += 1
                all_vless_raw.extend(links)
                short = url[:70] + ("..." if len(url) > 70 else "")
                print(f"  [{fetched}/{total_files}] ✓ {len(links):>5} ссылок  {short}")
            else:
                fail += 1
            # Прогресс каждые 100 файлов
            if fetched % 200 == 0 and not links:
                print(f"  ... обработано {fetched}/{total_files}, vless-ссылок: {len(all_vless_raw)}")

    print(f"\n  Файлов с данными: {success}")
    print(f"  Пустых / недоступных: {fail}")
    print(f"  Всего vless:// ссылок: {len(all_vless_raw)}")

    # ── Этап 3: Фильтрация ───────────────────────────────────────────
    print(f"\n\n🔧 Этап 3: Фильтрация (reality + vision + sni)")
    print("─" * 58)

    filtered: list[dict] = []
    for raw_link in all_vless_raw:
        info = parse_vless(raw_link)
        if info and passes_filter(info):
            filtered.append(info)

    # Дедупликация + исключаем уже проверенные
    seen = set(existing_keys)
    unique: list[dict] = []
    for info in filtered:
        key = (info["host"], info["port"])
        if key not in seen:
            seen.add(key)
            unique.append(info)

    print(f"  Прошли фильтр: {len(filtered)}")
    print(f"  Уже в файле: {len(existing_keys)}")
    print(f"  Новых уникальных: {len(unique)}")

    if not unique and not existing_alive:
        print("\nНет конфигов для проверки.")
        return

    if not unique:
        existing_alive.sort(key=lambda x: x[1])
        save_servers(OUTPUT_FILE, [c for c, _ in existing_alive])
        print(f"\nНовых не найдено. {OUTPUT_FILE}: {len(existing_alive)} серверов.")
        return

    # ── Этап 4: Проверка доступности ─────────────────────────────────
    print(f"\n\n⚡ Этап 4: Проверка {len(unique)} серверов ({MAX_WORKERS} потоков, таймаут {TIMEOUT_CONNECT}с)")
    print("─" * 58)
    print()

    new_working: list[tuple[str, float]] = []
    checked = 0
    start_time = time.time()

    def check_task(info):
        return info, *check_server(info)

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(check_task, info): info for info in unique}
        for fut in concurrent.futures.as_completed(futures):
            info, alive, ping_ms = fut.result()
            checked += 1
            h = f"{info['host']}:{info['port']}"
            sni = info['params'].get('sni', [''])[0].split(",")[0]
            if alive:
                print(f"  [{checked}/{len(unique)}] ✓  {h:<24} {ping_ms:>7.0f} ms   sni={sni}")
                new_working.append((info["raw"], ping_ms))
            else:
                print(f"  [{checked}/{len(unique)}] ✗  {h:<24}   --- ms   sni={sni}")

    elapsed = time.time() - start_time

    # ── Этап 5: Объединение и сохранение ─────────────────────────────
    all_working = new_working + existing_alive
    all_working.sort(key=lambda x: x[1])
    new_set = set(c for c, _ in new_working)

    print(f"\n{'═' * 60}")
    print(f"Поиск завершён за {elapsed:.1f}с (проверка серверов)")
    print(f"  Новых рабочих:       {len(new_working)}")
    print(f"  Существующих:        {len(existing_alive)}")
    print(f"  Итого:               {len(all_working)}")

    if all_working:
        print(f"\n🏆 Топ-15 по пингу:")
        for i, (cfg, ping_ms) in enumerate(all_working[:15], 1):
            info = parse_vless(cfg)
            if info:
                h = f"{info['host']}:{info['port']}"
                sni = info['params'].get('sni', [''])[0].split(",")[0]
                tag = " [NEW]" if cfg in new_set else ""
                print(f"  {i:>2}. {h:<26} {ping_ms:>7.0f} ms   sni={sni}{tag}")
        if len(all_working) > 15:
            print(f"  ... и ещё {len(all_working) - 15}")

        save_servers(OUTPUT_FILE, [c for c, _ in all_working])
        print(f"\n💾 {OUTPUT_FILE}: {len(all_working)} серверов (отсортировано по пингу)")
    else:
        print("Рабочих серверов не найдено.")

    print()


if __name__ == "__main__":
    main()
