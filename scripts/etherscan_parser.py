#!/usr/bin/env python3
"""Парсер последних верифицированных контрактов с Etherscan /contractsVerified."""

from __future__ import annotations

import csv
import logging
import os
import random
import re
import sys
import time
from typing import NamedTuple

from bs4 import BeautifulSoup
from curl_cffi import requests as curl_requests

logger = logging.getLogger("etherscan_verified_parser")

BASE_URL = "https://etherscan.io/contractsVerified"
OUTPUT_CSV = os.getenv("OUTPUT_CSV", "data/contracts.csv")
MAX_PAGES = int(os.getenv("MAX_PAGES", "3"))
MIN_DELAY = 2.0
MAX_DELAY = 5.0
MAX_RETRIES = 3

USER_AGENTS: tuple[str, ...] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
)

IMPERSONATE_TARGETS: tuple[str, ...] = (
    "chrome124",
    "chrome123",
    "chrome120",
    "chrome110",
    "edge101",
    "safari15_5",
)

BLOCK_MARKERS: tuple[str, ...] = (
    "cf-browser-verification",
    "checking your browser",
    "enable javascript and cookies",
    "just a moment",
    "attention required",
    "security check",
)

ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")


class VerifiedContract(NamedTuple):
    address: str
    name: str
    compiler: str


def _build_headers() -> dict[str, str]:
    """Возвращает случайные антибот-заголовки с корректными Sec-Ch гедерами."""
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                  "image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Referer": BASE_URL,
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
    }


def _is_blocked(html: str) -> bool:
    """Проверяет, не вернулась ли страница-заглушка Cloudflare/Etherscan."""
    lower = html.lower()
    return any(marker in lower for marker in BLOCK_MARKERS)


def _clean_text(text: str) -> str:
    """Нормализует пробелы в тексте HTML-ноды."""
    return " ".join(text.split())


def _extract_address(cell) -> str:
    """Извлекает полный адрес контракта из ячейки таблицы."""
    cell_text = _clean_text(cell.get_text(" ", strip=True))
    match = ADDRESS_RE.search(cell_text)
    if match:
        return match.group(0)

    link = cell.find("a", href=True)
    if link is not None:
        match = ADDRESS_RE.search(link.get("href", ""))
        if match:
            return match.group(0)

    return ""


def _extract_compiler(compiler_cell: str, version_cell: str | None) -> str:
    """Объединяет имя компилятора и версию без дублирования соседних токенов."""
    tokens: list[str] = []
    for raw in (compiler_cell, version_cell):
        if not raw:
            continue
        for token in raw.split():
            if not tokens or tokens[-1] != token:
                tokens.append(token)
    return " ".join(tokens)


def parse_contract_rows(html: str) -> list[VerifiedContract]:
    """Парсит строки таблицы верифицированных контрактов из HTML."""
    soup = BeautifulSoup(html, "html.parser")

    table_body = soup.select_one("#table-container table tbody")
    if table_body is None:
        table_body = soup.select_one("table.table tbody")
    if table_body is None:
        logger.warning("Не удалось найти таблицу контрактов в HTML")
        return []

    rows: list[VerifiedContract] = []

    for tr in table_body.select("tr"):
        cells = tr.find_all("td", recursive=False)
        if len(cells) < 3:
            cells = tr.find_all("td")
            if len(cells) < 3:
                continue

        address = _extract_address(cells[0])
        if not address:
            continue

        name = _clean_text(cells[1].get_text(" ", strip=True)) or "Unknown"
        compiler_cell = _clean_text(cells[2].get_text(" ", strip=True))

        version_cell: str | None = None
        if len(cells) >= 4:
            version_text = _clean_text(cells[3].get_text(" ", strip=True))
            if version_text:
                version_cell = version_text

        compiler = _extract_compiler(compiler_cell, version_cell)
        rows.append(VerifiedContract(address=address, name=name, compiler=compiler))

    return rows


def create_anonymous_session() -> curl_requests.Session:
    """Создаёт сессию с TLS-имперсонацией и случайными заголовками."""
    last_error: Exception | None = None

    for target in IMPERSONATE_TARGETS:
        try:
            session = curl_requests.Session(impersonate=target)
        except Exception as exc:  # поддержка разных версий curl_cffi
            last_error = exc
            continue

        session.headers.update(_build_headers())
        return session

    logger.warning("Не удалось использовать impersonation: %s", last_error)
    session = curl_requests.Session()
    session.headers.update(_build_headers())
    return session


def fetch_page(page: int) -> str | None:
    """Загружает HTML страницы /contractsVerified с ретраями и задержками."""
    params = {"ps": 100, "p": page}

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            session = create_anonymous_session()
            response = session.get(BASE_URL, params=params, timeout=30)

            if response.status_code != 200:
                logger.warning(
                    "Страница %s, попытка %d: HTTP %s",
                    page, attempt, response.status_code,
                )
                if attempt < MAX_RETRIES:
                    time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
                continue

            html = response.text
            if _is_blocked(html):
                logger.warning(
                    "Страница %s, попытка %d: Cloudflare/Etherscan подозревает бота",
                    page, attempt,
                )
                if attempt < MAX_RETRIES:
                    time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
                continue

            return html

        except Exception as exc:
            logger.warning(
                "Страница %s, попытка %d: ошибка запроса: %s",
                page, attempt, exc,
            )
            if attempt < MAX_RETRIES:
                time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))

    return None


def collect_contracts(max_pages: int = MAX_PAGES) -> list[VerifiedContract]:
    """Собирает и дедуплицирует контракты со страниц Etherscan."""
    records: list[VerifiedContract] = []
    seen: set[str] = set()
    page = 1

    while page <= max_pages:
        logger.info("Загружаем страницу %d/%d", page, max_pages)

        html = fetch_page(page)
        if html is None:
            logger.warning("Не удалось получить страницу %d, останавливаюсь", page)
            break

        page_records = parse_contract_rows(html)
        if not page_records:
            logger.info("На странице %d контракты не найдены, останавливаюсь", page)
            break

        new_count = 0
        for record in page_records:
            key = record.address.lower()
            if key not in seen:
                seen.add(key)
                records.append(record)
                new_count += 1

        logger.info(
            "Страница %d: извлечено %d контрактов, новых: %d",
            page, len(page_records), new_count,
        )

        if page >= max_pages:
            break

        page += 1
        time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))

    return records


def save_to_csv(records: list[VerifiedContract], filename: str = OUTPUT_CSV) -> None:
    """Сохраняет записи в CSV с BOM для совместимости с Excel."""
    if not records:
        logger.warning("Нет данных для записи в %s", filename)
        return

    with open(filename, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=["address", "name", "compiler"])
        writer.writeheader()
        writer.writerows(record._asdict() for record in records)

    logger.info("Сохранено %d записей в %s", len(records), filename)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    try:
        contracts = collect_contracts(MAX_PAGES)
        save_to_csv(contracts, OUTPUT_CSV)
    except KeyboardInterrupt:
        logger.info("Прервано пользователем")
        sys.exit(130)


if __name__ == "__main__":
    main()
