#!/usr/bin/env python3
"""Парсер contractsVerified через Camoufox (анти-детект Firefox)."""
from __future__ import annotations

import csv
import random
import time
from pathlib import Path

from bs4 import BeautifulSoup
from camoufox.sync_api import Camoufox

URL = "https://etherscan.io/contractsVerified?ps=100&p=1"
OUT = Path("data") / "contracts.csv"

rows: list[list[str]] = []

for attempt in range(1, 4):
    try:
        with Camoufox(headless=True, humanize=True) as browser:
            page = browser.new_page()
            page.goto(URL, timeout=60_000)
            page.wait_for_selector("table tbody tr", timeout=30_000)
            html = page.content()

        soup = BeautifulSoup(html, "html.parser")
        for tr in soup.select("table tbody tr"):
            tds = tr.find_all("td", recursive=False)
            if len(tds) < 3:
                continue
            a0 = tds[0].find("a", href=True)
            addr = tds[0].get_text(strip=True)[:42]
            if a0 and "/address/" in a0.get("href", ""):
                addr = a0["href"].split("/address/")[-1][:42]
            name = tds[1].get_text(" ", strip=True)
            compiler = tds[2].get_text(" ", strip=True)
            if len(tds) >= 4:
                compiler = f"{compiler} {tds[3].get_text(' ', strip=True)}".strip()
            if addr.startswith("0x") and len(addr) == 42:
                rows.append([addr, name, compiler])
        print(f"попытка {attempt}: строк извлечено {len(rows)}")
        if rows:
            break
    except Exception as exc:
        print(f"попытка {attempt}: ошибка {type(exc).__name__}: {exc}")
        time.sleep(random.uniform(3, 6))

with open(OUT, "w", newline="", encoding="utf-8-sig") as fh:
    w = csv.writer(fh)
    w.writerow(["address", "name", "compiler"])
    w.writerows(rows)

print(f"сохранено: {len(rows)} строк в {OUT}")
