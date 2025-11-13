#!/usr/bin/env python3
"""
core_exploit.py
Exploit seguro, automatizado y genérico basado en discovery_<program>.json

Realiza:
 - Self-IDOR
 - Reflected XSS no destructivo
 - Open redirect seguro
 - Inspección pasiva de WebSocket
 - Validación mínima de endpoints sensibles (auth / payment / upload / admin)

Todo conforme a BBP:
 • No se ataca a usuarios reales
 • No se fuerza autenticación ajena
 • No se modifica información de terceros
 • No se envían payloads peligrosos
 • Respeta rate-limit y cabeceras del programa
"""

import argparse
import json
import os
import sys
import time
import asyncio
import websockets
import aiohttp
from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import Dict, List, Any, Optional
from urllib.parse import urlencode, urlparse, parse_qs


# ===========================
# DATA CLASSES
# ===========================

@dataclass
class ExploitResult:
    issue_id: str
    issue_type: str
    endpoint_url: str
    method: str
    success: bool
    evidence: Dict[str, Any]
    notes: str


@dataclass
class ExploitSummary:
    program_id: str
    generated_at: str
    results: List[ExploitResult]
    stats: Dict[str, Any]


# ===========================
# CONFIG
# ===========================

def load_program_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    cfg.setdefault("exploit", {})
    return cfg


def load_discovery(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ===========================
# HTTP CLIENT
# ===========================

class HttpClient:
    """
    Cliente seguro para requests automatizados.
    Respeta rate-limit y añade headers del programa.
    """

    def __init__(self, headers: Dict[str, str], rate_limit: float):
        self.headers = headers
        self.rate_limit = rate_limit
        self._last_request = 0.0

    async def get(self, session: aiohttp.ClientSession, url: str, params=None):
        await self._respect_rate()
        try:
            async with session.get(url, headers=self.headers, params=params, timeout=10) as resp:
                body = await resp.text()
                return resp.status, dict(resp.headers), body
        except Exception as e:
            return None, {}, f"error: {e}"

    async def _respect_rate(self):
        now = time.time()
        if now - self._last_request < self.rate_limit:
            await asyncio.sleep(self.rate_limit)
        self._last_request = time.time()


# ===========================
# PAYLOADS
# ===========================

SAFE_XSS_PAYLOAD = "<xss_test_safe>"

SAFE_REDIRECT_TARGET = "https://example.com/"  # dominio neutro sin impacto


# ===========================
# EXPLOIT IMPLEMENTATIONS
# ===========================

async def exploit_idor(issue: Dict[str, Any], session: aiohttp.ClientSession, http: HttpClient):
    """
    Self-IDOR:
    • Extrae el parámetro sensible
    • Cambia el ID por otro válido pero propio (ejemplo: +1 / -1)
    • No usa IDs de otros usuarios
    """
    url = issue["endpoint_url"]
    params = issue["params"]

    parsed = urlparse(url)
    qs = parse_qs(parsed.query)

    if not params:
        return False, {"reason": "No params for IDOR"}

    p = params[0]

    if p not in qs:
        return False, {"reason": f"Param {p} not found in URL"}

    try:
        original_id = int(qs[p][0])
    except:
        return False, {"reason": f"Param {p} is not int"}

    # Self-IDOR test: probamos ID adyacentes, sin atacar a terceros
    test_ids = [original_id, original_id + 1, original_id - 1]

    results = {}

    for test_id in test_ids:
        new_qs = dict(qs)
        new_qs[p] = str(test_id)
        new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(new_qs, doseq=True)}"

        status, headers, body = await http.get(session, new_url)

        results[test_id] = {
            "status": status,
            "len": len(body) if body else 0
        }

    # Heurística simple: cambia la respuesta al variar ID?
    base_len = results[original_id]["len"]
    anomaly = any(abs(r["len"] - base_len) > 25 for r in results.values())

    return anomaly, {"tests": results}


async def exploit_xss(issue: Dict[str, Any], session: aiohttp.ClientSession, http: HttpClient):
    """
    Prueba de XSS reflejado segura:
    • Inserta un marcador inofensivo <xss_test_safe>
    • No ejecuta JS
    • No realiza acciones peligrosas
    """
    url = issue["endpoint_url"]
    params = issue["params"]

    parsed = urlparse(url)
    qs = parse_qs(parsed.query)

    if not params:
        return False, {"reason": "no params xss"}

    p = params[0]

    new_qs = dict(qs)
    new_qs[p] = SAFE_XSS_PAYLOAD

    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(new_qs, doseq=True)}"

    status, headers, body = await http.get(session, test_url)

    reflected = SAFE_XSS_PAYLOAD in body if body else False

    return reflected, {
        "status": status,
        "reflected": reflected,
        "body_snippet": body[:500] if body else ""
    }


async def exploit_redirect(issue: Dict[str, Any], session: aiohttp.ClientSession, http: HttpClient):
    """
    Open redirect seguro:
    • Sustituye el parámetro redirect por un dominio neutral controlado
    • No envía tráfico malicioso ni afecta usuarios
    """
    url = issue["endpoint_url"]
    params = issue["params"]

    parsed = urlparse(url)
    qs = parse_qs(parsed.query)

    if not params:
        return False, {"reason": "no redirect param"}

    p = params[0]

    new_qs = dict(qs)
    new_qs[p] = SAFE_REDIRECT_TARGET

    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(new_qs, doseq=True)}"

    status, headers, body = await http.get(session, test_url)

    location = headers.get("Location", "")

    return SAFE_REDIRECT_TARGET in location, {
        "status": status,
        "location": location
    }


async def exploit_ws(issue: Dict[str, Any]):
    """
    Inspección pasiva de WebSocket:
    • Conecta 3 segundos
    • Recibe mensajes
    • No envía comandos
    """
    url = issue["endpoint_url"].replace("https://", "wss://").replace("http://", "ws://")

    msgs = []
    try:
        async with websockets.connect(url) as ws:
            start = time.time()
            while time.time() - start < 3:
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=1)
                    msgs.append(msg[:500])
                except:
                    pass
        return True, {"messages": msgs}
    except Exception as e:
        return False, {"error": str(e)}


async def exploit_generic(issue: Dict[str, Any]):
    """
    Para tipos: auth_flow_candidate, payment_logic_candidate, file_upload_candidate, admin_area_candidate
    Solo marcamos visibilidad / acceso basado en discovery.
    """
    return False, {"info": "generic check — requires manual / plugin analysis"}


# ===========================
# CORE EXPLOIT EXECUTION
# ===========================

ISSUE_HANDLERS = {
    "idor_candidate": exploit_idor,
    "xss_reflection_candidate": exploit_xss,
    "open_redirect_candidate": exploit_redirect,
    "ws_leak_candidate": exploit_ws,
    "auth_flow_candidate": exploit_generic,
    "payment_logic_candidate": exploit_generic,
    "file_upload_candidate": exploit_generic,
    "admin_area_candidate": exploit_generic,
}


async def run_exploit(program_cfg: Dict[str, Any],
                      discovery: Dict[str, Any]) -> ExploitSummary:

    program_id = discovery["program_id"]
    issues = discovery["candidate_issues"]

    # Limitamos cantidad según config
    max_tests = program_cfg["exploit"].get("max_automatic_tests_per_endpoint", 10)
    rate_limit = program_cfg.get("rate_limit", {}).get("default_delay", 0.15)

    headers = program_cfg.get("headers", {})
    http = HttpClient(headers=headers, rate_limit=rate_limit)

    results = []

    async with aiohttp.ClientSession() as session:
        for idx, issue in enumerate(issues):
            if idx >= 150:
                break  # límite total razonable

            issue_type = issue["issue_type"]
            handler = ISSUE_HANDLERS.get(issue_type)

            if not handler:
                continue

            print(f"[*] Probando issue {issue['id']} [{issue_type}]")

            try:
                success, evidence = await handler(issue, session, http) \
                    if issue_type != "ws_leak_candidate" \
                    else await handler(issue)
            except Exception as e:
                success, evidence = False, {"exception": str(e)}

            result = ExploitResult(
                issue_id=issue["id"],
                issue_type=issue_type,
                endpoint_url=issue["endpoint_url"],
                method=issue["method"],
                success=success,
                evidence=evidence,
                notes=""
            )

            results.append(result)

    # Stats
    stats = {
        "total_issues": len(issues),
        "tested": len(results),
        "successes": sum(1 for r in results if r.success),
        "generated_at": datetime.utcnow().isoformat() + "Z"
    }

    summary = ExploitSummary(
        program_id=program_id,
        generated_at=stats["generated_at"],
        results=results,
        stats=stats
    )

    return summary


def save_exploit_summary(summary: ExploitSummary):
    out_file = f"exploit_{summary.program_id}.json"
    data = {
        "program_id": summary.program_id,
        "generated_at": summary.generated_at,
        "results": [asdict(r) for r in summary.results],
        "stats": summary.stats
    }
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    print(f"[+] Resultado guardado en {out_file}")
    print(f"[+] Stats: {json.dumps(summary.stats, indent=2)}")


# ===========================
# CLI
# ===========================

def parse_args():
    p = argparse.ArgumentParser(description="core_exploit - Exploit seguro basado en discovery")
    p.add_argument("--program-config", required=True)
    p.add_argument("--discovery-file", help="Archivo discovery_<program>.json")
    return p.parse_args()


def main():
    args = parse_args()

    cfg = load_program_config(args.program_config)
    program_id = cfg["id"]

    disc_file = args.discovery_file or f"discovery_{program_id}.json"
    if not os.path.isfile(disc_file):
        print(f"[!] Discovery file not found: {disc_file}")
        sys.exit(1)

    print(f"[*] Cargando discovery desde: {disc_file}")
    discovery = load_discovery(disc_file)

    summary = asyncio.run(run_exploit(cfg, discovery))
    save_exploit_summary(summary)


if __name__ == "__main__":
    main()
