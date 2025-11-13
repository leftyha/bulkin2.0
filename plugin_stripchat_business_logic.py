#!/usr/bin/env python3
"""Stripchat business-logic plugin.

Este plugin consume la salida de discovery/exploit y realiza comprobaciones
específicas de Stripchat comparando el comportamiento entre los perfiles
``viewer`` y ``model`` configurados en el programa.

Las verificaciones son de solo lectura y se limitan a peticiones GET con las
cookies suministradas para cada rol. Se detectan accesos indebidos cuando el
usuario *viewer* recibe respuestas equivalentes a las del perfil *model* en
endpoints marcados como sensibles por `core_discovery`.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

import requests


SENSITIVE_TYPES = {
    "auth_flow_candidate",
    "payment_logic_candidate",
    "file_upload_candidate",
    "admin_area_candidate",
    "business_logic_candidate",
}

CONTENT_SIMILARITY_THRESHOLD = 150
PROTECTED_STATUS_CODES = {401, 403}


@dataclass
class EndpointTest:
    issue_id: str
    issue_type: str
    endpoint_url: str
    method: str
    viewer_status: Optional[int]
    model_status: Optional[int]
    viewer_length: Optional[int]
    model_length: Optional[int]
    viewer_snippet: str
    model_snippet: str
    accessible_by_viewer: bool
    notes: str


@dataclass
class PluginReport:
    program_id: str
    generated_at: str
    tested_endpoints: List[EndpointTest]
    findings: List[EndpointTest]
    stats: Dict[str, Any]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_cookies(path: str) -> Dict[str, str]:
    """Acepta ficheros exportados desde navegadores o Burp."""

    data = load_json(path)
    cookies: Dict[str, str] = {}

    if isinstance(data, list):
        iterable: Iterable[Any] = data
    else:
        iterable = data.get("cookies", []) if isinstance(data, dict) else []

    for entry in iterable:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        value = entry.get("value")
        if not name or value is None:
            continue
        cookies[name] = value

    return cookies


class RateLimitedSession:
    def __init__(self, headers: Dict[str, str], cookies: Dict[str, str], delay: float) -> None:
        self._session = requests.Session()
        if headers:
            self._session.headers.update(headers)
        for name, value in cookies.items():
            # Dominio opcional; requests acepta None y lo aplica a todos los hosts.
            self._session.cookies.set(name, value)
        self._delay = max(delay, 0.0)
        self._last_call = 0.0

    def get(self, url: str) -> Optional[requests.Response]:
        now = time.time()
        wait = self._delay - (now - self._last_call)
        if wait > 0:
            time.sleep(wait)
        self._last_call = time.time()
        try:
            response = self._session.get(url, allow_redirects=True, timeout=12)
        except requests.RequestException:
            return None
        return response


def build_snippet(text: Optional[str]) -> str:
    if not text:
        return ""
    snippet = text[:400]
    return snippet.replace("\n", " ")


def responses_equivalent(viewer: Optional[requests.Response], model: Optional[requests.Response]) -> bool:
    if viewer is None or model is None:
        return False
    if viewer.status_code in PROTECTED_STATUS_CODES:
        return False
    if viewer.status_code != model.status_code:
        return False

    viewer_text = viewer.text or ""
    model_text = model.text or ""
    if not model_text:
        return False

    length_gap = abs(len(viewer_text) - len(model_text))
    if length_gap > CONTENT_SIMILARITY_THRESHOLD:
        return False

    # Como heurística adicional, comprobamos que varias palabras clave de negocio
    # aparezcan en la respuesta del viewer.
    keywords = {"token", "price", "model", "private", "gold"}
    matches = sum(1 for kw in keywords if kw in viewer_text.lower())
    return matches >= 1


def analyze_endpoint(issue: Dict[str, Any],
                     viewer_session: RateLimitedSession,
                     model_session: RateLimitedSession) -> EndpointTest:
    url = issue["endpoint_url"]
    method = issue.get("method", "GET").upper()
    issue_id = issue.get("id", "unknown")
    issue_type = issue.get("issue_type", "unknown")

    viewer_resp: Optional[requests.Response] = None
    model_resp: Optional[requests.Response] = None
    notes: List[str] = []

    if method != "GET":
        notes.append("Método no soportado (solo GET)")
    else:
        viewer_resp = viewer_session.get(url)
        model_resp = model_session.get(url)
        if viewer_resp is None:
            notes.append("Error al solicitar con perfil viewer")
        if model_resp is None:
            notes.append("Error al solicitar con perfil model")

    accessible = responses_equivalent(viewer_resp, model_resp)
    if accessible:
        notes.append("Viewer obtiene respuesta equivalente a la del perfil model")
    elif viewer_resp is not None and viewer_resp.status_code in PROTECTED_STATUS_CODES:
        notes.append("Viewer recibe estado protegido (401/403)")

    test = EndpointTest(
        issue_id=issue_id,
        issue_type=issue_type,
        endpoint_url=url,
        method=method,
        viewer_status=None if viewer_resp is None else viewer_resp.status_code,
        model_status=None if model_resp is None else model_resp.status_code,
        viewer_length=None if viewer_resp is None or viewer_resp.text is None else len(viewer_resp.text),
        model_length=None if model_resp is None or model_resp.text is None else len(model_resp.text),
        viewer_snippet="" if viewer_resp is None else build_snippet(viewer_resp.text),
        model_snippet="" if model_resp is None else build_snippet(model_resp.text),
        accessible_by_viewer=accessible,
        notes="; ".join(notes),
    )

    return test


def generate_report(program_id: str,
                    tests: List[EndpointTest]) -> PluginReport:
    findings = [test for test in tests if test.accessible_by_viewer]
    stats = {
        "total_tested": len(tests),
        "findings": len(findings),
        "protected": sum(1 for test in tests if test.viewer_status in PROTECTED_STATUS_CODES),
    }
    report = PluginReport(
        program_id=program_id,
        generated_at=datetime.utcnow().isoformat() + "Z",
        tested_endpoints=tests,
        findings=findings,
        stats=stats,
    )
    return report


def write_report(report: PluginReport) -> str:
    output_file = f"plugin_stripchat_business_{report.program_id}.json"
    payload = {
        "program_id": report.program_id,
        "generated_at": report.generated_at,
        "stats": report.stats,
        "tested_endpoints": [asdict(test) for test in report.tested_endpoints],
        "findings": [asdict(test) for test in report.findings],
    }
    with open(output_file, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return output_file


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Stripchat business logic checks")
    parser.add_argument("--program-config", required=True)
    parser.add_argument("--discovery-file", required=True)
    parser.add_argument("--exploit-file", help="Archivo exploit_<program>.json", default=None)
    parser.add_argument("--viewer-session", required=True)
    parser.add_argument("--model-session", required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not os.path.isfile(args.program_config):
        print(f"[ERROR] Program config no encontrado: {args.program_config}")
        sys.exit(1)
    if not os.path.isfile(args.discovery_file):
        print(f"[ERROR] Discovery file no encontrado: {args.discovery_file}")
        sys.exit(1)

    cfg = load_json(args.program_config)
    program_id = cfg.get("id", "program")

    discovery = load_json(args.discovery_file)
    issues: List[Dict[str, Any]] = discovery.get("candidate_issues", [])

    headers = cfg.get("headers", {}).copy()
    rate_limit = cfg.get("rate_limit", {}).get("default_delay", 0.25)

    viewer_cookies = load_cookies(args.viewer_session)
    model_cookies = load_cookies(args.model_session)

    viewer = RateLimitedSession(headers=headers, cookies=viewer_cookies, delay=rate_limit)
    model = RateLimitedSession(headers=headers, cookies=model_cookies, delay=rate_limit)

    tests: List[EndpointTest] = []

    for issue in issues:
        issue_type = issue.get("issue_type")
        if issue_type not in SENSITIVE_TYPES:
            continue
        test = analyze_endpoint(issue, viewer, model)
        tests.append(test)

    report = generate_report(program_id, tests)
    output_file = write_report(report)

    print(f"[+] Plugin Stripchat completado. Resultados en {output_file}")
    print(json.dumps(report.stats, indent=2))


if __name__ == "__main__":
    main()
