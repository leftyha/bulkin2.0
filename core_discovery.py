#!/usr/bin/env python3
"""
core_discovery.py
Discovery genérico y configurable para programas de Bug Bounty (bulkin).

Toma la salida de core_recon.py (recon_<program_id>.json) y:
 - Enriquecer endpoints con metadatos (scores, flags, categorías refinadas).
 - Detectar patrones sospechosos y generar CandidateIssues:
    * idor_candidate
    * open_redirect_candidate
    * xss_reflection_candidate (heurístico)
    * ws_leak_candidate
    * auth_flow_candidate
    * payment_logic_candidate
    * file_upload_candidate
    * admin_area_candidate
 - Exporta discovery_<program_id>.json

No lanza payloads ni hace requests. Solo analiza datos ya recolectados.
"""

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import List, Dict, Any, Optional


# =========================
#   DATA CLASSES
# =========================

@dataclass
class TargetHost:
    host: str
    base_url: str
    scope_status: str
    tags: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)


@dataclass
class Endpoint:
    url: str
    method: str
    host: str
    path: str
    categories: List[str] = field(default_factory=list)
    params: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RequestSample:
    url: str
    method: str
    status: Optional[int]
    reason: Optional[str]
    headers: Dict[str, str]
    content_type: Optional[str]
    body_snippet_path: Optional[str]
    timestamp: str
    host: str


@dataclass
class CandidateIssue:
    id: str
    issue_type: str
    endpoint_url: str
    method: str
    host: str
    params: List[str]
    evidence: Dict[str, Any]
    priority_score: int
    notes: str
    tags: List[str]


@dataclass
class DiscoveryResult:
    program_id: str
    generated_at: str
    endpoints_enriched: List[Endpoint]
    candidate_issues: List[CandidateIssue]
    stats: Dict[str, Any]


# =========================
#   CONFIG & UTILS
# =========================

def load_program_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    cfg.setdefault("id", cfg.get("program_name", "program").lower().replace(" ", "_"))
    cfg.setdefault("discovery", {})
    cfg["discovery"].setdefault("interesting_keywords", [])
    cfg["discovery"].setdefault("sensitive_param_names", [])
    cfg.setdefault("scopes", {})
    cfg["scopes"].setdefault("in_scope", [])
    cfg["scopes"].setdefault("out_of_scope", [])
    cfg.setdefault("exploit", {})
    return cfg


def load_recon_result(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


def extract_filename(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    return os.path.basename(path)


def safe_lower(s: Optional[str]) -> str:
    return (s or "").lower()


# =========================
#   DISCOVERY LOGIC
# =========================

def index_recon_data(recon: Dict[str, Any]):
    """
    Construye índices útiles a partir del JSON de recon.
    """
    targets = []
    endpoints = []
    samples = []

    for t in recon.get("targets", []):
        targets.append(TargetHost(**t))

    for e in recon.get("endpoints", []):
        # compatibilidad si meta no existe
        if "meta" not in e:
            e["meta"] = {}
        endpoints.append(Endpoint(**e))

    for s in recon.get("samples", []):
        samples.append(RequestSample(**s))

    endpoints_by_url: Dict[str, Endpoint] = {ep.url: ep for ep in endpoints}
    samples_by_url: Dict[str, List[RequestSample]] = {}
    for s in samples:
        samples_by_url.setdefault(s.url, []).append(s)

    params_index: Dict[str, List[Endpoint]] = {}
    for ep in endpoints:
        for p in ep.params:
            params_index.setdefault(p, []).append(ep)

    return targets, endpoints, samples, endpoints_by_url, samples_by_url, params_index


def categorize_endpoint(ep: Endpoint):
    """
    Asegura que las categorías de endpoint están alineadas con las heurísticas base.
    (Refina lo que ya haya, similar a core_recon pero aquí podemos enriquecer.)
    """
    cats = set(ep.categories)
    path_lower = safe_lower(ep.path)
    url_lower = safe_lower(ep.url)

    if "/api/" in path_lower or path_lower.startswith("/api"):
        cats.add("api")
    if path_lower.endswith(".js"):
        cats.add("static_js")
    if any(path_lower.endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico"]):
        cats.add("static_asset")
    if path_lower.endswith(".css"):
        cats.add("static_css")
    if path_lower.startswith("/ws") or url_lower.startswith("ws://") or url_lower.startswith("wss://"):
        cats.add("ws")
    if any(k in path_lower for k in ["login", "signin", "auth", "oauth", "token"]):
        cats.add("auth")
    if any(k in path_lower for k in ["admin", "cpanel", "manage", "moderation", "staff"]):
        cats.add("admin_like")
    if any(k in path_lower for k in ["pay", "billing", "invoice", "gold", "price", "purchase", "token"]):
        cats.add("payment")
    if any(k in path_lower for k in ["upload", "file", "media", "avatar"]):
        cats.add("upload")

    ep.categories = list(cats)


def enrich_endpoints(endpoints: List[Endpoint],
                     samples_by_url: Dict[str, List[RequestSample]],
                     program_cfg: Dict[str, Any]):
    """
    Enriquecer cada endpoint con meta información (score base, flags, etc.).
    """
    sensitive_params = set(program_cfg["discovery"].get("sensitive_param_names", []))
    interesting_keywords = set(program_cfg["discovery"].get("interesting_keywords", []))

    for ep in endpoints:
        categorize_endpoint(ep)
        meta = ep.meta or {}
        meta_flags = set(meta.get("flags", []))

        # Sensitive params
        has_sensitive = any(p in sensitive_params for p in ep.params)
        if has_sensitive:
            meta_flags.add("has_sensitive_params")

        # Keywords en path
        path_lower = safe_lower(ep.path)
        for kw in interesting_keywords:
            if kw.lower() in path_lower:
                meta_flags.add(f"kw_{kw.lower()}")

        # Categoría -> flags
        if "auth" in ep.categories:
            meta_flags.add("auth_related")
        if "admin_like" in ep.categories:
            meta_flags.add("admin_related")
        if "payment" in ep.categories:
            meta_flags.add("payment_related")
        if "ws" in ep.categories:
            meta_flags.add("ws_related")
        if "upload" in ep.categories:
            meta_flags.add("upload_related")

        # Status codes & content types
        status_set = set()
        ctype_set = set()
        for s in samples_by_url.get(ep.url, []):
            if s.status is not None:
                status_set.add(s.status)
            if s.content_type:
                ctype_set.add(s.content_type.split(";")[0].strip())

        meta["status_codes"] = sorted(list(status_set))
        meta["content_types"] = sorted(list(ctype_set))

        # Score base
        base_score = 0
        if "api" in ep.categories:
            base_score += 20
        if has_sensitive:
            base_score += 15
        if "auth_related" in meta_flags:
            base_score += 10
        if "admin_related" in meta_flags:
            base_score += 12
        if "payment_related" in meta_flags:
            base_score += 12
        if "upload_related" in meta_flags:
            base_score += 10
        if "ws_related" in meta_flags:
            base_score += 10

        # status codes sospechosos
        if any(code in status_set for code in [403, 401]):
            base_score += 5
        if any(code in status_set for code in [500, 502, 503]):
            base_score += 5

        # fuentes
        for src in ep.sources:
            if src == "fuzz":
                base_score += 5
            if src == "wayback":
                base_score += 5

        # clamp
        if base_score < 0:
            base_score = 0
        if base_score > 100:
            base_score = 100

        meta["base_score"] = base_score
        meta["flags"] = sorted(list(meta_flags))
        ep.meta = meta


def detect_idor_candidates(endpoints: List[Endpoint],
                           program_cfg: Dict[str, Any]) -> List[CandidateIssue]:
    issues = []
    sensitive_params = set(program_cfg["discovery"].get("sensitive_param_names", []))
    counter = 0

    for ep in endpoints:
        if "api" not in ep.categories:
            continue
        suspicious_params = [p for p in ep.params if p in sensitive_params]
        if not suspicious_params:
            continue
        # evitamos estáticos obvios
        if "static_asset" in ep.categories or "static_js" in ep.categories:
            continue

        counter += 1
        issue_id = f"disc-idor-{counter:04d}"

        meta = ep.meta or {}
        base_score = meta.get("base_score", 0)
        score = base_score + 25  # boost IDOR
        if score > 100:
            score = 100

        evidence = {
            "source": "discovery",
            "from": "endpoint",
            "status_codes": meta.get("status_codes", []),
            "content_types": meta.get("content_types", []),
            "endpoint_sources": ep.sources,
        }

        tags = list(set(ep.categories + ["idor_candidate"]))

        issue = CandidateIssue(
            id=issue_id,
            issue_type="idor_candidate",
            endpoint_url=ep.url,
            method=ep.method,
            host=ep.host,
            params=suspicious_params,
            evidence=evidence,
            priority_score=score,
            notes="Endpoint API con parámetros sensibles (potencial IDOR).",
            tags=tags
        )
        issues.append(issue)

    return issues


def detect_open_redirect_candidates(endpoints: List[Endpoint]) -> List[CandidateIssue]:
    issues = []
    redirect_like = [
        "redirect", "next", "return_to", "url", "rurl",
        "continue", "dest", "destination", "goto", "redirect_uri", "callback_url"
    ]
    redirect_like_set = set(redirect_like)
    counter = 0

    for ep in endpoints:
        param_lower = [p.lower() for p in ep.params]
        suspicious_params = [p for p in ep.params if p.lower() in redirect_like_set]
        if not suspicious_params:
            continue
        if "static_asset" in ep.categories or "static_js" in ep.categories:
            continue

        counter += 1
        issue_id = f"disc-redirect-{counter:04d}"

        meta = ep.meta or {}
        base_score = meta.get("base_score", 0)
        score = base_score + 10
        if score > 100:
            score = 100

        evidence = {
            "source": "discovery",
            "from": "params",
            "status_codes": meta.get("status_codes", []),
            "content_types": meta.get("content_types", []),
            "endpoint_sources": ep.sources,
        }

        tags = list(set(ep.categories + ["open_redirect_candidate"]))

        issue = CandidateIssue(
            id=issue_id,
            issue_type="open_redirect_candidate",
            endpoint_url=ep.url,
            method=ep.method,
            host=ep.host,
            params=suspicious_params,
            evidence=evidence,
            priority_score=score,
            notes="Endpoint con parámetros tipo redirect/next/url (potencial open redirect).",
            tags=tags
        )
        issues.append(issue)

    return issues


def detect_xss_candidates(endpoints: List[Endpoint],
                          samples_by_url: Dict[str, List[RequestSample]]) -> List[CandidateIssue]:
    """
    Heurística para detectar candidatos a XSS reflejado.
    NO inyecta payloads, solo marca endpoints donde:
      - content-type text/html
      - hay parámetros típicamente de entrada de texto (q, search, query, message, comment, text, content)
    """
    issues = []
    text_params = {"q", "query", "search", "s", "message", "comment", "text", "content", "body"}
    counter = 0

    for ep in endpoints:
        # Sólo sentido para HTML
        meta = ep.meta or {}
        content_types = meta.get("content_types", [])
        if not any(ct.startswith("text/html") for ct in content_types):
            continue

        # Busca parámetros "de texto"
        suspicious_params = [p for p in ep.params if p.lower() in text_params]
        if not suspicious_params:
            continue

        counter += 1
        issue_id = f"disc-xss-{counter:04d}"

        base_score = meta.get("base_score", 0)
        score = base_score + 20
        if score > 100:
            score = 100

        evidence = {
            "source": "discovery",
            "from": "html",
            "status_codes": meta.get("status_codes", []),
            "content_types": content_types,
            "endpoint_sources": ep.sources,
            "body_snippets": [
                extract_filename(s.body_snippet_path) for s in samples_by_url.get(ep.url, [])
                if s.body_snippet_path
            ]
        }

        tags = list(set(ep.categories + ["xss_reflection_candidate"]))

        issue = CandidateIssue(
            id=issue_id,
            issue_type="xss_reflection_candidate",
            endpoint_url=ep.url,
            method=ep.method,
            host=ep.host,
            params=suspicious_params,
            evidence=evidence,
            priority_score=score,
            notes="Endpoint HTML con parámetros de texto (potencial XSS reflejado).",
            tags=tags
        )
        issues.append(issue)

    return issues


def detect_ws_candidates(endpoints: List[Endpoint]) -> List[CandidateIssue]:
    issues = []
    counter = 0

    for ep in endpoints:
        if "ws" not in ep.categories and not ep.url.startswith(("ws://", "wss://")):
            continue

        path_lower = safe_lower(ep.path)
        suspicious = False
        hints = []
        for kw in ["room", "session", "model", "private", "broadcast", "stream"]:
            if kw in path_lower:
                suspicious = True
                hints.append(kw)

        if not suspicious:
            # Igual lo marcamos, pero con menor prioridad
            hints.append("generic_ws")

        counter += 1
        issue_id = f"disc-ws-{counter:04d}"
        meta = ep.meta or {}
        base_score = meta.get("base_score", 0)
        score = base_score + (15 if suspicious else 8)
        if score > 100:
            score = 100

        evidence = {
            "source": "discovery",
            "from": "ws",
            "status_codes": meta.get("status_codes", []),
            "content_types": meta.get("content_types", []),
            "endpoint_sources": ep.sources,
            "hints": hints
        }

        tags = list(set(ep.categories + ["ws_leak_candidate"]))

        issue = CandidateIssue(
            id=issue_id,
            issue_type="ws_leak_candidate",
            endpoint_url=ep.url,
            method=ep.method,
            host=ep.host,
            params=ep.params,
            evidence=evidence,
            priority_score=score,
            notes="Endpoint WebSocket potencialmente sensible (streams/salas/sesiones).",
            tags=tags
        )
        issues.append(issue)

    return issues


def detect_generic_flow_candidates(endpoints: List[Endpoint]) -> List[CandidateIssue]:
    """
    Detecta candidatos genéricos basados en categorías:
      - auth_flow_candidate
      - payment_logic_candidate
      - file_upload_candidate
      - admin_area_candidate
    """
    issues = []
    counter_auth = 0
    counter_pay = 0
    counter_upload = 0
    counter_admin = 0

    for ep in endpoints:
        meta = ep.meta or {}
        base_score = meta.get("base_score", 0)

        # AUTH
        if "auth" in ep.categories:
            counter_auth += 1
            issue_id = f"disc-auth-{counter_auth:04d}"
            score = min(100, base_score + 15)
            evidence = {
                "source": "discovery",
                "from": "path",
                "status_codes": meta.get("status_codes", []),
                "content_types": meta.get("content_types", []),
                "endpoint_sources": ep.sources,
            }
            tags = list(set(ep.categories + ["auth_flow_candidate"]))
            issues.append(
                CandidateIssue(
                    id=issue_id,
                    issue_type="auth_flow_candidate",
                    endpoint_url=ep.url,
                    method=ep.method,
                    host=ep.host,
                    params=ep.params,
                    evidence=evidence,
                    priority_score=score,
                    notes="Endpoint relacionado con autenticación / tokens.",
                    tags=tags
                )
            )

        # PAYMENT
        if "payment" in ep.categories:
            counter_pay += 1
            issue_id = f"disc-payment-{counter_pay:04d}"
            score = min(100, base_score + 15)
            evidence = {
                "source": "discovery",
                "from": "path",
                "status_codes": meta.get("status_codes", []),
                "content_types": meta.get("content_types", []),
                "endpoint_sources": ep.sources,
            }
            tags = list(set(ep.categories + ["payment_logic_candidate"]))
            issues.append(
                CandidateIssue(
                    id=issue_id,
                    issue_type="payment_logic_candidate",
                    endpoint_url=ep.url,
                    method=ep.method,
                    host=ep.host,
                    params=ep.params,
                    evidence=evidence,
                    priority_score=score,
                    notes="Endpoint relacionado con pagos, tokens o gold.",
                    tags=tags
                )
            )

        # UPLOAD
        if "upload" in ep.categories:
            counter_upload += 1
            issue_id = f"disc-upload-{counter_upload:04d}"
            score = min(100, base_score + 15)
            evidence = {
                "source": "discovery",
                "from": "path",
                "status_codes": meta.get("status_codes", []),
                "content_types": meta.get("content_types", []),
                "endpoint_sources": ep.sources,
            }
            tags = list(set(ep.categories + ["file_upload_candidate"]))
            issues.append(
                CandidateIssue(
                    id=issue_id,
                    issue_type="file_upload_candidate",
                    endpoint_url=ep.url,
                    method=ep.method,
                    host=ep.host,
                    params=ep.params,
                    evidence=evidence,
                    priority_score=score,
                    notes="Endpoint relacionado con subida de ficheros/media.",
                    tags=tags
                )
            )

        # ADMIN
        if "admin_like" in ep.categories:
            counter_admin += 1
            issue_id = f"disc-admin-{counter_admin:04d}"
            score = min(100, base_score + 15)
            evidence = {
                "source": "discovery",
                "from": "path",
                "status_codes": meta.get("status_codes", []),
                "content_types": meta.get("content_types", []),
                "endpoint_sources": ep.sources,
            }
            tags = list(set(ep.categories + ["admin_area_candidate"]))
            issues.append(
                CandidateIssue(
                    id=issue_id,
                    issue_type="admin_area_candidate",
                    endpoint_url=ep.url,
                    method=ep.method,
                    host=ep.host,
                    params=ep.params,
                    evidence=evidence,
                    priority_score=score,
                    notes="Endpoint que parece área de admin/moderación.",
                    tags=tags
                )
            )

    return issues


def run_discovery(program_cfg: Dict[str, Any],
                  recon_data: Dict[str, Any]) -> DiscoveryResult:
    program_id = program_cfg["id"]
    targets, endpoints, samples, endpoints_by_url, samples_by_url, params_index = index_recon_data(recon_data)

    # Enriquecemos cada endpoint
    enrich_endpoints(endpoints, samples_by_url, program_cfg)

    # Detectamos candidate issues por tipo
    idor_issues = detect_idor_candidates(endpoints, program_cfg)
    redirect_issues = detect_open_redirect_candidates(endpoints)
    xss_issues = detect_xss_candidates(endpoints, samples_by_url)
    ws_issues = detect_ws_candidates(endpoints)
    flow_issues = detect_generic_flow_candidates(endpoints)

    all_issues = idor_issues + redirect_issues + xss_issues + ws_issues + flow_issues

    # Stats
    stats = {
        "num_endpoints_total": len(endpoints),
        "num_candidate_issues_total": len(all_issues),
        "num_idor_candidates": len(idor_issues),
        "num_open_redirect_candidates": len(redirect_issues),
        "num_xss_candidates": len(xss_issues),
        "num_ws_candidates": len(ws_issues),
        "num_flow_candidates": len(flow_issues),
        "generated_at": datetime.utcnow().isoformat() + "Z"
    }

    # Ordenar issues por prioridad descendente
    all_issues.sort(key=lambda x: x.priority_score, reverse=True)

    discovery_result = DiscoveryResult(
        program_id=program_id,
        generated_at=stats["generated_at"],
        endpoints_enriched=endpoints,
        candidate_issues=all_issues,
        stats=stats
    )
    return discovery_result


def save_discovery_result(result: DiscoveryResult):
    out_file = f"discovery_{result.program_id}.json"
    data = {
        "program_id": result.program_id,
        "generated_at": result.generated_at,
        "endpoints_enriched": [asdict(e) for e in result.endpoints_enriched],
        "candidate_issues": [asdict(c) for c in result.candidate_issues],
        "stats": result.stats,
    }
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"[*] Discovery guardado en: {out_file}")
    print(f"[*] Stats: {json.dumps(result.stats, indent=2)}")


# =========================
#   CLI
# =========================

def parse_args():
    p = argparse.ArgumentParser(description="Core discovery genérico para BBP (bulkin).")
    p.add_argument("--program-config", required=True,
                   help="Ruta al archivo JSON de configuración del programa (program_X.json)")
    p.add_argument("--recon-file", help="Archivo recon_<program_id>.json (si se omite, se deduce por id del programa)")
    return p.parse_args()


def main():
    args = parse_args()
    program_cfg = load_program_config(args.program_config)
    program_id = program_cfg["id"]

    recon_file = args.recon_file or f"recon_{program_id}.json"
    if not os.path.isfile(recon_file):
        print(f"[!] Archivo de recon no encontrado: {recon_file}")
        sys.exit(1)

    print(f"[*] Usando program_id={program_id}")
    print(f"[*] Cargando recon desde: {recon_file}")

    recon_data = load_recon_result(recon_file)
    discovery_result = run_discovery(program_cfg, recon_data)
    save_discovery_result(discovery_result)


if __name__ == "__main__":
    main()
