#!/usr/bin/env python3
"""
core_recon.py
Recon genérico y configurable para programas de Bug Bounty.

- Funciona según la configuración definida en un JSON de programa (program_X.json).
- Respeta scope (in_scope / out_of_scope) definido por regex/patrones.
- Usa headers configurados (incluyendo HackerOne: <handle> si se proporciona).
- Ejecuta:
    * Recon pasivo (crt.sh, opcional Wayback)
    * Probing HTTP básico
    * Harvesting de HTML y JS (extracción de endpoints)
    * Fuzzing ligero y seguro (GET-only)
- Guarda resultados estructurados en recon_<program_id>.json
- Guarda HTML/JS recolectados en data/<program_id>/

Diseñado para ser simple de estructura, pero potente en detalle.
"""

import argparse
import asyncio
import json
import os
import re
import sys
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urlparse, urljoin, parse_qs

import aiohttp


# =========================
#   DATA CLASSES
# =========================

@dataclass
class TargetHost:
    host: str
    base_url: str
    scope_status: str  # "in_scope", "out_of_scope", "conditional"
    tags: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    host: str = ""
    path: str = ""
    categories: List[str] = field(default_factory=list)
    params: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)


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
class ReconResult:
    program_id: str
    generated_at: str
    targets: List[TargetHost]
    endpoints: List[Endpoint]
    samples: List[RequestSample]
    stats: Dict[str, Any]


# =========================
#   UTILS
# =========================

def load_program_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    # defaults
    cfg.setdefault("id", cfg.get("program_name", "program").lower().replace(" ", "_"))
    cfg.setdefault("scopes", {})
    cfg["scopes"].setdefault("in_scope", [])
    cfg["scopes"].setdefault("out_of_scope", [])
    cfg.setdefault("rate_limit", {})
    cfg["rate_limit"].setdefault("max_rps", 80)
    cfg["rate_limit"].setdefault("default_concurrency", 10)
    cfg["rate_limit"].setdefault("default_delay", 0.12)
    cfg.setdefault("recon", {})
    r = cfg["recon"]
    r.setdefault("enable_crtsh", True)
    r.setdefault("enable_wayback", False)
    r.setdefault("max_subdomains", 500)
    r.setdefault("wordlist_file", None)
    r.setdefault("max_fuzz_words", 200)
    r.setdefault("max_hosts_for_fuzz", 10)
    r.setdefault("capture_js", True)
    r.setdefault("capture_html", True)
    cfg.setdefault("headers", {})
    cfg.setdefault("discovery", {})
    return cfg


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def normalize_target(t: str) -> Optional[str]:
    t = t.strip()
    if not t:
        return None
    if not t.startswith("http://") and not t.startswith("https://"):
        t = "https://" + t
    try:
        p = urlparse(t)
        if not p.hostname:
            return None
        # normalizamos base_url sin path
        base = f"{p.scheme}://{p.hostname}"
        if p.port:
            base += f":{p.port}"
        return base
    except Exception:
        return None


def hostname_from_url(url: str) -> str:
    return urlparse(url).hostname or ""


def compile_scope_patterns(program_cfg: Dict[str, Any]):
    in_scope_patterns = []
    out_scope_hosts = set()

    for entry in program_cfg["scopes"]["in_scope"]:
        pat = entry.get("pattern")
        if pat:
            in_scope_patterns.append((re.compile(pat), entry))

    for entry in program_cfg["scopes"]["out_of_scope"]:
        # puede ser host exacto o patrón simple
        out_scope_hosts.add(entry.strip().lower())

    return in_scope_patterns, out_scope_hosts


def classify_scope(host: str, in_patterns, out_hosts) -> str:
    h = host.lower()
    if h in out_hosts:
        return "out_of_scope"

    for regex, meta in in_patterns:
        if regex.search(h):
            # podríamos usar meta para condicionales (min_severity, etc.)
            if "min_severity" in meta or "max_severity" in meta:
                return "conditional"
            return "in_scope"

    return "out_of_scope"


def build_headers(program_cfg: Dict[str, Any], handle: Optional[str]) -> Dict[str, str]:
    headers = dict(program_cfg.get("headers", {}))
    # Si el config trae HackerOne con placeholder, podemos sustituir
    if handle:
        headers.setdefault("HackerOne", handle)
        # también personalizamos user-agent
        if "User-Agent" not in headers:
            headers["User-Agent"] = f"bulkin-recon/1.0 (+{handle})"
    else:
        headers.setdefault("User-Agent", "bulkin-recon/1.0")
    return headers


def extract_links_and_scripts(html: str, base_url: str):
    links = set()
    scripts = set()

    # href
    for m in re.finditer(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE):
        href = m.group(1)
        if href.startswith("javascript:"):
            continue
        if href.startswith("#"):
            continue
        if href.startswith("http://") or href.startswith("https://"):
            links.add(href)
        else:
            links.add(urljoin(base_url, href))

    # script src
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
        src = m.group(1)
        if src.startswith("http://") or src.startswith("https://"):
            scripts.add(src)
        else:
            scripts.add(urljoin(base_url, src))

    return links, scripts


def extract_urls_from_js(js_text: str, base_url: str):
    urls = set()
    # muy simple: busca cadenas tipo "/algo" o "https://algo"
    for m in re.finditer(r'["\'](https?://[^"\']+)["\']', js_text):
        urls.add(m.group(1))
    for m in re.finditer(r'["\'](/[^"\']+)["\']', js_text):
        urls.add(urljoin(base_url, m.group(1)))
    return urls


def extract_params_from_url(url: str) -> List[str]:
    qs = urlparse(url).query
    if not qs:
        return []
    parsed = parse_qs(qs)
    return list(parsed.keys())


def categorize_endpoint(ep: Endpoint) -> List[str]:
    cats = set(ep.categories)

    path_lower = ep.path.lower()
    url_lower = ep.url.lower()

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
    if any(k in path_lower for k in ["login", "signin", "auth", "oauth"]):
        cats.add("auth")
    if any(k in path_lower for k in ["admin", "cpanel", "manage"]):
        cats.add("admin_like")
    if any(k in path_lower for k in ["pay", "billing", "invoice", "token", "gold"]):
        cats.add("payment")

    ep.categories = list(cats)
    return ep.categories


# =========================
#   CRT.SH & WAYBACK
# =========================

async def fetch_json(session: aiohttp.ClientSession, url: str, timeout: int = 30) -> Any:
    try:
        async with session.get(url, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            text = await resp.text()
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return None
    except Exception:
        return None


async def crtsh_subdomains(session: aiohttp.ClientSession, domain: str, limit: int) -> Set[str]:
    """
    Consulta crt.sh para enumerar subdominios de manera pasiva.
    """
    q = f"https://crt.sh/?q=%25.{domain}&output=json"
    data = await fetch_json(session, q, timeout=60)
    if not data:
        return set()
    subs = set()
    for entry in data:
        name_val = entry.get("name_value")
        if not name_val:
            continue
        for line in str(name_val).splitlines():
            s = line.strip().lower()
            if not s:
                continue
            subs.add(s)
            if len(subs) >= limit:
                return subs
    return subs


async def wayback_paths(session: aiohttp.ClientSession, domain: str, limit: int = 500) -> Set[str]:
    """
    Consulta simple a Wayback (Internet Archive) para URLs históricas.
    """
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
    data = await fetch_json(session, url, timeout=60)
    if not data or not isinstance(data, list):
        return set()
    # primera fila suele ser cabecera
    all_urls = set()
    for row in data[1:]:
        if not row:
            continue
        original = row[0]
        all_urls.add(original)
        if len(all_urls) >= limit:
            break
    return all_urls


# =========================
#   HTTP FETCHING
# =========================

async def rate_limited_fetch(session: aiohttp.ClientSession,
                             url: str,
                             headers: Dict[str, str],
                             semaphore: asyncio.Semaphore,
                             delay: float,
                             timeout: int = 30):
    async with semaphore:
        await asyncio.sleep(delay)
        try:
            async with session.get(url, headers=headers, allow_redirects=True, timeout=timeout) as resp:
                status = resp.status
                reason = resp.reason
                resp_headers = dict(resp.headers)
                content_type = resp_headers.get("Content-Type", "")
                body = await resp.text(errors="ignore")
                return status, reason, resp_headers, content_type, body
        except Exception as e:
            return None, str(e), {}, None, ""


# =========================
#   MAIN RECON LOGIC
# =========================

async def run_recon(program_cfg: Dict[str, Any],
                    handle: Optional[str],
                    targets_file: Optional[str] = None) -> ReconResult:
    program_id = program_cfg["id"]
    recon_cfg = program_cfg["recon"]
    rate_cfg = program_cfg["rate_limit"]

    in_patterns, out_hosts = compile_scope_patterns(program_cfg)

    # Directorios de salida
    base_data_dir = os.path.join("data", program_id)
    html_dir = os.path.join(base_data_dir, "html")
    js_dir = os.path.join(base_data_dir, "js")
    ensure_dir(base_data_dir)
    ensure_dir(html_dir)
    ensure_dir(js_dir)

    # 1) Cargar targets iniciales
    initial_targets: Set[str] = set()
    if targets_file:
        with open(targets_file, "r", encoding="utf-8") as f:
            for line in f:
                base = normalize_target(line)
                if base:
                    initial_targets.add(base)

    # Opcionalmente, podríamos tener base_targets en config
    for entry in program_cfg.get("base_targets", []):
        base = normalize_target(entry)
        if base:
            initial_targets.add(base)

    if not initial_targets:
        print("[!] No se encontraron targets iniciales. Verifica --targets o base_targets en config.")
        sys.exit(1)

    # 2) Normalizar y clasificar scope
    target_hosts: Dict[str, TargetHost] = {}
    for base_url in initial_targets:
        host = hostname_from_url(base_url)
        scope_status = classify_scope(host, in_patterns, out_hosts)
        if scope_status == "out_of_scope":
            print(f"[-] {host} fuera de scope, ignorando.")
            continue
        th = TargetHost(
            host=host,
            base_url=base_url,
            scope_status=scope_status,
            tags=["initial"],
            sources=["initial_targets"]
        )
        target_hosts[host] = th

    if not target_hosts:
        print("[!] No hay hosts en scope después de filtrar. Revisa la config de scope.")
        sys.exit(1)

    headers = build_headers(program_cfg, handle)

    # 3) Recon pasivo (crt.sh + Wayback)
    async with aiohttp.ClientSession() as session:
        # 3.1 crt.sh
        all_subdomains: Set[str] = set()
        if recon_cfg.get("enable_crtsh", True):
            print("[*] Ejecutando recon pasivo con crt.sh ...")
            for host, th in list(target_hosts.items()):
                domain = host
                # tomamos el dominio de segundo nivel por simplicidad
                parts = domain.split(".")
                if len(parts) >= 2:
                    domain = ".".join(parts[-2:])
                subs = await crtsh_subdomains(session, domain, recon_cfg["max_subdomains"])
                print(f"    - {domain}: {len(subs)} subdominios potenciales")
                all_subdomains.update(subs)

        # Normalizamos subdominios y los agregamos si están en scope
        for sub in all_subdomains:
            base = normalize_target(sub)
            if not base:
                continue
            host = hostname_from_url(base)
            scope_status = classify_scope(host, in_patterns, out_hosts)
            if scope_status == "out_of_scope":
                continue
            if host not in target_hosts:
                target_hosts[host] = TargetHost(
                    host=host,
                    base_url=base,
                    scope_status=scope_status,
                    tags=["subdomain"],
                    sources=["crtsh"]
                )

        # 3.2 Wayback opcional
        wayback_urls: Set[str] = set()
        if recon_cfg.get("enable_wayback", False):
            print("[*] Consultando Wayback para URLs históricas ...")
            for host, th in list(target_hosts.items()):
                domain = host
                parts = domain.split(".")
                if len(parts) >= 2:
                    domain = ".".join(parts[-2:])
                paths = await wayback_paths(session, domain, limit=recon_cfg.get("max_wayback_urls", 500))
                print(f"    - {domain}: {len(paths)} URLs desde Wayback")
                wayback_urls.update(paths)

    # 4) HTTP Probing básico para hosts activos
    concurrency = rate_cfg["default_concurrency"]
    delay = rate_cfg["default_delay"]
    semaphore = asyncio.Semaphore(concurrency)

    connector = aiohttp.TCPConnector(limit_per_host=concurrency, ssl=False)
    endpoints: Dict[str, Endpoint] = {}
    samples: List[RequestSample] = []
    html_bodies: Dict[str, str] = {}  # base_url -> html body

    async with aiohttp.ClientSession(connector=connector) as session:
        probe_urls = []

        # base_url para cada host
        for th in target_hosts.values():
            probe_urls.append(th.base_url)
            # algunos paths básicos
            for path in ["/", "/robots.txt", "/sitemap.xml"]:
                url = th.base_url.rstrip("/") + path
                probe_urls.append(url)

        # además, si tenemos wayback, añadimos unos cuantos
        for u in list(wayback_urls)[:200]:  # limit por seguridad
            base = normalize_target(u)
            if not base:
                continue
            host = hostname_from_url(base)
            if host not in target_hosts:
                # forzamos scope check
                scope_status = classify_scope(host, in_patterns, out_hosts)
                if scope_status == "out_of_scope":
                    continue
                target_hosts[host] = TargetHost(
                    host=host,
                    base_url=f"https://{host}",
                    scope_status=scope_status,
                    tags=["wayback"],
                    sources=["wayback"]
                )
            probe_urls.append(u)

        # deduplicamos
        probe_urls = list(dict.fromkeys(probe_urls))

        print(f"[*] HTTP probing de {len(probe_urls)} URLs (concurrency={concurrency}, delay={delay}s)")
        tasks = []
        for url in probe_urls:
            tasks.append(rate_limited_fetch(session, url, headers, semaphore, delay))
        results = await asyncio.gather(*tasks)

        ts_now = datetime.utcnow().isoformat() + "Z"
        for i, url in enumerate(probe_urls):
            status, reason, resp_headers, content_type, body = results[i]
            host = hostname_from_url(url)
            # guardamos sample
            snippet_path = None
            if body and recon_cfg.get("capture_html", True) and "text/html" in (content_type or ""):
                safe_host = re.sub(r"[^a-zA-Z0-9_.-]", "_", host or "unknown")
                safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", url.replace("://", "_"))
                snippet_fn = f"{safe_name}.html"
                snippet_path_full = os.path.join(html_dir, snippet_fn)
                try:
                    with open(snippet_path_full, "w", encoding="utf-8", errors="ignore") as f:
                        f.write(body)
                    snippet_path = snippet_path_full
                    # sólo guardamos la primera "página principal" por host
                    if url.rstrip("/").lower() == (target_hosts.get(host, TargetHost(host, url, "in_scope"))).base_url.rstrip("/").lower():
                        html_bodies[host] = body
                except Exception:
                    pass

            sample = RequestSample(
                url=url,
                method="GET",
                status=status,
                reason=reason,
                headers=resp_headers,
                content_type=content_type,
                body_snippet_path=snippet_path,
                timestamp=ts_now,
                host=host or ""
            )
            samples.append(sample)

    # 5) Harvesting de links y scripts de HTML
    js_to_fetch: Set[str] = set()
    link_urls: Set[str] = set()

    for host, body in html_bodies.items():
        base_url = target_hosts[host].base_url
        links, scripts = extract_links_and_scripts(body, base_url)
        link_urls.update(links)
        js_to_fetch.update(scripts)

    # 6) Descarga de JS y extracción de endpoints desde JS
    print(f"[*] Descargando y analizando {len(js_to_fetch)} scripts JS ...")
    connector = aiohttp.TCPConnector(limit_per_host=concurrency, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for js_url in js_to_fetch:
            tasks.append(rate_limited_fetch(session, js_url, headers, semaphore, delay))
        results = await asyncio.gather(*tasks)

    js_extracted_urls: Set[str] = set()
    for i, js_url in enumerate(js_to_fetch):
        status, reason, resp_headers, content_type, body = results[i]
        if not body:
            continue
        # guardamos JS si está habilitado
        if recon_cfg.get("capture_js", True):
            safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", js_url.replace("://", "_"))
            snippet_fn = f"{safe_name}.js"
            snippet_path_full = os.path.join(js_dir, snippet_fn)
            try:
                with open(snippet_path_full, "w", encoding="utf-8", errors="ignore") as f:
                    f.write(body)
            except Exception:
                pass
        # extraemos URLs
        base_url = f"{urlparse(js_url).scheme}://{urlparse(js_url).hostname}"
        js_urls = extract_urls_from_js(body, base_url)
        js_extracted_urls.update(js_urls)

    # 7) Construcción de Endpoints (HTML links + JS URLs + Wayback + Fuzz luego)
    all_endpoint_urls: Set[str] = set()
    all_endpoint_urls.update(link_urls)
    all_endpoint_urls.update(js_extracted_urls)
    all_endpoint_urls.update(wayback_urls)

    # normalizamos y filtramos por scope
    for url in list(all_endpoint_urls):
        base = normalize_target(url)
        if not base:
            all_endpoint_urls.discard(url)
            continue
        host = hostname_from_url(base)
        scope_status = classify_scope(host, in_patterns, out_hosts)
        if scope_status == "out_of_scope":
            all_endpoint_urls.discard(url)
            continue
        # aseguramos que el host esté en target_hosts
        if host not in target_hosts:
            target_hosts[host] = TargetHost(
                host=host,
                base_url=f"{urlparse(base).scheme}://{host}",
                scope_status=scope_status,
                tags=["discovered"],
                sources=["html_js_wayback"]
            )

    # 8) Fuzzing ligero
    fuzz_endpoints: Set[str] = set()
    wordlist_file = recon_cfg.get("wordlist_file")
    if wordlist_file and os.path.isfile(wordlist_file):
        print("[*] Ejecutando fuzzing ligero (GET-only) ...")
        # Cargamos wordlist con límite
        words: List[str] = []
        with open(wordlist_file, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f):
                if i >= recon_cfg["max_fuzz_words"]:
                    break
                w = line.strip()
                if w:
                    words.append(w)

        # Seleccionamos algunos hosts para fuzz
        hosts_for_fuzz = list(target_hosts.values())[:recon_cfg["max_hosts_for_fuzz"]]
        connector = aiohttp.TCPConnector(limit_per_host=concurrency, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            fuzz_tasks = []
            fuzz_urls = []
            for th in hosts_for_fuzz:
                for w in words:
                    url = th.base_url.rstrip("/") + "/" + w
                    fuzz_urls.append(url)
                    fuzz_tasks.append(
                        rate_limited_fetch(session, url, headers, semaphore, delay)
                    )
            results = await asyncio.gather(*fuzz_tasks)

        for i, url in enumerate(fuzz_urls):
            status, reason, resp_headers, content_type, body = results[i]
            if status and status < 400:
                fuzz_endpoints.add(url)

    # Añadimos endpoints fuzzed
    all_endpoint_urls.update(fuzz_endpoints)

    # 9) Construcción final de objetos Endpoint
    for url in all_endpoint_urls:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        path = parsed.path or "/"
        params = extract_params_from_url(url)
        ep = Endpoint(
            url=url,
            method="GET",
            host=host,
            path=path,
            params=params,
            sources=["recon"]
        )
        categorize_endpoint(ep)
        endpoints[url] = ep

    # 10) Stats y empaquetado
    stats = {
        "num_hosts": len(target_hosts),
        "num_endpoints": len(endpoints),
        "num_samples": len(samples),
        "num_js_files": len(js_to_fetch),
        "num_wayback_urls": len(wayback_urls),
        "num_fuzz_hits": len(fuzz_endpoints),
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }

    recon_result = ReconResult(
        program_id=program_id,
        generated_at=stats["generated_at"],
        targets=list(target_hosts.values()),
        endpoints=list(endpoints.values()),
        samples=samples,
        stats=stats
    )
    return recon_result


def save_recon_result(result: ReconResult):
    out_file = f"recon_{result.program_id}.json"
    data = {
        "program_id": result.program_id,
        "generated_at": result.generated_at,
        "targets": [asdict(t) for t in result.targets],
        "endpoints": [asdict(e) for e in result.endpoints],
        "samples": [asdict(s) for s in result.samples],
        "stats": result.stats,
    }
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"[*] Recon guardado en: {out_file}")
    print(f"[*] Stats: {json.dumps(result.stats, indent=2)}")


# =========================
#   CLI
# =========================

def parse_args():
    p = argparse.ArgumentParser(description="Core recon genérico para BBP (bulkin).")
    p.add_argument("--program-config", required=True, help="Ruta al archivo JSON de configuración del programa (program_X.json)")
    p.add_argument("--handle", help="Handle de HackerOne (se usará en header HackerOne)")
    p.add_argument("--targets", help="Archivo con targets iniciales (uno por línea)")
    return p.parse_args()


def main():
    args = parse_args()
    program_cfg = load_program_config(args.program_config)

    # Advertencia si no hay handle
    if not args.handle:
        print("[!] No se proporcionó --handle. Se recomienda usar tu handle de HackerOne para el header 'HackerOne'.")
    else:
        print(f"[*] Usando handle HackerOne: {args.handle}")

    loop = asyncio.get_event_loop()
    recon_result = loop.run_until_complete(
        run_recon(program_cfg, args.handle, args.targets)
    )
    save_recon_result(recon_result)


if __name__ == "__main__":
    main()
