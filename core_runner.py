#!/usr/bin/env python3
"""
core_runner.py

Orquestador maestro de la suite BULKIN:

Pipeline:
 1. core_recon
 2. core_discovery
 3. core_exploit
 4. plugin_stripchat_business_logic

Ejemplo:
 python core_runner.py \
    --program-config program_stripchat.json \
    --handle TU_HANDLE \
    --targets stripchat_targets.txt \
    --viewer-session sessions/stripchat_viewer.json \
    --model-session sessions/stripchat_model.json \
    --run-plugin
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from typing import Dict, Any


# ============================
# UTILS
# ============================

def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def exists(path: str) -> bool:
    return os.path.isfile(path)


def banner(msg: str):
    print("\n" + "="*60)
    print(msg)
    print("="*60 + "\n")


def run_cmd(cmd: list):
    """
    Ejecuta un comando y transmite stdout / stderr.
    Devuelve True/False si fue exitoso.
    """
    print(f"[CMD] {' '.join(cmd)}")
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )
    for line in process.stdout:
        print(line, end="")
    process.wait()
    return process.returncode == 0


# ============================
# CORE RUNNER LOGIC
# ============================

def run_pipeline(program_config: str,
                 targets_path: str,
                 handle: str,
                 viewer_session: str,
                 model_session: str,
                 run_plugin: bool):

    # ---------- Load program config ----------
    banner("1. Cargando configuración del programa")
    if not exists(program_config):
        print(f"[ERROR] No existe program-config: {program_config}")
        sys.exit(1)
    cfg = load_json(program_config)
    program_id = cfg.get("id", "program")
    print(f"[*] Program ID: {program_id}")

    # ---------- Recon ----------
    banner("2. Ejecutando RECON (core_recon.py)")
    recon_file = f"recon_{program_id}.json"

    cmd_recon = [
        sys.executable, "core_recon.py",
        "--program-config", program_config,
        "--handle", handle,
        "--targets", targets_path
    ]

    if not run_cmd(cmd_recon):
        print("[ERROR] Falló core_recon.py")
        sys.exit(1)

    if not exists(recon_file):
        print(f"[ERROR] No se generó el archivo {recon_file}")
        sys.exit(1)

    # ---------- Discovery ----------
    banner("3. Ejecutando DISCOVERY (core_discovery.py)")
    discovery_file = f"discovery_{program_id}.json"

    cmd_discovery = [
        sys.executable, "core_discovery.py",
        "--program-config", program_config,
        "--recon-file", recon_file
    ]

    if not run_cmd(cmd_discovery):
        print("[ERROR] Falló core_discovery.py")
        sys.exit(1)

    if not exists(discovery_file):
        print(f"[ERROR] No se generó {discovery_file}")
        sys.exit(1)

    # ---------- Exploit genérico ----------
    banner("4. Ejecutando EXPLOIT seguro (core_exploit.py)")
    exploit_file = f"exploit_{program_id}.json"

    cmd_exploit = [
        sys.executable, "core_exploit.py",
        "--program-config", program_config,
        "--discovery-file", discovery_file
    ]

    if not run_cmd(cmd_exploit):
        print("[ERROR] Falló core_exploit.py")
        sys.exit(1)

    if not exists(exploit_file):
        print(f"[ERROR] No se generó {exploit_file}")
        sys.exit(1)

    # ---------- Plugin (business logic) ----------
    plugin_output = None
    if run_plugin:
        banner("5. Ejecutando plugin Stripchat Business Logic")

        if not exists(viewer_session):
            print(f"[ERROR] Viewer session no encontrada: {viewer_session}")
            sys.exit(1)

        if not exists(model_session):
            print(f"[ERROR] Model session no encontrada: {model_session}")
            sys.exit(1)

        plugin_file = f"plugin_stripchat_business_{program_id}.json"

        cmd_plugin = [
            sys.executable, "plugin_stripchat_business_logic.py",
            "--program-config", program_config,
            "--discovery-file", discovery_file,
            "--exploit-file", exploit_file,
            "--viewer-session", viewer_session,
            "--model-session", model_session
        ]

        if not run_cmd(cmd_plugin):
            print("[ERROR] Falló plugin_stripchat_business_logic.py")
            sys.exit(1)

        if not exists(plugin_file):
            print(f"[ERROR] Plugin no generó archivo: {plugin_file}")
            sys.exit(1)

        plugin_output = plugin_file

    # ---------- SUMMARY ----------
    banner("6. Pipeline completado")

    report = {
        "program_id": program_id,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "files": {
            "recon": recon_file,
            "discovery": discovery_file,
            "exploit": exploit_file,
            "plugin": plugin_output
        },
        "notes": "Pipeline ejecutado correctamente."
    }

    summary_file = f"pipeline_summary_{program_id}.json"
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[+] Summary guardado en {summary_file}")
    print("[+] Fin del pipeline BULKIN.")


# ============================
# CLI
# ============================

def parse_args():
    p = argparse.ArgumentParser(description="BULKIN Pipeline Runner")
    p.add_argument("--program-config", required=True, help="Archivo JSON del programa (program_stripchat.json)")
    p.add_argument("--targets", required=True, help="Archivo de targets para core_recon")
    p.add_argument("--handle", required=True, help="HackerOne handle para header obligatorio")
    p.add_argument("--viewer-session", required=False, help="JSON cookies viewer", default="")
    p.add_argument("--model-session", required=False, help="JSON cookies model", default="")
    p.add_argument("--run-plugin", action="store_true", help="Ejecutar plugin Stripchat Business Logic")
    return p.parse_args()


def main():
    args = parse_args()
    run_pipeline(
        program_config=args.program_config,
        targets_path=args.targets,
        handle=args.handle,
        viewer_session=args.viewer_session,
        model_session=args.model_session,
        run_plugin=args.run_plugin
    )


if __name__ == "__main__":
    main()
