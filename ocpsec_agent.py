#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ocpsec v1.0 - Downstream Security Auditor for SAP PM
Author: Youssef AZIZE | ENSA El Jadida
License: MIT
GitHub: https://github.com/Yusuf-Cyber-hub/ocpsec
"""

import sys
import os
import argparse
import csv
import io
import re
import time
import hashlib
import json
import threading
import webbrowser
from datetime import datetime

# ==========================================
# 1. GESTION DES COULEURS (Windows + Linux)
# ==========================================
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    class Fore:
        RED = ''; GREEN = ''; YELLOW = ''; BLUE = ''; CYAN = ''; RESET = ''
    class Style:
        BRIGHT = ''; DIM = ''; RESET_ALL = ''

# ==========================================
# 2. AUTO-SCHEMA MAPPER (Colonnes Dynamiques)
# ==========================================
class AutoSchemaMapper:
    """Détecte et normalise automatiquement les noms de colonnes variables des fichiers SAP"""

    PATTERNS = {
        'ot_id': [r'ot.*id', r'num.*ot', r'ordre', r'order.*id', r'n_ot', r'num_ordre', r'ot_id', r'work_order'],
        'equipment': [r'equip', r'eqp', r'asset', r'appareil', r'installation', r'moteur', r'pompe', r'equipment'],
        'status': [r'statut', r'status', r'state', r'stat_ot', r'sys_stat'],
        'loto_validation': [r'loto', r'consign', r'lockout', r'cadenas', r'deconsign', r'validation_loto'],
        'user_id': [r'user.*id', r'matricule', r'utilisateur', r'user', r'tech_id'],
        'role': [r'role', r'fonct', r'profil', r'access_level'],
        'action': [r'action', r'op.*type', r'transaction', r'event'],
        'timestamp': [r'time', r'date', r'horodatage', r'timestamp']
    }

    ORDER_SIGNALS = {'ot_id', 'equipment', 'status', 'loto_validation', 'loto'}
    LOG_SIGNALS = {'action', 'timestamp', 'user', 'user_id', 'ot_id'}
    USER_SIGNALS = {'user_id', 'role'}

    @staticmethod
    def normalize_headers(raw_dict_list):
        if not raw_dict_list:
            return []

        sample_keys = list(raw_dict_list[0].keys())
        key_mapping = {}

        for key in sample_keys:
            clean_key = key.strip().lower()
            mapped = False
            for target_col, regex_list in AutoSchemaMapper.PATTERNS.items():
                if any(re.search(pat, clean_key) for pat in regex_list):
                    key_mapping[key] = target_col
                    mapped = True
                    break
            if not mapped:
                key_mapping[key] = key

        normalized_list = []
        for row in raw_dict_list:
            norm_row = {}
            for k, v in row.items():
                norm_key = key_mapping.get(k, k)
                norm_row[norm_key] = v.strip() if isinstance(v, str) else v
            normalized_list.append(norm_row)

        return normalized_list

    @staticmethod
    def detect_category(filename, normalized_rows):
        """Associe automatiquement un fichier CSV à orders, logs ou users."""
        if not normalized_rows:
            return None

        fname = (filename or '').lower()
        sample_keys = set(normalized_rows[0].keys())
        scores = {'orders': 0, 'logs': 0, 'users': 0}

        if any(x in fname for x in ('order', 'ordre', 'ot', 'iw28', 'iw38', 'work')):
            scores['orders'] += 4
        if any(x in fname for x in ('log', 'audit', 'journal', 'cdhdr', 'cdpos', 'trace')):
            scores['logs'] += 4
        if any(x in fname for x in ('user', 'utilisateur', 'iam', 'role', 'profil', 'account')):
            scores['users'] += 4

        scores['orders'] += len(sample_keys & AutoSchemaMapper.ORDER_SIGNALS) * 2
        scores['logs'] += len(sample_keys & AutoSchemaMapper.LOG_SIGNALS) * 2
        scores['users'] += len(sample_keys & AutoSchemaMapper.USER_SIGNALS) * 2

        if 'loto_validation' in sample_keys or ('status' in sample_keys and 'equipment' in sample_keys):
            scores['orders'] += 5
        if 'action' in sample_keys and ('timestamp' in sample_keys or 'user' in sample_keys or 'user_id' in sample_keys):
            scores['logs'] += 5
        if 'role' in sample_keys and ('user_id' in sample_keys or 'user' in sample_keys) and 'action' not in sample_keys:
            scores['users'] += 5

        best = max(scores, key=scores.get)
        return best if scores[best] > 0 else None


# ==========================================
# 2b. PARSING CSV ROBUSTE
# ==========================================
def detect_csv_delimiter(first_line):
    """Détecte le séparateur CSV (, ; ou tabulation) à partir de la première ligne."""
    if not first_line:
        return ','
    candidates = [(',', first_line.count(',')), (';', first_line.count(';')), ('\t', first_line.count('\t'))]
    best = max(candidates, key=lambda item: item[1])
    return best[0] if best[1] > 0 else ','


def decode_csv_bytes(raw_bytes):
    """Décode les octets CSV en texte (UTF-8 BOM, Latin-1, CP1252)."""
    for encoding in ('utf-8-sig', 'utf-8', 'cp1252', 'latin-1'):
        try:
            return raw_bytes.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw_bytes.decode('latin-1', errors='ignore')


def parse_csv_content(content):
    """Parse un contenu CSV brut en liste de dicts normalisés."""
    if not content or not content.strip():
        return []

    lines = content.splitlines()
    first_line = next((line for line in lines if line.strip()), '')
    delimiter = detect_csv_delimiter(first_line)
    reader = list(csv.DictReader(io.StringIO(content), delimiter=delimiter))
    return AutoSchemaMapper.normalize_headers(reader)


def parse_csv_bytes(raw_bytes):
    """Parse des octets CSV bruts."""
    return parse_csv_content(decode_csv_bytes(raw_bytes))


def collect_uploaded_files(flask_request):
    """Récupère tous les fichiers uploadés (clé 'files', 'file' ou toute autre clé)."""
    seen = set()
    collected = []

    for field in ('files', 'file'):
        for item in flask_request.files.getlist(field):
            ident = (item.filename, id(item))
            if item and item.filename and ident not in seen:
                seen.add(ident)
                collected.append(item)

    if not collected:
        for key in flask_request.files:
            for item in flask_request.files.getlist(key):
                ident = (item.filename, id(item))
                if item and item.filename and ident not in seen:
                    seen.add(ident)
                    collected.append(item)

    return collected


def assign_csv_to_live_data(filename, normalized_rows, live_data):
    """Route un CSV parsé vers orders / logs / users dans live_data."""
    category = AutoSchemaMapper.detect_category(filename, normalized_rows)
    if not category:
        for fallback in ('orders', 'logs', 'users'):
            if not live_data[fallback]:
                category = fallback
                break
        if not category:
            category = 'orders'

    live_data[category] = normalized_rows
    return category


# ==========================================
# 3. BANNIÈRE ASCII
# ==========================================
def print_banner():
    banner = f"""
{Fore.CYAN if COLORS_AVAILABLE else ''}  ╔══════════════════════════════════════════════════════════════╗
  ║                                                              ║
  ║   ██████╗  ██████╗██████╗ ███████╗███████╗ ██████╗           ║
  ║  ██╔═══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝           ║
  ║  ██║   ██║██║     ██████╔╝███████╗█████╗  ██║                ║
  ║  ██║   ██║██║     ██╔═══╝ ╚════██║██╔══╝  ██║                ║
  ║  ╚██████╔╝╚██████╗██║     ███████║███████╗╚██████╗           ║
  ║   ╚═════╝  ╚═════╝╚═╝     ╚══════╝╚══════╝ ╚═════╝           ║
  ║                                                              ║
  ║  {Fore.GREEN if COLORS_AVAILABLE else ''}v1.0{Fore.CYAN if COLORS_AVAILABLE else ''}  Downstream Security Auditor for SAP PM{Fore.RESET if COLORS_AVAILABLE else ''}                 ║
  ║  {Fore.YELLOW if COLORS_AVAILABLE else ''}Author: Youssef AZIZE | ENSA El Jadida{Fore.RESET if COLORS_AVAILABLE else ''}                      ║
  ║  {Style.DIM if COLORS_AVAILABLE else ''}License: MIT | GitHub: https://github.com/Yusuf-Cyber-hub/ocpsec{Fore.RESET if COLORS_AVAILABLE else ''}      ║
  ║                                                              ║
  ╚══════════════════════════════════════════════════════════════╝
{Fore.GREEN if COLORS_AVAILABLE else ''}[+] Ready.{Fore.RESET if COLORS_AVAILABLE else ''}
"""
    print(banner)
# ==========================================
# 4. GÉNÉRATION DE DONNÉES FICTIVES (--demo)
# ==========================================
def generate_demo_data():
    print(f"{Fore.CYAN if COLORS_AVAILABLE else ''}[*] Generating demo data...{Fore.RESET if COLORS_AVAILABLE else ''}")
    os.makedirs('data', exist_ok=True)

    orders = [
        {'ot_id': 'OT-001', 'equipment': 'POMPE-ACIDE-A01', 'status': 'TECO', 'loto_validation': 'NON'},
        {'ot_id': 'OT-002', 'equipment': 'COMPRESSEUR-B03', 'status': 'LANC', 'loto_validation': 'OUI'},
        {'ot_id': 'OT-003', 'equipment': 'VENTILATEUR-C12', 'status': 'TECO', 'loto_validation': 'NON'},
        {'ot_id': 'OT-004', 'equipment': 'MOTEUR-D07', 'status': 'REL', 'loto_validation': 'OUI'},
        {'ot_id': 'OT-005', 'equipment': 'CONVOYEUR-E09', 'status': 'TECO', 'loto_validation': 'OUI'}
    ]
    with open('data/orders.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['ot_id', 'equipment', 'status', 'loto_validation'])
        writer.writeheader()
        writer.writerows(orders)

    logs = [
        {'timestamp': '2026-08-01 08:15:23', 'user': 'TECH-01', 'action': 'MODIFY_COST', 'ot_id': 'OT-001'},
        {'timestamp': '2026-08-01 09:30:45', 'user': 'TECH-02', 'action': 'START_WORK', 'ot_id': 'OT-002'},
        {'timestamp': '2026-08-02 10:00:12', 'user': 'ADMIN-07', 'action': 'VALIDATE_LOTO', 'ot_id': 'OT-001'},
        {'timestamp': '2026-08-02 11:20:33', 'user': 'TECH-03', 'action': 'COMPLETE_ORDER', 'ot_id': 'OT-003'},
        {'timestamp': '2026-08-03 14:45:21', 'user': 'PREP-01', 'action': 'START_WORK', 'ot_id': 'OT-003'},
        {'timestamp': '2026-08-04 08:05:10', 'user': 'TECH-01', 'action': 'CHANGE_STATUS', 'ot_id': 'OT-005'}
    ]
    with open('data/logs.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['timestamp', 'user', 'action', 'ot_id'])
        writer.writeheader()
        writer.writerows(logs)

    users = [
        {'user_id': 'TECH-01', 'role': 'TECHNICIEN'},
        {'user_id': 'TECH-02', 'role': 'TECHNICIEN'},
        {'user_id': 'TECH-03', 'role': 'TECHNICIEN'},
        {'user_id': 'ADMIN-07', 'role': 'ADMIN'},
        {'user_id': 'PREP-01', 'role': 'PREPARATEUR'}
    ]
    with open('data/users.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['user_id', 'role'])
        writer.writeheader()
        writer.writerows(users)

    print(f"{Fore.GREEN if COLORS_AVAILABLE else ''}[+] Demo data generated in 'data/' folder.{Fore.RESET if COLORS_AVAILABLE else ''}")

# ==========================================
# 5. CHARGEMENT & NORMALISATION
# ==========================================
def load_data(folder='data/'):
    """Charge les fichiers CSV et normalise les colonnes automatiquement"""
    orders, logs, users = [], [], []

    for fname, target in [('orders.csv', 'orders'), ('logs.csv', 'logs'), ('users.csv', 'users')]:
        path = os.path.join(folder, fname)
        if os.path.exists(path):
            try:
                with open(path, 'rb') as f:
                    norm = parse_csv_bytes(f.read())
                    if target == 'orders':
                        orders = norm
                    elif target == 'logs':
                        logs = norm
                    elif target == 'users':
                        users = norm
            except Exception:
                pass

    if orders or logs or users:
        return orders, logs, users

    if os.path.isdir(folder):
        for f_item in os.listdir(folder):
            if not f_item.lower().endswith('.csv'):
                continue
            path = os.path.join(folder, f_item)
            try:
                with open(path, 'rb') as f:
                    norm_reader = parse_csv_bytes(f.read())
                    if not norm_reader:
                        continue
                    category = AutoSchemaMapper.detect_category(f_item, norm_reader)
                    if category == 'logs':
                        logs = norm_reader
                    elif category == 'users':
                        users = norm_reader
                    elif category == 'orders':
                        orders = norm_reader
            except Exception:
                pass

    return orders, logs, users

# ==========================================
# 6. FONCTIONS D'AUDIT
# ==========================================
def audit_loto(orders):
    violations = []
    for order in orders:
        status = order.get('status', '').upper()
        loto = order.get('loto_validation', order.get('loto', '')).upper()
        if status in ['LANC', 'TECO', 'RELEASED', 'COMPLETED'] and loto not in ['OUI', 'YES', 'TRUE', '1']:
            violations.append({
                "ot_id": order.get('ot_id', 'N/A'),
                "equipment": order.get('equipment', 'N/A'),
                "status": status,
                "loto_validation": loto if loto else 'NON',
                "severity": "CRITICAL",
                "rule": "R-01 - Consignation LOTO manquante",
                "details": f"OT {order.get('ot_id', 'N/A')} sur équipement {order.get('equipment', 'N/A')} en statut '{status}' sans fiche LOTO signée"
            })
    return violations

def audit_iam(logs, users):
    role_matrix = {
        'TECHNICIEN': ['START_WORK', 'COMPLETE_ORDER', 'VIEW_OT', 'CHANGE_STATUS'],
        'PREPARATEUR': ['CREATE_OT', 'VALIDATE_LOTO', 'VIEW_OT'],
        'ADMIN': ['ALL']
    }
    user_role = {u.get('user_id', u.get('user', '')): u.get('role', '') for u in users}
    violations = []
    for log in logs:
        user = log.get('user_id', log.get('user', ''))
        action = log.get('action', '')
        if not user:
            continue
        if user not in user_role:
            violations.append({
                "user": user,
                "action": action,
                "message": "Utilisateur inconnu dans la base IAM",
                "severity": "HIGH",
                "rule": "R-02 - Utilisateur Non Référencé",
                "details": f"Compte '{user}' a exécuté l'action '{action}' sans rôle valide f-IAM"
            })
            continue
        role = user_role[user]
        allowed = role_matrix.get(role, [])
        if 'ALL' not in allowed and action not in allowed:
            violations.append({
                "user": user,
                "role": role,
                "action": action,
                "message": f"Action non autorisée pour le rôle {role}",
                "severity": "HIGH",
                "rule": "R-02 - Violation Ségrégation des Tâches (SoD)",
                "details": f"L'utilisateur '{user}' (Rôle {role}) a effectué '{action}' (Hors périmètre autorisé)"
            })
    return violations

def audit_integrity(orders):
    anomalies = []
    ids = [o.get('ot_id', '') for o in orders if o.get('ot_id')]
    if len(ids) != len(set(ids)):
        duplicates = [id for id in set(ids) if ids.count(id) > 1]
        anomalies.append({
            "ot_id": ", ".join(duplicates),
            "message": f"Doublons détectés: {', '.join(duplicates)}",
            "severity": "MEDIUM",
            "rule": "R-03 - Doublon d'Ordres",
            "details": f"Identifiant d'OT réutilisé plusieurs fois dans SAP PM: {', '.join(duplicates)}"
        })
    valid_statuses = ['CREATED', 'LANC', 'TECO', 'REL', 'CLOS', 'RELEASED', 'COMPLETED']
    for order in orders:
        status = order.get('status', '').upper()
        if status and status not in valid_statuses:
            anomalies.append({
                "ot_id": order.get('ot_id', 'N/A'),
                "message": f"Statut invalide: {status}",
                "severity": "MEDIUM",
                "rule": "R-03 - Statut Non Conforme",
                "details": f"OT {order.get('ot_id', 'N/A')} possède un statut inconnu dans le workflow SAP: {status}"
            })
    blockchain = []
    prev_hash = ""
    for order in sorted(orders, key=lambda x: x.get('ot_id', '')):
        data = f"{order.get('ot_id', '')}|{order.get('status', '')}|{order.get('loto_validation', '')}|{prev_hash}"
        hash_val = hashlib.sha256(data.encode()).hexdigest()
        blockchain.append({
            'ot_id': order.get('ot_id', 'N/A'),
            'hash': hash_val[:16],
            'previous_hash': prev_hash[:16] if prev_hash else 'GENESIS'
        })
        prev_hash = hash_val
    return anomalies, blockchain

def print_info():
    """Affiche la description de l'outil et les règles appliquées (--info)"""
    c_cyan = Fore.CYAN if COLORS_AVAILABLE else ''
    c_green = Fore.GREEN if COLORS_AVAILABLE else ''
    c_amber = Fore.YELLOW if COLORS_AVAILABLE else ''
    c_rose = Fore.RED if COLORS_AVAILABLE else ''
    c_reset = Fore.RESET if COLORS_AVAILABLE else ''

    print(f"\n{c_cyan}========================================================================={c_reset}")
    print(f"{c_cyan}                ocpsec v1.0 Pro — Informations & Règles                  {c_reset}")
    print(f"{c_cyan}========================================================================={c_reset}")
    print(f"📌 {c_green}Sujet d'Ingénierie:{c_reset} Audit & Sécurisation du Cycle de Vie des Ordres de Travail (OT)")
    print(f"🏭 {c_green}Contexte Industriel:{c_reset} OCP Group (Site Jorf Lasfar) — Département Downstream (Service OIK/PD)")
    print(f"🎓 {c_green}Auteur:{c_reset} Youssef AZIZE | Projet de Fin d'Études (ENSA El Jadida)")
    print(f"🛡️ {c_green}Objectif Cyber-Résilience:{c_reset} Détecter automatiquement les fraudes, sabotages et incohérences dans SAP PM\n")

    print(f"{c_amber}📋 RÈGLES DE SÉCURITÉ APPLIQUÉES EN TEMPS RÉEL :{c_reset}")
    print(f"-------------------------------------------------------------------------")
    print(f"🔴 {c_rose}R-01 : Consignation LOTO (Lockout/Tagout) — Sécurité Physique / OT{c_reset}")
    print(f"   • Contrôle le verrouillage électrique/mécanique avant le lancement d'un OT.")
    print(f"   • Risque: Lancement d'interventions sur des équipements sous tension sans fiche LOTO.")
    print(f"   • Sévérité: CRITICAL\n")

    print(f"🟠 {c_amber}R-02 : IAM & Ségrégation des Tâches (SoD) — Contrôle d'Accès SAP{c_reset}")
    print(f"   • Empêche le cumul de rôles incompatibles f-SAP (Création IW31 / Approbation / Clôture IW41).")
    print(f"   • Risque: Auto-validation d'ordres de travail fictifs ou frauduleux par un seul compte.")
    print(f"   • Sévérité: HIGH\n")

    print(f"🔵 {c_cyan}R-03 : Intégrité & Horodatage Cryptographique SHA-256 — Registre Immuable{c_reset}")
    print(f"   • Génère une chaîne de hachage SHA-256 (Blockchain style) sur chaque OT.")
    print(f"   • Détecte les doublons, statuts orphelins et falsifications de logs CDHDR/CDPOS.")
    print(f"   • Sévérité: MEDIUM\n")
    print(f"{c_cyan}========================================================================={c_reset}\n")

def print_results(loto, iam, integrity, total_orders):
    """Affiche le résumé détaillé des violations CLI"""
    c_rose = Fore.RED if COLORS_AVAILABLE else ''
    c_amber = Fore.YELLOW if COLORS_AVAILABLE else ''
    c_cyan = Fore.CYAN if COLORS_AVAILABLE else ''
    c_green = Fore.GREEN if COLORS_AVAILABLE else ''
    c_reset = Fore.RESET if COLORS_AVAILABLE else ''

    print(f"\n{c_cyan}========================================================================={c_reset}")
    print(f"{c_green}[+] Scan Cyber-Résilience Terminé sur {total_orders} Ordres de Travail (OT){c_reset}")
    print(f"{c_cyan}========================================================================={c_reset}")
    print(f"Résumé des Violations : {c_rose}CRITICAL (LOTO): {len(loto)}{c_reset} | {c_amber}HIGH (IAM): {len(iam)}{c_reset} | {c_cyan}MEDIUM (Intégrité): {len(integrity)}{c_reset}\n")

    if loto:
        print(f"{c_rose}🔴 CRITICAL — VIOLATIONS CONSIGNATION LOTO (R-01) [{len(loto)}] :{c_reset}")
        for v in loto:
            print(f"  • OT: {v['ot_id']} | Équipement: {v['equipment']} | Statut: {v['status']} | LOTO: {v['loto_validation']}")
            print(f"    └── DÉTAIL: {v['details']}")
        print()

    if iam:
        print(f"{c_amber}🟠 HIGH — VIOLATIONS IAM / SÉGRÉGATION DES TÂCHES (R-02) [{len(iam)}] :{c_reset}")
        for v in iam:
            print(f"  • Utilisateur: {v['user']} | Action: {v['action']} | Règle: {v['rule']}")
            print(f"    └── DÉTAIL: {v['details']}")
        print()

    if integrity:
        print(f"{c_cyan}🔵 MEDIUM — ANOMALIES INTÉGRITÉ & WORKFLOW (R-03) [{len(integrity)}] :{c_reset}")
        for v in integrity:
            print(f"  • Cible: {v.get('ot_id', 'Global')} | {v['message']}")
            print(f"    └── DÉTAIL: {v['details']}")
        print()

# ==========================================
# 7. DASHBOARD WEB INTERACTIF (Flask Upload)
# ==========================================
def launch_web_dashboard(data_folder='data/', auto_open=True):
    try:
        from flask import Flask, render_template_string, jsonify, request, Response
    except ImportError:
        print(f"{Fore.RED if COLORS_AVAILABLE else ''}[!] Flask not installed. Run: pip install flask{Fore.RESET if COLORS_AVAILABLE else ''}")
        return

    app = Flask(__name__)

    live_data = {'orders': [], 'logs': [], 'users': [], 'filenames': []}

    HTML_TEMPLATE = """
    <!DOCTYPE html>
    <html lang="fr" class="dark">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>OCPSec Agent - Dashboard Audit Cyber SAP PM</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
        <style>
            body { font-family: 'Plus Jakarta Sans', sans-serif; background: #080c14; color: #e2e8f0; }
            .font-mono { font-family: 'JetBrains Mono', monospace; }
            .panel { background: rgba(15, 23, 42, 0.75); backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.07); }
            .card-hover { transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1); }
            .card-hover:hover { transform: translateY(-2px); border-color: rgba(56, 189, 248, 0.3); }
            #dropZone.drag-active { border-color: rgba(34, 211, 238, 0.8); background: rgba(8, 51, 68, 0.35); }
            @media print {
                .no-print { display: none !important; }
                body { background: #ffffff !important; color: #000000 !important; }
                .panel { background: #ffffff !important; border: 1px solid #cbd5e1 !important; color: #000000 !important; }
            }
        </style>
    </head>
    <body class="min-h-screen pb-12 selection:bg-cyan-500/20 selection:text-cyan-300">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-6 space-y-6">

            <header class="panel rounded-xl p-5 border border-slate-800 flex flex-col md:flex-row items-center justify-between gap-4">
                <div class="flex items-center space-x-4">
                    <div class="w-12 h-12 rounded-lg bg-slate-900 border border-slate-700 flex items-center justify-center font-mono font-bold text-cyan-400 text-lg shadow-inner">
                        OCP
                    </div>
                    <div>
                        <div class="flex items-center space-x-3">
                            <h1 class="text-xl font-bold text-slate-100 tracking-tight font-mono">ocpsec</h1>
                            <span class="text-[11px] px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-mono font-medium">v1.0 Pro</span>
                        </div>
                        <p class="text-xs text-slate-400 mt-0.5">Auditeur Cyber-Résilience SAP PM & Normalisation Dynamique (OCP Jorf Lasfar)</p>
                    </div>
                </div>

                <div class="flex flex-wrap items-center gap-3 no-print">
                    <div id="statusBadge" class="flex items-center space-x-2 bg-slate-900 px-3 py-1.5 rounded-lg border border-slate-800 text-xs font-mono text-amber-400">
                        <span class="w-2 h-2 rounded-full bg-amber-400 animate-pulse"></span>
                        <span>En attente de fichiers CSV</span>
                    </div>

                    <button type="button" id="demoBtn" onclick="loadDemoData()" class="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-cyan-400 font-mono text-xs font-medium rounded-lg border border-cyan-500/30 hover:border-cyan-500/60 transition-all flex items-center space-x-1.5 cursor-pointer active:scale-95">
                        <span>🧪 Charger Démo OCP</span>
                    </button>

                    <button type="button" id="resetBtn" onclick="resetData()" class="px-3 py-1.5 bg-slate-900 hover:bg-rose-950/40 text-rose-400 font-mono text-xs font-medium rounded-lg border border-rose-500/30 hover:border-rose-500/60 transition-all flex items-center space-x-1.5 cursor-pointer active:scale-95">
                        <span>🗑️ Réinitialiser</span>
                    </button>

                    <button type="button" id="exportBtn" onclick="exportJSON()" class="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-emerald-400 font-mono text-xs font-medium rounded-lg border border-emerald-500/30 hover:border-emerald-500/60 transition-all flex items-center space-x-1.5 cursor-pointer active:scale-95">
                        <span>📥 Exporter JSON</span>
                    </button>

                    <button type="button" id="printBtn" onclick="window.print()" class="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-slate-300 font-mono text-xs font-medium rounded-lg border border-slate-700 transition-all flex items-center space-x-1.5 cursor-pointer active:scale-95">
                        <span>🖨️ Imprimer</span>
                    </button>
                </div>
            </header>

            <div id="dropZone" class="panel rounded-xl p-6 text-center border-2 border-dashed border-slate-700 hover:border-cyan-500/60 transition-all cursor-pointer relative group no-print">
                <input type="file" id="fileInput" name="files" multiple accept=".csv,.txt,text/csv" class="hidden">
                <div class="space-y-2 pointer-events-none">
                    <div class="w-12 h-12 mx-auto rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-center text-cyan-400 font-mono font-bold text-sm group-hover:border-cyan-500/40 transition-colors">
                        CSV
                    </div>
                    <div>
                        <h3 class="text-sm font-semibold text-slate-200">Glissez-déposez vos fichiers CSV SAP ici (ou cliquez pour parcourir)</h3>
                        <p class="text-xs text-slate-400 mt-1">Détection automatique des entêtes et routage intelligent des données</p>
                    </div>
                    <div id="fileBadges" class="inline-flex flex-wrap gap-2 text-[11px] font-mono text-slate-400 bg-slate-900/60 px-3 py-1 rounded border border-slate-800">
                        <span>Fichiers supportés: orders.csv, logs.csv, users.csv ou exports IW28 / IW38</span>
                    </div>
                </div>
                <div class="mt-4 flex items-center justify-center space-x-3">
                    <button type="button" id="browseBtn" class="px-5 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-mono text-xs font-bold rounded-lg transition-all shadow-md shadow-cyan-500/20 active:scale-95">
                        Importer & Analyser Fichiers
                    </button>
                </div>
            </div>

            <div class="panel p-4 rounded-xl border border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-4 no-print">
                <div class="relative w-full sm:w-96">
                    <span class="absolute inset-y-0 left-0 flex items-center pl-3 text-slate-500 font-mono text-xs">🔍</span>
                    <input type="text" id="searchInput" oninput="applyFilters()" placeholder="Rechercher par N° OT, Équipement, Utilisateur..." class="w-full pl-9 pr-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono">
                </div>

                <div class="flex items-center space-x-3 w-full sm:w-auto">
                    <span class="text-xs text-slate-400 font-mono">Filtre Règle:</span>
                    <select id="ruleFilter" onchange="applyFilters()" class="bg-slate-900 border border-slate-800 text-xs text-slate-200 rounded-lg px-3 py-2 font-mono focus:outline-none focus:border-cyan-500">
                        <option value="ALL">Toutes les règles (R-01, R-02, R-03)</option>
                        <option value="R-01">R-01 : LOTO uniquement</option>
                        <option value="R-02">R-02 : IAM / SoD uniquement</option>
                        <option value="R-03">R-03 : Intégrité uniquement</option>
                    </select>
                </div>
            </div>

            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div class="panel p-5 rounded-xl border-l-4 border-l-rose-500 card-hover">
                    <div class="flex items-center justify-between">
                        <span class="text-xs font-medium text-slate-400">Critical LOTO (R-01)</span>
                        <span class="text-[10px] px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 font-mono font-medium">Consignation</span>
                    </div>
                    <p id="k1" class="text-2xl font-bold text-slate-100 mt-2 font-mono">0</p>
                </div>

                <div class="panel p-5 rounded-xl border-l-4 border-l-amber-500 card-hover">
                    <div class="flex items-center justify-between">
                        <span class="text-xs font-medium text-slate-400">High IAM / SoD (R-02)</span>
                        <span class="text-[10px] px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 font-mono font-medium">Conflit Rôle</span>
                    </div>
                    <p id="k2" class="text-2xl font-bold text-slate-100 mt-2 font-mono">0</p>
                </div>

                <div class="panel p-5 rounded-xl border-l-4 border-l-cyan-500 card-hover">
                    <div class="flex items-center justify-between">
                        <span class="text-xs font-medium text-slate-400">Medium Intégrité (R-03)</span>
                        <span class="text-[10px] px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 font-mono font-medium">Anomalie</span>
                    </div>
                    <p id="k3" class="text-2xl font-bold text-slate-100 mt-2 font-mono">0</p>
                </div>

                <div class="panel p-5 rounded-xl border-l-4 border-l-emerald-500 card-hover">
                    <div class="flex items-center justify-between">
                        <span class="text-xs font-medium text-slate-400">Total Ordres Traités</span>
                        <span class="text-[10px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 font-mono font-medium">SAP PM</span>
                    </div>
                    <p id="k4" class="text-2xl font-bold text-slate-100 mt-2 font-mono">0</p>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div class="panel rounded-xl p-5 lg:col-span-1 space-y-3 border border-slate-800">
                    <h2 class="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono">Répartition des Risques</h2>
                    <div class="relative h-56 w-full flex items-center justify-center">
                        <canvas id="chart"></canvas>
                        <div id="chartEmpty" class="absolute inset-0 flex items-center justify-center text-slate-500 text-xs font-mono">
                            Aucune donnée chargée
                        </div>
                    </div>
                </div>

                <div class="panel rounded-xl p-5 lg:col-span-2 space-y-3 border border-slate-800">
                    <div class="flex items-center justify-between">
                        <h2 class="text-xs font-bold text-rose-400 uppercase tracking-wider font-mono">Violations Consignation LOTO (R-01)</h2>
                        <span class="text-[10px] text-slate-500 font-mono">Sécurité Physique / Terrain</span>
                    </div>
                    <div id="loto" class="space-y-2 max-h-56 overflow-y-auto pr-1 font-mono text-xs">
                        <p class="text-slate-500">En attente d'analyse...</p>
                    </div>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div class="panel rounded-xl p-5 space-y-3 border border-slate-800">
                    <div class="flex items-center justify-between">
                        <h2 class="text-xs font-bold text-amber-400 uppercase tracking-wider font-mono">Violations Ségrégation des Tâches / IAM (R-02)</h2>
                        <span class="text-[10px] text-slate-500 font-mono">Accès & Matrice SoD</span>
                    </div>
                    <div id="iam" class="space-y-2 max-h-56 overflow-y-auto pr-1 font-mono text-xs">
                        <p class="text-slate-500">En attente d'analyse...</p>
                    </div>
                </div>

                <div class="panel rounded-xl p-5 space-y-3 border border-slate-800">
                    <div class="flex items-center justify-between">
                        <h2 class="text-xs font-bold text-cyan-400 uppercase tracking-wider font-mono">Traces Cryptographiques SHA-256 (R-03)</h2>
                        <span class="text-[10px] text-slate-500 font-mono">Registre Immuable</span>
                    </div>
                    <div id="bc" class="space-y-2 max-h-56 overflow-y-auto pr-1 font-mono text-xs">
                        <p class="text-slate-500">En attente d'analyse...</p>
                    </div>
                </div>
            </div>
        </div>

        <script>
            let rawData = { loto: [], iam: [], integrity: [], blockchain: [], total_orders: 0, loaded: { orders: 0, logs: 0, users: 0 } };
            let chartInstance = null;
            let dragCounter = 0;

            function hasLoadedData(d) {
                return (d.total_orders || 0) > 0
                    || (d.loaded && (d.loaded.orders + d.loaded.logs + d.loaded.users) > 0)
                    || (d.loto && d.loto.length)
                    || (d.iam && d.iam.length)
                    || (d.blockchain && d.blockchain.length);
            }

            function updateStatusBadge(d) {
                const badge = document.getElementById('statusBadge');
                const loaded = d.loaded || { orders: d.total_orders || 0, logs: 0, users: 0 };
                const totalRows = (loaded.orders || 0) + (loaded.logs || 0) + (loaded.users || 0);

                if (!hasLoadedData(d)) {
                    badge.className = "flex items-center space-x-2 bg-slate-900 px-3 py-1.5 rounded-lg border border-slate-800 text-xs font-mono text-amber-400";
                    badge.innerHTML = '<span class="w-2 h-2 rounded-full bg-amber-400 animate-pulse"></span><span>En attente de fichiers CSV</span>';
                } else {
                    badge.className = "flex items-center space-x-2 bg-emerald-950/60 px-3 py-1.5 rounded-lg border border-emerald-500/30 text-xs font-mono text-emerald-400";
                    badge.innerHTML = '<span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span><span>Scan Actif — OT:' + (loaded.orders||0) + ' Logs:' + (loaded.logs||0) + ' Users:' + (loaded.users||0) + ' (' + totalRows + ' lignes)</span>';
                }
            }

            function applyFilters() {
                const search = document.getElementById('searchInput').value.toLowerCase().trim();
                const selectedRule = document.getElementById('ruleFilter').value;

                let filteredLoto = rawData.loto.filter(v => {
                    const matchSearch = (v.ot_id || '').toLowerCase().includes(search) || (v.equipment || '').toLowerCase().includes(search) || (v.details || '').toLowerCase().includes(search);
                    const matchRule = selectedRule === 'ALL' || selectedRule === 'R-01';
                    return matchSearch && matchRule;
                });

                let filteredIam = rawData.iam.filter(v => {
                    const matchSearch = (v.user || '').toLowerCase().includes(search) || (v.action || '').toLowerCase().includes(search) || (v.details || '').toLowerCase().includes(search);
                    const matchRule = selectedRule === 'ALL' || selectedRule === 'R-02';
                    return matchSearch && matchRule;
                });

                let filteredIntegrity = rawData.integrity.filter(v => {
                    const matchSearch = (v.ot_id || '').toLowerCase().includes(search) || (v.message || '').toLowerCase().includes(search) || (v.details || '').toLowerCase().includes(search);
                    const matchRule = selectedRule === 'ALL' || selectedRule === 'R-03';
                    return matchSearch && matchRule;
                });

                let filteredBc = rawData.blockchain.filter(b => {
                    const matchSearch = (b.ot_id || '').toLowerCase().includes(search) || (b.hash || '').toLowerCase().includes(search);
                    const matchRule = selectedRule === 'ALL' || selectedRule === 'R-03';
                    return matchSearch && matchRule;
                });

                renderViews({
                    loto: filteredLoto,
                    iam: filteredIam,
                    integrity: filteredIntegrity,
                    blockchain: filteredBc,
                    total_orders: rawData.total_orders,
                    loaded: rawData.loaded
                });
            }

            function renderViews(d) {
                document.getElementById('k1').textContent = d.loto.length;
                document.getElementById('k2').textContent = d.iam.length;
                document.getElementById('k3').textContent = d.integrity.length;
                document.getElementById('k4').textContent = d.total_orders;

                updateStatusBadge(d);

                const chartEmpty = document.getElementById('chartEmpty');
                const hasData = hasLoadedData(d);

                if (!hasData) {
                    if (chartInstance) chartInstance.destroy();
                    chartEmpty.style.display = 'flex';
                    document.getElementById('loto').innerHTML = '<div class="p-4 rounded-lg bg-slate-900/60 border border-slate-800 text-xs text-slate-500 font-mono text-center">Aucun ordre de travail chargé. Veuillez glisser-déposer vos CSV.</div>';
                    document.getElementById('iam').innerHTML = '<div class="p-4 rounded-lg bg-slate-900/60 border border-slate-800 text-xs text-slate-500 font-mono text-center">Aucun journal d\\'audit chargé.</div>';
                    document.getElementById('bc').innerHTML = '<div class="p-4 rounded-lg bg-slate-900/60 border border-slate-800 text-xs text-slate-500 font-mono text-center">Aucun hachage généré.</div>';
                    return;
                }

                chartEmpty.style.display = 'none';
                if (chartInstance) chartInstance.destroy();

                const ctx = document.getElementById('chart').getContext('2d');
                chartInstance = new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: ['LOTO (R-01)', 'IAM (R-02)', 'Intégrité (R-03)'],
                        datasets: [{
                            data: [d.loto.length, d.iam.length, d.integrity.length],
                            backgroundColor: ['#f43f5e', '#f59e0b', '#06b6d4'],
                            borderWidth: 0,
                            hoverOffset: 4
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { position: 'bottom', labels: { color: '#94a3b8', font: { size: 11, family: 'Plus Jakarta Sans' } } }
                        },
                        cutout: '72%'
                    }
                });

                if ((d.loaded && d.loaded.orders) || d.total_orders > 0) {
                    document.getElementById('loto').innerHTML = d.loto.map(v => `
                        <div class="p-3 rounded-lg bg-rose-500/5 border border-rose-500/20 text-xs text-slate-200 space-y-1">
                            <div class="flex items-center justify-between">
                                <div class="flex items-center space-x-2">
                                    <span class="font-bold text-rose-400 font-mono">${v.ot_id}</span>
                                    <span class="text-slate-400 font-sans">Équipement: ${v.equipment}</span>
                                </div>
                                <div class="flex items-center space-x-2 font-mono text-[11px]">
                                    <span class="bg-rose-500/20 px-2 py-0.5 rounded text-rose-300 font-medium">${v.status}</span>
                                    <span class="bg-slate-900 px-2 py-0.5 rounded text-slate-400 border border-slate-800">LOTO: ${v.loto_validation}</span>
                                </div>
                            </div>
                            <p class="text-[11px] text-slate-400 font-sans border-t border-rose-500/10 pt-1 mt-1">${v.details}</p>
                        </div>
                    `).join('') || '<div class="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-xs text-emerald-300 font-mono">Conforme: Aucune violation LOTO détectée.</div>';
                } else {
                    document.getElementById('loto').innerHTML = '<div class="p-4 rounded-lg bg-slate-900/60 border border-slate-800 text-xs text-slate-500 font-mono text-center">Fichier orders.csv non fourni — audit LOTO (R-01) non applicable.</div>';
                }

                if (d.loaded && d.loaded.logs) {
                    document.getElementById('iam').innerHTML = d.iam.map(v => `
                        <div class="p-3 rounded-lg bg-amber-500/5 border border-amber-500/20 text-xs text-slate-200 space-y-1">
                            <div class="flex items-center justify-between">
                                <div class="flex items-center space-x-2">
                                    <span class="font-bold text-amber-400 font-mono">${v.user}</span>
                                    <span class="text-slate-400 font-sans">${v.message}</span>
                                </div>
                                <span class="text-[10px] font-mono bg-amber-500/10 text-amber-300 px-2 py-0.5 rounded border border-amber-500/20 font-medium">${v.action || 'R-02'}</span>
                            </div>
                            <p class="text-[11px] text-slate-400 font-sans border-t border-amber-500/10 pt-1 mt-1">${v.details}</p>
                        </div>
                    `).join('') || '<div class="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-xs text-emerald-300 font-mono">Conforme: Aucune violation IAM / SoD détectée.</div>';
                } else {
                    document.getElementById('iam').innerHTML = '<div class="p-4 rounded-lg bg-slate-900/60 border border-slate-800 text-xs text-slate-500 font-mono text-center">Fichier logs.csv non fourni — audit IAM (R-02) non applicable.</div>';
                }

                if ((d.loaded && d.loaded.orders) || d.total_orders > 0) {
                    document.getElementById('bc').innerHTML = d.blockchain.map((b, i) => `
                        <div class="p-2 rounded-lg bg-slate-900/90 border border-slate-800 text-xs font-mono flex items-center justify-between">
                            <span class="text-cyan-400 font-semibold">#${i+1} ${b.ot_id}</span>
                            <span class="text-slate-400 text-[11px]">SHA256: <code class="text-emerald-400">${b.hash}</code></span>
                        </div>
                    `).join('') || '<div class="p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-xs text-slate-500 font-mono text-center">Aucun hachage généré.</div>';
                } else {
                    document.getElementById('bc').innerHTML = '<div class="p-4 rounded-lg bg-slate-900/60 border border-slate-800 text-xs text-slate-500 font-mono text-center">Fichier orders.csv non fourni — registre SHA-256 (R-03) non applicable.</div>';
                }
            }

            function setActionButtonsDisabled(disabled) {
                ['demoBtn', 'resetBtn', 'exportBtn', 'printBtn', 'browseBtn'].forEach(id => {
                    const el = document.getElementById(id);
                    if (el) {
                        el.disabled = disabled;
                        el.classList.toggle('opacity-50', disabled);
                        el.classList.toggle('pointer-events-none', disabled);
                    }
                });
            }

            function handleApiError(action, err) {
                console.error(action + ' error:', err);
                alert('Erreur « ' + action + ' » : ' + (err.message || err));
                fetchAuditData();
            }

            function fetchAuditData() {
                return fetch('/api/audit')
                    .then(r => {
                        if (!r.ok) throw new Error('HTTP ' + r.status);
                        return r.json();
                    })
                    .then(data => {
                        rawData = data;
                        applyFilters();
                        return data;
                    })
                    .catch(err => handleApiError('Chargement audit', err));
            }

            function resetData() {
                if (!confirm('Réinitialiser toutes les données chargées ?')) return;
                setActionButtonsDisabled(true);
                document.getElementById('statusBadge').innerHTML = '<span class="w-2 h-2 rounded-full bg-rose-400 animate-pulse"></span><span>Réinitialisation...</span>';

                fetch('/api/reset', { method: 'POST' })
                    .then(r => {
                        if (!r.ok) throw new Error('HTTP ' + r.status);
                        return r.json();
                    })
                    .then(data => {
                        rawData = data;
                        document.getElementById('fileBadges').innerHTML = '<span>Fichiers supportés: orders.csv, logs.csv, users.csv</span>';
                        document.getElementById('fileInput').value = '';
                        applyFilters();
                    })
                    .catch(err => handleApiError('Réinitialiser', err))
                    .finally(() => setActionButtonsDisabled(false));
            }

            function loadDemoData() {
                setActionButtonsDisabled(true);
                document.getElementById('statusBadge').innerHTML = '<span class="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span><span>Chargement démo OCP...</span>';

                fetch('/api/demo', { method: 'POST' })
                    .then(r => {
                        if (!r.ok) throw new Error('HTTP ' + r.status);
                        return r.json();
                    })
                    .then(data => {
                        rawData = data;
                        document.getElementById('fileBadges').innerHTML = '<span class="text-cyan-400 font-bold">▶ Données Démo OCP Chargées (5 OT, 6 Logs, 5 Users)</span>';
                        applyFilters();
                    })
                    .catch(err => handleApiError('Charger Démo OCP', err))
                    .finally(() => setActionButtonsDisabled(false));
            }

            function exportJSON() {
                const loaded = rawData.loaded || { orders: 0, logs: 0, users: 0 };
                const totalRows = (loaded.orders || 0) + (loaded.logs || 0) + (loaded.users || 0);
                if (totalRows === 0) {
                    alert('Aucune donnée à exporter. Chargez des CSV ou cliquez sur « Charger Démo OCP ».');
                    return;
                }

                setActionButtonsDisabled(true);
                fetch('/api/export')
                    .then(r => {
                        if (!r.ok) throw new Error('HTTP ' + r.status);
                        return r.blob();
                    })
                    .then(blob => {
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = 'ocpsec_audit_report.json';
                        document.body.appendChild(a);
                        a.click();
                        a.remove();
                        URL.revokeObjectURL(url);
                    })
                    .catch(err => {
                        console.warn('Téléchargement blob échoué, fallback window.open:', err);
                        window.open('/api/export', '_blank');
                    })
                    .finally(() => setActionButtonsDisabled(false));
            }

            function filterCsvFiles(fileList) {
                const out = [];
                for (let i = 0; i < fileList.length; i++) {
                    const f = fileList[i];
                    const name = (f.name || '').toLowerCase();
                    if (name.endsWith('.csv') || name.endsWith('.txt') || f.type === 'text/csv' || f.type === 'application/vnd.ms-excel') {
                        out.push(f);
                    }
                }
                return out;
            }

            function uploadFiles(customFileList) {
                const input = document.getElementById('fileInput');
                const rawList = customFileList || (input ? input.files : null);
                if (!rawList || rawList.length === 0) return;

                const fileList = filterCsvFiles(rawList);
                if (fileList.length === 0) {
                    alert('Veuillez sélectionner au moins un fichier CSV (.csv ou .txt).');
                    return;
                }

                const formData = new FormData();
                const names = [];
                for (let i = 0; i < fileList.length; i++) {
                    const f = fileList[i];
                    formData.append('files', f, f.name);
                    names.push(f.name);
                }

                document.getElementById('fileBadges').innerHTML = names.map(n =>
                    `<span class="text-cyan-300 font-semibold bg-slate-800/80 px-2.5 py-1 rounded border border-cyan-500/30 font-mono text-[11px]">📄 ${n}</span>`
                ).join(' ');

                setActionButtonsDisabled(true);
                const badge = document.getElementById('statusBadge');
                badge.innerHTML = '<span class="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span><span>Import en cours...</span>';

                fetch('/api/upload', { method: 'POST', body: formData })
                    .then(r => {
                        if (!r.ok) throw new Error('HTTP ' + r.status);
                        return r.json();
                    })
                    .then(d => {
                        if (d.error) throw new Error(d.error);
                        rawData = d;
                        if (d.upload_meta && d.upload_meta.length) {
                            const meta = d.upload_meta.map(m => `${m.filename} → ${m.category} (${m.rows} lignes)`).join(' | ');
                            document.getElementById('fileBadges').innerHTML = '<span class="text-emerald-400 font-bold">✓ ' + meta + '</span>';
                        }
                        applyFilters();
                    })
                    .catch(err => {
                        console.error('Upload error:', err);
                        alert('Erreur lors de l\\'import CSV: ' + err.message);
                        fetchAuditData();
                    })
                    .finally(() => setActionButtonsDisabled(false));
            }

            function preventDefaults(e) {
                e.preventDefault();
                e.stopPropagation();
            }

            // Bloquer l'ouverture/téléchargement natif du navigateur sur toute la page
            ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(evtName => {
                document.body.addEventListener(evtName, preventDefaults, false);
                window.addEventListener(evtName, preventDefaults, false);
            });

            // dragover doit être non-passif pour que preventDefault() soit effectif (Chrome/Firefox)
            document.addEventListener('dragover', preventDefaults, { passive: false });
            document.addEventListener('drop', preventDefaults, { passive: false });

            const dz = document.getElementById('dropZone');
            const fileInput = document.getElementById('fileInput');
            const browseBtn = document.getElementById('browseBtn');

            browseBtn.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                fileInput.click();
            });

            dz.addEventListener('click', function(e) {
                if (e.target === browseBtn || browseBtn.contains(e.target)) return;
                fileInput.click();
            });

            fileInput.addEventListener('change', function() {
                uploadFiles(fileInput.files);
            });

            dz.addEventListener('dragenter', function(e) {
                preventDefaults(e);
                dragCounter++;
                dz.classList.add('drag-active');
            });

            dz.addEventListener('dragover', function(e) {
                preventDefaults(e);
                if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy';
            });

            dz.addEventListener('dragleave', function(e) {
                preventDefaults(e);
                dragCounter--;
                if (dragCounter <= 0) {
                    dragCounter = 0;
                    dz.classList.remove('drag-active');
                }
            });

            dz.addEventListener('drop', function(e) {
                preventDefaults(e);
                dragCounter = 0;
                dz.classList.remove('drag-active');

                const dt = e.dataTransfer;
                if (dt && dt.files && dt.files.length > 0) {
                    uploadFiles(dt.files);
                }
            });

            // Exposer les handlers au scope global pour les onclick HTML
            window.loadDemoData = loadDemoData;
            window.resetData = resetData;
            window.exportJSON = exportJSON;
            window.uploadFiles = uploadFiles;
            window.applyFilters = applyFilters;

            fetchAuditData();
        </script>
    </body>
    </html>
    """

    def build_audit_response(extra=None):
        orders = live_data['orders'] or []
        logs = live_data['logs'] or []
        users = live_data['users'] or []

        loto_v = audit_loto(orders)
        iam_v = audit_iam(logs, users)
        integ_a, blockchain = audit_integrity(orders)

        payload = {
            'loto': loto_v,
            'iam': iam_v,
            'integrity': integ_a,
            'blockchain': blockchain,
            'total_orders': len(orders),
            'loaded': {
                'orders': len(orders),
                'logs': len(logs),
                'users': len(users)
            }
        }
        if extra:
            payload.update(extra)
        return jsonify(payload)

    @app.route('/')
    def dashboard():
        return render_template_string(HTML_TEMPLATE)

    @app.route('/api/audit')
    def api_audit():
        return build_audit_response()

    @app.route('/api/reset', methods=['POST'])
    def api_reset():
        live_data['orders'] = []
        live_data['logs'] = []
        live_data['users'] = []
        live_data['filenames'] = []
        return build_audit_response()

    @app.route('/api/demo', methods=['POST'])
    def api_demo():
        live_data['orders'] = [
            {'ot_id': 'OT-001', 'equipment': 'POMPE-ACIDE-A01', 'status': 'TECO', 'loto_validation': 'NON'},
            {'ot_id': 'OT-002', 'equipment': 'COMPRESSEUR-B03', 'status': 'LANC', 'loto_validation': 'OUI'},
            {'ot_id': 'OT-003', 'equipment': 'VENTILATEUR-C12', 'status': 'TECO', 'loto_validation': 'NON'},
            {'ot_id': 'OT-004', 'equipment': 'MOTEUR-D07', 'status': 'REL', 'loto_validation': 'OUI'},
            {'ot_id': 'OT-005', 'equipment': 'CONVOYEUR-E09', 'status': 'TECO', 'loto_validation': 'OUI'}
        ]
        live_data['logs'] = [
            {'timestamp': '2026-08-01 08:15:23', 'user': 'TECH-01', 'action': 'MODIFY_COST', 'ot_id': 'OT-001'},
            {'timestamp': '2026-08-01 09:30:45', 'user': 'TECH-02', 'action': 'START_WORK', 'ot_id': 'OT-002'},
            {'timestamp': '2026-08-02 10:00:12', 'user': 'ADMIN-07', 'action': 'VALIDATE_LOTO', 'ot_id': 'OT-001'},
            {'timestamp': '2026-08-02 11:20:33', 'user': 'TECH-03', 'action': 'COMPLETE_ORDER', 'ot_id': 'OT-003'},
            {'timestamp': '2026-08-03 14:45:21', 'user': 'PREP-01', 'action': 'START_WORK', 'ot_id': 'OT-003'},
            {'timestamp': '2026-08-04 08:05:10', 'user': 'TECH-01', 'action': 'CHANGE_STATUS', 'ot_id': 'OT-005'}
        ]
        live_data['users'] = [
            {'user_id': 'TECH-01', 'role': 'TECHNICIEN'},
            {'user_id': 'TECH-02', 'role': 'TECHNICIEN'},
            {'user_id': 'TECH-03', 'role': 'TECHNICIEN'},
            {'user_id': 'ADMIN-07', 'role': 'ADMIN'},
            {'user_id': 'PREP-01', 'role': 'PREPARATEUR'}
        ]
        return build_audit_response()

    @app.route('/api/export')
    def api_export():
        orders = live_data['orders'] or []
        logs = live_data['logs'] or []
        users = live_data['users'] or []
        loto_v = audit_loto(orders)
        iam_v = audit_iam(logs, users)
        integ_a, blockchain = audit_integrity(orders)
        report = {
            'auditor': 'Youssef AZIZE (ENSA El Jadida)',
            'context': 'OCP Group - Downstream Jorf Lasfar (OIK/PD)',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_orders': len(orders),
            'summary': {
                'critical_loto': len(loto_v),
                'high_iam': len(iam_v),
                'medium_integrity': len(integ_a)
            },
            'loto_violations': loto_v,
            'iam_violations': iam_v,
            'integrity_anomalies': integ_a,
            'blockchain_ledger': blockchain
        }
        return Response(json.dumps(report, indent=2, ensure_ascii=False), mimetype='application/json', headers={'Content-Disposition': 'attachment;filename=ocpsec_audit_report.json'})

    @app.route('/api/upload', methods=['POST'])
    def api_upload():
        uploaded_files = collect_uploaded_files(request)

        if not uploaded_files:
            return jsonify({'error': 'Aucun fichier CSV reçu. Utilisez le champ multipart "files".'}), 400

        upload_meta = []
        errors = []

        for file in uploaded_files:
            if not file or not file.filename:
                continue
            if not file.filename.lower().endswith(('.csv', '.txt')):
                errors.append(f"{file.filename}: extension non supportée (CSV attendu)")
                continue

            try:
                normalized_rows = parse_csv_bytes(file.read())
                if not normalized_rows:
                    errors.append(f"{file.filename}: fichier vide ou sans en-têtes valides")
                    continue

                category = assign_csv_to_live_data(file.filename, normalized_rows, live_data)
                live_data['filenames'].append(file.filename)

                upload_meta.append({
                    'filename': file.filename,
                    'category': category,
                    'rows': len(normalized_rows)
                })
            except Exception as exc:
                errors.append(f"{file.filename}: {exc}")
                print(f"Error parsing file {file.filename}: {exc}")

        if not upload_meta and errors:
            return jsonify({'error': '; '.join(errors)}), 400

        extra = {'upload_meta': upload_meta}
        if errors:
            extra['warnings'] = errors

        return build_audit_response(extra)

    url = "http://127.0.0.1:5000"
    print(f"\n{Fore.GREEN if COLORS_AVAILABLE else ''}[+] Interactive Web Dashboard: {url}{Fore.RESET if COLORS_AVAILABLE else ''}")
    print(f"{Fore.CYAN if COLORS_AVAILABLE else ''}[*] Opening browser automatically...{Fore.RESET if COLORS_AVAILABLE else ''}\n")

    if auto_open:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()

    app.run(debug=False, host='127.0.0.1', port=5000)

# ==========================================
# 8. MAIN ENTRYPOINT
# ==========================================
def main():
    parser = argparse.ArgumentParser(description="OCPSec Agent - Cyber-Resilience Auditor for SAP PM")
    parser.add_argument('--info', action='store_true', help="Afficher les détails de l'outil et les règles appliquées")
    parser.add_argument('--demo', action='store_true', help="Générer démo CSV dans data/")
    parser.add_argument('--web', action='store_true', help="Lancer le Dashboard Web Interactif (Flask)")
    parser.add_argument('--no-browser', action='store_true', help="Ne pas ouvrir le navigateur automatiquement")
    parser.add_argument('--json', action='store_true', help="Exporter le rapport d'audit en JSON")
    parser.add_argument('--data', type=str, default='data/', help="Chemin du dossier contenant les fichiers CSV")
    args = parser.parse_args()

    print_banner()

    if args.info:
        print_info()
        return

    if args.demo:
        generate_demo_data()
        return

    if args.web:
        launch_web_dashboard(data_folder=args.data, auto_open=not args.no_browser)
        return

    orders, logs, users = load_data(args.data)
    loto_v = audit_loto(orders)
    iam_v = audit_iam(logs, users)
    integ_a, blockchain = audit_integrity(orders)

    if args.json:
        report = {
            'total_orders': len(orders),
            'summary': {
                'critical_loto': len(loto_v),
                'high_iam': len(iam_v),
                'medium_integrity': len(integ_a)
            },
            'loto_violations': loto_v,
            'iam_violations': iam_v,
            'integrity_anomalies': integ_a,
            'blockchain_ledger': blockchain
        }
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return

    print_results(loto_v, iam_v, integ_a, len(orders))

if __name__ == '__main__':
    main()
