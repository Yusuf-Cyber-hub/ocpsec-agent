#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OCPSec Agent v1.0 - Downstream Security Auditor for SAP PM
Author: Youssef AZIZE | ENSA El Jadida
License: MIT
GitHub: https://github.com/Yusuf-Cyber-hub/ocpsec-agent
"""

import sys
import os
import argparse
import csv
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
# 2. BANNIÈRE MODERNE (Style Simple)
# ==========================================
def print_banner():
    """Affiche une bannière épurée"""
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
  ║  {Fore.GREEN if COLORS_AVAILABLE else ''}v1.0{Fore.CYAN if COLORS_AVAILABLE else ''}  Downstream Security Auditor for SAP PM{Fore.RESET if COLORS_AVAILABLE else ''}        ║
  ║  {Fore.YELLOW if COLORS_AVAILABLE else ''}Author: Youssef AZIZE | ENSA El Jadida{Fore.RESET if COLORS_AVAILABLE else ''}            ║
  ║  {Style.DIM if COLORS_AVAILABLE else ''}License: MIT | GitHub: https://github.com/Yusuf-Cyber-hub/ocpsec-agent{Fore.RESET if COLORS_AVAILABLE else ''}║
  ║                                                              ║
  ╚══════════════════════════════════════════════════════════════╝
{Fore.GREEN if COLORS_AVAILABLE else ''}[+] Ready. Type --help for usage.{Fore.RESET if COLORS_AVAILABLE else ''}
"""
    print(banner)

# ==========================================
# 3. GÉNÉRATION DE DONNÉES FICTIVES (--demo)
# ==========================================
def generate_demo_data():
    """Génère des fichiers CSV fictifs pour tester l'outil sans SAP"""
    
    print(f"{Fore.CYAN if COLORS_AVAILABLE else ''}[*] Generating demo data...{Fore.RESET if COLORS_AVAILABLE else ''}")
    
    # Créer le dossier data/ si nécessaire
    os.makedirs('data', exist_ok=True)
    
    # ----- 1. orders.csv (Ordres de Travail) -----
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
    
    # ----- 2. logs.csv (Logs utilisateur) -----
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
    
    # ----- 3. users.csv (Utilisateurs) -----
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
    print(f"{Fore.CYAN if COLORS_AVAILABLE else ''}[*] Files: orders.csv, logs.csv, users.csv{Fore.RESET if COLORS_AVAILABLE else ''}")

# ==========================================
# 4. MAIN (Point d'entrée + Arguments)
# ==========================================
def main():
    # ---------- Configuration des arguments ----------
    parser = argparse.ArgumentParser(
        description="OCPSec Agent - Security Auditor for SAP PM Work Orders",
        epilog="Example: python ocpsec_agent.py --demo"
    )
    
    parser.add_argument(
        '--demo',
        action='store_true',
        help='Generate demo CSV files in data/ folder (no SAP required)'
    )
    
    parser.add_argument(
        '--web',
        action='store_true',
        help='Launch Web Dashboard (requires Flask)'
    )
    
    parser.add_argument(
        '--json',
        action='store_true',
        help='Export results to JSON file'
    )
    
    parser.add_argument(
        '--data',
        type=str,
        default='data/',
        help='Path to folder containing CSV files (default: data/)'
    )
    
    args = parser.parse_args()
    
    # ---------- Afficher la bannière ----------
    print_banner()
    
    # ---------- Mode --demo ----------
    if args.demo:
        generate_demo_data()
        print(f"{Fore.GREEN if COLORS_AVAILABLE else ''}[+] Demo data ready. Run without --demo to audit.{Fore.RESET if COLORS_AVAILABLE else ''}")
        return
    
    # ---------- Mode --web (à implémenter à l'étape suivante) ----------
    if args.web:
        print(f"{Fore.YELLOW if COLORS_AVAILABLE else ''}[!] Web mode coming soon (Step 4)...{Fore.RESET if COLORS_AVAILABLE else ''}")
        return
    
    # ---------- Mode normal (audit) ----------
    print(f"{Fore.CYAN if COLORS_AVAILABLE else ''}[*] Loading data from: {args.data}{Fore.RESET if COLORS_AVAILABLE else ''}")
    print(f"{Fore.YELLOW if COLORS_AVAILABLE else ''}[!] Audit engine coming soon (Step 3)...{Fore.RESET if COLORS_AVAILABLE else ''}")

if __name__ == '__main__':
    main()