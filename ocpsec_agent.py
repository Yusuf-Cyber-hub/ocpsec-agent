#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OCPSec Agent v1.0 - Downstream Security Auditor for SAP PM
Author: Youssef AZIZE | ENSA El Jadida
License: MIT
GitHub: https://github.com/yourusername/ocpsec-agent
"""

import sys
import os

# ==========================================
# 1. GESTION DES COULEURS (Windows + Linux)
# ==========================================
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)  # Active les couleurs sous Windows
    COLORS_AVAILABLE = True
except ImportError:
    # Fallback si colorama n'est pas installé
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
  ║  {Style.DIM if COLORS_AVAILABLE else ''}License: MIT | GitHub: https://github.com/Yusuf-Cyber-hub{Fore.RESET if COLORS_AVAILABLE else ''}║
  ║                                                              ║
  ╚══════════════════════════════════════════════════════════════╝
{Fore.GREEN if COLORS_AVAILABLE else ''}[+] Ready. Type --help for usage.{Fore.RESET if COLORS_AVAILABLE else ''}
"""
    print(banner)

# ==========================================
# 3. MAIN (Point d'entrée)
# ==========================================
def main():
    print_banner()
    
    # Afficher un message simple
    print(f"{Fore.CYAN if COLORS_AVAILABLE else ''}[*] OCPSec Agent initialized successfully.{Fore.RESET if COLORS_AVAILABLE else ''}")

if __name__ == '__main__':
    main()