# 🔐 OCPSec Agent v1.0 Pro

**Auditeur Cyber-Résilience pour SAP PM**  
*Auteur: Youssef AZIZE | ENSA El Jadida*  
*Contexte: OCP Group (Jorf Lasfar) - Service OIK/PD*

---

## 📌 Description

`OCPSec Agent` est un outil d'audit automatique conçu pour renforcer la **cyber‑résilience** du processus de maintenance **Downstream** sur **SAP PM**. Il détecte en quelques secondes trois familles de risques critiques :

| Règle | Description | Sévérité |
|-------|-------------|----------|
| **R‑01** | Consignation LOTO manquante sur les OT en statut `LANC` / `TECO` – Sécurité physique des intervenants | **CRITICAL** |
| **R‑02** | Violations de la Ségrégation des Tâches (SoD) et abus de privilèges IAM (ex : modification de coûts par un technicien) | **HIGH** |
| **R‑03** | Anomalies d’intégrité (doublons d’OT, statuts invalides) et traçabilité cryptographique SHA‑256 (blockchain légère) | **MEDIUM** |

L’outil s’appuie sur des **exports CSV** depuis SAP (transactions `SE16N`, `SM20`, `SUIM`) et normalise automatiquement les noms de colonnes grâce à un **moteur de mapping dynamique** (`AutoSchemaMapper`).

Il propose deux interfaces :
- **CLI** : terminal coloré style `nmap` pour les administrateurs système.
- **Dashboard Web** interactif avec glisser‑déposer, graphiques et export de rapport.

---

## 🚀 Installation

### Pour l’utilisateur final (recommandé)

1. Téléchargez l’installateur `ocpsec-installer.exe` depuis la section [Releases](https://github.com/Yusuf-Cyber-hub/ocpsec/releases).
2. Double‑cliquez et suivez les étapes (Suivant → Suivant → Installer → Terminer).
3. Ouvrez un terminal (PowerShell ou CMD) et tapez :
   ```bash
   ocpsec --help
L’outil est maintenant accessible de n’importe où.
Pour les développeurs (exploration / modification)
code
Bash
git clone https://github.com/Yusuf-Cyber-hub/ocpsec.git
cd ocpsec
pip install -r requirements.txt
python ocpsec_agent.py --help
🧪 Utilisation (commandes principales)
Commande	Description
ocpsec --info	Affiche la description de l’outil et les 3 règles d’audit
ocpsec --demo	Génère des données fictives dans data/ pour tester sans SAP
ocpsec	Exécute l’audit CLI sur les fichiers data/*.csv
ocpsec --json	Exécute l’audit et affiche le rapport en JSON (stdout)
ocpsec --web	Lance le dashboard web (ouvre automatiquement le navigateur)
ocpsec --web --no-browser	Lance le serveur web sans ouvrir le navigateur
ocpsec --data /chemin/	Charge les CSV depuis un dossier personnalisé
ocpsec --json --data /chemin/	Combine les deux
Exemple (admin SAP) :
code
Bash
# Export SAP → dossier C:\audit_ocp
ocpsec --data C:\audit_ocp --json > rapport.json
📊 Dashboard Web (interactif)
Lancé avec ocpsec --web, il offre :
Glisser‑déposer de 3 fichiers CSV (ordres, logs, utilisateurs).
Détection automatique des colonnes (pas de KeyError).
KPI : compteurs LOTO, IAM, Intégrité.
Graphique circulaire des violations.
Recherche en temps réel (OT, équipement, utilisateur).
Filtre par règle (R‑01, R‑02, R‑03).
Export JSON du rapport d’audit.
Impression avec styles adaptés au papier.
📁 Structure du dépôt
code
Code
ocpsec/
├── ocpsec_agent.py          # Code source principal
├── requirements.txt         # Dépendances (Flask, Colorama)
├── ocpsec.iss               # Script Inno Setup (installateur)
├── ocpsec.bat               # Lanceur batch (optionnel)
├── data/                    # Dossier des CSV (généré automatiquement)
├── dist/                    # Exécutable généré par PyInstaller
├── Output/                  # Installateur généré par Inno Setup
└── README.md                # Ce fichier
🛠️ Technologies utilisées
Élément	Technologie
Langage	Python 3.x
Interface CLI	Colorama + Argparse
Dashboard Web	Flask + Chart.js + Tailwind CSS
Export	JSON / TXT
Installateur Windows	Inno Setup
Exécutable autonome	PyInstaller
Mapping des colonnes	Regex (AutoSchemaMapper)
⚠️ Disclaimer (Avertissement)
Ce logiciel est fourni à des fins éducatives et d’audit interne.
Il ne doit en aucun cas être utilisé pour des activités illégales, malveillantes ou sans autorisation explicite du propriétaire du système audité. L’auteur décline toute responsabilité en cas d’usage inapproprié ou de dommages causés par l’utilisation de cet outil.
L’outil est distribué sous licence MIT, sans garantie d’aucune sorte.
📄 Licence
MIT License – Voir le fichier LICENSE pour plus de détails.
🙏 Remerciements
OCP S.A. (Site Jorf Lasfar) pour l’accueil et le contexte industriel.
Mme Jihad MAKHLOUF pour son encadrement et sa confiance.
L’ENSA El Jadida pour la formation en cybersécurité.
📬 Contact
Auteur : Youssef AZIZE
Email : youssef.azize@ensaj.ucd.ac.ma
GitHub : Yusuf-Cyber-hub
LinkedIn : Youssef AZIZE
code
Code
---

### 💡 Khidmat li drna f l-Application Web :
1. **Dashboard Cyber-Résilience** : Visualisation en direct dyal les 3 règles (R-01 LOTO, R-02 SoD/IAM, R-03 Intégrité & SHA-256).
2. **Console CLI interactive** : Mode terminal coloré (`nmap` style) li kaysimuler les commandes `ocpsec --info`, `--demo`, `--json`, `--web`.
3. **Onglet README.md** : Kayn onglet dédié f l'interface fih had le README li m'affiché mni'm w fih bouton **"Copier README.md en 1-Clic"** bch t-téléchargih wla tcopih de manière instantanée.