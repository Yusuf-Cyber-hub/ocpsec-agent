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
L'outil est maintenant accessible de n'importe où. Pour les développeurs (exploration / modification) :

   ```bash
# Cloner le dépôt
git clone [https://github.com/Yusuf-Cyber-hub/ocpsec.git](https://github.com/Yusuf-Cyber-hub/ocpsec.git)
cd ocpsec

# Installer les dépendances
pip install -r requirements.txt

# Lancer le script principal
python ocpsec_agent.py --help
🚀 Utilisation (Commandes Principales)CommandeDescriptionocpsec --infoAffiche la description de l'outil et les 3 règles d'audit.ocpsec --demoGénère des données fictives dans data/ pour tester sans SAP.ocpsecExécute l'audit CLI sur les fichiers data/*.csv.ocpsec --jsonExécute l'audit et affiche le rapport en JSON (stdout).ocpsec --webLance le dashboard web (ouvre automatiquement le navigateur).ocpsec --web --no-browserLance le serveur web sans ouvrir le navigateur.ocpsec --data /chemin/Charge les CSV depuis un dossier personnalisé.ocpsec --json --data /chemin/Combine les deux exemples.💻 Exemple (Admin SAP)Bash# Export SAP -> dossier C:\audit_ocp
ocpsec --data C:\audit_ocp --json > rapport.json
📊 Dashboard Web (Interactif)Lancé avec ocpsec --web, il offre :Glisser-déposer de 3 fichiers CSV (ordres, logs, utilisateurs).Détection automatique des colonnes (pas de KeyError).KPI : compteurs LOTO, IAM, Intégrité.Graphique circulaire des violations.Recherche en temps réel (OT, équipement, utilisateur).Filtre par règle (R-01, R-02, R-03).Export JSON du rapport d'audit.Impression avec styles adaptés au papier.📂 Structure du dépôtPlaintextocpsec/
├── ocpsec_agent.py      # Code source principal
├── requirements.txt     # Dépendances (Flask, Colorama)
├── ocpsec.iss           # Script Inno Setup (installateur)
├── ocpsec.bat           # Lanceur batch (optionnel)
├── data/                # Dossier des CSV (généré automatiquement)
├── dist/                # Exécutable généré par PyInstaller
├── Output/              # Installateur généré par Inno Setup
└── README.md            # Ce fichier
🛠️ Technologies utiliséesÉlémentTechnologieLangagePython 3.xInterface CLIColorama + ArgparseDashboard WebFlask + Chart.js + Tailwind CSSExportJSON / TXTInstallateur WindowsInno SetupExécutable autonomePyInstallerMapping des colonnesRegex (AutoSchemaMapper)
⚠️ Disclaimer (Avertissement)Ce logiciel est fourni à des fins éducatives et d'audit interne.Il ne doit en aucun cas être utilisé pour des activités illégales, malveillantes ou sans autorisation explicite du propriétaire du système audité. L'auteur décline toute responsabilité en cas d'usage inapproprié ou de dommages causés par l'utilisation de cet outil.
📜 LicenceMIT License — Voir le fichier LICENSE pour plus de détails.
🙏 Remerciements OCP S.A. (Site Jorf Lasfar) pour l'accueil et le contexte industriel.Mme Jihad MAKHLOUF pour son encadrement et sa confiance.L'ENSA El Jadida pour la formation en cybersécurité.
📧 ContactAuteur : Youssef AZIZE
Email : azize.youssef.05.@gmail.com
GitHub : Yusuf-Cyber-hub
LinkedIn : Youssef AZIZE
