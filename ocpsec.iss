; Script Inno Setup pour OCPSec Agent v1.0 Pro
; Auteur: Youssef AZIZE - ENSA El Jadida

[Setup]
AppName=OCPSec Agent
AppVersion=1.0 Pro
AppPublisher=Youssef AZIZE - ENSA El Jadida
AppPublisherURL=https://github.com/Yusuf-Cyber-hub/ocpsec-agent
AppSupportURL=https://github.com/Yusuf-Cyber-hub/ocpsec-agent
AppUpdatesURL=https://github.com/Yusuf-Cyber-hub/ocpsec-agent
DefaultDirName={pf}\OCPSec
DefaultGroupName=OCPSec Agent
AllowNoIcons=yes
OutputBaseFilename=ocpsec-installer
Compression=lzma2
SolidCompression=yes
ChangesEnvironment=yes
UninstallDisplayIcon={app}\ocpsec.exe
WizardStyle=modern

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"

[Tasks]
Name: "desktopicon"; Description: "Créer une icône sur le Bureau"; GroupDescription: "Icônes supplémentaires:"; Flags: unchecked

[Files]
Source: "dist\ocpsec.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{commondesktop}\OCPSec Agent"; Filename: "{app}\ocpsec.exe"; Tasks: desktopicon
Name: "{group}\OCPSec Agent"; Filename: "{app}\ocpsec.exe"
Name: "{group}\Désinstaller OCPSec"; Filename: "{uninstallexe}"

[Registry]
; Ajout automatique du dossier au PATH (sans que l'utilisateur fasse rien)
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Check: NeedsAddPath(ExpandConstant('{app}'))

[Code]
function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'Path', OrigPath)
  then begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Param + ';', ';' + OrigPath + ';') = 0;
end;

[Run]
Filename: "{app}\ocpsec.exe"; Description: "Lancer OCPSec Agent pour tester"; Flags: postinstall nowait skipifsilent unchecked