#define VCRedistPath "..\assets\vcredist_x64.exe"
#if FileExists(VCRedistPath)
#define IncludeVCRedist
#endif

#define AppVer "2026.02.13-7"

[Setup]
AppId={{B8A5C2E1-7F3D-4A1B-9C6E-2D8F5A4E3B71}
AppName=PCAP Sentry
AppVersion={#AppVer}
AppVerName=PCAP Sentry {#AppVer}
VersionInfoVersion=2026.2.13.7
AppPublisher=industrial-dave
AppSupportURL=https://github.com/industrial-dave/PCAP-Sentry
DefaultDirName={autopf}\PCAP Sentry
DefaultGroupName=PCAP Sentry
OutputDir=..\dist
OutputBaseFilename=PCAP_Sentry_Setup
Compression=lzma
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
SetupIconFile=..\assets\pcap_sentry.ico
LicenseFile=..\LICENSE.txt
InfoBeforeFile=..\README.txt
UninstallDisplayIcon={app}\PCAP_Sentry.exe
UninstallDisplayName=PCAP Sentry {#AppVer}
CloseApplications=yes
RestartApplications=yes
MinVersion=10.0

[Files]
Source: "..\dist\PCAP_Sentry.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion
#ifdef IncludeVCRedist
Source: "{#VCRedistPath}"; DestDir: "{tmp}"; Flags: deleteafterinstall
#endif

[Icons]
Name: "{group}\PCAP Sentry"; Filename: "{app}\PCAP_Sentry.exe"
Name: "{commondesktop}\PCAP Sentry"; Filename: "{app}\PCAP_Sentry.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop icon"; GroupDescription: "Additional icons:"; Flags: unchecked
Name: "installollama"; Description: "Install Ollama (local LLM runtime)"; GroupDescription: "Optional LLM setup:"; Flags: unchecked

[Run]
#ifdef IncludeVCRedist
Filename: "{tmp}\vcredist_x64.exe"; Parameters: "/install /quiet /norestart"; StatusMsg: "Installing VC++ Runtime..."; Flags: waituntilterminated skipifsilent
#endif
Filename: "{app}\PCAP_Sentry.exe"; Description: "Launch PCAP Sentry"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Remove app-created subdirectories under the install directory
Type: filesandordirs; Name: "{app}\data"
Type: filesandordirs; Name: "{app}\logs"

[Code]
const
  LocalAppDataFolder = '{localappdata}\PCAP_Sentry';

var
  OllamaModelsPage: TInputOptionWizardPage;
  OllamaModelIds: array of string;

procedure AddOllamaModel(const ModelId, LabelText: String; DefaultChecked: Boolean);
var
  Index: Integer;
begin
  Index := OllamaModelsPage.Add(LabelText);
  OllamaModelsPage.Values[Index] := DefaultChecked;
  SetArrayLength(OllamaModelIds, GetArrayLength(OllamaModelIds) + 1);
  OllamaModelIds[GetArrayLength(OllamaModelIds) - 1] := ModelId;
end;

procedure InitializeWizard;
begin
  OllamaModelsPage := CreateInputOptionPage(
    wpSelectTasks,
    'Ollama Models',
    'Select models to download',
    'Choose one or more Ollama models to download after installation.' + #13#10 +
    'This may take a while and requires an internet connection.',
    True,
    False
  );

  AddOllamaModel('llama3.2', 'llama3.2 (balanced, recommended)', True);
  AddOllamaModel('qwen2.5', 'qwen2.5 (fast general-purpose)', False);
  AddOllamaModel('phi4', 'phi4 (small, fast)', False);
  AddOllamaModel('mistral', 'mistral (compact, solid general)', False);
  AddOllamaModel('llama3.1', 'llama3.1 (larger, higher quality)', False);
  AddOllamaModel('llama3:8b', 'llama3:8b (older 8B)', False);
  AddOllamaModel('qwen2.5:14b', 'qwen2.5:14b (larger)', False);
  AddOllamaModel('gemma2:9b', 'gemma2:9b (medium)', False);
  AddOllamaModel('deepseek-r1:7b', 'deepseek-r1:7b (reasoning)', False);
  AddOllamaModel('phi3.5', 'phi3.5 (small, fast)', False);
  AddOllamaModel('tinyllama', 'tinyllama (very small)', False);
  AddOllamaModel('codestral', 'codestral (code-focused)', False);
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  if (OllamaModelsPage <> nil) and (PageID = OllamaModelsPage.ID) then
  begin
    Result := not WizardIsTaskSelected('installollama');
    exit;
  end;
  Result := False;
end;

function AnyOllamaModelSelected: Boolean;
var
  I: Integer;
begin
  Result := False;
  if OllamaModelsPage = nil then
    exit;
  for I := 0 to GetArrayLength(OllamaModelIds) - 1 do
  begin
    if OllamaModelsPage.Values[I] then
    begin
      Result := True;
      exit;
    end;
  end;
end;

function GetOllamaExePath: String;
var
  Candidate: String;
begin
  Candidate := ExpandConstant('{localappdata}\Programs\Ollama\ollama.exe');
  if FileExists(Candidate) then
  begin
    Result := Candidate;
    exit;
  end;
  Candidate := ExpandConstant('{pf}\Ollama\ollama.exe');
  if FileExists(Candidate) then
  begin
    Result := Candidate;
    exit;
  end;
  Result := 'ollama.exe';
end;

function InstallOllama: Boolean;
var
  ResultCode: Integer;
  DownloadPath: String;
  DownloadCmd: String;
begin
  Result := False;

  if Exec('cmd.exe', '/c winget install -e --id Ollama.Ollama -h', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    if ResultCode = 0 then
    begin
      Result := True;
      exit;
    end;
  end;

  DownloadPath := ExpandConstant('{tmp}\OllamaSetup.exe');
  DownloadCmd := '-NoProfile -ExecutionPolicy Bypass -Command "' +
    '$p = ''' + DownloadPath + '''; ' +
    'Invoke-WebRequest -Uri https://ollama.com/download/OllamaSetup.exe -OutFile $p"';

  if Exec('powershell.exe', DownloadCmd, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    if ResultCode = 0 then
    begin
      if Exec(DownloadPath, '/S', '', SW_SHOW, ewWaitUntilTerminated, ResultCode) then
      begin
        if ResultCode = 0 then
        begin
          Result := True;
          exit;
        end;
      end;
    end;
  end;
end;

procedure PullOllamaModels;
var
  I: Integer;
  OllamaExe: String;
  ResultCode: Integer;
begin
  if not AnyOllamaModelSelected then
    exit;

  OllamaExe := GetOllamaExePath;
  for I := 0 to GetArrayLength(OllamaModelIds) - 1 do
  begin
    if OllamaModelsPage.Values[I] then
    begin
      Exec(OllamaExe, 'pull ' + OllamaModelIds[I], '', SW_SHOW, ewWaitUntilTerminated, ResultCode);
    end;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  KeepKB: Integer;
  LocalDir, KBFile, KBBackupDir: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    LocalDir := ExpandConstant(LocalAppDataFolder);

    { Check if knowledge base exists }
    KBFile := LocalDir + '\pcap_knowledge_base_offline.json';
    KBBackupDir := LocalDir + '\kb_backups';

    if FileExists(KBFile) or DirExists(KBBackupDir) then
    begin
      KeepKB := MsgBox(
        'Do you want to keep your trained Knowledge Base data?' + #13#10 + #13#10 +
        'If you plan to reinstall later, choosing Yes will preserve ' +
        'your training data so you do not have to retrain.' + #13#10 + #13#10 +
        'Choose No to remove ALL application data.',
        mbConfirmation, MB_YESNO);

      if KeepKB = IDYES then
      begin
        { Delete everything EXCEPT the knowledge base and its backups }
        DeleteFile(LocalDir + '\settings.json');
        DeleteFile(LocalDir + '\pcap_local_model.joblib');
        DeleteFile(LocalDir + '\startup_errors.log');
        DeleteFile(LocalDir + '\app_errors.log');
        { Remove update staging area }
        DelTree(LocalDir + '\updates', True, True, True);
        { Leave pcap_knowledge_base_offline.json and kb_backups\ intact }
      end
      else
      begin
        { Remove everything }
        DelTree(LocalDir, True, True, True);
      end;
    end
    else
    begin
      { No knowledge base found - clean up everything silently }
      DelTree(LocalDir, True, True, True);
    end;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  OllamaInstalled: Boolean;
begin
  if CurStep = ssPostInstall then
  begin
    if WizardIsTaskSelected('installollama') then
    begin
      OllamaInstalled := InstallOllama;
      if not OllamaInstalled then
      begin
        MsgBox('Ollama installation failed. You can install it later from https://ollama.com.', mbError, MB_OK);
        exit;
      end;
      PullOllamaModels;
    end;
  end;
end;
