Unicode true
!include MUI2.nsh
!include LogicLib.nsh
!include x64.nsh
Name "Firaw Network · Instalador online"
OutFile "..\release\Firaw-Network-Instalador-Online.exe"
RequestExecutionLevel user
SetCompressor /SOLID lzma
Icon "..\src-tauri\icons\icon.ico"
!define MUI_ICON "..\src-tauri\icons\icon.ico"
!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE "Instalar Firaw Network"
!define MUI_WELCOMEPAGE_TEXT "Este instalador baixa a versão 0.2.1 para Windows 64 bits e confere o SHA-256 e o certificado de assinatura Firawynix antes de instalar.$\r$\n$\r$\nO certificado público .cer acompanha o programa. Na próxima tela, você pode optar por confiar no certificado Firawynix apenas neste usuário."
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_RUN "$LOCALAPPDATA\Firaw Network\FirawNetwork.exe"
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_LANGUAGE "PortugueseBR"
VIProductVersion "0.2.1.0"
VIAddVersionKey /LANG=1046 "ProductName" "Firaw Network"
VIAddVersionKey /LANG=1046 "CompanyName" "Firawynix"
VIAddVersionKey /LANG=1046 "FileDescription" "Instalador online Firaw Network"
VIAddVersionKey /LANG=1046 "FileVersion" "0.2.1"
VIAddVersionKey /LANG=1046 "LegalCopyright" "Firawynix 2026"
Section "Firaw Network (obrigatório)" Core
  SectionIn RO
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File "release.json"
  File "download-install.ps1"
  File "FirawNetwork.cer"
  File "trust-certificate.ps1"
SectionEnd
Section /o "Confiar no certificado Firawynix neste usuário" Trust
  nsExec::ExecToStack '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PLUGINSDIR\trust-certificate.ps1"'
  Pop $0
  Pop $1
  ${If} $0 != 0
    DetailPrint "Não foi possível importar o certificado. A instalação continuará com verificação de SHA-256 e identidade."
  ${EndIf}
SectionEnd
Section ""
  DetailPrint "Baixando e verificando Firaw Network..."
  nsExec::ExecToStack '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PLUGINSDIR\download-install.ps1"'
  Pop $0
  Pop $1
  ${If} $0 != 0
    IfSilent +2
    MessageBox MB_ICONSTOP "Não foi possível concluir a instalação. Detalhes em %TEMP%\FirawNetwork-install-error.txt. Confira a conexão e tente novamente."
    SetErrorLevel 1
    Abort
  ${EndIf}
  DetailPrint "Firaw Network instalado com sucesso."
SectionEnd
