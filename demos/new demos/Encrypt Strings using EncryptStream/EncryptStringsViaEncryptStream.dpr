program EncryptStringsViaEncryptStream;

uses
  Forms,
  SysUtils,
  ShellAPI,
  windows,
  uMain in 'uMain.pas' {frmMain},
  UnitUtilitaires in 'UnitUtilitaires.pas';

{$R *.res}

begin
       
  Application.Initialize;
  Application.CreateForm(TfrmMain, frmMain);
  Application.Run;
end.
