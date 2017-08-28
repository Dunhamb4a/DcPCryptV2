{******************************************************************************}
{* DCPcrypt v2.0 written by David Barton (crypto@cityinthesky.co.uk) **********}
{******************************************************************************}
{* A file encryption/decryption demo with Thread*******************************}
{******************************************************************************}
{* Copyright (c) 2003 David Barton                                            *}
{* Permission is hereby granted, free of charge, to any person obtaining a    *}
{* copy of this software and associated documentation files (the "Software"), *}
{* to deal in the Software without restriction, including without limitation  *}
{* the rights to use, copy, modify, merge, publish, distribute, sublicense,   *}
{* and/or sell copies of the Software, and to permit persons to whom the      *}
{* Software is furnished to do so, subject to the following conditions:       *}
{*                                                                            *}
{* The above copyright notice and this permission notice shall be included in *}
{* all copies or substantial portions of the Software.                        *}
{*                                                                            *}
{* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR *}
{* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,   *}
{* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL    *}
{* THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER *}
{* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING    *}
{* FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER        *}
{* DEALINGS IN THE SOFTWARE.                                                  *}
{******************************************************************************}
{*                                                                            *}
{* This isn't the most well written of demos but it should be relatively      *}
{* informative. Any problems, queries, (bugs?) feel free to email me at the   *}
{* above address (I may not reply depending on my workload at the time, but I *}
{* will do my best).                                                          *}
{*                               Dave.                                        *}
{*                                                                            *}
{* Note: this program does not store the cipher or hash used to encrypt the   *}
{* original file and so you will need to note this yourself. Also it will     *}
{* happily decrypt with the wrong cipher/hash/passphrase and give you utter   *}
{* garbage out :-)                                                            *}
{*                                                                            *}
{******************************************************************************}
unit uMain;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, DCPtiger, DCPsha512, DCPsha256, DCPsha1, DCPripemd160,
  DCPripemd128, DCPmd5, DCPmd4, DCPcrypt2, DCPhaval, DCPtwofish, DCPtea,
  DCPserpent, DCPblockciphers, DCPrijndael, DCPrc4, DCPrc2, DCPice, DCPdes,
  DCPcast128, DCPblowfish, StdCtrls, Buttons, SHFolder,ShlObj,System.IOUtils,
  UnitUtilitaires, Vcl.ComCtrls, Vcl.ImgList,ShellAPI;

type
TProgressEvent=procedure(Sender:TObject;progress:integer)of object;
 { Thread  }
  TThreadTaf = class(TThread)
  private
    { Déclarations privées }
    _Hash: TDCP_hash;
    _Cipher: TDCP_cipher;
    _passphrase,_inputfile,_outputfile:string;
    _success:boolean;
    _ModeEncrypt:boolean;
    FOnProgress:TProgressEvent;
    _btnEncrypWasEnabled,_btnDecryptWasEnabled:boolean;
  protected
    constructor Create(CreateSuspended: Boolean);
    destructor Destroy; override;
    procedure Execute; override;
    procedure DoEncrypt;
    procedure DoDecrypt ;
    procedure ReActiveControles();
    procedure CancelAllOperations();
    procedure EndingMessageEncryption();
    procedure EndingMessageDecryption();

  public
    property OnProgress: TProgressEvent read FOnProgress write FOnProgress;
    property btnEncrypWasEnabled:boolean read _btnEncrypWasEnabled write _btnEncrypWasEnabled;
    property btnDecryptWasEnabled:boolean read _btnDecryptWasEnabled write _btnDecryptWasEnabled;
    property ModeEncrypt: boolean read _ModeEncrypt write _ModeEncrypt;
    Property Hash: TDCP_hash read _Hash write _Hash;
    Property Cipher: TDCP_cipher read _Cipher write _Cipher;
    Property passphrase: string read _passphrase write _passphrase;
    Property inputfile:string read _inputfile write _inputfile;
    Property outputfile:string read _outputfile write _outputfile;
    procedure Pourcentage(sender:Tobject;value:integer);

  end;

  TfrmMain = class(TForm)
    grpInput: TGroupBox;
    boxInputFile: TEdit;
    btnInputBrowse: TSpeedButton;
    lblInputFileSize: TLabel;
    dblInputFileSize: TLabel;
    grpOutput: TGroupBox;
    boxOutputFile: TEdit;
    btnOutputBrowse: TSpeedButton;
    grpOptions: TGroupBox;
    cbxCipher: TComboBox;
    lblCipher: TLabel;
    lblHash: TLabel;
    cbxHash: TComboBox;
    lblKeySize: TLabel;
    dblKeySize: TLabel;
    boxPassphrase: TEdit;
    lblPassphrase: TLabel;
    boxConfirmPassphrase: TEdit;
    lblConfirmPassphrase: TLabel;
    DCP_blowfish1: TDCP_blowfish;
    DCP_cast1281: TDCP_cast128;
    DCP_des1: TDCP_des;
    DCP_3des1: TDCP_3des;
    DCP_ice1: TDCP_ice;
    DCP_thinice1: TDCP_thinice;
    DCP_ice21: TDCP_ice2;
    DCP_rc21: TDCP_rc2;
    DCP_rc41: TDCP_rc4;
    DCP_rijndael1: TDCP_rijndael;
    DCP_serpent1: TDCP_serpent;
    DCP_tea1: TDCP_tea;
    DCP_twofish1: TDCP_twofish;
    DCP_haval1: TDCP_haval;
    DCP_md41: TDCP_md4;
    DCP_md51: TDCP_md5;
    DCP_ripemd1281: TDCP_ripemd128;
    DCP_ripemd1601: TDCP_ripemd160;
    DCP_sha11: TDCP_sha1;
    DCP_sha2561: TDCP_sha256;
    DCP_sha3841: TDCP_sha384;
    DCP_sha5121: TDCP_sha512;
    DCP_tiger1: TDCP_tiger;
    dlgInput: TOpenDialog;
    dlgOutput: TSaveDialog;
    Progress: TProgressBar;
    btnEncrypt: TSpeedButton;
    btnDecrypt: TSpeedButton;
    btnClose: TSpeedButton;
    procedure FormCreate(Sender: TObject);
    procedure boxInputFileExit(Sender: TObject);
    procedure btnInputBrowseClick(Sender: TObject);
    procedure btnOutputBrowseClick(Sender: TObject);
    procedure cbxCipherChange(Sender: TObject);
    procedure boxPassphraseChange(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: Boolean);
    procedure Pourcentage(sender:Tobject;value:integer);
    procedure btnEncryptClick(Sender: TObject);
    procedure btnDecryptClick(Sender: TObject);
    procedure btnCloseClick(Sender: TObject);
  private
    { Private declarations }
    bDec,bEnc:boolean;
    CurrentDir:string;
    procedure DisableForm;
    procedure DisableControls;
    procedure AppMessage(var Msg: Tmsg; var Handled: Boolean);
    function DoEncryptFile(infile,outfile,passphrase:String;
                        Hash: TDCP_hash;Cipher: TDCP_cipher):Boolean;

    function DoDecryptFile(infile,outfile,passphrase:String;
                        Hash: TDCP_hash;Cipher: TDCP_cipher):Boolean;
  public
    { Public declarations }
  end;

var
  frmMain: TfrmMain;
  ThreadRunning: boolean;
  ThreadTaf: TThreadTaf;
implementation

{$R *.dfm}

procedure TfrmMain.DisableForm;
begin
  grpInput.Enabled:= false;
  grpOutput.Enabled:= false;
  grpOptions.Enabled:= false;
  btnEncrypt.Enabled:= false;
  btnDecrypt.Enabled:= false;
end;
procedure TfrmMain.DisableControls;
begin
boxInputFile.Enabled:=False;
boxOutputFile.Enabled:=False;
cbxCipher.Enabled:=False;
cbxHash.Enabled:=False;
boxPassphrase.Enabled:=False;
boxConfirmPassphrase.Enabled:=False;
btnInputBrowse.Enabled:=False;
btnOutputBrowse.Enabled:=False;
btnEncrypt.Enabled:=False;
btnDecrypt.Enabled:=False;
end;
procedure TfrmMain.FormCloseQuery(Sender: TObject; var CanClose: Boolean);
begin
if ThreadRunning then
   if MessageDlg('application is working ! Are you sure you want to quit ?', mtConfirmation, [mbYes, mbNo], 0) = mrYes then
   begin
      ThreadTaf.CancelAllOperations ;
      Repeat
         Application.ProcessMessages;
      Until (not ThreadRunning) ;
   end
   else
   begin
       CanClose:=not ThreadRunning;
   end;

end;
procedure TfrmMain.Pourcentage(sender:Tobject;value:integer);
begin
 if value<=100 then
    if value>=0 then
      progress.position:=value;
end;

procedure TfrmMain.AppMessage(var Msg: Tmsg; var Handled: Boolean);
const
   BufferLength : DWORD = 511;
var
   xPoint            : TPoint;
   DroppedFilename   : string;
   FileIndex         : DWORD;
   NumDroppedFiles   : DWORD;
   pDroppedFilename  : array [0..511] of Char;
 Stream : TStream;
 Ext,dest:string;
begin

   if Msg.message = WM_DROPFILES then
   begin


     FileIndex := $FFFFFFFF;
     DragQueryPoint(Msg.wParam, xPoint);
     NumDroppedFiles := DragQueryFile(Msg.WParam, FileIndex,
                                      pDroppedFilename, BufferLength);

     Case FindVCLWindow(ClientToScreen(xPoint)).Tag of

      1: begin // TEdit
          DragQueryFile(Msg.WParam, 0, pDroppedFilename, BufferLength);

          CurrentDir:=ExtractFilePath(StrPas(pDroppedFilename));
          boxInputFile.Text := StrPas(pDroppedFilename);

          boxInputFile.OnExit(boxInputFile);
          dest:=boxInputFile.Text;
          Ext:=AnsiLowerCase(ExtractFileExt(dest));
          dest:=ChangeFileExt(dest,'');
          dest:=dest+'_NEW';
          dest:=dest+Ext;
          boxoutputfile.Text:=dest;
          bEnc:=false;bDec:=false;
          boxPassphrase.Text:='';
          boxConfirmPassphrase.Text:='';
        end;

     end; // Case
     DragFinish(Msg.WParam);
     Handled := true;
   end;
end;

procedure TfrmMain.FormCreate(Sender: TObject);
var
  i: integer;Ext,dest:string;
begin
        if ParamStr(1) <> '' then
        begin

          if FileExists(ParamStr(1)) then
            begin
            boxinputfile.Text:=ParamStr(1);
            dest:=ParamStr(1);
            Ext:=AnsiLowerCase(ExtractFileExt(dest));
            dest:=ChangeFileExt(dest,'');

            if ParamStr(2)='/decrypt' then
            begin
               btnEncrypt.Enabled:=false;bDec:=true;
               dest:=dest+'_Decrypted';
            end
            else
            begin
               btnDecrypt.Enabled:=false;bEnc:=true;
               dest:=dest+'_Encrypted';
            end;
            dest:=dest+Ext;
            boxoutputfile.Text:=dest;
          end;
        end;
          DragAcceptFiles(frmMain.Handle, true);
          Application.OnMessage := AppMessage;
  Randomize;
  //ClientWidth:= 296;
  //ClientHeight:= 440;
  //MessageDlg('This is a file encryption demo using the DCPcrypt component set.'+#13+'For more information see http://www.cityinthesky.co.uk/cryptography.html',mtInformation,[mbOK],0);
  // iterate through all the components and find the ciphers/hashes
  for i := 0 to (ComponentCount - 1) do
  begin
    if (Components[i] is TDCP_cipher) then
      cbxCipher.Items.AddObject(TDCP_cipher(Components[i]).Algorithm,Components[i])
    else if (Components[i] is TDCP_hash) then
      cbxHash.Items.AddObject(TDCP_hash(Components[i]).Algorithm,Components[i]);
  end;
  if (cbxCipher.Items.Count = 0) then
  begin
    MessageDlg('No ciphers were found',mtError,[mbOK],0);
    DisableForm;
  end
  else
  begin
    cbxCipher.ItemIndex := 0;
    if (cbxHash.Items.Count = 0) then
    begin
      MessageDlg('No hashes were found',mtError,[mbOK],0);
      DisableForm;
    end
    else
    begin
      cbxHash.ItemIndex := 0;
      cbxCipher.OnChange(cbxCipher);
    end;
  end;
end;

// Add commas into a numerical string (e.g. 12345678 becomes 12,345,678)
// Not the best way but I can't find the code I wrote last time...
function AddCommas(const S: string): string;
var
  i, j: integer;
begin
  i := Length(S) mod 3;
  if ((i <> 0) and (Length(S) > 3)) then
    Result := Copy(S,1,i) + ',';
  for j := 0 to ((Length(S) div 3) - 2) do
    Result := Result + Copy(S,1 + i + j*3,3) + ',';
  if (Length(S) > 3) then
    Result := Result + Copy(S,Length(S) - 2,3)
  else
    Result := S;
end;

procedure TfrmMain.boxInputFileExit(Sender: TObject);
var
  strmInput: TFileStream;
begin
  if (boxInputFile.Text = '') then
    dblInputFileSize.Caption := 'no file specified'
  else if FileExists(boxInputFile.Text) then
  begin
    // If the file exists then see how big it is
    strmInput := nil;
    try
      strmInput := TFileStream.Create(boxInputFile.Text,fmOpenRead);
      dblInputFileSize.Caption := AddCommas(IntToStr(strmInput.Size)) + ' bytes';
      strmInput.Free;
    except
      strmInput.Free;
      dblInputFileSize.Caption := 'unable to open file';
    end;
  end
  else
    dblInputFileSize.Caption := 'file does not exist';
end;

procedure TfrmMain.btnInputBrowseClick(Sender: TObject);
var
  openDialog : TOpenDialog;    // Open dialog variable
begin
  openDialog := TOpenDialog.Create(self);
  openDialog.InitialDir := CurrentDir;
  openDialog.Filter:='All Files (*.*) |*.*';
  if openDialog.Execute
  then
  begin
    CurrentDir:=ExtractFilePath(openDialog.Files[0]);
    boxInputFile.Text := openDialog.FileName;
    boxInputFile.OnExit(boxInputFile);
    bEnc:=false;bDec:=false;boxoutputfile.Text:='';
    boxPassphrase.Text:='';
    boxConfirmPassphrase.Text:='';
    btnEncrypt.Enabled:=false;
    btnDecrypt.Enabled:=false;
  end;

  openDialog.Free;
end;

procedure TfrmMain.btnOutputBrowseClick(Sender: TObject);
var
  openDialog : TSaveDialog;    // Open dialog variable
begin
  openDialog := TSaveDialog.Create(self);
  openDialog.InitialDir := CurrentDir;
  openDialog.Filter:='All Files (*.*) |*.*';
  if openDialog.Execute
  then
  begin
    boxOutputFile.Text := openDialog.FileName;
  end;

  openDialog.Free;
end;
procedure TfrmMain.cbxCipherChange(Sender: TObject);
var
  Cipher: TDCP_cipher;
  Hash: TDCP_hash;
begin
  // Set the effective keysize to be the minimum of the hash size and the max key size
  // i.e. if the max key size is sufficiently large then use the entire hash as the
  //  key, other wise truncate the hash
  Cipher := TDCP_cipher(cbxCipher.Items.Objects[cbxCipher.ItemIndex]);
  Hash := TDCP_hash(cbxHash.Items.Objects[cbxHash.ItemIndex]);
  if (Cipher.MaxKeySize < Hash.HashSize) then
    dblKeySize.Caption := IntToStr(Cipher.MaxKeySize) + ' bits'
  else
    dblKeySize.Caption := IntToStr(Hash.HashSize) + ' bits'
end;

procedure TfrmMain.boxPassphraseChange(Sender: TObject);
begin
  if (Length(boxPassphrase.Text) > 0) then
  begin
    if not BEnc then btnDecrypt.Enabled := true;


    if (boxPassphrase.Text = boxConfirmPassphrase.Text) then
      if not bDec then btnEncrypt.Enabled := true
    else
      btnEncrypt.Enabled := false;
  end
  else
    btnDecrypt.Enabled := false;
end;

function Min(a, b: integer): integer;
begin
  if (a < b) then
    Result := a
  else
    Result := b;
end;


function TfrmMain.DoEncryptFile(infile,outfile,passphrase:String;
                        Hash: TDCP_hash;Cipher: TDCP_cipher):Boolean;
begin
  result := true;
if ThreadRunning then exit;
  ThreadRunning := true;
  ThreadTaf := TThreadTaf.Create(true);
  ThreadTaf.ModeEncrypt :=true;
  ThreadTaf.passphrase :=passphrase;
  ThreadTaf.inputfile:=infile;
  ThreadTaf.outputfile:=outfile;
  ThreadTaf.Hash:=Hash;
  ThreadTaf.Cipher:=Cipher;
  ThreadTaf.OnProgress:=pourcentage;
  ThreadTaf.btnEncrypWasEnabled :=btnencrypt.Enabled;
  ThreadTaf.btnDecryptWasEnabled:=btndecrypt.Enabled;
  DisableControls;
    ThreadTaf.Resume;
end;

function TfrmMain.DoDecryptFile(infile,outfile,passphrase:String;
                        Hash: TDCP_hash;Cipher: TDCP_cipher):Boolean;
begin

  result := true;
if ThreadRunning then exit;
  ThreadRunning := true;
  ThreadTaf := TThreadTaf.Create(true);
  ThreadTaf.ModeEncrypt :=False;
  ThreadTaf.passphrase :=passphrase;
  ThreadTaf.inputfile:=infile;
  ThreadTaf.outputfile:=outfile;
  ThreadTaf.Hash:=Hash;
  ThreadTaf.Cipher:=Cipher;
  ThreadTaf.OnProgress:=pourcentage;
  ThreadTaf.btnEncrypWasEnabled :=btnencrypt.Enabled;
  ThreadTaf.btnDecryptWasEnabled:=btndecrypt.Enabled;
  DisableControls;
    ThreadTaf.Resume;
end;

procedure TfrmMain.btnEncryptClick(Sender: TObject);
var
  Hash: TDCP_hash;             // the hash to use
  Cipher: TDCP_cipher;         // the cipher to use
begin
if ThreadRunning then exit;
  if not FileExists(boxinputFile.Text) then
     begin MessageDlg('Input filename doesn''t exists !',mtConfirmation,[mbOK],0);exit;end;
  if not IsValidFilename(boxoutputFile.text)  then
     begin  MessageDlg('Output filename is not valid !',mtConfirmation,[mbOK],0);exit;end;
  if  (trim(boxinputFile.text)=trim(boxoutputFile.text))  then
     begin MessageDlg('Output filename: Please choose a different name',mtConfirmation,[mbOK],0);exit;end;
  if FileExists(boxOutputFile.Text) then
    if (MessageDlg('Output file already exists. Overwrite?',mtConfirmation,mbYesNoCancel,0) <> mrYes) then
      Exit;

  Hash := TDCP_hash(cbxHash.Items.Objects[cbxHash.ItemIndex]);
  Cipher := TDCP_cipher(cbxCipher.Items.Objects[cbxCipher.ItemIndex]);
   DoEncryptFile( boxInputFile.Text,
                        boxOutputFile.Text,
                        boxPassphrase.Text,
                        hash,
                        cipher );


end;

procedure TfrmMain.btnDecryptClick(Sender: TObject);
var
  Cipher: TDCP_cipher;         // the cipher to use
  Hash: TDCP_hash;             // the hash to use
begin
if ThreadRunning then exit;
  if not FileExists(boxinputFile.Text) then
     begin MessageDlg('Input filename doesn''t exists !',mtConfirmation,[mbOK],0);exit;end;
  if not IsValidFilename(boxoutputFile.text)  then
     begin  MessageDlg('Output filename is not valid !',mtConfirmation,[mbOK],0);exit;end;
  if  (trim(boxinputFile.text)=trim(boxoutputFile.text))  then
     begin MessageDlg('Output filename: Please choose a different name',mtConfirmation,[mbOK],0);exit;end;
  if FileExists(boxOutputFile.Text) then
    if (MessageDlg('Output file already exists. Overwrite?',mtConfirmation,mbYesNoCancel,0) <> mrYes) then
      Exit;

  Hash := TDCP_hash(cbxHash.Items.Objects[cbxHash.ItemIndex]);
  Cipher := TDCP_cipher(cbxCipher.Items.Objects[cbxCipher.ItemIndex]);
   DoDecryptFile( boxInputFile.Text,
                        boxOutputFile.Text,
                        boxPassphrase.Text,
                        hash,
                        cipher );

end;

procedure TfrmMain.btnCloseClick(Sender: TObject);
begin
  Close;
end;

{----------------------------}
{ procédures de TThreadTaf }
{----------------------------}
constructor TThreadTaf.Create(CreateSuspended: Boolean);
begin
  inherited Create(True);
  FreeOnTerminate := true;
  Priority := tpNormal;
  _success:=false;

end;
destructor TThreadTaf.Destroy;
begin
  inherited;
end;
procedure TThreadTaf.CancelAllOperations;
begin
   _Cipher.CancelByCallingThread:=true;
end;
procedure TThreadTaf.Execute;
begin
  _Cipher.OnProgressEvent:=Pourcentage;
 if _ModeEncrypt then
  DoEncrypt()
 else
  DoDecrypt;
end;
procedure TThreadTaf.DoDecrypt ;
var
  CipherIV: array of byte;     // the initialisation vector (for chaining modes)
  HashDigest: array of byte;   // the result of hashing the passphrase with the salt
  Salt: array[0..7] of byte;   // a random salt to help prevent precomputated attacks
  strmInput, strmOutput: TFileStream;
begin

  strmInput := nil;
  strmOutput := nil;
  try
    strmInput := TFileStream.Create(_inputfile,fmOpenRead);
    strmOutput := TFileStream.Create(_outputfile,fmCreate);

    SetLength(HashDigest,_Hash.HashSize div 8);
    strmInput.ReadBuffer(Salt[0],Sizeof(Salt));  // read the salt in from the file
    _Hash.Init;
    _Hash.Update(Salt[0],Sizeof(Salt));   // hash the salt
    _Hash.UpdateStr(passphrase);  // and the passphrase
    _Hash.Final(HashDigest[0]);           // store the hash in HashDigest

    if (_Cipher is TDCP_blockcipher) then            // if it is a block cipher we need the IV
    begin
      SetLength(CipherIV,TDCP_blockcipher(_Cipher).BlockSize div 8);
      strmInput.ReadBuffer(CipherIV[0],Length(CipherIV));       // read the initialisation vector from the file
      _Cipher.Init(HashDigest[0],Min(_Cipher.MaxKeySize,_Hash.HashSize),CipherIV);  // initialise the cipher
      TDCP_blockcipher(_Cipher).CipherMode := cmCBC;
    end
    else
      _Cipher.Init(HashDigest[0],Min(_Cipher.MaxKeySize,_Hash.HashSize),nil);  // initialise the cipher

    _Cipher.DecryptStream(strmInput,strmOutput,strmInput.Size - strmInput.Position); // decrypt!
    _Cipher.Burn;
    strmInput.Free;
    strmOutput.Free;
    ThreadRunning:=false;
    _success:=true;Synchronize(EndingMessageDecryption);
  except
    strmInput.Free;
    strmOutput.Free;
    _success:=false;Synchronize(EndingMessageDecryption);
    ThreadRunning:=false;
  end;
end;
procedure TThreadTaf.DoEncrypt ;
var
  CipherIV: array of byte;     // the initialisation vector (for chaining modes)
  HashDigest: array of byte;   // the result of hashing the passphrase with the salt
  Salt: array[0..7] of byte;   // a random salt to help prevent precomputated attacks
  strmInput, strmOutput: TFileStream;
  i: integer;
begin
  strmInput := nil;
  strmOutput := nil;
  try
    strmInput := TFileStream.Create(_inputfile,fmOpenRead);
    strmOutput := TFileStream.Create(_outputfile,fmCreate);

    SetLength(HashDigest,Hash.HashSize div 8);
    for i := 0 to 7 do
      Salt[i] := Random(256);  // just fill the salt with random values (crypto secure PRNG would be better but not _really_ necessary)
    strmOutput.WriteBuffer(Salt,Sizeof(Salt));  // write out the salt so we can decrypt!
    _Hash.Init;
    _Hash.Update(Salt[0],Sizeof(Salt));   // hash the salt
    _Hash.UpdateStr(_passphrase);  // and the passphrase
    _Hash.Final(HashDigest[0]);           // store the output in HashDigest

    if (_Cipher is TDCP_blockcipher) then      // if the cipher is a block cipher we need an initialisation vector
    begin
      SetLength(CipherIV,TDCP_blockcipher(_Cipher).BlockSize div 8);
      for i := 0 to (Length(CipherIV) - 1) do
        CipherIV[i] := Random(256);           // again just random values for the IV
      strmOutput.WriteBuffer(CipherIV[0],Length(CipherIV));  // write out the IV so we can decrypt!
      _Cipher.Init(HashDigest[0],Min(_Cipher.MaxKeySize,_Hash.HashSize),CipherIV);  // initialise the cipher with the hash as key
      TDCP_blockcipher(_Cipher).CipherMode := cmCBC;   // use CBC chaining when encrypting
    end
    else
      _Cipher.Init(HashDigest[0],Min(Cipher.MaxKeySize,Hash.HashSize),nil); // initialise the cipher with the hash as key


    _Cipher.EncryptStream(strmInput,strmOutput,strmInput.Size); // encrypt the entire file
    _Cipher.Burn;   // important! get rid of keying information
    strmInput.Free;
    strmOutput.Free;
    ThreadRunning:=false;
    _success:=true;Synchronize(EndingMessageEncryption);
  except
    strmInput.Free;
    strmOutput.Free;
    _success:=false;Synchronize(EndingMessageEncryption);
    ThreadRunning:=false;
  end;
end;
procedure TThreadTaf.Pourcentage(sender:Tobject;value:integer);
begin
     if Assigned(FOnProgress) then
          FOnProgress(Self,value);
end;
procedure TThreadTaf.EndingMessageEncryption;
begin
  if _success then
      MessageDlg('File encrypted',mtInformation,[mbOK],0)
  else
      MessageDlg('An error occurred while processing the file',mtError,[mbOK],0);
  ReActiveControles;
end;
procedure TThreadTaf.EndingMessageDecryption;
begin
  if _success then
      MessageDlg('File Decrypted',mtInformation,[mbOK],0)
  else
      MessageDlg('An error occurred while processing the file',mtError,[mbOK],0);
  ReActiveControles;
end;
procedure TThreadTaf.ReActiveControles;
begin
FrmMain.boxInputFile.Enabled:=True;
FrmMain.boxOutputFile.Enabled:=True;
FrmMain.cbxCipher.Enabled:=True;
FrmMain.cbxHash.Enabled:=True;
FrmMain.boxPassphrase.Enabled:=True;
FrmMain.boxConfirmPassphrase.Enabled:=True;
FrmMain.btnInputBrowse.Enabled:=True;
FrmMain.btnOutputBrowse.Enabled:=True;
if btnEncrypWasEnabled then
   FrmMain.btnEncrypt.Enabled:=True
else
   FrmMain.btnEncrypt.Enabled:=False;
if btnDecryptWasEnabled then
   FrmMain.btnDecrypt.Enabled:=True
else
   FrmMain.btnDecrypt.Enabled:=False;
end;

end.

