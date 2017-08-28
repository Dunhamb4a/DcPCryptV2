{******************************************************************************}
{* DCPcrypt v2.0 written by David Barton (crypto@cityinthesky.co.uk) **********}
{******************************************************************************}
{* A Unicode string encryption/decryption demo using EncryptStreams ***********}
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
  UnitUtilitaires, Vcl.ComCtrls, Vcl.ExtCtrls, Vcl.ImgList,ShellAPI;

type

  TfrmMain = class(TForm)
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
    Panel1: TPanel;
    grpOptions: TGroupBox;
    lblCipher: TLabel;
    lblHash: TLabel;
    lblKeySize: TLabel;
    dblKeySize: TLabel;
    lblPassphrase: TLabel;
    cbxCipher: TComboBox;
    cbxHash: TComboBox;
    boxPassphrase: TEdit;
    btnEncrypt: TSpeedButton;
    btnDecrypt: TSpeedButton;
    btnClose: TSpeedButton;
    btn_Copy: TSpeedButton;
    btn_Paste: TSpeedButton;
    Panel2: TPanel;
    Panel3: TPanel;
    Memo1: TMemo;
    Progress: TProgressBar;
    procedure FormCreate(Sender: TObject);
    procedure cbxCipherChange(Sender: TObject);
    procedure boxPassphraseChange(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: Boolean);
    procedure Pourcentage(sender:Tobject;value:integer);
    procedure btn_CopyClick(Sender: TObject);
    procedure btn_PasteClick(Sender: TObject);
    procedure btnCloseClick(Sender: TObject);
    procedure btnDecryptClick(Sender: TObject);
    procedure btnEncryptClick(Sender: TObject);
  private
    { Private declarations }
    procedure DisableForm;

    function DoEncryptStringStream(passphrase:String;
                        Hash: TDCP_hash;Cipher: TDCP_cipher):Boolean;
    function DoDecryptStringStream(passphrase:String;
                        Hash: TDCP_hash;Cipher: TDCP_cipher):Boolean;
  public
    { Public declarations }
  end;

var
  frmMain: TfrmMain;
  ConvertRunning: boolean;
implementation

{$R *.dfm}
function Min(a, b: integer): integer;
begin
  if (a < b) then
    Result := a
  else
    Result := b;
end;

procedure TfrmMain.DisableForm;
begin
  grpOptions.Enabled:= false;
  btnEncrypt.Enabled:= false;
  btnDecrypt.Enabled:= false;
end;
{procedure TfrmMain.DisableControls;
begin
cbxCipher.Enabled:=False;
cbxHash.Enabled:=False;
boxPassphrase.Enabled:=False;
btnEncrypt.Enabled:=False;
btnDecrypt.Enabled:=False;
end;  }
procedure TfrmMain.FormCloseQuery(Sender: TObject; var CanClose: Boolean);
begin
if ConvertRunning then
   if MessageDlg('application is working ! Are you sure you want to quit ?', mtConfirmation, [mbYes, mbNo], 0) = mrYes then
   begin

      Repeat
         Application.ProcessMessages; //ce point est à gérer dans les procédures d'encyptage/décryptage
      Until (not ConvertRunning) ;
   end
   else
   begin
       CanClose:=not ConvertRunning;
   end;

end;
procedure TfrmMain.Pourcentage(sender:Tobject;value:integer);
begin
 if value<=100 then
    if value>=0 then
      progress.position:=value;
end;

procedure TfrmMain.FormCreate(Sender: TObject);
var
  i: integer;Ext,dest:string;
begin
Constraints.MinWidth := 600;
  Constraints.MinHeight := 480;

  Randomize;
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

function TfrmMain.DoDecryptStringStream(passphrase:String;
                        Hash: TDCP_hash;Cipher: TDCP_cipher):Boolean;
var
  CipherIV: array of byte;     // the initialisation vector (for chaining modes)
  HashDigest: array of byte;   // the result of hashing the passphrase with the salt
  Salt: array[0..7] of byte;   // a random salt to help prevent precomputated attacks
  strmInput, strmOutput: TStringStream;
begin

  strmInput := nil;
  strmOutput := nil;
  try
    strmInput := TStringStream.Create(HexToString16(Trim(memo1.Text)), TEncoding.Unicode);
    strmOutput := TStringStream.Create('', TEncoding.Unicode);

    SetLength(HashDigest,Hash.HashSize div 8);
    strmInput.ReadBuffer(Salt[0],Sizeof(Salt));  // read the salt in from the file
    Hash.Init;
    Hash.Update(Salt[0],Sizeof(Salt));   // hash the salt
    Hash.UpdateStr(passphrase);  // and the passphrase
    Hash.Final(HashDigest[0]);           // store the hash in HashDigest

    if (Cipher is TDCP_blockcipher) then            // if it is a block cipher we need the IV
    begin
      SetLength(CipherIV,TDCP_blockcipher(Cipher).BlockSize div 8);
      strmInput.ReadBuffer(CipherIV[0],Length(CipherIV));       // read the initialisation vector from the file
      Cipher.Init(HashDigest[0],Min(Cipher.MaxKeySize,Hash.HashSize),CipherIV);  // initialise the cipher
      TDCP_blockcipher(Cipher).CipherMode := cmCBC;
    end
    else
      Cipher.Init(HashDigest[0],Min(Cipher.MaxKeySize,Hash.HashSize),nil);  // initialise the cipher

    Cipher.DecryptStream(strmInput,strmOutput,strmInput.Size - strmInput.Position); // decrypt!
    Cipher.Burn;
    strmoutput.Position:=0;
    memo1.Text:=strmoutput.DataString ;
    strmInput.Free;
    strmOutput.Free;
    ConvertRunning:=false;
  except
    strmInput.Free;
    strmOutput.Free;
    ConvertRunning:=false;
  end;
end;


procedure TfrmMain.btn_CopyClick(Sender: TObject);
begin
  Memo1.SelectAll;
  Memo1.CopyToClipboard;
end;

function TfrmMain.DoEncryptStringStream(passphrase:String;
                        Hash: TDCP_hash;Cipher: TDCP_cipher):Boolean;
var
  CipherIV: array of byte;     // the initialisation vector (for chaining modes)
  HashDigest: array of byte;   // the result of hashing the passphrase with the salt
  Salt: array[0..7] of byte;   // a random salt to help prevent precomputated attacks
  strmInput, strmOutput: TStringStream;
  i: integer;
begin
  result:=true;
  strmInput := nil;
  strmOutput := nil;
  Cipher.OnProgressEvent:=Pourcentage;
  try
    strmInput := TStringStream.Create(memo1.text, TEncoding.Unicode);
    strmOutput := TStringStream.Create('', TEncoding.Unicode);

    SetLength(HashDigest,Hash.HashSize div 8);
    for i := 0 to 7 do
      Salt[i] := Random(256);  // just fill the salt with random values (crypto secure PRNG would be better but not _really_ necessary)
    strmOutput.WriteBuffer(Salt,Sizeof(Salt));  // write out the salt so we can decrypt!
    Hash.Init;
    Hash.Update(Salt[0],Sizeof(Salt));   // hash the salt
    Hash.UpdateStr(passphrase);  // and the passphrase
    Hash.Final(HashDigest[0]);           // store the output in HashDigest

    if (Cipher is TDCP_blockcipher) then      // if the cipher is a block cipher we need an initialisation vector
    begin
      SetLength(CipherIV,TDCP_blockcipher(Cipher).BlockSize div 8);
      for i := 0 to (Length(CipherIV) - 1) do
        CipherIV[i] := Random(256);           // again just random values for the IV
      strmOutput.WriteBuffer(CipherIV[0],Length(CipherIV));  // write out the IV so we can decrypt!
      Cipher.Init(HashDigest[0],Min(Cipher.MaxKeySize,Hash.HashSize),CipherIV);  // initialise the cipher with the hash as key
      TDCP_blockcipher(Cipher).CipherMode := cmCBC;   // use CBC chaining when encrypting
    end
    else
      Cipher.Init(HashDigest[0],Min(Cipher.MaxKeySize,Hash.HashSize),nil); // initialise the cipher with the hash as key


    Cipher.EncryptStream(strmInput,strmOutput,strmInput.Size); // encrypt the entire file
    Cipher.Burn;   // important! get rid of keying information
    strmoutput.Position:=0;
    memo1.Text:=StringToHex16(strmoutput.DataString);
    strmInput.Free;
    strmOutput.Free;
    ConvertRunning:=false;
  except
    strmInput.Free;
    strmOutput.Free;
    ConvertRunning:=false;
  end;
end;

procedure TfrmMain.btn_PasteClick(Sender: TObject);
begin
  memo1.Clear;
  Memo1.PasteFromClipboard;
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

      btnEncrypt.Enabled := true;
      btnDecrypt.Enabled:=true;
  end
  else
  begin
    btnEncrypt.Enabled := false;
    btnDecrypt.Enabled := false;
  end;
end;

procedure TfrmMain.btnCloseClick(Sender: TObject);
begin
  Close;
end;

procedure TfrmMain.btnDecryptClick(Sender: TObject);
  var
  Hash: TDCP_hash;             // the hash to use
  Cipher: TDCP_cipher;         // the cipher to use
begin
if  ConvertRunning then exit;
if trim(memo1.Text)='' then exit;
if not IsHex(trim(memo1.Text)) then exit;
    ConvertRunning:=true;
progress.Position:=0;
Hash := TDCP_hash(cbxHash.Items.Objects[cbxHash.ItemIndex]);
  Cipher := TDCP_cipher(cbxCipher.Items.Objects[cbxCipher.ItemIndex]);
     DoDecryptStringStream(   boxPassphrase.Text,
                        hash,
                        cipher );
end;

procedure TfrmMain.btnEncryptClick(Sender: TObject);
  var
  Hash: TDCP_hash;             // the hash to use
  Cipher: TDCP_cipher;         // the cipher to use
begin
  if  ConvertRunning then exit;
  if trim(memo1.Text)='' then exit;

  ConvertRunning:=true;
  progress.Position:=0;

  Hash := TDCP_hash(cbxHash.Items.Objects[cbxHash.ItemIndex]);
  Cipher := TDCP_cipher(cbxCipher.Items.Objects[cbxCipher.ItemIndex]);
  DoEncryptStringStream(   boxPassphrase.Text,
                        hash,
                        cipher );

end;

end.

