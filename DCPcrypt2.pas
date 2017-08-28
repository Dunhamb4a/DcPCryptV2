{ ****************************************************************************** }
{ * DCPcrypt v2.1 written by David Barton (crypto@cityinthesky.co.uk) ********** }
{ * MODIFICATIONS BY WARREN POSTMA FOR VERSION 2.1 : XE, XE2+ support          * }
{ * Also, Unicode support fixes, and removal of "overloading".                 *)
  {*                                                                            * }
{ ****************************************************************************** }
{ * Main component definitions ************************************************* }
{ ****************************************************************************** }
{ * Copyright (c) 1999-2003 David Barton                                       * }
{ * Permission is hereby granted, free of charge, to any person obtaining a    * }
{ * copy of this software and associated documentation files (the "Software"), * }
{ * to deal in the Software without restriction, including without limitation  * }
{ * the rights to use, copy, modify, merge, publish, distribute, sublicense,   * }
{ * and/or sell copies of the Software, and to permit persons to whom the      * }
{ * Software is furnished to do so, subject to the following conditions:       * }
{ *                                                                            * }
{ * The above copyright notice and this permission notice shall be included in * }
{ * all copies or substantial portions of the Software.                        * }
{ *                                                                            * }
{ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR * }
{ * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,   * }
{ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL    * }
{ * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER * }
{ * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING    * }
{ * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER        * }
{ * DEALINGS IN THE SOFTWARE.                                                  * }
{ ****************************************************************************** }
unit DCPcrypt2;

interface

uses  {$ifdef NEXTGEN_FIXES}
      ORawByteString,
      {$endif}
      Classes,
      Types,
      Sysutils,
      DCPbase64;


{ Enable this block to enable a unicode string Encrypt/Decrypt feature that is
  completely NON-backwards compatible with the existing ANSI String version }

 {$ifdef UNICODE}
 {$define UNICODE_CIPHER}
 {$endif}

{ ************************************ }
{ A few predefined types to help out }
{ ************************************ }

type
   Pbyte = ^byte;
   Pword = ^word;
   Pdword = ^dword;
   Pint64 = ^int64;
   dword = longword;
   Pwordarray = ^Twordarray;
   Twordarray = array [0 .. 19383] of word;
   Pdwordarray = ^Tdwordarray;
   Tdwordarray = array [0 .. 8191] of dword;

type

{$IF CompilerVersion >= 23}
{$DEFINE DELPHIXE2_UP}
{$IFEND}
{$IFNDEF DELPHIXE2_UP}
   NativeInt = {$IFDEF WIN64} int64 {$ELSE} Longint {$ENDIF};
{$ENDIF}
   PointerToInt = {$IFDEF DELPHIXE2_UP} Pbyte {$ELSE} NativeInt {$ENDIF};

   { ****************************************************************** }
   { The base class from which all hash algorithms are to be derived }

type
   EDCP_hash = class(Exception);

   TDCP_hash = class(TComponent)
   protected
      fInitialized: boolean;
      { Whether or not the algorithm has been initialized }

      procedure DeadInt(Value: integer);
      { Knudge to display vars in the object inspector }
      procedure DeadStr(Value: string);
      { Knudge to display vars in the object inspector }

   private
      function _GetId: integer;
      function _GetAlgorithm: string;
      function _GetHashSize: integer;

   public
      property Initialized: boolean read fInitialized;

      class function GetId: integer; virtual;
      { Get the algorithm id }
      class function GetAlgorithm: string; virtual;
      { Get the algorithm name }
      class function GetHashSize: integer; virtual;
      { Get the size of the digest produced - in bits }
      class function SelfTest: boolean; virtual;
      { Tests the implementation with several test vectors }

      procedure Init; virtual;
      { Initialize the hash algorithm }
      procedure Final(var Digest); virtual;
      { Create the final digest and clear the stored information.
        The size of the Digest var must be at least equal to the hash size }
      procedure Burn; virtual;
      { Clear any stored information with out creating the final digest }

      procedure Update(const Buffer; Size: longword); virtual;
      { Update the hash buffer with Size bytes of data from Buffer }
      procedure UpdateStream(Stream: TStream; Size: longword);
      { Update the hash buffer with Size bytes of data from the stream }
      procedure UpdateStr(const Str: RawByteString);

      { Update the hash buffer with the string }
{$IFDEF UNICODE_CIPHER}
      procedure UpdateUnicodeStr(const Str: UnicodeString); overload;
      { Update the hash buffer with the string }
{$ENDIF}
      destructor Destroy; override;

   published
      property Id: integer read _GetId write DeadInt;
      property Algorithm: string read _GetAlgorithm write DeadStr;
      property HashSize: integer read _GetHashSize write DeadInt;
   end;

   TDCP_hashclass = class of TDCP_hash;

   { ****************************************************************************** }
   { The base class from which all encryption components will be derived. }
   { Stream ciphers will be derived directly from this class where as }
   { Block ciphers will have a further foundation class TDCP_blockcipher. }

type
   TProgressEvent=procedure(Sender:TObject;progress:integer)of object;

   EDCP_cipher = class(Exception);
   TDCP_cipher = class(TComponent)
   protected
      fInitialized: boolean; { Whether or not the key setup has been done yet }

      procedure DeadInt(Value: integer);
      { Knudge to display vars in the object inspector }
      procedure DeadStr(Value: string);
      { Knudge to display vars in the object inspector }

   private
      _CancelByCallingThread:boolean;
      FOnProgressEvent:TProgressEvent;

      function _GetId: integer;
      function _GetAlgorithm: string;
      function _GetMaxKeySize: integer;

   public
      property OnProgressEvent: TProgressEvent read FOnProgressEvent write FOnProgressEvent;
      property CancelByCallingThread: boolean read _CancelByCallingThread write _CancelByCallingThread;
      property Initialized: boolean read fInitialized;

      class function GetId: integer; virtual;
      { Get the algorithm id }
      class function GetAlgorithm: string; virtual;
      { Get the algorithm name }
      class function GetMaxKeySize: integer; virtual;
      { Get the maximum key size (in bits) }
      class function SelfTest: boolean; virtual;
      { Tests the implementation with several test vectors }

      procedure Init(const Key; Size: longword; InitVector: pointer); virtual;
      { Do key setup based on the data in Key, size is in bits }
      procedure InitStr(const Key: RawByteString; HashType: TDCP_hashclass);

      { Do key setup based on a hash of the key string }

{$IFDEF UNICODE_CIPHER}
      procedure InitUnicodeStr(const Key: UnicodeString;
        HashType: TDCP_hashclass);
      { Do key setup based on a hash of the key string }
{$ENDIF}
      procedure Burn; virtual;
      { Clear all stored key information }
      procedure Reset; virtual;
      { Reset any stored chaining information }
      procedure Encrypt(const Indata; var Outdata; Size: longword); virtual;
      { Encrypt size bytes of data and place in Outdata }
      procedure Decrypt(const Indata; var Outdata; Size: longword); virtual;
      { Decrypt size bytes of data and place in Outdata }
      function EncryptStream(InStream, OutStream: TStream; Size: Int64)
        : longword;
      { Encrypt size bytes of data from InStream and place in OutStream }
      function DecryptStream(InStream, OutStream: TStream; Size: int64)
        : longword;
      { Decrypt size bytes of data from InStream and place in OutStream }
      function EncryptString(const Str: RawByteString): RawByteString; virtual;
      { Encrypt a string and return Base64 encoded }
      function DecryptString(const Str: RawByteString): RawByteString; virtual;
      { Decrypt a Base64 encoded string }

{$IFDEF UNICODE_CIPHER}
      function EncryptUnicodeString(const Str: UnicodeString)
        : UnicodeString; virtual;
      { Encrypt a Unicode string and return Base64 encoded }
      function DecryptUnicodeString(const Str: UnicodeString)
        : UnicodeString; virtual;
      { Decrypt a Base64 encoded Unicode string }
{$ENDIF}
      function PartialEncryptStream(AStream: TMemoryStream; Size: longword)
        : longword;
      { Partially Encrypt up to 16K bytes of data in AStream }
      function PartialDecryptStream(AStream: TMemoryStream; Size: longword)
        : longword;
      { Partially Decrypt up to 16K bytes of data in AStream }

      constructor Create(AOwner: TComponent); override;
      destructor Destroy; override;

   published
      property Id: integer read _GetId write DeadInt;
      property Algorithm: string read _GetAlgorithm write DeadStr;
      property MaxKeySize: integer read _GetMaxKeySize write DeadInt;
   end;

   TDCP_cipherclass = class of TDCP_cipher;

   { ****************************************************************************** }
   { The base class from which all block ciphers are to be derived, this }
   { extra class takes care of the different block encryption modes. }

type
   TDCP_ciphermode = (cmCBC, cmCFB8bit, cmCFBblock, cmOFB, cmCTR);
   // cmCFB8bit is equal to DCPcrypt v1.xx's CFB mode
   EDCP_blockcipher = class(EDCP_cipher);

   TDCP_blockcipher = class(TDCP_cipher)
   protected
      fCipherMode: TDCP_ciphermode; { The cipher mode the encrypt method uses }

      procedure InitKey(const Key; Size: longword); virtual;

   private
      function _GetBlockSize: integer;

   public
      class function GetBlockSize: integer; virtual;
      { Get the block size of the cipher (in bits) }

      procedure SetIV(const Value); virtual;
      { Sets the IV to Value and performs a reset }
      procedure GetIV(var Value); virtual;
      { Returns the current chaining information, not the actual IV }

      procedure Encrypt(const Indata; var Outdata; Size: longword); override;
      { Encrypt size bytes of data and place in Outdata using CipherMode }
      procedure Decrypt(const Indata; var Outdata; Size: longword); override;
      { Decrypt size bytes of data and place in Outdata using CipherMode }
      function EncryptString(const Str: RawByteString): RawByteString;
        overload; override;
      { Encrypt a string and return Base64 encoded }
      function DecryptString(const Str: RawByteString): RawByteString;
        overload; override;
      { Decrypt a Base64 encoded string }

{$IFDEF UNICODE_CIPHER}
      function EncryptUnicodeString(const Str: UnicodeString): UnicodeString; override;
      { Encrypt a Unicode string and return Base64 encoded }
      function DecryptUnicodeString(const Str: UnicodeString): UnicodeString; override;
      { Decrypt a Base64 encoded Unicode string }
{$ENDIF}

      procedure EncryptECB(const Indata; var Outdata); virtual;
      { Encrypt a block of data using the ECB method of encryption }
      procedure DecryptECB(const Indata; var Outdata); virtual;
      { Decrypt a block of data using the ECB method of decryption }
      procedure EncryptCBC(const Indata; var Outdata; Size: longword); virtual;
      { Encrypt size bytes of data using the CBC method of encryption }
      procedure DecryptCBC(const Indata; var Outdata; Size: longword); virtual;
      { Decrypt size bytes of data using the CBC method of decryption }
      procedure EncryptCFB8bit(const Indata; var Outdata;
        Size: longword); virtual;
      { Encrypt size bytes of data using the CFB (8 bit) method of encryption }
      procedure DecryptCFB8bit(const Indata; var Outdata;
        Size: longword); virtual;
      { Decrypt size bytes of data using the CFB (8 bit) method of decryption }
      procedure EncryptCFBblock(const Indata; var Outdata;
        Size: longword); virtual;
      { Encrypt size bytes of data using the CFB (block) method of encryption }
      procedure DecryptCFBblock(const Indata; var Outdata;
        Size: longword); virtual;
      { Decrypt size bytes of data using the CFB (block) method of decryption }
      procedure EncryptOFB(const Indata; var Outdata; Size: longword); virtual;
      { Encrypt size bytes of data using the OFB method of encryption }
      procedure DecryptOFB(const Indata; var Outdata; Size: longword); virtual;
      { Decrypt size bytes of data using the OFB method of decryption }
      procedure EncryptCTR(const Indata; var Outdata; Size: longword); virtual;
      { Encrypt size bytes of data using the CTR method of encryption }
      procedure DecryptCTR(const Indata; var Outdata; Size: longword); virtual;
      { Decrypt size bytes of data using the CTR method of decryption }

      constructor Create(AOwner: TComponent); override;

   published
      property BlockSize: integer read _GetBlockSize write DeadInt;
      property CipherMode: TDCP_ciphermode read fCipherMode write fCipherMode
        default cmCBC;
   end;

   TDCP_blockcipherclass = class of TDCP_blockcipher;

   { ****************************************************************************** }
   { Helper functions }

procedure XorBlock(var InData1, InData2; Size: longword);

implementation

{$IFDEF MSWINDOWS}
uses Windows;
{$ENDIF}


{$Q-}{$R-}
{ ** TDCP_hash ***************************************************************** }

procedure TDCP_hash.DeadInt(Value: integer);
begin
end;

procedure TDCP_hash.DeadStr(Value: string);
begin
end;

function TDCP_hash._GetId: integer;
begin
   Result := GetId;
end;

function TDCP_hash._GetAlgorithm: string;
begin
   Result := GetAlgorithm;
end;

function TDCP_hash._GetHashSize: integer;
begin
   Result := GetHashSize;
end;

class function TDCP_hash.GetId: integer;
begin
   Result := -1;
end;

class function TDCP_hash.GetAlgorithm: string;
begin
   Result := '';
end;

class function TDCP_hash.GetHashSize: integer;
begin
   Result := -1;
end;

class function TDCP_hash.SelfTest: boolean;
begin
   Result := false;
end;

procedure TDCP_hash.Init;
begin
end;

procedure TDCP_hash.Final(var Digest);
begin
end;

procedure TDCP_hash.Burn;
begin
end;

procedure TDCP_hash.Update(const Buffer; Size: longword);
begin
end;

procedure TDCP_hash.UpdateStream(Stream: TStream; Size: longword);
var
   Buffer: array [0 .. 8191] of byte;
   i, read: integer;
begin
   FillChar(Buffer, SizeOf(Buffer), 0);
   for i := 1 to (Size div SizeOf(Buffer)) do
   begin
      read := Stream.read(Buffer, SizeOf(Buffer));
      Update(Buffer, read);
   end;
   if (Size mod SizeOf(Buffer)) <> 0 then
   begin
      read := Stream.read(Buffer, Size mod SizeOf(Buffer));
      Update(Buffer, read);
   end;
end;

procedure TDCP_hash.UpdateStr(const Str: RawByteString);
begin
{$IFDEF NEXTGEN}
  Update(Str.GetBuffer[0], AnsiLength(Str));
{$ELSE}
  Update(Str[1], Length(Str));
{$ENDIF}
end;

{$IFDEF UNICODE_CIPHER}

procedure TDCP_hash.UpdateUnicodeStr(const Str: UnicodeString);
begin
   Update(Str[1], Length(Str) * SizeOf(Str[1]));
end; { DecryptString }
{$ENDIF}

destructor TDCP_hash.Destroy;
begin
   if fInitialized then
      Burn;
   inherited Destroy;
end;

{ ** TDCP_cipher *************************************************************** }

procedure TDCP_cipher.DeadInt(Value: integer);
begin
end;

procedure TDCP_cipher.DeadStr(Value: string);
begin
end;

function TDCP_cipher._GetId: integer;
begin
   Result := GetId;
end;

function TDCP_cipher._GetAlgorithm: string;
begin
   Result := GetAlgorithm;
end;

function TDCP_cipher._GetMaxKeySize: integer;
begin
   Result := GetMaxKeySize;
end;

class function TDCP_cipher.GetId: integer;
begin
   Result := -1;
end;

class function TDCP_cipher.GetAlgorithm: string;
begin
   Result := '';
end;

class function TDCP_cipher.GetMaxKeySize: integer;
begin
   Result := -1;
end;

class function TDCP_cipher.SelfTest: boolean;
begin
   Result := false;
end;

procedure TDCP_cipher.Init(const Key; Size: longword; InitVector: pointer);
begin
   if fInitialized then
      Burn;
   if (Size <= 0) or ((Size and 3) <> 0) or (Size > longword(GetMaxKeySize))
   then
      raise EDCP_cipher.Create('Invalid key size')
   else
      fInitialized := true;
end;

procedure TDCP_cipher.InitStr(const Key: RawByteString; HashType: TDCP_hashclass);
var
   Hash: TDCP_hash;
   Digest: pointer;
begin
   if fInitialized then
      Burn;
   try
      GetMem(Digest, HashType.GetHashSize div 8);
      Hash := HashType.Create(Self);
      Hash.Init;
      Hash.UpdateStr(Key);
      Hash.Final(Digest^);
      Hash.Free;
      if MaxKeySize < HashType.GetHashSize then
      begin
         Init(Digest^, MaxKeySize, nil);
      end
      else
      begin
         Init(Digest^, HashType.GetHashSize, nil);
      end;
      FillChar(Digest^, HashType.GetHashSize div 8, $FF);
      FreeMem(Digest);
   except
      raise EDCP_cipher.Create
        ('Unable to allocate sufficient memory for hash digest');
   end;
end;

{$IFDEF UNICODE_CIPHER}
procedure TDCP_cipher.InitUnicodeStr(const Key: UnicodeString;
  HashType: TDCP_hashclass);
var
   Hash: TDCP_hash;
   Digest: pointer;
begin
   if fInitialized then
      Burn;
   try
      GetMem(Digest, HashType.GetHashSize div 8);
      Hash := HashType.Create(Self);
      Hash.Init;
      Hash.UpdateUnicodeStr(Key);
      Hash.Final(Digest^);
      Hash.Free;
      if MaxKeySize < HashType.GetHashSize then
         Init(Digest^, MaxKeySize, nil)
      else
         Init(Digest^, HashType.GetHashSize, nil);
      FillChar(Digest^, HashType.GetHashSize div 8, $FF);
      FreeMem(Digest);
   except
      raise EDCP_cipher.Create
        ('Unable to allocate sufficient memory for hash digest');
   end;
end;
{$ENDIF}


procedure TDCP_cipher.Burn;
begin
   fInitialized := false;
end;

procedure TDCP_cipher.Reset;
begin
end;

procedure TDCP_cipher.Encrypt(const Indata; var Outdata; Size: longword);
begin
end;

procedure TDCP_cipher.Decrypt(const Indata; var Outdata; Size: longword);
begin
end;

const
   EncryptBufSize = 1024 * 1024 * 8; // 8 Megs
   EncryptLimit = (16 * 1024); // 16K operation size

   // modified by SR - 10/6/2003
function TDCP_cipher.EncryptStream(InStream, OutStream: TStream; Size: Int64)
  : longword;
var
   Buffer: TByteDynArray;
   i, read: longword;
   Range: Int64;
   Remainder: Int64;
begin
   Result := 0;

   if Size < EncryptBufSize then
      SetLength(Buffer, Size)
   else
      SetLength(Buffer, EncryptBufSize);

   Range := Size div Int64(Length(Buffer));
   for i := 1 to Range do
   begin
      Read := InStream.read(Buffer[0], Length(Buffer));
      Inc(Result, Read);
      Encrypt(Buffer[0], Buffer[0], Read);
      OutStream.Write(Buffer[0], Read);
      if _CancelByCallingThread then
            Break;
      if Assigned(FOnProgressEvent) then
         FOnProgressEvent(Self,round((100*i)/Range));
   end;

   Remainder := Size mod Int64(Length(Buffer));
   if Remainder <> 0 then
   begin
      Read := InStream.read(Buffer[0], Remainder);
      Inc(Result, Read);
      Encrypt(Buffer[0], Buffer[0], Read);
      OutStream.Write(Buffer[0], Read);
   end;
end;

// modified by SR - 10/6/2003
function TDCP_cipher.DecryptStream(InStream, OutStream: TStream; Size: int64)
  : longword;
var
   Buffer: TByteDynArray;
   i, read: longword;
   Range: int64;
   Remainder: int64;
begin
   Result := 0;
   if Size < EncryptBufSize then
      SetLength(Buffer, Size)
   else
      SetLength(Buffer, EncryptBufSize);

   Range := Size div int64(Length(Buffer));
   for i := 1 to Range do
   begin
      Read := InStream.read(Buffer[0], Length(Buffer));
      Inc(Result, Read);
      Decrypt(Buffer[0], Buffer[0], Read);
      OutStream.Write(Buffer[0], Read);
      if _CancelByCallingThread then
            Break;
      if Assigned(FOnProgressEvent) then
         FOnProgressEvent(Self,round((100*i)/Range));
   end;

   Remainder := Size mod int64(Length(Buffer));
   if Remainder <> 0 then
   begin
      Read := InStream.read(Buffer[0], Remainder);
      Inc(Result, Read);
      Decrypt(Buffer[0], Buffer[0], Read);
      OutStream.Write(Buffer[0], Read);
   end;
end;

function TDCP_cipher.EncryptString(const Str: RawByteString): RawByteString;
var
  lLength : integer;
begin
{$IFDEF NEXTGEN}
  Result.SetLength(AnsiLength(Str));
  Encrypt(Str.GetBuffer[0], Result.GetBuffer[0], AnsiLength(Str));
{$ELSE}
  SetLength(Result, Length(Str));
  Encrypt(Str[1], Result[1], Length(Str));
{$ENDIF}
   Result := Base64EncodeStr(Result);
end;

function TDCP_cipher.DecryptString(const Str: RawByteString): RawByteString;
begin
   Result := Base64DecodeStr(Str);
{$IFDEF NEXTGEN}
  Decrypt(Result.GetBuffer[0], Result.GetBuffer[0], AnsiLength(Result));
{$ELSE}
  Decrypt(Result[1], Result[1], Length(Result));
{$ENDIF}
end;

{$IFDEF UNICODE_CIPHER}
function TDCP_cipher.EncryptUnicodeString(const Str: UnicodeString): UnicodeString;
begin
   SetLength(Result, Length(Str));
   Encrypt(Str[1], Result[1], Length(Str) * SizeOf(Str[1]));
   Result := Base64EncodeStr(Result);
end;

function TDCP_cipher.DecryptUnicodeString(const Str: UnicodeString): UnicodeString;
begin
   Result := Base64DecodeStr(Str);
   Decrypt(Result[1], Result[1], Length(Result) * SizeOf(Result[1]));
end;
{$ENDIF}

constructor TDCP_cipher.Create(AOwner: TComponent);
begin
   inherited Create(AOwner);
   Burn;
end;

destructor TDCP_cipher.Destroy;
begin
   if fInitialized then
      Burn;
   inherited Destroy;
end;

{ ** TDCP_blockcipher ********************************************************** }

procedure TDCP_blockcipher.InitKey(const Key; Size: longword);
begin
end;

function TDCP_blockcipher._GetBlockSize: integer;
begin
   Result := GetBlockSize;
end;

class function TDCP_blockcipher.GetBlockSize: integer;
begin
   Result := -1;
end;

procedure TDCP_blockcipher.SetIV(const Value);
begin
end;

procedure TDCP_blockcipher.GetIV(var Value);
begin
end;

procedure TDCP_blockcipher.Encrypt(const Indata; var Outdata; Size: longword);
begin
   case fCipherMode of
      cmCBC:
         EncryptCBC(Indata, Outdata, Size);
      cmCFB8bit:
         EncryptCFB8bit(Indata, Outdata, Size);
      cmCFBblock:
         EncryptCFBblock(Indata, Outdata, Size);
      cmOFB:
         EncryptOFB(Indata, Outdata, Size);
      cmCTR:
         EncryptCTR(Indata, Outdata, Size);
   end;
end;

function TDCP_blockcipher.EncryptString(const Str: RawByteString): RawByteString;
begin
{$IFDEF NEXTGEN}
  Result.SetLength(AnsiLength(Str));
  EncryptCFB8bit(Str.GetBuffer[0], Result.GetBuffer[0], AnsiLength(Str));
{$ELSE}
  SetLength(Result, Length(Str));
  EncryptCFB8bit(Str[1], Result[1], Length(Str));
{$ENDIF}
   Result := Base64EncodeStr(Result);
end;

function TDCP_blockcipher.DecryptString(const Str: RawByteString): RawByteString;
begin
   Result := Base64DecodeStr(Str);
{$IFDEF NEXTGEN}
  DecryptCFB8bit(Result.GetBuffer[0], Result.GetBuffer[0], AnsiLength(Result));
{$ELSE}
  DecryptCFB8bit(Result[1], Result[1], Length(Result));
{$ENDIF}
end;

{$IFDEF UNICODE_CIPHER}

// TODO: Make this semi-backwards compatible with EncrypteString, via UTF8

function TDCP_blockcipher.EncryptUnicodeString(const Str: UnicodeString)
  : UnicodeString;
begin
   SetLength(Result, Length(Str));
   EncryptCFB8bit(Str[1], Result[1], Length(Str) * SizeOf(Str[1]));
   Result := Base64EncodeStr(Result);
end;

function TDCP_blockcipher.DecryptUnicodeString(const Str: UnicodeString)
  : UnicodeString;
begin
   Result := Base64DecodeStr(Str);
   DecryptCFB8bit(Result[1], Result[1], Length(Result) * SizeOf(Result[1]));
end;
{$ENDIF}



procedure TDCP_blockcipher.Decrypt(const Indata; var Outdata; Size: longword);
begin
   case fCipherMode of
      cmCBC:
         DecryptCBC(Indata, Outdata, Size);
      cmCFB8bit:
         DecryptCFB8bit(Indata, Outdata, Size);
      cmCFBblock:
         DecryptCFBblock(Indata, Outdata, Size);
      cmOFB:
         DecryptOFB(Indata, Outdata, Size);
      cmCTR:
         DecryptCTR(Indata, Outdata, Size);
   end;
end;

procedure TDCP_blockcipher.EncryptECB(const Indata; var Outdata);
begin
end;

procedure TDCP_blockcipher.DecryptECB(const Indata; var Outdata);
begin
end;

procedure TDCP_blockcipher.EncryptCBC(const Indata; var Outdata;
  Size: longword);
begin
end;

procedure TDCP_blockcipher.DecryptCBC(const Indata; var Outdata;
  Size: longword);
begin
end;

procedure TDCP_blockcipher.EncryptCFB8bit(const Indata; var Outdata;
  Size: longword);
begin
end;

procedure TDCP_blockcipher.DecryptCFB8bit(const Indata; var Outdata;
  Size: longword);
begin
end;

procedure TDCP_blockcipher.EncryptCFBblock(const Indata; var Outdata;
  Size: longword);
begin
end;

procedure TDCP_blockcipher.DecryptCFBblock(const Indata; var Outdata;
  Size: longword);
begin
end;

procedure TDCP_blockcipher.EncryptOFB(const Indata; var Outdata;
  Size: longword);
begin
end;

procedure TDCP_blockcipher.DecryptOFB(const Indata; var Outdata;
  Size: longword);
begin
end;

procedure TDCP_blockcipher.EncryptCTR(const Indata; var Outdata;
  Size: longword);
begin
end;

procedure TDCP_blockcipher.DecryptCTR(const Indata; var Outdata;
  Size: longword);
begin
end;

constructor TDCP_blockcipher.Create(AOwner: TComponent);
begin
   inherited Create(AOwner);
   fCipherMode := cmCBC;
end;

{ ** Helper functions ********************************************************* }
procedure XorBlock(var InData1, InData2; Size: longword);
var
   b1: PByteArray;
   b2: PByteArray;
   i: longword;
begin
   b1 := @InData1;
   b2 := @InData2;
   for i := 0 to Size - 1 do
      b1[i] := b1[i] xor b2[i];
end;

{ ** RECENT Additions after Version 2.0 ** }

// Version 2.1 : Partial Stream Read capability.
function TDCP_cipher.PartialDecryptStream(AStream: TMemoryStream;
  Size: longword): longword;
var
   Buffer: PLongInt;
begin
   if Size > EncryptLimit then
      Size := EncryptLimit;

   Result := Size;
   Buffer := PLongInt(AStream.Memory);
   // only process the limited size:
   Decrypt(Buffer^, Buffer^, Size);
end;

// Version 2.1 : Partial Stream Read capability.
function TDCP_cipher.PartialEncryptStream(AStream: TMemoryStream;
  Size: longword): longword;
var
   Buffer: PLongInt;
begin
   if Size > EncryptLimit then
      Size := EncryptLimit;

   Result := Size;
   Buffer := PLongInt(AStream.Memory);
   // only process the limited size:
   Encrypt(Buffer^, Buffer^, Size);
end;

end.
