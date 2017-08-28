unit UnitUtilitaires;

interface
uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, DCPtiger, DCPsha512, DCPsha256, DCPsha1, DCPripemd160,
  DCPripemd128, DCPmd5, DCPmd4, DCPcrypt2, DCPhaval, DCPtwofish, DCPtea,
  DCPserpent, DCPblockciphers, DCPrijndael, DCPrc4, DCPrc2, DCPice, DCPdes,
  DCPcast128, DCPblowfish, StdCtrls, Buttons, SHFolder,ShlObj,System.IOUtils;
  function StringToHex(S: String): string;
function HexToString(H: String): String;
function StringToHex16(str: string): string;
function HexToString16(const str: string): string;
function IsHex(s: string): boolean;
  function IsValidFilename(const FileName: string): boolean;
  function StringIndex(const aString: String;
                       const aCases: array of String;
                       const aCaseSensitive: Boolean = TRUE): Integer;
implementation
function IsValidFilename(const FileName: string): boolean;
begin
  result := DirectoryExists(ExtractFilePath(FileName)) and TPath.HasValidFileNameChars(ExtractFileName(FileName), false);
end;

  function StringIndex(const aString: String;
                       const aCases: array of String;
                       const aCaseSensitive: Boolean): Integer;
  begin
    if aCaseSensitive then
    begin
      for result := 0 to Pred(Length(aCases)) do
        if ANSISameText(aString, aCases[result]) then
          EXIT;
    end
    else
    begin
      for result := 0 to Pred(Length(aCases)) do
        if ANSISameStr(aString, aCases[result]) then
          EXIT;
    end;

    result := -1;
  end;
function StringToHex(S: String): string;
var I: Integer;
begin
  Result:= '';
  for I := 1 to length (S) do
    Result:= Result+IntToHex(ord(S[i]),2);
end;
function StringToHex16(str: string): string;
var
   i:integer;
   s:string;
begin
       s:='';

       for i:=1 to length(str) do begin
           s:=s+inttohex(Integer(str[i]),4);
       end;
       result:=s;

end;
function HexToString16(const str: string): string;
var
  i: Integer;
  code: string;
begin
  Result := '';
  i := 1;
  while i < Length(str) do begin
    code := Copy(str, i, 4);
    Result := Result + Chr(StrToInt('$' + code));
    Inc(i, 4);
  end;
end;
function HexToString(H: String): String;
var I: Integer;
begin
  Result:= '';
  for I := 1 to length (H) div 2 do
    Result:= Result+Char(StrToInt('$'+Copy(H,(I-1)*2+1,2)));
end;
function IsHex(s: string): boolean;
var
  i: integer;
begin
  Result := True;
  for i := 1 to length(s) do
    if not (char(s[i]) in ['0'..'9']) and not (char(s[i]) in ['A'..'F']) then
    begin
      Result := False;
      exit;
    end;
end;

end.
