unit UnitUtilitaires;

interface
uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, DCPtiger, DCPsha512, DCPsha256, DCPsha1, DCPripemd160,
  DCPripemd128, DCPmd5, DCPmd4, DCPcrypt2, DCPhaval, DCPtwofish, DCPtea,
  DCPserpent, DCPblockciphers, DCPrijndael, DCPrc4, DCPrc2, DCPice, DCPdes,
  DCPcast128, DCPblowfish, StdCtrls, Buttons, SHFolder,ShlObj,System.IOUtils;

  function IsValidFilename(const FileName: string): boolean;
implementation
function IsValidFilename(const FileName: string): boolean;
begin
  result := DirectoryExists(ExtractFilePath(FileName)) and TPath.HasValidFileNameChars(ExtractFileName(FileName), false);
end;
end.
