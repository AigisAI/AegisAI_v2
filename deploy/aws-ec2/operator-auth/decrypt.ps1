param([Parameter(Mandatory=$true)][string]$Path)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Security
$cipher=[IO.File]::ReadAllBytes($Path)
$entropy=[Text.Encoding]::UTF8.GetBytes('AegisAI-OperatorAuthentication-v1')
$plain=[Security.Cryptography.ProtectedData]::Unprotect($cipher,$entropy,[Security.Cryptography.DataProtectionScope]::CurrentUser)
[Console]::Write([Text.Encoding]::UTF8.GetString($plain))
[Array]::Clear($plain,0,$plain.Length)
