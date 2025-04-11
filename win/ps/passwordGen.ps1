function ConvertTo-Rc4ByteStream {
<#
    .SYNOPSIS
        Converts an input byte array to a RC4 cipher stream using the specified key.
        Author: @harmj0y
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None
    .PARAMETER InputObject
        The input byte array to encrypt with the RC4 cipher.
    .PARAMETER Key
        The byte array of the RC4 key to use.
    .EXAMPLE
        $Enc = [System.Text.Encoding]::ASCII
        $Data = $Enc.GetBytes('This is a test! This is only a test.')
        $Key = $Enc.GetBytes('SECRET')
        ($Data | ConvertTo-Rc4ByteStream -Key $Key | ForEach-Object { "{0:X2}" -f $_ }) -join ' '
    .LINK
        https://en.wikipedia.org/wiki/RC4
        http://www.remkoweijnen.nl/blog/2013/04/05/rc4-encryption-in-powershell/
#>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [Byte[]]
        $InputObject,

        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Byte[]]
        $Key
    )

    begin {
        # key-scheduling algorithm
        [Byte[]] $S = 0..255
        $J = 0
        0..255 | ForEach-Object {
            $J = ($J + $S[$_] + $Key[$_ % $Key.Length]) % 256
            $S[$_], $S[$J] = $S[$J], $S[$_]
        }
        $I = $J = 0
    }

    process {
        # pseudo-random generation algorithm (PRGA) combined with XOR logic
        ForEach($Byte in $InputObject) {
            $I = ($I + 1) % 256
            $J = ($J + $S[$I]) % 256
            $S[$I], $S[$J] = $S[$J], $S[$I]
            $Byte -bxor $S[($S[$I] + $S[$J]) % 256]
        }
    }
}


# minimized RC4 function
$R={$D,$K=$Args;$S=0..255;0..255|%{$J=($J+$S[$_]+$K[$_%$K.Length])%256;$S[$_],$S[$J]=$S[$J],$S[$_]};$D|%{$I=($I+1)%256;$H=($H+$S[$I])%256;$S[$I],$S[$H]=$S[$H],$S[$I];$_-bxor$S[($S[$I]+$S[$H])%256]}}


$Enc = [System.Text.Encoding]::ASCII
$UEnc = [System.Text.Encoding]::UNICODE

$Data = $Enc.GetBytes('This is a test! This is only a test.')
$Key = $Enc.GetBytes('SecretPassword')

($Data | ConvertTo-Rc4ByteStream -Key $Key | ForEach-Object { "{0:X2}" -f $_ }) -join ' '

(& $R $data $key | ForEach-Object { "{0:X2}" -f $_ }) -join ' '


$Enc = [System.Text.Encoding]::ASCII
$D = $Enc.GetBytes('This is a test! This is only a test.')
$K = $Enc.GetBytes('SecretPassword')
# *almost* in a single tweet
-join[Char[]]([Text.Encoding]::Unicode|% *es '匤〽⸮㔲㬵⠤匤簩笥䨤⠽䨤␫孓弤⭝䬤⑛╟䬤䌮畯瑮⥝㈥㘵␻孓弤ⱝ匤⑛嵊␽孓䨤ⱝ匤⑛嵟㭽䐤╼⑻㵉⬫䤤㈥㘵␻㵈␨⭈匤⑛嵉┩㔲㬶匤⑛嵉␬孓䠤㵝匤⑛嵈␬孓䤤㭝弤戭潸⑲孓␨孓䤤⭝匤⑛嵈┩㔲崶⁽')|IEX

$domain = "DC=dc2016,DC=com"
$users = Get-ADUser -Filter * -SearchBase $domain 
$key = (Read-Host "k" -AsSecureString)
$str = ""
foreach ($user in $users) {
    $pw = New-Password -Length 12 -Lower -Upper -Digits -Symbols
    $name = $user | Select-Object -expand SamAccountName
    $str += "$name,$pw`n" 
    #Set-ADAccountPassword -Identity $user -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $pw -Force)
}
$ctxt = ([System.Text.Encoding]::ASCII.GetBytes($str) | ConvertTo-Rc4ByteStream -Key ([System.Text.Encoding]::ASCII.GetBytes([System.Net.NetworkCredential]::new("",$key).Password)))
Write-Host ([Convert]::ToBase64String($ctxt))
