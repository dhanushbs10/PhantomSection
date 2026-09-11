param([string]$InputFile)
 $key = 0x55
 $buf = [System.IO.File]::ReadAllBytes($InputFile)
 $enc = [byte[]]::new($buf.Length)
for ($i=0; $i -lt $buf.Length; $i++) { $enc[$i] = $buf[$i] -bxor $key }
[System.IO.File]::WriteAllBytes("payload.bin", $enc)
Write-Host "Encrypted payload saved to payload.bin"