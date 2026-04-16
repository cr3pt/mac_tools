rule PowerShellLoader {
 strings:
  $a = "powershell"
  $b = "URLDownloadToFile"
 condition:
  any of them
}
