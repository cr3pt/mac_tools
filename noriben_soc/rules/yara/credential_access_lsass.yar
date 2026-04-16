rule CredentialAccessLsass {
 strings:
  $a = "lsass"
 condition:
  $a
}
