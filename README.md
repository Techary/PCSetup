# PCSetup
## Baseline PC Setup script

- Download the .ps1 file
- Save to a USB, ensuring the .ps1 extension is kept
- Move USB to client's new PC
- Open powershell as admin  
- CD to location
- run: `powershell.exe -executionpolicy unrestricted .\PCSetup.ps1`

### Does the following:  
  - Removes pre-installed bloatware  
  - Removes any current 365 installations  
  - Installs Chrome  
  - Installs Adobe  
  - Installs Office 365  
  - Installs S1 (if needed)  
  - Sets up, and connects to, a VPN (if needed)  
  - Connects to a domain (If needed)  
  - Installs all currently released windows updates (with no reboot, some may fail)
