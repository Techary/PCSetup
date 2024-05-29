# PCSetup
## Baseline PC Setup script

- Run `set-executionpolicy unrestricted -force; invoke-webrequest https://raw.githubusercontent.com/Techary/PCSetup/beta/PCSetup.ps1 -outfile PCSetup.ps1; .\PCSetup.ps1`
- Profit

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
