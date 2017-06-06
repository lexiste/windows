Temporary Password Checker 
Written: 2011.09.09
Updated: 2015.07.21
Author: Todd Fencl [tfencl[at]radial[dot]com]
Mod Author: Todd Fencl

Description: Address an issue that we have where we create accounts and/or reset passwords for accounts that then actually 
never get changed or used. We have the ADUM project that will disable accounts not active for >= 60 days, but we need something
else that will look for accounts with the "Password change at next logon" set and is >= 10 days. If so, we need to disable, 
warn do something to these accounts as well. This is directly addressing a concern of Target, but is a good process and should
help with SAS and PCI as well. 
