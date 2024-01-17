### Description

This is meant to be a very simple standalone script to do quick lookups for a single domain and to allow for automated data entry into spreadsheets for domain whois and dns records. The overall purpose of this program is to cut down on the time analysts spend performing manual dns and whois lookups and automate the data entry process. 

#### Usage

Configure the config.json file if you want. Then, simply run the main script and enter the FQDN when prompted. The program will perform the lookup, save the results, and print the primary details for the domain. Note that the lookups may take a minute depending on your network connection. 

The program will save the results to the running sheets called 'domain-records.xlsx' and 'tracked-domains.xlsx' within the 'data/' directory for the DNS records and whois records respectively. The new information will be appended to the sheets, assuming they exist. You can change these paths in the main.py script if you want. 

The sheets contain a colunmn for "threat-assessment" - this is indeded to be a placeholder for an anlysts to provide a manual threat assessment for the domains, as the purpose of this program is to simply automate the data entry process, not the threat analysis. 