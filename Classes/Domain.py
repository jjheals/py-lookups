import socket 
import requests 
import json
import whois 
import dns.resolver 

import socket 
import pandas as pd
import requests 
import json
import whois 
import dns.resolver 
import datetime as dt 

class Domain: 
    
    threat_assessment:int
    fqdn:str
    server_ip:str
    registrar:str
    registrant_country:str
    registrant_name:str 
    creation_date:str
    server_country:str
    ns_records:list[str]
    mx_records:list[str]
    txt_records:list[str]
    a_records:list[str]
    aaaa_records:list[str]
    asn:int 
    
    def __init__(self, fqdn:str, server_ip):
        
        # Domain attributes
        self.threat_assessment = -1
        self.fqdn = fqdn
        self.server_ip = server_ip
        self.registrar = "NONE"
        self.registrant_name = "NONE"
        self.registrant_country = "NONE"
        self.creation_date = dt.datetime(year=1900, month=1, day=1)
        self.server_country = "NONE"
        self.ns_records = []
        self.mx_records = []
        self.txt_records = []
        self.a_records = []
        self.aaaa_records = []
        self.asn = "NONE"
        self.__getNetDetails__()
        self.__lookup__()
        
    ''' toString() - format the important information for this domain in a meaningful string format to be printed to the terminal
        :return this domain as a properly formatted (meaningful) string
    '''
    def toString(self) -> str:
        s:str = f"FQDN: {self.fqdn}\n"
        s += f"\tRegistrar: {self.registrar}\n"
        s += f"\tASN: {self.asn}\n"
        s += f"\tServer IP: {self.server_ip}\n"
        s += f"\tServer Country: {self.server_country}\n"
        s += f"\tNS Records: {self.ns_records}\n"
        s += f"\tA Records: {self.a_records}\n"
        s += f"\tMX Records: {self.mx_records}\n"
        return s
    
    ''' to_excel_row() - format this domain as a list to be added to a running excel sheet 
        :return the information for this domain as a list (in the order/format needed by Domain.to_excel()).
    '''
    def to_excel_row(self) -> list: 
        lst:list = []
        
        lst.append(self.threat_assessment)      # Col 1 - threat_assessment
        lst.append(self.fqdn)                   # Col 2 - fqdn
        lst.append(self.fqdn.split('.')[-1])    # Col 3 - tld
        lst.append(self.server_ip)              # Col 4 - server_ip
        lst.append(self.registrar)              # Col 5 - registrar
        lst.append(self.asn)                    # Col 6 - asn
        lst.append(bool(self.mx_records)),      # Col 7 - has_mx
        lst.append(bool(self.a_records))        # Col 8 - has_a
        lst.append(self.registrant_country)     # Col 9 - registrant_country
        lst.append(self.creation_date)          # Col 10 - creation_date
        lst.append(dt.datetime.now().strftime("%Y-%m-%d"))   # Col 11 - date_of_lookup
        
        return lst
    
    ''' domain_to_excel(pathToFile) - add this domain to a running sheet 
        :param pathToFile:str path to the excel file to add the domain to. the file will be created if it does not exist. 
        :return False if error, True if success
    '''
    def domain_to_excel(self, pathToFile) -> bool:
        try: 
            # Check if there is an existing sheet
            try: existingDf:pd.DataFrame = pd.read_excel(pathToFile)
            except: existingDf:pd.DataFrame = pd.DataFrame()
            
            # List of the column names 
            columnNames:list[str] = ['threat_assessment',       # Col 1
                                    'fqdn',                    # Col 2
                                    'tld',                     # Col 3
                                    'server_ip',               # Col 4
                                    'registrar',               # Col 5
                                    'asn',                     # Col 6
                                    'has_mx',                  # Col 7
                                    'has_a',                   # Col 8
                                    'registrant_country',      # Col 9
                                    'creation_date',           # Col 10
                                    'date_of_lookup'           # Col 11
                                    ]
            
            newDf:pd.DataFrame = pd.DataFrame([self.to_excel_row()], columns=columnNames) # Create a new dataframe for this domain
            newDf.reset_index(drop=True)                                            # Drop the index col
            comb:pd.DataFrame = pd.concat([existingDf, newDf], ignore_index=True)   # Combine the two
            comb = comb.drop_duplicates(subset='fqdn', keep='last')                              # Drop duplicates
            comb.to_excel(pathToFile, index=False)                                  # Write to the excel sheet
            
            return True
        
        except Exception as e:
            print(f"ERROR: There was some error saving the domain to the given file at the path {pathToFile}.")
            print(e)
            return False
    
    ''' respToExcel(response) - convert the given response to the respective excel sheets
        :param response a response from the API
        :return bool whether success or not
    ''' 
    def records_to_excel(self, pathToFile) -> bool:        
        try: 
            recordsCols:list[str] = ["fqdn", "record_type", "value", "date_observed"]
            now:str = dt.datetime.now().strftime('%Y-%m-%d')
            
            # List of records
            lor:list = []
            
            # Add all of the records for this domain to lor
            for n in self.ns_records: lor.append([self.fqdn, 'NS', n, now])        # NS records
            for t in self.txt_records: lor.append([self.fqdn, 'TXT', t, now])      # TXT records
            for a in self.a_records: lor.append([self.fqdn, 'A', a, now])          # A records
            for a in self.aaaa_records: lor.append([self.fqdn, 'AAAA', a, now])    # AAAA records
            for m in self.mx_records: lor.append([self.fqdn, 'MX', m, now])        # MX records

            # Create the dataframe
            recordsDf = pd.DataFrame(lor, columns=recordsCols)
                    
            try: existingRecordsData = pd.read_excel(pathToFile, engine="openpyxl")
            except: 
                print("NOTICE: existing records data not found.")
                existingRecordsData = pd.DataFrame(columns=recordsCols)
                
            existingRecordsData.reset_index(drop=True)
            combRecordData = pd.concat([existingRecordsData, recordsDf], ignore_index=True)
            combRecordData.to_excel(pathToFile, index=False) 
                
            return True
        
        except Exception as e: 
            print("ERROR: there was an error saving the records to excel. Exiting program.")
            print(e)
            return False
    
    ''' __lookup__() - lookup the information for this fqdn (whois and DNS)
        :return None
    '''
    def __lookup__(self) -> None: 

        # WhoIs lookup
        try: 
            jsonData = whois.whois(self.fqdn)               # Perform whois lookup
            
            self.ns_records = jsonData['name_servers']      # Get the NS records
            self.registrant_name = jsonData['name']         # Get the registrant name
            self.registrar = jsonData['registrar']          # Get the Registrar
            self.registrant_country = jsonData['country']   # Get the registrant country
            self.creation_date = jsonData['creation_date']  # Get the creation date
        
            if type(self.creation_date) == list: self.creation_date = self.creation_date[0] 
            
        except:
            print(f"ERROR in Domain.__lookup__() retrieving whois information for \"{self.fqdn}\". There could be a network error, or the TLD may be incompatible, or the domain is not registered. \nNOTE: The public whois database sometimes fails to retrieve information for non .COM, .NET, or .EDU domains.")
        
        # DNS Records Lookup
        # Get the A records 
        try: 
            ARecords = dns.resolver.resolve(self.fqdn, 'A')
            for a in ARecords: self.a_records.append(a.address)
        except: pass

        # Get the AAAA records 
        try: 
            AAAARecords = dns.resolver.resolve(self.fqdn, 'AAAA')
            for a in AAAARecords: self.aaaa_records.append(a.address)
        except: pass
        
        # Get the Txt records 
        try: 
            TxtRecords = dns.resolver.resolve(self.fqdn, 'TXT')
            for t in TxtRecords: self.txt_records.append(t)
        except: pass 

        # Get the MX records 
        try:
            mxRecords = dns.resolver.resolve(self.fqdn, 'MX')
            for r in mxRecords: self.mx_records.append(str(r.exchange)[:-1])
        except: pass

    ''' __getNetDetails__() - look up the net/inet details for this fqdn (server ip, asn)
        :return None
    '''
    def __getNetDetails__(self) -> None:
        try:
            # Perform DNS lookup to get the server IP address
            if not self.server_ip:
                try: self.server_ip = socket.gethostbyname(self.fqdn)
                except: pass
                
            url = f"https://ipinfo.io/{self.server_ip}/"
            ip_info = requests.get(url)
            
            try: self.asn = str(ip_info.json()['org']).split(" ")[0]
            except: pass
            
        except (socket.gaierror, Exception) as e:
            print(f"ERROR in Domain.__getNetDetails__(): {e}")
            return None    


