import pandas as pd
import socket 
import requests
import json 

class IPAddress: 
    
    value:str
    version:int
    details:dict
    
    def __init__(self, value:str, version:int=4): 
        self.value = value
        self.version = version
        self.dict = {}
    
    def lookup(self, save_to_file:str="") -> None: 
        pass
    
    
    def __getNetDetails__(self) -> dict:
        try:
            # Perform DNS lookup to get the server IP address
            url = f"https://ipinfo.io/{self.value}?token={json.load(open('config/config.json', 'r'))['ipinfo-api-token']}"
            headers = { 
                "Accept": "application/json"
            }
            
            ip_info = requests.get(url, headers=headers)    
            self.dict = ip_info.json()
            
            return self.dict
        except (socket.gaierror, Exception) as e:
            print(f"ERROR in Domain.__getNetDetails__(): {e}")
            return {}