
from Classes.Domain import Domain

# Get user input
input_domain = input("[+] Enter the domain to lookup:\n")

# Create the domain object and perform the lookup
domain:Domain = Domain(input_domain,"")

# Print the domain as a string
print("\n[+] Results:\n")
print(domain.toString())

# Save the domain and records to the respective excel sheets
domain.domain_to_excel('data/tracked-domains.xlsx')
domain.records_to_excel('data/domain-records.xlsx')

