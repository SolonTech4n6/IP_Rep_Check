# IP_Rep_Check

This python script parses IPv4 addresses from text based files and submits them to https://www.AbuseIPDB.com and https://www.ipqualityscore.com/ and creates a output file named ip_report.csv.' 

Script Options 

'-o', '--output_path'  - The path to store the output file ip_report.cvs.
'-f', '--input_file' -  The path to the input file containing IP addresses to check.
'-d', '--directory'  The path to the directory containing files to check for IP addresses

The script is currently restricted to the following file types
	*.txt', '.csv', '.log', '.xml', '.json', '.html', '.htm', 'bat', 'ps1', 'psm1', 'psd1', 'ps1xml', 'pssc', 'reg', 'inf', 'config', 'conf', 'cnf', 'config'

Your API keys for AbuseIPDB.com and ipqualitysocre.com need to by added to the api_keys.txt file after the `:` no spaces or quotes `""`   The files needs to be located in the same folder as the script.

The output of the script combines key outputs from the two websites and wirtes the output to the ip_report.cvs and is currrently limited to 1000 IP addresses. 

Example ip_report.csv File Header 

"IP Address", "Country Code", "Domain", "Host Names", "ISP", "Usage Type", "Abuse Confidence", "Total Reports", "Proxy", "VPN", "Tor", "Fraud Score", "Bot", "Recent Abuse"
