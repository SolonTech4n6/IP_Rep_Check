import requests
import json
import argparse
import csv
import ipaddress
import regex as re 
import os
from time import sleep
 

# A function to determine if arg -f or -d is set if -d is set recurcivley get and parse filenames from the directory.
def  get_files(args):
    if args.input_file is not None:
        if os.path.isfile(args.input_file):
            file_list = [args.input_file] 
        else:
            print('Please enter a valid file.')
            exit()
    if args.directory is not None:
        if os.path.isdir(args.directory):
            file_list = []
            ext = ('.txt', '.csv', '.log', '.xml', '.json', '.html', '.htm', 'bat', 'ps1', 'psm1', 'psd1', 'ps1xml', 'pssc', 'reg', 'inf', 'config', 'conf', 'cnf', 'config','ini', 'aspx', 'asp')
            for root, dirs, files in os.walk(args.directory):
                for file in files:
                    if file.endswith(ext):
                        file_list.append(os.path.join(root, file))
        else:
            print('Please enter a valid directory path.')
            exit()
    if args.input_file is None and args.directory is None:
        print('Please enter a valid file or directory path.')
        exit()
    return file_list
           

# A function to parse the files, then the lines of the files to a list of valid public IPv4 addresses and IPv6 addresses using regex. find all ipv4 and ipv6 addresses in the lines and add to a list. return the list.  
def parse_files(file_list):
    parsed_ip = []
    for file in file_list:
        with open(file, 'r') as f:
            for line in f:
                ipv4 = re.findall(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])', line)
                for ip in ipv4:
                    if ip not in parsed_ip:
                        parsed_ip.append(ip)                
    return parsed_ip

   
# A function to determine if the IP address is public, remove from parsed_ip if not
def is_public_ip(parsed_ip):
    valid_ips = []
    for ip in parsed_ip:
        try:
            ip_obj = ipaddress.ip_address(ip)
            if not (ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_loopback or
                    ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified):
                valid_ips.append(ip)
        except ValueError:
            pass
    return valid_ips


# A funciton to get a list of API keys from a file named api_keys.txt as key:value pairs and return a dictionary
def get_api_keys():
    with open('api_keys.txt', 'r') as f:
        api_keys = {}
        for line in f:
            (key, val) = line.split(':')
            api_keys[key] = val.strip('\n')
    return api_keys


# A function to request IP address data from the ipqualityscore api and return the response as a python dictionary
def ip_quality_score_lookup(ip, api):
    url = 'https://www.ipqualityscore.com/api/json/ip/' + api['ipqualityscore'] + '/' + ip + '/' + '?strictness=0&allow_public_access_points=true'
    response = requests.get(url)
    ip_quality_response_dict = response.text
    return ip_quality_response_dict


# A function to request data from the abuseipdb api v2 and return the response as a python dictionary
def abuse_ip_lookup(api, ip):
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {'ipAddress':ip, 'maxAgeInDays': '90'}
    headers = {'accept': 'application/json', 'key': api['abuseipdb']}
    response = requests.get(url, headers=headers, params=querystring)
    abuse_response_dict = response.text
    return abuse_response_dict

# A funtion to call the abuse_ip_lookup and ip_quality_score_lookup functions and return the results as a python dictionary limited to 500 requests 4 per minute
def get_ip_data(valid_ips, api, writer, i=0):    
    if i <= 1000:
        for ip in valid_ips:
            abuse_response_dict = abuse_ip_lookup(api, ip)
            ip_quality_response_dict = ip_quality_score_lookup(ip, api)
            i += 1
            write_to_output_file(writer, abuse_response_dict, ip_quality_response_dict)
            sleep(5)
    else:
        print('You have exceeded the maximum number of requests per day.')                  
    return 

# A function to create the output csv file
def create_output_file(args):
    global f
    if args.output_path is not None:
        # A if statement to check if args.o is a directory not a file.
        if os.path.isdir(args.output_path):
            f = open(args.output_path + '/ip_report.csv', 'w', newline='')
            writer = csv.writer(f, delimiter=',')
            csv_header = ["IP Address", "Country Code", "Domain", "Host Names", "ISP", "Usage Type", "Abuse Confidence", "Total Reports", "Proxy", "VPN", "Tor", "Fraud Score", "Bot", "Recent Abuse"]
            writer.writerow(csv_header)
        else:
            print('Please enter a valid directory path.')
            exit()
    if args.output_path is None:
        f = open('ip_report.csv', 'w', newline='')
        writer = csv.writer(f, delimiter=',')
        csv_header = ["IP Address", "Country Code", "Domain", "Host Names", "ISP", "Usage Type", "Abuse Confidence", "Total Reports", "Proxy", "VPN", "Tor", "Fraud Score", "Bot", "Recent Abuse"]
        writer.writerow(csv_header)   
    return writer
        

# Write a function to loop thorugh the parsed_ip list and call the abuse_ip_lookup and virus_total_lookup functions for each IP address and write the results to an csv file
def write_to_output_file(writer, abuse_response_dict, ip_quality_response_dict):
    decodedResponse = json.loads(abuse_response_dict)
    decodedResponse1 = json.loads(ip_quality_response_dict)
    ip = decodedResponse["data"]["ipAddress"]
    countryCode = decodedResponse["data"]["countryCode"]
    domain = decodedResponse["data"]["domain"]
    host = decodedResponse["data"]["hostnames"] 
    isp = decodedResponse["data"]["isp"] 
    usageType = decodedResponse["data"]["usageType"]
    score = decodedResponse["data"]["abuseConfidenceScore"]
    reportNum = decodedResponse["data"]["totalReports"]
    proxy = decodedResponse1["proxy"]
    vpn = decodedResponse1["vpn"]
    tor = decodedResponse1["tor"]
    fraud = decodedResponse1["fraud_score"]
    bot = decodedResponse1["bot_status"]
    RecentAbuse = decodedResponse1["recent_abuse"]
    rowdata = [ip, countryCode, domain, host, isp, usageType, score, reportNum, proxy, vpn, tor, fraud, bot, RecentAbuse]
    writer.writerow(rowdata)  
    return


# Write a main function that calls the other functions in order:
def main():
    parser = argparse.ArgumentParser(description='IPv4 Reputation Check against AbuseIPDB and IP Quaility Score and creates a output file named ip_report.csv.')
    parser.add_argument('-o', '--output_path', help='Path to store the output file ip_report.cvs.')
    parser.add_argument('-f', '--input_file', help='Path to the input file containing IP addresses to check.')
    parser.add_argument('-d', '--directory', help='Path to the driectory containing files to check for ip addresses')
    args = parser.parse_args()  
    parsed_ip = (is_public_ip(parse_files(get_files(args))))
    get_ip_data(parsed_ip, get_api_keys(), create_output_file(args))
    f.close()
    return None
    

__name__ == '__main__'
main()


