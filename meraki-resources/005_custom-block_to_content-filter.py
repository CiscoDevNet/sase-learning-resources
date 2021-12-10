import json
import sys
import configparser
import requests


def import_APIkeys():
    try:
        config = configparser.ConfigParser()
        config.read('/Users/suddesai/learning_labs_API.cfg')
        APIkey = config
    except:
        print('the script exited when trying to read the configuration file')
        sys.exit(1)
    
    return APIkey

def get_orgIDs(api_key):
    url = "https://api.meraki.com/api/v1/organizations"
    payload = None
    headers = {"Content-Type": "application/json", "Accept": "application/json", "X-Cisco-Meraki-API-Key": api_key}
    response = requests.request('GET', url, headers=headers, data = payload)
    if (response.status_code != 200):
        print(f'the request was unsuccessful because of an error {response.status_code}, specifically: {response.text}')
        sys.exit(1)
    
    org_list = []
    for org in json.loads(response.text):
        org_list.append(org['id'])
    org_IDs = dict.fromkeys(org_list)
    return org_IDs

def add_netIDs(api_key, org_dict):
    for org in org_dict.keys():
        url = f'https://api.meraki.com/api/v1/organizations/{org}/networks'
        payload = None
        headers = {"Content-Type": "application/json", "Accept": "application/json", "X-Cisco-Meraki-API-Key": api_key}
        response = requests.request('GET', url, headers=headers, data = payload)
        if (response.status_code != 200):
            print(f'the request was unsuccessful because of an error {response.status_code}, specifically: {response.text}')
            sys.exit(1)
        net_list = []
        for net in json.loads(response.text):
            net_list.append(net['id'])
        org_dict[org] = net_list

def get_fwRules(api_key, net_id):
    # meraki.getmxl3fwrules(meraki_APIkey,net_ids)
    url = f"https://api.meraki.com/api/v1/networks/{net_id}/groupPolicies"
    payload = None
    headers = {"Content-Type": "application/json", "Accept": "application/json", "X-Cisco-Meraki-API-Key": api_key}
    response = requests.request('GET', url, headers=headers, data = payload)
    if (response.status_code != 200):
        print(f'the request was unsuccessful because of an error {response.status_code}, specifically: {response.text}')
        sys.exit(1)

    # return list of l3 firewall rules
    l3rules = json.loads(response.text)
    return l3rules

if __name__ == "__main__":

    # The following three lines instantiate a dictionary of organizations and associated networks.
    APIkeys = import_APIkeys()
    meraki_OrgsAndNets = get_orgIDs(APIkeys["meraki"]["key"])
    add_netIDs(APIkeys["meraki"]["key"], meraki_OrgsAndNets)


    ### inserting Meraki-provided output to CSV file script here and changing to the requests format ###
    # Set the CSV output file and write a header row
    # output_file = open('mx_fw_rules.csv', mode='w')
    # csv_writer = csv.writer(output_file, escapechar=' ', quoting=csv.QUOTE_NONE)
    # header_row_text = "OrgID, NetID, Comment, Policy, Protocol, Source Port, Source CIDR, Destination Port, Destination CIDR, Syslog Enabled ?"
    # csv_writer.writerow([header_row_text])

    # loop through the dictionary keys (org_id)
    for org_id in meraki_OrgsAndNets.keys():
        # loop through the values for each dictionary key (net_id)
        for net_ids in meraki_OrgsAndNets[org_id]:
            # use the get_fwRules function 
            fw_rules = get_fwRules(APIkeys["meraki"]["keys"], net_ids)
            print("^^^ Full output:", fw_rules)

            # # loop through each firewall rule, create a csv row and write to file
            # for rule in fw_rules:
            #     print("@@@ Print each rule from the GET response:", str(rule))
            #     csv_row = "{0},{1},{2},{3},{4},{5},{6},{7},{8},{9}".format(org_id, net_ids, rule['comment'], rule['policy'], rule['protocol'], rule['srcPort'], rule['srcCidr'], rule['destPort'], rule['destCidr'], rule['syslogEnabled'])
            #     print("### Writing this row to CSV:", csv_row)
            #     csv_writer.writerow([csv_row])

    # output_file.close()
