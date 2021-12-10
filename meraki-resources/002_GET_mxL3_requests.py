import configparser
import csv
import json
import requests
import sys



def import_APIkey():
    try:
        config = configparser.ConfigParser()
        config.read('/path/to/learning_labs_API.cfg')
    except:
        print('the script exited when trying to read the configuration file')
        sys.exit(1)
    
    return config

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


def get_gPolicies(api_key, net_id):
    # meraki.getmxl3fwrules(meraki_APIkey,net_ids)
    url = f"https://api.meraki.com/api/v1/networks/{net_id}/groupPolicies"
    payload = None
    headers = {"Content-Type": "application/json", "Accept": "application/json", "X-Cisco-Meraki-API-Key": api_key}
    response = requests.request('GET', url, headers=headers, data = payload)
    if (response.status_code != 200):
        print(f'the request was unsuccessful because of an error {response.status_code}, specifically: {response.text}')
        sys.exit(1)
        
    # return list of group policies
    gPolicy = json.loads(response.text)
    return gPolicy

if __name__ == "__main__":

    # The following three lines instantiate a dictionary of organizations and associated networks.
    meraki_APIkey = import_APIkey()["meraki"]["key"]
    meraki_OrgsAndNets = get_orgIDs(meraki_APIkey)
    add_netIDs(meraki_APIkey, meraki_OrgsAndNets)


    ### inserting Meraki-provided output to CSV file script here and changing to the requests format ###
    # Set the CSV output file and write a header row
    output_file = open('/path/to/mx_fw_rules.csv', mode='w')
    csv_writer = csv.writer(output_file, escapechar=' ', quoting=csv.QUOTE_NONE)
    header_row_text = "OrgID,NetID,PolicyID,Comment,Policy,Protocol,Source Port,Source CIDR,Destination Port,Destination CIDR,Syslog Enabled ?"
    csv_writer.writerow([header_row_text])
    # loop through the dictionary keys (org_id)
    for org_id in meraki_OrgsAndNets.keys():
        # loop through the values for each dictionary key (net_id)
        for net_id in meraki_OrgsAndNets[org_id]:
            # use the get_gPolicies function 
            gPolicies = get_gPolicies(meraki_APIkey, net_id)

            # # loop through each firewall rule, create a csv row and write to file
            for policy in gPolicies:
                for rule in policy['firewallAndTrafficShaping']['l3FirewallRules']:
                    
                    l3rule = {}
                    l3rule['org'] = org_id
                    l3rule['net'] = net_id
                    l3rule['polID'] = policy['groupPolicyId']
                    if 'comment' in rule:
                        l3rule['comment'] = rule['comment']
                    else:
                        l3rule['comment'] = 'no comment'
                    if 'policy' in rule:
                        l3rule['policy'] = rule['policy']
                    else:
                        l3rule['policy'] = 'block'
                    if 'protocol' in rule:
                        l3rule['protocol'] = rule['protocol']
                    else:
                        l3rule['protocol'] = 'any'
                    if 'srcPort' in rule:
                        l3rule['srcPort'] = rule['srcPort']
                    else:
                        l3rule['srcPort'] = 'any'
                    if 'srcCidr' in rule:
                        l3rule['srcCidr'] = rule['srcCidr']
                    else:
                        l3rule['srcCidr'] = 'any'
                    if 'destPort' in rule:
                        l3rule['destPort'] = rule['destPort']
                    else:
                        l3rule['destPort'] = 'any'
                    if 'destCidr' in rule:
                        l3rule['destCidr'] = rule['destCidr']
                    else:
                        l3rule['destCidr'] = 'any'
                    if 'syslogEnabled' in rule:
                        l3rule['syslogEnabled'] = rule['syslogEnabled']
                    else:
                        l3rule['syslogEnabled'] = 'false'
               
                    print("@@@ Print each rule from the GET response:", str(l3rule))
                    csv_row = "{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10}".format(l3rule['org'].strip(), l3rule['net'].strip(), l3rule['polID'].strip(), l3rule['comment'].strip(), l3rule['policy'].strip(), l3rule['protocol'].strip(), l3rule['srcPort'].strip(), l3rule['srcCidr'].strip(), l3rule['destPort'].strip(), l3rule['destCidr'].strip(), l3rule['syslogEnabled'].strip())
                    print("### Writing this row to CSV:", csv_row)
                    csv_writer.writerow([csv_row])

    output_file.close()
