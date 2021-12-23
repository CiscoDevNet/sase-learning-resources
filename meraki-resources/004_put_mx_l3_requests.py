#!/usr/bin/env python3
"""GET Meraki MX Layer 3 Firewall Rules with the Meraki API

This script Imports MX L3 outbound firewall rules from CSV file (format below).
Note that if there is a final "default rule" with logging enabled, then a
syslog server needs to be configured on the Network-wide > General page.

CSV File Format:
OrgID, NetID, Comment, Policy, Protocol, Source Port, Source CIDR,
    Destination Port, Destination CIDR, Syslog Enabled ?

This script requires that the noted below imports are installed
    within the Python 3 environment you execute this script inside.

This file can be imported as a module and contains the following
functions:

    * import_APIkey - imports API keys from the designated config file
    * get_orgIDs - gathers Meraki Organization IDs and adds them to a list
    * add_netIDs - gathers Meraki Network IDs and adds them as values to an org dict
    * get_gPolicies - GETs and returns the group policies for a specified network
    * main - the main function of the script


__main__ for this script if run independently:

Parameters
----------
config_file_loc : filename
    absolute path to configuration file

Returns
-------
mx_fw_rules.csv : csv-formatted file
    list of L3 firewall rules for all managed organizations
"""
# standard imports
import argparse
import configparser
import csv
import json
import os
import sys
import textwrap

# module imports
import requests


def parse_cli_arguments():
    """Parses CLI arguments

    Parameters
    ----------
    none

    Returns
    -------
    args : dict
        a dict of cli_argument:cli_value
    """
    # first set up the command line arguments and parse them
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.description = textwrap.dedent("""This script Imports MX L3 outbound firewall rules from \
        CSV file (format below). Note that if there is a final "default rule" with logging enabled, \
        then a syslog server needs to be configured on the Network-wide > General page.\
        \
        CSV File Format:\
        OrgID, NetID, PolicyID, Comment, Policy, Protocol, Source Port, Source CIDR, \
        Destination Port, Destination CIDR, Syslog Enabled ?""")
    parser.add_argument("-c", "--config", default=os.path.join(os.path.expanduser("~"),
                        ".cisco","api_keys","learning_labs_API.cfg"), type=str,
                        help="provide the configuration file containing API keys with default \
                            as ~/.cisco/api_keys/learning_labs_API.cfg")
    parser.add_argument("-i", "--inputfile", default=os.path.join(os.path.expanduser("~"),
                        "mx_fw_rules.csv"), type=str,
                        help="set the input file path with default as the home directory")
    args = parser.parse_args()
    return args


def import_api_key(config_file_path):
    """Imports API keys from the designated config file

    Parameters
    ----------
    config_file_path : str
        the absolute path of the configuration file

    Returns
    -------
    config : configfile object
        configparser parsed configuration file
    """
    try:
        config = configparser.ConfigParser()
        config.read(config_file_path)
    except OSError as err:
        print(f'The script exited with {err} when trying to read the configuration file')
        sys.exit(1)

    return config


if __name__ == '__main__':
    # process CLI arguments
    cli_args = parse_cli_arguments()
    # process api_keys
    api_key = import_api_key(cli_args.config)["meraki"]["key"]

    # Read CSV input file, and skip header row
    input_file = open(cli_args.inputfile)
    csv_reader = csv.reader(input_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
    next(csv_reader, None)
    print(f'Reading file {cli_args.inputfile}')

    # Loop through each firewall rule from CSV file and build PUT data
    fw_rules = []
    for row in csv_reader:
        # OrgID, NetID, PolicyID, Comment, Policy, Protocol, Source Port, Source CIDR,
        # Destination Port, Destination CIDR, Syslog Enabled ?
        rule = dict({'org': row[0].strip(), 'net': row[1].strip(), 'id': row[2].strip(),
            'policy': row[4].strip(), 'protocol': row[5].strip(), 'srcCidr': row[7].strip(),
            'srcPort': row[6].strip(), 'destCidr': row[9].strip(), 'destPort': row[8].strip(),
            'comment': row[3].strip(),
            'syslogEnabled':(row[10] or row[10].strip()=='True' or row[10].strip()=='true')})

        # Append implied "/32" for IP addresses for just one host
        if '/' not in rule['srcCidr'] and rule['srcCidr'].lower() != 'any':
            rule['srcCidr'] += '/32'
        if '/' not in rule['destCidr'] and rule['destCidr'].lower() != 'any':
            rule['destCidr'] += '/32'

        # put the rule into a list for further digestion
        fw_rules.append(rule)
    old_rules = list(fw_rules)

    # create dict out of rules to pull out orgID, netID, and policyID
    # policyID is guaranteed unique for each network
    fw_rules_dict = {}
    for rule in fw_rules:
        org_id = rule.pop('org')
        net_id = rule.pop('net')
        pol_id = rule.pop('id')
        if org_id not in fw_rules_dict:
            fw_rules_dict[org_id] = {}
        if net_id not in fw_rules_dict[org_id]:
            fw_rules_dict[org_id][net_id] = {}
        if pol_id not in fw_rules_dict[org_id][net_id]:
            # after completing necessary checks, add the new rule
            fw_rules_dict[org_id][net_id][pol_id] = [rule]
        else:
            fw_rules_dict[org_id][net_id][pol_id].append(rule)

    print(f'Processed all {len(fw_rules)} rules of file {cli_args.inputfile}')


    # Update MX L3 firewall rules
    print('Attempting update of firewall rules.')
    for org in fw_rules_dict:
        for net in fw_rules_dict[org]:
            for grp_pol in fw_rules_dict[org][net]:
                # Confirm whether changes were successfully made in commit mode by getting status
                # if there was an issue, an exception will be raised by the meraki module
                # set up body and headers for the appropriate API method to PUT group policies
                url = f"https://api.meraki.com/api/v1/networks/{net}/groupPolicies/{grp_pol}"
                payload = f'{{"firewallAndTrafficShaping": {{"l3FirewallRules": {json.dumps(fw_rules_dict[org][net][grp_pol])}}}}}'
                headers = {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "X-Cisco-Meraki-API-Key": api_key
                }
                response = requests.request('PUT', url, headers=headers, data = payload)
                # perform request
                if response.status_code != 200:
                    print(f'the request was unsuccessful because of an error {response.status_code}, specifically: {response.text}')
                    sys.exit(1)
    # if we haven't errored out
    print('Update successful.')
