#!/usr/bin/env python3
"""GET Meraki MX Layer 3 Firewall Rules with the Meraki API

This script interacts with the Meraki API to GET the L3 Firewall rules
from each Network in your Organization. After GETing the L3 rules,
this script writes them to CSV in the following format:
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
import os.path
import sys

# module imports
import argparse
import configparser
import csv
import meraki


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
    parser.add_argument("-c", "--config", default=os.path.join(os.path.expanduser("~"),
                        ".cisco","api_keys","learning_labs_API.cfg"), type=str,
                        help="provide the configuration file containing API keys with default \
                            as ~/.cisco/api_keys/learning_labs_API.cfg")
    parser.add_argument("-o", "--output", default=os.path.join(os.path.expanduser("~"),
                        "mx_fw_rules.csv"), type=str,
                        help="set the output file path with default as the home directory")
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


def get_org_ids(api_key):
    """Gathers Meraki Organization IDs and adds them to a list

    Parameters
    ----------
    api_key : str
        the Meraki API key

    Returns
    -------
    org_IDs : list
        python list object containing organization UUIDs
    """
    dashboard = meraki.DashboardAPI(api_key, print_console=False)
    organizations = dashboard.organizations.getOrganizations()
    org_list = []

    for org in organizations:
        org_list.append(org['id'])
    org_ids = dict.fromkeys(org_list)

    return org_ids


def add_net_ids(api_key, org_dict):
    """Gathers Meraki Network IDs and adds them as values to the org dict

    Parameters
    ----------
    api_key : str
        The Meraki API key
    org_dict : dict
        python dict object containing organization:[network] object

    Returns
    -------
    none
    """
    for org in org_dict:
        dashboard = meraki.DashboardAPI(api_key, print_console=False)
        networks_in_organization = dashboard.organizations.getOrganizationNetworks(org,
            total_pages='all')
        net_list = []
        for net in networks_in_organization:
            net_list.append(net['id'])
        org_dict[org] = net_list


def get_group_policies(api_key, network_id):
    """GETs and returns the group policies for a specified network

    Parameters
    ----------
    api_key : str
        The Meraki API key
    net_id : num
        UID of the Network

    Returns
    -------
    group_policy : json
        list of json group policy objects in the network
    """
    dashboard = meraki.DashboardAPI(api_key, print_console=False)
    group_policy = dashboard.networks.getNetworkGroupPolicies(network_id)

    # return group policies within the network
    return group_policy


if __name__ == "__main__":
    # parse the CLI arguments
    cli_arguments = parse_cli_arguments()
    # The following three lines instantiate a dictionary of organizations and associated networks.
    meraki_api_key = import_api_key(cli_arguments.config)["meraki"]["key"]
    meraki_orgs_and_nets = get_org_ids(meraki_api_key)
    add_net_ids(meraki_api_key, meraki_orgs_and_nets)

    try:
        # Set the CSV output file and write a header row
        output_file = open(cli_arguments.output, mode='w')
        csv_writer = csv.writer(output_file, escapechar=' ', quoting=csv.QUOTE_NONE)
        header_row_text = "OrgID,NetID,PolicyID,Comment,Policy,Protocol,Source Port,Source CIDR,\
            Destination Port,Destination CIDR,Syslog Enabled ?"
        csv_writer.writerow([header_row_text])
        # loop through the dictionary keys (org_id)
        for org_id in meraki_orgs_and_nets:
            # loop through the values for each dictionary key (net_id)
            for net_id in meraki_orgs_and_nets[org_id]:
                # use the get_group_policies function
                group_policies = get_group_policies(meraki_api_key, net_id)
                # loop through each firewall rule, create a csv row and write to file
                for policy in group_policies:
                    for rule in policy['firewallAndTrafficShaping']['l3FirewallRules']:

                        l3rule = {}
                        l3rule['org'] = org_id
                        l3rule['net'] = net_id
                        l3rule['polID'] = policy['groupPolicyId']
                        # if then else block for all needed csv fields
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

                        # print rules returned, format them, and write to file
                        print("@@@ Print each rule from the GET response:", str(l3rule))
                        csv_row = "{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10}".format(
                            l3rule['org'].strip(), l3rule['net'].strip(), l3rule['polID'].strip(),
                            l3rule['comment'].strip(), l3rule['policy'].strip(),
                            l3rule['protocol'].strip(), l3rule['srcPort'].strip(),
                            l3rule['srcCidr'].strip(), l3rule['destPort'].strip(),
                            l3rule['destCidr'].strip(), l3rule['syslogEnabled'].strip())
                        print("### Writing this row to CSV:", csv_row)
                        csv_writer.writerow([csv_row])

        output_file.close()
    except OSError as err:
        print(f'The error {err} occurred while trying to write firewall rules to CSV.')
        sys.exit(1)
