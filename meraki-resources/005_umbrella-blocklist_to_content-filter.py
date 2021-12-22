#!/usr/bin/env python3
"""GET Umbrella Custom  Block List and add to the Meraki MX Content Filter

This script GETs the Umbrella Custom Block list and then Meraki API to GET the
Group Policy from each Network in your Organization. After that, it adds each entry in the
Umbrella Block List to the Content Filter of each Meraki Group Policy.

This script requires that the noted below imports are installed
    within the Python 3 environment you execute this script inside.

This file can be imported as a module and contains the following
functions:

    * import_APIkey - imports API keys from the designated config file
    * get_orgIDs - gathers Meraki Organization IDs and adds them to a list
    * add_netIDs - gathers Meraki Network IDs and adds them as values to an org dict
    * get_gPolicies - GETs and returns the group policies for a specified network
    * get_umbrella_custom_blocklist - GETs umbrella management custom_blocklist
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
import base64
import configparser
import json
import meraki
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
    parser.add_argument("-bl", "--blocklist", default="custom_block", type=str,
                        help="provide the custom blocklist with default as custom_block")
    parser.add_argument("-c", "--config", default=os.path.join(os.path.expanduser("~"),
                        ".cisco","api_keys","learning_labs_API.cfg"), type=str,
                        help="provide the configuration file containing API keys with default \
                            as ~/.cisco/api_keys/learning_labs_API.cfg")
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


def get_umbrella_custom_dest_list(api_keys_config, dest_list_name):
    """GETs umbrella enforcement custom blocklist
        Parameters
    ----------
    api_keys : dict
        The set of api_keys to pull out network and management API key and secrets
    dest_list_name : list
        The list of destinations in the specified destination list

    Returns
    -------
    domains_list : list
        The list of destinations in the specified destination list
    """
    # first set up the network API (needs to be base64 encoded)
    # base64-encode the umbrella network api key:secret
    net_key = api_keys_config["umb"]["net_key"]
    net_secret = api_keys_config["umb"]["net_secret"]
    net_creds_string = f'{net_key}:{net_secret}'
    net_creds_bytes = net_creds_string.encode('ascii')
    base64_bytes = base64.b64encode(net_creds_bytes)
    network_b64_token = base64_bytes.decode('ascii')

    # put together umbrella request to get the organization ID with network API and store it
    headers = {'Content-Type':'application/json',
        'Accept': 'application/json',
        'Authorization': f'Basic {network_b64_token}'
    }
    payload = None
    url = "https://management.api.umbrella.com/v1/organizations"
    org_response = requests.request('GET', url, headers = headers, data = payload)

    # sys.exit in case we don't get a status code of 200 (success)
    if org_response.status_code != 200:
        print(f'The request to gather the list of organizations exited with status: \
{org_response.status_code}, {json.loads(org_response.text)["message"]}')
        sys.exit(1)

    # save the org_id to a variable for cleaner code below
    org_id = org_response.json()[0]['organizationId']

    # then set up the management API key (needs to be base64 encoded)
    # base64-encode the umbrella management api key:secret
    mgmt_key = api_keys_config["umb"]["mgmt_key"]
    mgmt_secret = api_keys_config["umb"]["mgmt_secret"]
    mgmt_creds_string = f'{mgmt_key}:{mgmt_secret}'
    mgmt_creds_bytes = mgmt_creds_string.encode('ascii')
    base64_bytes = base64.b64encode(mgmt_creds_bytes)
    management_b64_token = base64_bytes.decode('ascii')

    # put together umbrella request to get the list of custom destination blocklists
    headers = {'Content-Type':'application/json',
        "Accept": "application/json",
        'Authorization': f'Basic {management_b64_token}'
    }
    payload = None
    url = f"https://management.api.umbrella.com/v1/organizations/{org_id}/destinationlists"
    org_blocklists_response = requests.request('GET', url, headers = headers, data = payload)

    # sys.exit in case we don't get a status code of 200 (success)
    if org_blocklists_response.status_code != 200:
        print(f'The request to gather the list of destinations exited with status code \
{org_blocklists_response.status_code}, {org_blocklists_response.json()["message"]}')
        sys.exit(1)

    # figure out if the custom destination list we want is contained in the destination lists
    # pull the json out of the response
    destination_lists = org_blocklists_response.json()['data']
    dest_list_id = dest_list_name
    for org_list in destination_lists:
        if org_list['name'] == dest_list_id:
            dest_list_id = org_list['id']
    if dest_list_id == dest_list_name:
        print(f"{dest_list_name} does not exist. Please choose another list to import.")
        sys.exit(1)

    # instantiate the domain_list we want to add to meraki's content block
    domain_list = []
    # keep doing GET requests, until looped through all domains
    # set up initial requests GET
    headers = {'Content-Type':'application/json',
        "Accept": "application/json",
        'Authorization': f'Basic {management_b64_token}'
    }
    payload = None
    url = f"https://management.api.umbrella.com/v1/organizations/{org_id}/destinationlists/{dest_list_id}/destinations"


    # if there is more than one page, loop through them (h/t chrivand@cisco.com)
    while True:
        dest_list_response = requests.request('GET', url, headers = headers, data = payload)
        # sys.exit in case we don't get a status code of 200 (success)
        if dest_list_response.status_code != 200:
            print(f'The request to gather the list of destinations exited with status code \
{dest_list_response.status_code}, {dest_list_response.json()["message"]}')
            sys.exit(1)
        dest_list_response_json = dest_list_response.json()
        for row in dest_list_response_json["data"]:
            domain_list.append(row["destination"])
        # GET requests will only list 200 domains, if more than that
        # it will request next bulk of 200 domains
        if "next" in dest_list_response_json["meta"]:
            url = dest_list_response_json["meta"]["next"]
        # break out of loop when finished
        else:
            break


    return domain_list


def get_org_ids(api_key):
    """Gathers Meraki Organization IDs and adds them to a list

    Parameters
    ----------
    api_key : str
        the Meraki API key

    Returns
    -------
    org_ids : list
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
        networks_in_organization = dashboard.organizations.getOrganizationNetworks(org)
        net_list = []
        for net in networks_in_organization:
            net_list.append(net['id'])
        org_dict[org] = net_list


def get_group_policies(api_key, net_id):
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
    group_policy = dashboard.networks.getNetworkGroupPolicies(net_id)

    # return group policies within the network
    return group_policy


def update_group_policy(api_key, net_id, group_policy, dest_list):
    """PUTs the modified group policy

    Parameters
    ----------
    api_key : str
        The Meraki API key
    net_id : str
        UID of the Network
    group_policy : json
        json object containing the group policy
    dest_list : list
        list containing URLs to update group policy

    Returns
    -------
    none
    """
    # extend the patterns list with the destination list
    # patterns = group_policy['contentFiltering']['blockedUrlPatterns']['patterns']
    # patterns.extend(dest_list)
    for dest in dest_list:
        if dest not in group_policy['contentFiltering']['blockedUrlPatterns']['patterns']:
            group_policy['contentFiltering']['blockedUrlPatterns']['patterns'].append(dest)
        else:
            pass

    group_policy['contentFiltering']['blockedUrlPatterns']['settings'] = 'append'
    # finally PUT the modified group policy back where we found it using the same format:
    #response = dashboard.networks.updateNetworkGroupPolicy(
    # network_id, group_policy_id,
    # name='No video streaming',
    # scheduling={'enabled': True, 'monday': {'active': True, 'from': '9:00', 'to': '17:00'}, 'tuesday': {'active': True, 'from': '9:00', 'to': '17:00'}, 'wednesday': {'active': True, 'from': '9:00', 'to': '17:00'}, 'thursday': {'active': True, 'from': '9:00', 'to': '17:00'}, 'friday': {'active': True, 'from': '9:00', 'to': '17:00'}, 'saturday': {'active': False, 'from': '0:00', 'to': '24:00'}, 'sunday': {'active': False, 'from': '0:00', 'to': '24:00'}},
    # bandwidth={'settings': 'custom', 'bandwidthLimits': {'limitUp': 1000000, 'limitDown': 1000000}},
    # firewallAndTrafficShaping={'settings': 'custom', 'trafficShapingRules': [{'definitions': [{'type': 'host', 'value': 'google.com'}, {'type': 'port', 'value': '9090'}, {'type': 'ipRange', 'value': '192.1.0.0'}, {'type': 'ipRange', 'value': '192.1.0.0/16'}, {'type': 'ipRange', 'value': '10.1.0.0/16:80'}, {'type': 'localNet', 'value': '192.168.0.0/16'}], 'perClientBandwidthLimits': {'settings': 'custom', 'bandwidthLimits': {'limitUp': 1000000, 'limitDown': 1000000}}, 'dscpTagValue': 0, 'pcpTagValue': 0}], 'l3FirewallRules': [{'comment': 'Allow TCP traffic to subnet with HTTP servers.', 'policy': 'allow', 'protocol': 'tcp', 'destPort': '443', 'destCidr': '192.168.1.0/24'}], 'l7FirewallRules': [{'policy': 'deny', 'type': 'host', 'value': 'google.com'}, {'policy': 'deny', 'type': 'port', 'value': '23'}, {'policy': 'deny', 'type': 'ipRange', 'value': '10.11.12.00/24'}, {'policy': 'deny', 'type': 'ipRange', 'value': '10.11.12.00/24:5555'}]},
    # contentFiltering={'allowedUrlPatterns': {'settings': 'network default', 'patterns': []}, 'blockedUrlPatterns': {'settings': 'append', 'patterns': ['http://www.example.com', 'http://www.betting.com']}, 'blockedUrlCategories': {'settings': 'override', 'categories': ['meraki:contentFiltering/category/1', 'meraki:contentFiltering/category/7']}},
    # splashAuthSettings='bypass',
    # vlanTagging={'settings': 'custom', 'vlanId': '1'},
    # bonjourForwarding={'settings': 'custom', 'rules': [{'description': 'A simple bonjour rule', 'vlanId': '1', 'services': ['All Services']}]}
    # )
    #
    dashboard = meraki.DashboardAPI(api_key)
    # response = dashboard.networks.updateNetworkGroupPolicy(net_id, group_policy['groupPolicyId'], contentFiltering={'blockedUrlPatterns':{'patterns':patterns}})
    response = dashboard.networks.updateNetworkGroupPolicy(net_id, group_policy['groupPolicyId'],
        contentFiltering=group_policy['contentFiltering']
    )


if __name__ == "__main__":
    # parse the CLI arguments
    cli_arguments = parse_cli_arguments()
    api_keys = import_api_key(cli_arguments.config)

    # pull umbrella custom blocklist with name defined either in the command-line or the default
    umbrella_dest_list = get_umbrella_custom_dest_list(api_keys, cli_arguments.blocklist)

    # The following lines build a dictionary of group policies
    # from organizations and associated networks.
    meraki_orgs_and_nets = get_org_ids(api_keys["meraki"]["key"])
    add_net_ids(api_keys["meraki"]["key"], meraki_orgs_and_nets)
    for organization in meraki_orgs_and_nets:
        for network in meraki_orgs_and_nets[organization]:
            gp = get_group_policies(api_keys["meraki"]["key"], network)
            # and finally take the entries from the custom destination list and apply them
            # to group policies with policy['contentFiltering']['blockedUrlPatterns']['patterns']
            for policy in gp:
                update_group_policy(api_keys["meraki"]["key"], network, policy, umbrella_dest_list)
