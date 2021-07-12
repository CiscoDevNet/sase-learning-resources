#!/usr/bin/python

"""
Copyright (c) 2021 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at

             https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""

import json
import requests
import teapi
import datetime
import os
import webexteamssdk

def open_config():
    '''
    this function opens config.json
    '''
    if os.path.isfile("config.json"):
        global config_file
        with open("config.json", 'r') as config_file:
            config_file = json.loads(config_file.read())
            print("\nThe config.json file was loaded.\n")
    else:
        print("No config.json file, please make sure config.json file is in same directory.\n")


def post_umbrella_events(domain, api_key):

    url = f"https://s-platform.api.opendns.com/1.0/events?customerKey={api_key}"

    headers={'Content-type': 'application/json', 'Accept': 'application/json'}

    # Time for AlertTime and EventTime when domains are added to Umbrella
    time = datetime.now().isoformat()
    
    payload = {
        "alertTime": time + "Z",
        "deviceId": "ba6a59f4-e692-4724-ba36-c28132c761de",
        "deviceVersion": "13.7a",
        "dstDomain": domain,
        "dstUrl": "http://" + domain + "/",
        "eventTime": time + "Z",
        "protocolVersion": "1.0a",
        "providerName": "Security Platform"
    }

    response = requests.post(url, data=json.dumps(payload), headers=headers)
    response.raise_for_status()

def create_thousandeyes_test(username, api_token, test_url, test_name, aid=None):
    api = teapi.ThousandEyesApi(username, api_token, log_level=50)
    # Get all Endpoint agent labels and find the ID of the 'All Agents' label.
    response_json = api.get("groups/endpoint-agents", aid=aid)
    label_id = None
    for label in response_json["groups"]:
        if label["name"] == "All agents":
            label_id = label["groupId"]

    # Create an Entpoind agent scheduled HTTP test against the target URL
    test_payload = {
        "testName": test_name,
        "url": test_url,
        "groupId": label_id,
        "httpTimeLimit": 5000,
        "targetResponseTime": 3000,
        "maxMachines": 100,
        "sslVersion": 0,
        "verifyCertHostname": 1,
    }
    try:
        response_json = api.post(
            "endpoint-tests/http-server/new", test_payload, aid=aid
        )
    except teapi.HTTPResponseError as e:
        if e.status:
            print("HTTP Error %s (%s)" % (e.status, e.request_url))
        if e.request_body:
            print("Request Body:\n%s" % e.request_body)
        if e.response_body:
            print("Response Body:\n%s" % e.response_body)
        return

    if (
        "endpointTest" in response_json
        and "testName" in response_json["endpointTest"][0]
    ):
        print(
            "Endpoint agent scheduled test '%s' created."
            % response_json["endpointTest"][0]["testName"]
        )
    else:
        print("Failed to create the test:")
        pprint.pprint(response_json)

def send_webex_teams_message(domain,test_results,webex_access_token,webex_room_id):
    teams = webexteamssdk.WebexTeamsAPI(webex_access_token)
    webex_text =f"🚨🚨🚨\n\n---\n**Policy NOT enforced for domain: {domain}!**\n\nTest results: *{test_results}*.\n\n🚨🚨🚨"
    message = teams.messages.create(webex_room_id, markdown=webex_text)


if __name__ == "__main__":

    # [STEP 0] Load config.json file
    open_config()

    #TODO: [STEP 1] SCRIPT TRIGGER AND PARSE OBSERVABLES (e.g. security incident)
    # trigger
    domain = "internetbadguys.com"

    # [STEP 2] Block domain using the Umbrella Enforcement API
    umb_enf_api_key = config_file['umb_enf_api_key']
    post_umbrella_events(domain, umb_enf_api_key)

    # [STEP 3] Create instant test with ThousandEyes (NOTE: using endpoint tests now for testing)
    test_url = domain
    test_name = f"Umbrella Policy Enforecement Verifaction for domain: {domain}"

    create_thousandeyes_test(config_file['te_username'], config_file['te_api_token'], test_url, test_name, aid=None)

    #TODO: [STEP 4] Pull for ThousandEyes test result to confirm policy verification
    # api call for test results and then set boolean if not confirmed
    test_results = json.loads(response.text)
    enforced_confirmed_bool = False


    # [STEP 5] Send Webex Teams notification to notify to admins that policy is NOT enforced (otherwise causing noise)
    if enforced_confirmed_bool == False:
        send_webex_teams_message(domain,test_results,config_file['webex_access_token'],config_file['webex_room_id'])
    else:
        print(f"Policy enforced for domain: {domain}!")
