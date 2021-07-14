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
from datetime import datetime
import os
import webexteamssdk
import time

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
    print(f"Succesfully blocked {domain}!\n")

def create_thousandeyes_instant_test(username, api_token, test_url, test_name, no_of_reruns, time_between_reruns, aid=None):
    api = teapi.ThousandEyesApi(username, api_token, log_level=50)
    # Get all Endpoint agent labels and find the ID of the 'All Agents' label.
    response_json = api.get("groups/endpoint-agents", aid=aid)
    label_id = None
    for label in response_json["groups"]:
        if label["name"] == "All agents":
            label_id = label["groupId"]
    # Create an Entpoind agent Instant HTTP test against the target URL
    test_payload = {
        "testName": test_name,
        "url": f"https://{test_url}",
        "groupId": label_id,
        "httpTimeLimit": 5000,
        "targetResponseTime": 3000,
        "maxMachines": 100,
        "sslVersion": 0,
        "verifyCertHostname": 1,
    }
    try:
        response_json = api.post("endpoint-instant/http-server", test_payload, aid=aid)
        if (
            "endpointTest" in response_json
            and "testName" in response_json["endpointTest"][0]
        ):
            test_id = response_json["endpointTest"][0]["testId"]
            print(f"Endpoint agent instant test {response_json['endpointTest'][0]['testName']} with ID {test_id} created.\n")
        else:
            print("Failed to create the test:")
            pprint.pprint(response_json)
    # error handling
    except teapi.HTTPResponseError as e:
        if e.status:
            print(f"HTTP Error {e.status} ({e.request_url})")
        if e.request_body:
            print(f"Request Body:\n {e.request_body}")
        if e.response_body:
            print(f"Response Body:\n {e.response_body}")
        return

    # rerun test for as many times as set in config.json file
    reruns_to_go = no_of_reruns - 1
    while reruns_to_go > 0:
        print(f"Waiting {time_between_reruns}s before a rerun ({reruns_to_go} reruns to go)\n")
        time.sleep(time_between_reruns)
        try:
            print("Running test again.\n")
            response_json = api.post(f"endpoint-instant/{test_id}/rerun", test_payload, aid=aid)
        except teapi.HTTPResponseError as e:
            if e.status:
                print(f"HTTP Error {e.status} ({e.request_url})")
            if e.request_body:
                print(f"Request Body:\n{e.request_body}")
            if e.response_body:
                print(f"Response Body:\n{e.response_body}")
            return
        reruns_to_go -= 1

    # briefly sleeping before retrieving test results (configurable, currently set to 2 minutes)
    print("Waiting 10s to collect test data.\n")
    time.sleep(10)

    # Get all test results
    results = []
    while True:
        # set time window to retrieve test results from
        collect_time = no_of_reruns * time_between_reruns + 300
        #response_json = api.get(f"endpoint-data/tests/web/http-server/{test_id}", get_options={f"window": "{collect_time}s"}, aid=aid)
        response_json = api.get(
            "endpoint-data/tests/web/http-server/%s" % test_id,
            get_options={"window": "%ss" % collect_time},
            aid=aid,
        )
        if (
            "endpointWeb" in response_json
            and "httpServer" in response_json["endpointWeb"]
            and len(response_json["endpointWeb"]["httpServer"]) > 0
        ):
            results += response_json["endpointWeb"]["httpServer"]
            break

        # TODO: Missing pagination handling. If there are too many results, you
        # need to do paginated queries.

        # briefly sleeping before retrieving test results again (configurable, currently set to 30 seconds)
        print("No results yet. Waiting 30s to collect test data.\n")
        time.sleep(30)

    print("Agent                                 Time        URL Reachable")
    domain_reachable = True
    None
    for result in results:
        if result["errorType"] != "None":
            domain_reachable = False
            test_results = f"HTTP[{result['responseCode']}]"
        else:
            test_results = result["errorType"]
        print(f"{result['agentId']} {result['roundId']} Yes: HTTP[{result['responseCode']}]")
    print("\n")

    #return boolean to check if domain is reachable and test results.
    return domain_reachable,test_results

def send_webex_teams_message(webex_text,webex_access_token,webex_room_id):
    teams = webexteamssdk.WebexTeamsAPI(webex_access_token)
    message = teams.messages.create(webex_room_id, markdown=webex_text)


if __name__ == "__main__":

    # [STEP 0] Load config.json file
    open_config()

    #TODO: [STEP 1] SCRIPT TRIGGER AND PARSE OBSERVABLES (e.g. security incident)
    # right now hardcoded
    domain = "internetbadguys.com"

    # [STEP 2] Block domain using the Umbrella Enforcement API
    umb_enf_api_key = config_file['umb_enf_api_key']
    post_umbrella_events(domain, umb_enf_api_key)

    # [STEP 3] Create and retrieve results from instant test with ThousandEyes (NOTE: using endpoint tests now for testing)
    test_url = domain
    test_name = f"Umbrella Policy Enforecement Verifaction for domain: {domain}"

    domain_reachable,test_results = create_thousandeyes_instant_test(config_file['te_username'], config_file['te_api_token'], test_url, test_name, config_file['no_of_reruns'], config_file['time_between_reruns'], aid=None)

    # [STEP 4] Send Webex Teams notification to notify to admins that policy is/isn't enforced
    if domain_reachable == False:
        print(f"✅✅✅ Policy enforced for domain: {domain}! ✅✅✅\n")
        webex_text = f"✅✅✅\n\n---\n**Policy is enforced for domain: {domain}!**\nStatus code: *{test_results}*.\nVerified by Cisco ThousandEyes!\n\n---\n✅✅✅"
        send_webex_teams_message(webex_text,config_file['webex_access_token'],config_file['webex_room_id'])
    else:
        print(f"🚨🚨🚨 Policy NOT enforced for domain: {domain}! 🚨🚨🚨\n")
        webex_text = f"🚨🚨🚨\n\n---\n**Policy is NOT enforced for domain: {domain}!**\n\nTest results: *{test_results}*.\nVerified by Cisco ThousandEyes!\n\n---\n🚨🚨🚨"
        send_webex_teams_message(webex_text,config_file['webex_access_token'],config_file['webex_room_id'])
