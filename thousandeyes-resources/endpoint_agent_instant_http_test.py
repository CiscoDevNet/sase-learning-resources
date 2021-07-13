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

"""
An example script that shows how to utilize ThousandEyes API to run an
instant EPA HTTP server test against the target URL of your choice and
print out whether the URL is reachable.
"""

__author__ = "Primož Sečnik Kolman <primoz@cisco.com>"
__contributors__ = [
    "Primož Sečnik Kolman <primoz@cisco.com>",
]
__copyright__ = "Copyright (c) 2021 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.1"


import argparse
import time
import os
import pprint
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/")
import teapi


def main(
    username, api_token, test_url, no_of_reruns=1, time_between_reruns=300, aid=None
):
    api = teapi.ThousandEyesApi(username, api_token, log_level=50)
    # Get all Endpoint agent labels and find the ID of the 'All Agents' label.
    response_json = api.get("groups/endpoint-agents", aid=aid)
    label_id = None
    for label in response_json["groups"]:
        if label["name"] == "All agents":
            label_id = label["groupId"]

    # Create an Endpoint agent instant HTTP test against the target URL
    test_payload = {
        "testName": test_url,
        "url": test_url,
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
            print(
                "Endpoint agent instant test '%s' (%s) created."
                % (response_json["endpointTest"][0]["testName"], test_id)
            )
        else:
            print("Failed to create the test:")
            pprint.pprint(response_json)
    except teapi.HTTPResponseError as e:
        if e.status:
            print("HTTP Error %s (%s)" % (e.status, e.request_url))
        if e.request_body:
            print("Request Body:\n%s" % e.request_body)
        if e.response_body:
            print("Response Body:\n%s" % e.response_body)
        return

    reruns_to_go = no_of_reruns - 1
    while reruns_to_go > 0:
        print(
            "Waiting %ss before a rerun (%s reruns to go)"
            % (time_between_reruns, reruns_to_go)
        )
        time.sleep(time_between_reruns)
        try:
            print("Running test again.")
            response_json = api.post(
                "endpoint-instant/%s/rerun" % test_id, test_payload, aid=aid
            )
        except teapi.HTTPResponseError as e:
            if e.status:
                print("HTTP Error %s (%s)" % (e.status, e.request_url))
            if e.request_body:
                print("Request Body:\n%s" % e.request_body)
            if e.response_body:
                print("Response Body:\n%s" % e.response_body)
            return
        reruns_to_go -= 1

    print("Waiting %ss to collect test data." % 120)
    time.sleep(120)

    # Get all test results
    results = []
    while True:
        collect_time = no_of_reruns * time_between_reruns
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

        print("No results yet. Waiting %ss to collect test data." % 30)
        time.sleep(30)

    print("Agent                                 Time        URL Reachable")
    for result in results:
        reachable = "Yes (HTTP %s)" % result["responseCode"]
        if result["errorType"] != "None":
            reachable = result["errorType"]
        print("%s  %s  %s" % (result["agentId"], result["roundId"], reachable))


if __name__ == "__main__":
    # Parse CLI arguments
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "username",
        help="ThousandEyes Username (hint: don't forget to escape the @ sign with \\@)",
    )
    parser.add_argument(
        "api_token",
        help="ThousandEyes API Token (hint: https://app.thousandeyes.com/account-settings/users-roles/?section=profile)",
    )
    parser.add_argument(
        "test_url",
        help="Test target URL (hint: don't forget to escape the & sign with \\&)",
    )
    parser.add_argument(
        "--aid",
        dest="aid",
        default=None,
        help="Account group ID (default if omitted)",
    )
    parser.add_argument(
        "-n",
        dest="no_of_reruns",
        default=1,
        type=int,
        help="Number of test reruns before returning results (default: 1)",
    )
    parser.add_argument(
        "-t",
        dest="time_between_reruns",
        default=300,
        type=int,
        help="Time to between instant test reruns in seconds. Round it to nearest 300. (default: 300)",
    )
    args = parser.parse_args()

    main(
        args.username,
        args.api_token,
        args.test_url,
        no_of_reruns=args.no_of_reruns,
        time_between_reruns=args.time_between_reruns,
        aid=args.aid,
    )
