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
An example script that shows how to utilize ThousandEyes API to compile a comma
separated value list of all Enterprise Agent.
"""

__author__ = "Primož Sečnik Kolman <primoz@cisco.com>"
__contributors__ = [
    "Primož Sečnik Kolman <primoz@cisco.com>",
]
__copyright__ = "Copyright (c) 2021 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.1"


import argparse
import csv
import os
import pprint
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/")
import teapi


def main(username, api_token, test_url, test_name, aid=None):
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
        "test_name",
        help="Test name (hint: don't forget to escape the space with \\s)",
    )
    parser.add_argument(
        "--aid",
        dest="aid",
        default=None,
        help="Account group ID (default if omitted)",
    )
    args = parser.parse_args()

    main(args.username, args.api_token, args.test_url, args.test_name, aid=args.aid)
