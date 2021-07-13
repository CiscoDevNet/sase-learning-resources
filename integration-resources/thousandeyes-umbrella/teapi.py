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
ThousandEyes API module

This module provides a higher level abstraction class that allows you to query
the ThousandEyes API. Compared to standard urllib3 it provides a few advantages,
such as transparent handling of throttling mechanisms.

Usage:
  import teapi
  api = teapi.ThousandEyesApi('primoz@thousandeyes.com', 'API_TOKEN');

  tests = api.get('tests');
  cool_dashboard = api.get('dashboards/6082b053f8b2f30d282b9c62', api_version=7);

  body = {"interval": 300, "agents": [{"agentId":4532}], "testName": "New Test",
          "server": "www.thousandeyes.com", "port": 80}
  api.post('tests/agent-to-server/new', body);

API Documentation:
  https://developer.thousandeyes.com/
"""

__version__ = "0.1"
__author__ = "Primož Sečnik Kolman <primoz@cisco.com>"
__contributors__ = [
    "Rob Franz <robfranz@cisco.com>",
    "Ron Rodriguez <ronrodr@cisco.com>",
    "Primož Sečnik Kolman <primoz@cisco.com>",
]
__copyright__ = "Copyright (c) 2021 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.1"


import logging
import json
import base64
import time
import math
import threading

import certifi
import urllib3, urllib3.util.retry
from urllib.parse import urlencode
from random import randint


class ThousandEyesApi:
    """
    ThousandEyesApi class provides methods to interact with the ThousandEyes API.

    Attributes
    ----------
    email : str
        ThousandEyes platform user account

    api_token : str
        ThousandEyes platform user API token

    Methods
    -------
    test_api_connection()
        Test the connection to the ThousandEyes API
    get(query, get_options = {}, api_version=None, aid=None)
        Performs a GET request to the ThousandEyes API
    post(self, query, body, get_options=None, api_version=None, aid=None)
        Performs POST HTTP request to desired API endpoint and returns JSON data
    """

    hostname = "api.thousandeyes.com"
    default_api_version = 6

    def __init__(
        self,
        username,
        api_token,
        auth_type=None,
        timeout=None,
        http_pool_size=None,
        proxy_username=None,
        proxy_password=None,
        proxy_address=None,
        proxy_type=None,
        user_agent=None,
        keep_alive=True,
        retries=10,
        retry_on_error=False,
        log_level=logging.INFO,
        stg=False,
    ):

        self.username = username
        self.api_token = api_token
        self.timeout = timeout
        self.proxy_username = proxy_username
        self.proxy_password = proxy_password
        self.proxy_address = proxy_address
        self.proxy_type = proxy_type
        self.user_agent = user_agent
        if user_agent is None:
            self.user_agent = "ThousandEyesApi Python/" + __version__
        self.keep_alive = keep_alive
        self.retry = urllib3.util.retry.Retry(
            total=retries, connect=None, read=None, redirect=None, status=None
        )
        self.retry_on_error = retry_on_error
        self.logger = logging.getLogger()
        if log_level is not None:
            self.logger.setLevel(log_level)
            logging.getLogger("urllib3").setLevel(log_level)
        if stg is True:
            self.hostname = "api.stg.thousandeyes.com"

        self.__rate_limit = 1
        self.__rate_limit_remaining = 1
        self.__rate_limit_reset = 0
        self.__rate_limit_hard_keep = (
            0.05  # Always keep 5% of calls in the end, this is dynamic and
            # increases for 2% with each 429, up to 30%
        )
        self.__rate_limit_hard_keep_update = (
            0  # Ensures __rate_limit_hard_keep is only increased once per rate period
        )

        self.auth_type = auth_type
        if auth_type is None:
            self.auth_type = "basic"

        self.https_pool = None

        self.http_pool_size = http_pool_size
        if http_pool_size is None:
            self.http_pool_size = 50

        headers = None
        if self.auth_type == "basic":
            headers = self.__headers(
                username=self.username,
                auth_token=self.api_token,
                keep_alive=self.keep_alive,
                user_agent=self.user_agent,
                proxy_username=self.proxy_username,
                proxy_password=self.proxy_password,
            )
        elif self.auth_type == "oauth":
            headers = self.__headers(
                oauth_token=self.api_token,
                keep_alive=self.keep_alive,
                user_agent=self.user_agent,
            )

        try:
            if self.proxy_address is not None and self.proxy_type is not None:
                from urllib3 import make_headers

                proxy_headers = None
                if self.proxy_username is not None and self.proxy_password is not None:
                    proxy_headers = make_headers(
                        proxy_basic_auth=self.proxy_username + ":" + self.proxy_password
                    )

                if self.proxy_type == "http":
                    self.https_pool = urllib3.ProxyManager(
                        self.proxy_address,
                        maxsize=self.http_pool_size,
                        timeout=self.timeout,
                        proxy_headers=proxy_headers,
                        headers=headers,
                        cert_reqs="CERT_REQUIRED",
                        ca_certs=certifi.where(),
                        retries=self.retry,
                        block=True,
                    )
            else:
                # create thread-safe pool of connections to api.thousandeyes.com
                self.https_pool = urllib3.HTTPSConnectionPool(
                    self.hostname,
                    port=443,
                    timeout=self.timeout,
                    headers=headers,
                    maxsize=self.http_pool_size,
                    cert_reqs="CERT_REQUIRED",
                    ca_certs=certifi.where(),
                    retries=self.retry,
                    block=True,
                )
        except Exception as e:
            self.logger.exception(
                "%s.__init__() - Exception raised: %s" % (self.__class__.__name__, e)
            )

    def test_api_connection(self):
        """
        Tests the connection to the ThousandEyes API

        Returns
        -------
        bool
            True on success, False on failure
        """
        try:
            response_json = self.get("status")
            controller_time = time.strftime(
                "%Y-%m-%d %H:%M:%S",
                time.localtime(response_json.get("timestamp") / 1000),
            )
            self.logger.debug(
                "%s:test_api_connection:: Test successful, controller_time: %s"
                % (self.__class__.__name__, controller_time)
            )
            return True

        except Exception as e:
            self.logger.exception(
                "%s:test_api_connection() - Exception raised: %s"
                % (self.__class__.__name__, e)
            )
            return False

    def get(self, query, get_options=None, api_version=None, aid=None):
        """
        Performs a GET request to the ThousandEyes API

        Parameters
        ----------
        query : str
            API query string, i.e. 'tests' or 'agents'
        get_options : dict, optional
            A dictionary of API query GET options
        api_version : int, optional
            API version to be queried
        aid : int, optional
            ID of the Account Group to be queried

        Returns
        -------
        dict
            API endpoint response payload or None
        """

        if api_version is None:
            api_version = self.default_api_version

        query.replace(".json", "").strip("/")

        if aid is not None:
            if get_options is None:
                get_options = {}
            if type(get_options) is dict:
                get_options["aid"] = aid
            else:
                get_options = get_options + "&aid=" + aid

        if self.https_pool is None:
            headers = None

            if self.auth_type == "basic":
                headers = self.__headers(
                    username=self.username,
                    auth_token=self.api_token,
                    keep_alive=self.keep_alive,
                    user_agent=self.user_agent,
                    proxy_username=self.proxy_username,
                    proxy_password=self.proxy_password,
                )
            elif self.auth_type == "oauth":
                headers = self.__headers(
                    oauth_token=self.api_token,
                    keep_alive=self.keep_alive,
                    user_agent=self.user_agent,
                )

            # set our connection for reuse
            self.logger.info(
                "%s.get(): reinitializing https pool." % self.__class__.__name__
            )
            if self.proxy_address is not None and self.proxy_type is not None:
                from urllib3 import make_headers

                proxy_headers = None
                if self.proxy_username is not None and self.proxy_password is not None:
                    proxy_headers = make_headers(
                        proxy_basic_auth=self.proxy_username + ":" + self.proxy_password
                    )

                if self.proxy_type == "http":
                    self.https_pool = urllib3.ProxyManager(
                        self.proxy_address,
                        num_pools=20,
                        maxsize=self.http_pool_size,
                        timeout=self.timeout,
                        proxy_headers=proxy_headers,
                        headers=headers,
                        cert_reqs="CERT_REQUIRED",
                        ca_certs=certifi.where(),
                        retries=self.retry,
                        block=True,
                    )
            else:
                # create thread-safe pool of connections to api.thousandeyes.com
                self.https_pool = urllib3.HTTPSConnectionPool(
                    self.hostname,
                    port=443,
                    timeout=self.timeout,
                    headers=headers,
                    maxsize=self.http_pool_size,
                    cert_reqs="CERT_REQUIRED",
                    ca_certs=certifi.where(),
                    retries=self.retry,
                    block=True,
                )

        if type(get_options) is dict:
            get_options = urlencode(get_options)
        if get_options is not None:
            req_str = "/v%s/%s.json?%s" % (api_version, query, get_options)
        else:
            req_str = "/v%s/%s.json" % (api_version, query)

        req = None
        throttle_ct = 0

        self.__soft_throttle()

        while True:
            try:
                req = self.https_pool.request(
                    "GET", "https://" + self.hostname + req_str
                )
            except Exception as e:
                if self.retry_on_error is True:
                    rnd = randint(60, 180)
                    self.logger.warning(
                        "%s:get() Exception raised: %s" % (self.__class__.__name__, e)
                    )
                    self.logger.info(
                        "%s::get() failed, repeating in %s seconds: %s"
                        % (self.__class__.__name__, rnd, req_str)
                    )
                    time.sleep(rnd)
                    continue
                else:
                    self.logger.exception(
                        "%s:get() Exception raised: %s" % (self.__class__.__name__, e)
                    )

            if (req is not None) and (req.status == 200):
                # Collect rate limit data from the API, so later calls can enforce soft throttling
                if "X-Organization-Rate-Limit-Limit" in req.headers:
                    self.__rate_limit = int(
                        req.headers["X-Organization-Rate-Limit-Limit"]
                    )
                    self.__rate_limit_remaining = int(
                        req.headers["X-Organization-Rate-Limit-Remaining"]
                    )
                    self.__rate_limit_reset = int(
                        req.headers["X-Organization-Rate-Limit-Reset"]
                    )

                return json.loads(req.data.decode("utf-8"))

            elif (req is not None) and (req.status == 429):
                throttle_ct += 1
                self.__throttle_rate_limit(throttle_ct, req.headers)

            else:
                if req is not None:
                    self.logger.warning(
                        "%s:get() :: GET request failed, HTTP status: %s request: %s"
                        % (self.__class__.__name__, req.status, req_str)
                    )
                    raise HTTPResponseError(req)
                else:
                    self.logger.warning(
                        "%s:get() :: GET request failed. No API response received."
                        % self.__class__.__name__
                    )
                    raise HTTPResponseError(None)

    def post(self, query, body, get_options=None, api_version=None, aid=None):
        """
        Performs a POST request to the ThousandEyes API

        Parameters
        ----------
        query : str
            API query string, i.e. 'tests' or 'agents'
        body : dict
            POST request payload
        get_options : dict, optional
            A dictionary of API query GET options
        api_version : int, optional
            API version to be queried
        aid : int, optional
            ID of the Account Group to be queried

        Returns
        -------
        dict
            API endpoint response payload or None
        """

        if api_version is None:
            api_version = self.default_api_version

        query.replace(".json", "").strip("/")

        if aid is not None:
            if get_options is None:
                get_options = {}
            if type(get_options) is dict:
                get_options["aid"] = aid
            else:
                get_options = get_options + "&aid=" + aid

        if self.https_pool is None:
            headers = None
            if self.auth_type == "basic":
                headers = self.__headers(
                    username=self.username,
                    auth_token=self.api_token,
                    keep_alive=self.keep_alive,
                    user_agent=self.user_agent,
                    proxy_username=self.proxy_username,
                    proxy_password=self.proxy_password,
                )
            elif self.auth_type == "oauth":
                headers = self.__headers(
                    oauth_token=self.api_token,
                    keep_alive=self.keep_alive,
                    user_agent=self.user_agent,
                )

            # set our connection for reuse
            if self.proxy_address is not None and self.proxy_type is not None:
                from urllib3 import make_headers

                proxy_headers = None
                if self.proxy_username is not None and self.proxy_password is not None:
                    proxy_headers = make_headers(
                        proxy_basic_auth=self.proxy_username + ":" + self.proxy_password
                    )

                if self.proxy_type == "http":
                    self.https_pool = urllib3.ProxyManager(
                        self.proxy_address,
                        num_pools=20,
                        maxsize=self.http_pool_size,
                        timeout=self.timeout,
                        proxy_headers=proxy_headers,
                        headers=headers,
                        cert_reqs="CERT_REQUIRED",
                        ca_certs=certifi.where(),
                        retries=self.retry,
                        block=True,
                    )
            else:
                # create thread-safe pool of connections to api.thousandeyes.com
                self.https_pool = urllib3.HTTPSConnectionPool(
                    self.hostname,
                    port=443,
                    timeout=self.timeout,
                    headers=headers,
                    maxsize=self.http_pool_size,
                    cert_reqs="CERT_REQUIRED",
                    ca_certs=certifi.where(),
                    retries=self.retry,
                    block=True,
                )

        if type(body) is dict:
            body = json.dumps(body)
        if type(get_options) is dict:
            get_options = urlencode(get_options)
        if get_options is not None:
            req_str = "/v%s/%s.json?%s" % (api_version, query, get_options)
        else:
            req_str = "/v%s/%s.json" % (api_version, query)

        req = None
        throttle_ct = 0

        while True:
            try:
                req = self.https_pool.request(
                    "POST", "https://" + self.hostname + req_str, body=body
                )
            except Exception as e:
                if self.retry_on_error is True:
                    rnd = randint(60, 180)
                    self.logger.warning(
                        "%s:post() Exception raised: %s" % (self.__class__.__name__, e)
                    )
                    self.logger.info(
                        "%s::post() failed, repeating in %s seconds: %s"
                        % (self.__class__.__name__, rnd, req_str)
                    )
                    time.sleep(rnd)
                    continue
                else:
                    self.logger.exception(
                        "%s:post() Exception raised: %s" % (self.__class__.__name__, e)
                    )

            if req is not None and req.status >= 200 and req.status <= 201:
                try:
                    return json.loads(req.data.decode("utf-8"))
                except json.decoder.JSONDecodeError as e:
                    return req.data
            elif req is not None and req.status == 204:
                return None
            elif (req is not None) and (req.status == 429):
                throttle_ct += 1
                self.__throttle_rate_limit(throttle_ct, req.headers)
            else:
                if req is not None:
                    self.logger.warning(
                        "%s:post() :: POST request failed, HTTP status: %s request: %s\n\tRequest body:\n\t\t%s\n\tResponse body:\n\t\t%s"
                        % (
                            self.__class__.__name__,
                            req.status,
                            req_str,
                            body,
                            req.data.decode("utf-8"),
                        )
                    )
                    raise HTTPResponseError(req, body, req.data)
                else:
                    self.logger.warning(
                        "%:post() :: POST request failed. No API response received."
                        % self.__class__.__name__
                    )
                    raise HTTPResponseError(None)

    def __resp_code(self, status_code):
        """
        Purpose: returns status code from API call
        Inputs:
            status code (integer)
        Returns: API version
        """
        switch = {
            200: "200: OK",
            201: "201: CREATED",
            204: "204: NO CONTENT",
            301: "301: MOVED PERMANENTLY",
            400: "400: BAD REQUEST",
            403: "403: FORBIDDEN",
            404: "404: NOT FOUND",
            405: "405: METHOD NOT ALLOWED",
            406: "406: NOT ACCEPTABLE",
            415: "415: UNSUPPORTED MEDIA TYPE",
            429: "429: TOO MANY REQUESTS",
            500: "500: INTERNAL SERVER ERROR",
            503: "503: SERVICE UNAVIABLE",
        }
        return switch.get(status_code, "UNKNOWN status code")

    def __headers(
        self,
        username=None,
        auth_token=None,
        oauth_token=None,
        keep_alive=True,
        user_agent=None,
        proxy_username=None,
        proxy_password=None,
    ):
        """
        Purpose: utility to build headers for use with HTTP request basic authorization
        Inputs:
            username
            API auth token
        """

        if user_agent is None:
            user_agent = self.user_agent

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": user_agent,
        }

        if username is not None and auth_token is not None:
            credentials = bytes("{}:{}".format(username, auth_token).encode("utf8"))
            encoded = base64.b64encode(credentials)
            headers["Authorization"] = "Basic %s" % encoded.decode("ascii")
        elif oauth_token is not None:
            headers["Authorization"] = "bearer " + oauth_token

        if keep_alive == True:
            headers["Connection"] = "keep-alive"

        return headers

    def __soft_throttle(self):
        """
        This blocking method ensures API queries do not overload the API and let other
        applications use the API without interruption.

        Soft throttle delays the API query for a few seconds if the rate limit
        consumption is not linear, i.e. 6 seconds into the rate limit period there
        should be at least 90% API calls remaining, after 30 seconds there should be at
        least 50% API calls remaining, etc. If consumption is higher, API queries are
        delayed.

        Soft throttle delays the API query until the next rate limit reset if the
        remaining API calls are under 5% (dynamic) of total.
        """

        while True:

            # If there are over 90% absolute calls left, go for it
            if (self.__rate_limit_remaining / self.__rate_limit) >= 0.9:
                return
            # If there are under __rate_limit_hard_keep calls left, sleep until next
            # rate limit reset
            # Add active threads (=likely parallel calls in action) to
            # __rate_limit_hard_keep to ensure other currently running API queries are
            # accounted for
            elif (
                self.__rate_limit_remaining
                + min(self.http_pool_size, threading.active_count())
            ) / self.__rate_limit <= self.__rate_limit_hard_keep:
                sleep_time = randint(1, 5) + math.ceil(
                    self.__rate_limit_reset - time.time()
                )
                if sleep_time < 1:
                    sleep_time = 1
                self.logger.debug(
                    "%s:__soft_throttle() - soft-throttle, %d/%d API calls remaining. "
                    % (
                        self.__class__.__name__,
                        self.__rate_limit_remaining,
                        self.__rate_limit,
                    )
                    + "Normal operations will resume in %d seconds." % sleep_time
                )
                time.sleep(sleep_time)
                return
            # Else, soft throttle to linear consumption
            soft_rate_limit_reset = self.__rate_limit_reset - (
                60 * self.__rate_limit_remaining / self.__rate_limit
            )
            if soft_rate_limit_reset < time.time():
                return

            sleep_time = math.ceil(soft_rate_limit_reset - time.time())
            if sleep_time < 1:
                sleep_time = 1
            self.logger.debug(
                "%s:__soft_throttle() - soft-throttle, %d/%d API calls remaining. "
                % (
                    self.__class__.__name__,
                    self.__rate_limit_remaining,
                    self.__rate_limit,
                )
                + "Normal operations will resume in %d seconds." % sleep_time
            )
            time.sleep(sleep_time)

    def __throttle(self, throttle_ct):
        """
        Purpose: utlity to sleep request thread
        Inputs:
            throttle count
        Returns: (no return)
        """
        # based on exponential backoff

        power = throttle_ct % 8
        sleep_time = 1.5 ** power

        self.logger.info(
            "%s:__throttle:: throttle_ct:%s power:%s sleep_time:%.6f"
            % (self.__class__.__name__, throttle_ct, power, sleep_time)
        )

        time.sleep(sleep_time)

    def __throttle_rate_limit(self, throttle_ct, resp_hdrs):
        """
        Purpose: utility to rate limit/back off
        Inputs:
            throttle count
            HTTP response headers
        Returns: (no return)
        """
        # based on response header rate limit data

        # __rate_limit_hard_keep starts at 5%, but each time 429 is hit increase it for 2%, but no more than 30%
        first = False
        if abs(self.__rate_limit_hard_keep_update - time.time()) > 10:
            self.__rate_limit_hard_keep_update = time.time()
            first = True
            self.__rate_limit_hard_keep += 0.02
            if self.__rate_limit_hard_keep > 0.3:
                self.__rate_limit_hard_keep = 0.3

        if (
            resp_hdrs["X-Organization-Rate-Limit-Limit"] is None
            or resp_hdrs["X-Organization-Rate-Limit-Remaining"] is None
            or resp_hdrs["X-Organization-Rate-Limit-Reset"] is None
        ):
            # Collect rate limit data from the API, so later calls can enforce soft throttling
            self.__rate_limit = 240
            self.__rate_limit_remaining = 0
            # we don't have the data we need, default to exponential backoff
            self.logger.info(
                "%s:__throttle_rate_limit:: resp_hdrs:%s missing attributes"
                % (self.__class__.__name__, resp_hdrs)
            )
            self.__throttle(throttle_ct)
            return

        self.__rate_limit_remaining = int(
            resp_hdrs["X-Organization-Rate-Limit-Remaining"]
        )
        self.__rate_limit_reset = int(resp_hdrs["X-Organization-Rate-Limit-Reset"])

        time_to_next_reset = int(resp_hdrs["X-Organization-Rate-Limit-Reset"]) - int(
            time.time()
        )

        if time_to_next_reset > 0:
            # need to sleep until we can get our limit reset
            # Only put it in INFO log once, the rest should go in DEBUG
            if first:
                self.logger.info(
                    "%s:__throttle_rate_limit() - organization API calls per limit reached. "
                    "Normal operations will resume in %s seconds. "
                    % (self.__class__.__name__, time_to_next_reset % 60)
                    + "Will keep %d%% calls from now on."
                    % (self.__rate_limit_hard_keep * 100)
                )
            else:
                self.logger.debug(
                    "%s:__throttle_rate_limit() - organization API calls per limit reached. "
                    "Normal operations will resume in %s seconds. "
                    % (self.__class__.__name__, time_to_next_reset % 60)
                    + "Will keep %d%% calls from now on."
                    % (self.__rate_limit_hard_keep * 100)
                )

            time.sleep(1 + time_to_next_reset % 60)


class HTTPResponseError(Exception):
    """Raised when ThousandEyesApi.get() or .post() methods cannot handle a HTTP Response code.

    :param response: Response object
    :type response: HTTPResponse
    """

    def __init__(self, response, request_body=None, response_body=None):
        if response is not None:
            self.status = response.status
            if response._request_url is not None:
                self.request_url = response._request_url
        else:
            self.status = 0
        if request_body is not None:
            self.request_body = request_body
        if response_body is not None:
            try:
                self.response_body = json.loads(response_body.decode("utf-8"))
            except json.decoder.JSONDecodeError as e:
                self.response_body = response_body