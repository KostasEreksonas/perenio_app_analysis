#!/usr/bin/env python3

import os
import json
import requests

from dotenv import load_dotenv

load_dotenv()

# Load environment variables
PERENIO_USERNAME = os.environ["PERENIO_USERNAME"]
PERENIO_PASSWORD = os.environ["PERENIO_PASSWORD"]
PERENIO_CLIENT_SECRET = os.environ["PERENIO_CLIENT_SECRET"]

def probeUserStatus(email):
    """Check if user with a given username exist on the endpoint"""
    response = requests.post(
        "https://oauth.perenio.com/auth/realms/aaa.kaa/users/registrationStatus",
        headers={
            "tenantid": "perenio",
            "content-type": "application/json; charset=UTF-8",
            "accept-encoding": "gzip",
            "user-agent": "okhttp/4.10.0",
        },
        json={
            "email": email
        }
    )

    response.raise_for_status()
    return response.json()

def loginRequest():
    response = requests.post(
        "https://oauth.perenio.com/auth/realms/aaa.kaa/protocol/openid-connect/token",
        headers={
            "tenantid": "perenio"
        },
        data={
            "username": PERENIO_USERNAME,
            "password": PERENIO_PASSWORD,
            "grant_type": "password",
            "client_id": "perenio-app",
            "client_secret": PERENIO_CLIENT_SECRET,
        }
    )

    response.raise_for_status()
    return response.json()

def getUserInfo(token):
    response = requests.get(
        "https://oauth.perenio.com/auth/realms/aaa.kaa/users/me",
        headers={
            "authorization": f"Bearer {token}",
            "tenantid": "perenio",
            "accept-encoding": "gzip",
            "user-agent": "okhttp/4.10.0"
        },
        data={}
    )

    response.raise_for_status()
    return response.json()

def writeOutput(response, filename):
    """Write response data to JSON file"""
    with open(filename, 'w') as f:
        json.dump(response, f, ensure_ascii=False, indent=4)

def printOutput(response):
    """Print response data to screen"""
    for key,value in response.items():
        print(f"{key}: {value}")

def main():
    loginResponse = loginRequest()

    email = PERENIO_USERNAME
    userProbe = probeUserStatus(email)

    userInfo = getUserInfo(loginResponse["access_token"])

    writeOutput(loginResponse, "loginResponse.json")
    writeOutput(userProbe, "userStatus.json")
    writeOutput(userInfo, "userInfo.json")

    printOutput(loginResponse)
    printOutput(userProbe)
    printOutput(userInfo)

if __name__ == "__main__":
    main()