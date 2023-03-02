import base64
import hashlib
import json
import os

import boto3

API_KEY = os.environ.get('PINGSAFE_API_KEY')

RESPONSE_CODES = {
    "METHOD_NOT_ALLOWED": {
        "statusCode": 405,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": json.dumps({
            "error": "Method not allowed"
        })
    },
    "UNAUTHORIZED_REQUEST": {
        "statusCode": 401,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": json.dumps({
            "error": "Cannot verify request"
        })
    },
    "CHECKSUM_VERIFICATION_FAILED": {
        "statusCode": 403,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": json.dumps({
            "error": "Checksum verification failed"
        })
    },
    "INTERNAL_SERVER_ERROR": {
        "statusCode": 500,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": json.dumps({
            "error": "Something went wrong"
        })
    },
    "ALL_OK": {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": json.dumps({
            "error": "All is well"
        })
    }
}


def sha256_hash(string):
    # Create a new SHA-256 hash object
    sha256 = hashlib.sha256()
    # Update the hash object with the bytes of the string
    sha256.update(string.encode())
    # Return the hexadecimal representation of the hash
    return sha256.hexdigest()


def validate_request(event, body, headers):
    if event['requestContext']['http']['method'] != "POST":
        return False, RESPONSE_CODES['METHOD_NOT_ALLOWED']

    # verify checksum
    if 'x-pingsafe-checksum' not in headers:
        print("X-PingSafe-Checksum header cannot be found, aborting request")
        return False, RESPONSE_CODES['UNAUTHORIZED_REQUEST']

    checksum = headers['x-pingsafe-checksum']
    # For more details refer to https://docs.pingsafe.com/getting-pingsafe-events-on-custom-webhook
    if sha256_hash(f"{body['event']}.{API_KEY}") != checksum:
        return False, RESPONSE_CODES['CHECKSUM_VERIFICATION_FAILED']

    return True, None


def remediate_aws_iam_users_password_and_keys(pingsafe_event):
    iam = boto3.client('iam')
    iam_usernames = []
    for resource in pingsafe_event['newResources']:
        if resource['resourceType'] == 'AWS::IAM::User':
            iam_usernames.append(resource['resourceId'].split('/')[-1])
        else:
            print(f"Error: No IAM User found in the event")

    for iam_username in iam_usernames:
        try:
            iam.delete_login_profile(
                UserName=iam_username
            )
            print(f"Deleted login profile for IAM user {iam_username}")
        except Exception as e:
            print("failed to delete user, error: ", e)


remediation_handlers = {
    'AWS:IAM:usersPasswordAndKeys': remediate_aws_iam_users_password_and_keys
}


def lambda_handler(event, context):
    try:
        body = json.loads(event['body'])
        headers = event['headers']
        valid, response = validate_request(event, body, headers)
        if not valid:
            return response

        event = base64.b64decode(body['event'])
        pingsafe_event = json.loads(event)

        plugin_key = pingsafe_event['pluginKey']

        if plugin_key in remediation_handlers:
            handler = remediation_handlers[plugin_key]
            handler.__call__(pingsafe_event)
        else:
            print(f"Lambda doesn't support remediation for {plugin_key}")
        return RESPONSE_CODES["ALL_OK"]
    except Exception as e:
        print("failed to trigger the lambda function, error: ", e)
        return RESPONSE_CODES["INTERNAL_SERVER_ERROR"]