import base64
import hashlib
import json
import os

import boto3


def sha256_hash(string):
    # Create a new SHA-256 hash object
    sha256 = hashlib.sha256()
    # Update the hash object with the bytes of the string
    sha256.update(string.encode())
    # Return the hexadecimal representation of the hash
    return sha256.hexdigest()


def lambda_handler(event, context):
    api_key = os.environ.get('PINGSAFE_API_KEY')

    try:
        if event['requestContext']['http']['method'] != "POST":
            return {
                "statusCode": 405,
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": json.dumps({
                    "error": "Method not allowed"
                })
            }

        body = json.loads(event['body'])
        headers = event['headers']

        # verify checksum
        if 'x-pingsafe-checksum' not in headers:
            print("X-PingSafe-Checksum header cannot be found, aborting request")
            return {
                "statusCode": 401,
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": json.dumps({
                    "error": "cannot verify request"
                })
            }

        checksum = headers['x-pingsafe-checksum']
        # For more details refer to https://docs.pingsafe.com/getting-pingsafe-events-on-custom-webhook
        if sha256_hash(f"{body['event']}.{api_key}") != checksum:
            return {
                "statusCode": 403,
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": json.dumps({
                    "error": "checksum verification failed"
                })
            }

        event = base64.b64decode(body['event'])
        input_json = json.loads(event)

        plugin_key = input_json['pluginKey']
        iam = boto3.client('iam')

        if plugin_key == "AWS:IAM:usersPasswordAndKeys":
            iam_usernames = []
            for resource in input_json['newResources']:
                if resource['resourceType'] == 'AWS::IAM::User':
                    iam_usernames.append(resource['resourceId'].split('/')[-1])
                else:
                    print(f"Error: No IAM User found in the event")

            for iam_username in iam_usernames:
                try:
                    response = iam.delete_login_profile(
                        UserName=iam_username
                    )
                    print(f"Deleted login profile for IAM user {iam_username}")

                except Exception as e:
                    print("failed to delete user, error: ", e)

    except Exception as e:
        print("failed to trigger the lambda function, error: ", e)
