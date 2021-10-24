import json
import boto3
from botocore.exceptions import ClientError

ec2 = boto3.resource("ec2")
iam = boto3.resource('iam')
ec2_client = boto3.client("ec2")
log_client = boto3.client("logs")
iam_client = boto3.client("iam")

def lambda_handler(event, context):
    role_arn = get_flow_log_role_arn()
    log_group = get_flow_log_group()
    vpcs = get_all_vpcs()
    
    for vpc in vpcs:
        enable_flow_logs(vpc, role_arn, log_group)
def get_all_vpcs():
    return [vpc.id for vpc in list(ec2.vpcs.all())]

def get_flow_log_group(pattern="flow-logs-group", retention_perion=14):
    # Check if log group exist. Use it.
    for log_group in log_client.describe_log_groups()["logGroups"]:
        if pattern in log_group["logGroupName"]:
            print(
                f"Found existing group {log_group['logGroupName']}")
            return log_group["logGroupName"]
    else:
        # Create new log group, if no existing groups
        print("Log group not found. Creating new one!")
        log_client.create_log_group(
            logGroupName=f"{pattern}-{log_client.meta.region_name}"
        )
        log_group_name = log_client.describe_log_groups(
            logGroupNamePrefix=pattern
        )["logGroups"][0]["logGroupName"]
        log_client.put_retention_policy(
            logGroupName=log_group_name,
            retentionInDays=retention_perion
        )
        print(f"New log group is created - {log_group_name}")
        return log_group_name
        
policy_trust_document = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Principal": {
                "Service": "vpc-flow-logs.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
})
flow_logs_policy_document = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams"
            ],
            "Effect": "Allow",
            "Resource": "*"
        }
    ]
})
def get_flow_logs_policy(pattern="flow-logs-policy"):
    for policy in iam_client.list_policies(Scope="Local")["Policies"]:
        if pattern in policy["PolicyName"]:
            print(f"Found existing policy {policy['Arn']}.")
            return policy["Arn"]
    else:
        print("Policy not found. Creating new one!")
        flow_logs_policy = iam_client.create_policy(
            PolicyName=pattern,
            PolicyDocument=flow_logs_policy_document,
            Description="Policy for Flow Logs"
        )
        print(f"New policy is created - {flow_logs_policy['Policy']['Arn']}")
        return flow_logs_policy["Policy"]["Arn"]
def get_flow_log_role_arn(pattern="flow-logs-role"):
    for role in iam_client.list_roles()["Roles"]:
        if pattern in role["RoleName"]:
            print(f"Found existing role {role['Arn']}.")
            return role["Arn"]
    else:
        print("Role not found. Creating new one!")
        new_role = iam_client.create_role(
            RoleName="flow-logs-role",
            AssumeRolePolicyDocument=policy_trust_document
        )
        role = iam.Role('flow-logs-role')
        response1 = role.attach_policy(
            PolicyArn=get_flow_logs_policy()
        )
        print(f"New role is created - {new_role['Role']['Arn']}")
        return new_role["Role"]["Arn"]
def enable_flow_logs(vpc_id, flow_logs_role_arn, log_group):
    try:
        print(
            f"Trying to enable flow logs for {vpc_id},"
            f" using {log_group} log group and role {flow_logs_role_arn}")
        r1 = ec2_client.create_flow_logs(
                DeliverLogsPermissionArn=flow_logs_role_arn,
                LogGroupName=log_group,
                ResourceIds=[vpc_id],
                ResourceType="VPC",
                TrafficType="ALL",
                LogDestinationType="cloud-watch-logs"
            )
    except ClientError as e:
        if e.response['Error']['Code'] == "FlowLogAlreadyExists":
            print(f"Flow logs is already enabled for {vpc_id}\n")
    else:
        print(f"Flow logs is successfully enabled for {vpc_id}\n")
