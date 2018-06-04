import boto3
import collections
from datetime import datetime
from datetime import timedelta
import csv
from time import gmtime, strftime
import os
import logging
from botocore.exceptions import ClientError
from botocore import exceptions

# Set up logger. Feel free to change the logging format or add a FileHandler per your needs.
# logformat = ('%(asctime)s %(levelname)s [%(name)s] %(message)s')
# logging.basicConfig(level=logging.INFO, format=logformat)
# logger = logging.getLogger()
# logger.info('Starting.')

# Verify AWS CLI access
try:
    sts = boto3.client('sts')
    identity = sts.get_caller_identity()
except exceptions.NoCredentialsError:
    print ("ERROR: AWS CLI is not configured.")
    exit(1)
except ClientError as e:
    if e.response['Error']['Code'] == 'ExpiredToken' or 'InvalidClientTokenId':
        print ("ERROR: AWS security token has expired, please renew and try again.")
        exit(1)
    else:
        print ("ERROR: Unexpected error - ",e)
        exit(1)

# Find current owner ID
sts = boto3.client('sts')
identity = sts.get_caller_identity()
ownerId = identity['Account']

# Environment Variables
LIST_SNAPSHOTS_WITHIN_THE_LAST_N_DAYS="7"

# Constants
MAIL_SUBJECT="AWS Inventory for " + ownerId
MAIL_BODY=MAIL_SUBJECT + '\n'


# EC2 connection beginning
ec = boto3.client('ec2')
# S3 connection beginning
s3 = boto3.resource('s3')

# lambda function beginning
def lambda_handler(event, context):
    # get to the current date
    date_fmt = strftime("%Y_%m_%d-%H%M%S", gmtime())
    print('Audit Started', date_fmt)
    # Give your file path
    filepath ='AWS_Resources_' + date_fmt + '.csv'
    csv_file = open(filepath,'w+')

    print('Scanning Global Ojects')

    # IAM connection beginning
    iam = boto3.client('iam', region_name="us-east-1")

    thedate_fmt = strftime("%d-%m-%Y %H:%M:%S", gmtime())
    csv_file.write("%s %s\n" % ('AWS Inventory for account',ownerId))
    csv_file.write("%s %s\n" % ('Date and time -',thedate_fmt))

    # boto3 library IAM API
    # http://boto3.readthedocs.io/en/latest/reference/services/iam.html
    csv_file.write("%s,%s,%s,%s\n" % ('','','',''))
    csv_file.write("%s,%s\n"%('IAM','REGION : Global'))
    csv_file.write("%s,%s\n" % ('User','Policies'))
    csv_file.flush()
    users = iam.list_users()['Users']
    for user in users:
        user_name = user['UserName']
        policies = ''
        user_policies = iam.list_user_policies(UserName=user_name)["PolicyNames"]
        for user_policy in user_policies:
            if(len(policies) > 0):
                policies += ";"
            policies += user_policy
        attached_user_policies = iam.list_attached_user_policies(UserName=user_name)["AttachedPolicies"]
        for attached_user_policy in attached_user_policies:
            if(len(policies) > 0):
                policies += ";"
            policies += attached_user_policy['PolicyName']
        csv_file.write("%s,%s\n" % (user_name, policies))
        csv_file.flush()
    roles = iam.list_roles()
    csv_file.write("%s,%s,%s,%s\n" % ('','','',''))
    csv_file.write("%s,%s\n"%('IAM ROLES','REGION : Global'))
    csv_file.write("%s\n" % ('RoleName'))
    csv_file.flush()
    # pprint.pprint(roles)
    for role in roles.get('Roles'):
        csv_file.write("%s\n" % (role['RoleName']))

    # S3 Objects
    s3i = boto3.client('s3')
    #http://boto3.readthedocs.io/en/latest/reference/services/s3.html#client
    listbuckets = s3i.list_buckets()
    if len(listbuckets) > 0:
        csv_file.write("%s,%s,%s,%s\n" % ('','','',''))
        csv_file.write("%s,%s\n"%('S3 Buckets','REGION : Global'))
        csv_file.write("%s,%s,%s\n" % ('Name','Public','Has Website'))
        csv_file.flush()
        for bucket_dictionary in listbuckets['Buckets']:
            bucketname = bucket_dictionary['Name']
            is_public = 'unknown'
            has_website = 'unknown'
            try:
                website = s3i.get_bucket_website(Bucket=bucketname)
                has_website = 'yes'
            except ClientError as ce:
                if 'NoSuchWebsiteConfiguration' in ce.args[0]:
                    has_website = 'no'
            bucket_acl_response = s3i.get_bucket_acl(Bucket=bucket_dictionary['Name'])
            for grant in bucket_acl_response['Grants']:
                for (k, v) in grant.items():
                    if k == 'Permission' and any(permission in v for permission in ['READ', 'WRITE']):
                        for (grantee_attrib_k, grantee_attrib_v) in grant['Grantee'].items():
                            if 'URI' in grantee_attrib_k and grant['Grantee']['URI'] == 'http://acs.amazonaws.com/groups/global/AllUsers':
                                is_public = 'yes'
                            else:
                                is_public = 'no'
                    else:
                        is_public = 'no'
            csv_file.write("%s,%s,%s\n" % (bucketname,is_public,has_website))
            csv_file.flush()

    # boto3 library ec2 API describe region page
    # http://boto3.readthedocs.org/en/latest/reference/services/ec2.html#EC2.Client.describe_regions
    regions = ec.describe_regions().get('Regions',[] )
    for region in regions:
        reg=region['RegionName']
        regname='REGION :' + reg
        print('Scanning Region :', reg)
        # EC2 connection beginning
        ec2con = boto3.client('ec2',region_name=reg)
        # boto3 library ec2 API describe instance page
        # http://boto3.readthedocs.org/en/latest/reference/services/ec2.html#EC2.Client.describe_instances
        reservations = ec2con.describe_instances().get(
        'Reservations',[]
        )
        instances = sum(
            [
                [i for i in r['Instances']]
                for r in reservations
            ], [])
        instanceslist = len(instances)
        if instanceslist > 0:
            csv_file.write("%s,%s,%s,%s,%s,%s\n"%('','','','','',''))
            csv_file.write("%s,%s\n"%('EC2 INSTANCE',regname))
            csv_file.write("%s,%s,%s,%s,%s,%s,%s\n"%('InstanceID','Instance_State','InstanceName','Instance_Type','LaunchTime','Instance_Placement', 'SecurityGroupsStr'))
            csv_file.flush()

        for instance in instances:
            state=instance['State']['Name']
            Instancename = 'N/A'
            if 'Tags' in instance:
                    for tags in instance['Tags']:
                        key = tags['Key']
                        if key == 'Name' :
                            Instancename=tags['Value']
            if state =='running':
                instanceid=instance['InstanceId']
                instancetype=instance['InstanceType']
                launchtime =instance['LaunchTime']
                Placement=instance['Placement']['AvailabilityZone']
                securityGroups = instance['SecurityGroups']
                securityGroupsStr = ''
                for idx, securityGroup in enumerate(securityGroups):
                    if idx > 0:
                        securityGroupsStr += '; '
                    securityGroupsStr += securityGroup['GroupName']
                csv_file.write("%s,%s,%s,%s,%s,%s,%s\n"% (instanceid,state,Instancename,instancetype,launchtime,Placement,securityGroupsStr))
                csv_file.flush()

        for instance in instances:
            state=instance['State']['Name']
            Instancename = 'N/A'
            if 'Tags' in instance:
                    for tags in instance['Tags']:
                        key = tags['Key']
                        if key == 'Name' :
                            Instancename=tags['Value']
            if state =='stopped':
                instanceid=instance['InstanceId']
                instancetype=instance['InstanceType']
                launchtime =instance['LaunchTime']
                Placement=instance['Placement']['AvailabilityZone']
                csv_file.write("%s,%s,%s,%s,%s,%s\n"%(instanceid,state,Instancename,instancetype,launchtime,Placement))
                csv_file.flush()

        # boto3 library ec2 API describe volumes page
        # http://boto3.readthedocs.org/en/latest/reference/services/ec2.html#EC2.Client.describe_volumes
        ec2volumes = ec2con.describe_volumes().get('Volumes',[])
        volumes = sum(
            [
                [i for i in r['Attachments']]
                for r in ec2volumes
            ], [])
        volumeslist = len(volumes)
        if volumeslist > 0:
            csv_file.write("%s,%s,%s,%s\n"%('','','',''))
            csv_file.write("%s,%s\n"%('EBS Volume',regname))
            csv_file.write("%s,%s,%s,%s\n"%('VolumeId','InstanceId','AttachTime','State'))
            csv_file.flush()

        for volume in volumes:
            VolumeId=volume['VolumeId']
            InstanceId=volume['InstanceId']
            State=volume['State']
            AttachTime=volume['AttachTime']
            csv_file.write("%s,%s,%s,%s\n" % (VolumeId,InstanceId,AttachTime,State))
            csv_file.flush()

        # boto3 library ec2 API describe snapshots page
        # http://boto3.readthedocs.org/en/latest/reference/services/ec2.html#EC2.Client.describe_snapshots
        ec2snapshot = ec2con.describe_snapshots(OwnerIds=[
            ownerId,
        ],).get('Snapshots',[])
        
        snapshots_counter = 0
        for snapshot in ec2snapshot:
            snapshot_id = snapshot['SnapshotId']
            snapshot_state = snapshot['State']
            tz_info = snapshot['StartTime'].tzinfo
            # Snapshots that were not taken within the last configured days do not qualify for auditing
            timedelta_days=-int(LIST_SNAPSHOTS_WITHIN_THE_LAST_N_DAYS)
            if snapshot['StartTime'] > datetime.now(tz_info) + timedelta(days=timedelta_days):
                if snapshots_counter == 0:
                    csv_file.write("%s,%s,%s,%s,%s\n" % ('','','','',''))
                    csv_file.write("%s,%s\n"%('EC2 SNAPSHOT',regname))
                    csv_file.write("%s,%s,%s,%s,%s\n" % ('SnapshotId','VolumeId','StartTime','VolumeSize','Description'))
                    csv_file.flush()
                snapshots_counter += 1
                SnapshotId=snapshot['SnapshotId']
                VolumeId=snapshot['VolumeId']
                StartTime=snapshot['StartTime']
                VolumeSize=snapshot['VolumeSize']
                Description=snapshot['Description']
                csv_file.write("%s,%s,%s,%s,%s\n" % (SnapshotId,VolumeId,StartTime,VolumeSize,Description))
                csv_file.flush()

        # boto3 library ec2 API describe addresses page
        # http://boto3.readthedocs.org/en/latest/reference/services/ec2.html#EC2.Client.describe_addresses
        addresses = ec2con.describe_addresses().get('Addresses',[] )
        addresseslist = len(addresses)
        if addresseslist > 0:
            csv_file.write("%s,%s,%s,%s,%s\n"%('','','','',''))
            csv_file.write("%s,%s\n"%('EIPS INSTANCE',regname))
            csv_file.write("%s,%s,%s,%s\n"%('PublicIp','AllocationId','Domain','InstanceId'))
            csv_file.flush()
            for address in addresses:
                PublicIp=address['PublicIp']
                try:
                    AllocationId=address['AllocationId']
                except:
                    AllocationId="empty"
                Domain=address['Domain']
                if 'InstanceId' in address:
                    instanceId=address['InstanceId']
                else:
                    instanceId='empty'
                csv_file.write("%s,%s,%s,%s\n"%(PublicIp,AllocationId,Domain,instanceId))
                csv_file.flush()

        def printSecGroup(groupType, permission):
            ipProtocol = permission['IpProtocol']
            try:
                fromPort = permission['FromPort']
            except KeyError:
                fromPort = None
            try:
                toPort = permission['ToPort']
            except KeyError:
                toPort = None
            try:
                ipRanges = permission['IpRanges']
            except KeyError:
                ipRanges = []
            ipRangesStr = ''
            for idx, ipRange in enumerate(ipRanges):
                if idx > 0:
                    ipRangesStr += '; '
                ipRangesStr += ipRange['CidrIp']
            csv_file.write("%s,%s,%s,%s,%s,%s\n"%(groupName,groupType,ipProtocol,fromPort,toPort,ipRangesStr))
            csv_file.flush()

        # boto3 library ec2 API describe security groups page
        # http://boto3.readthedocs.io/en/latest/reference/services/ec2.html#EC2.Client.describe_security_groups
        securityGroups = ec2con.describe_security_groups(
            Filters = [
                {
                    'Name': 'owner-id',
                    'Values': [
                        ownerId,
                    ]
                }
            ]
        ).get('SecurityGroups')
        if len(securityGroups) > 0:
            csv_file.write("%s,%s,%s,%s,%s\n"%('','','','',''))
            csv_file.write("%s,%s\n"%('SEC GROUPS',regname))
            csv_file.write("%s,%s,%s,%s,%s,%s\n"%('GroupName','GroupType','IpProtocol','FromPort','ToPort','IpRangesStr'))
            csv_file.flush()
            for securityGroup in securityGroups:
                groupName = securityGroup['GroupName']
                ipPermissions = securityGroup['IpPermissions']
                for ipPermission in ipPermissions:
                    groupType = 'ingress'
                    printSecGroup (groupType, ipPermission)
                ipPermissionsEgress = securityGroup['IpPermissionsEgress']
                for ipPermissionEgress in ipPermissionsEgress:
                    groupType = 'egress'
                    printSecGroup (groupType, ipPermissionEgress)

        # boto3 library ec2 API describe VPC
        VPCs = ec2con.describe_vpcs().get('Vpcs')
        if len(VPCs) > 0:
            csv_file.write("%s,%s,%s,%s,%s\n"%('','','','',''))
            csv_file.write("%s,%s\n"%('VPC',regname))
            csv_file.write("%s,%s,%s,%s,%s\n"%('VpcId','InstanceTenancy','State','CidrBlock','Tags'))
            csv_file.flush()
            for vpc in VPCs:
                vpcid=vpc['VpcId']
                instancetenancy=vpc['InstanceTenancy']
                state=vpc['State']
                cidr=vpc['CidrBlock']
                tags=vpc.get('Tags','notag')
                csv_file.write("%s,%s,%s,%s,%s\n"%(vpcid,instancetenancy,state,cidr,tags))
                csv_file.flush()

        # Autoscaling
        # http://boto3.readthedocs.io/en/latest/reference/services/autoscaling.html#AutoScaling.Client.describe_auto_scaling_groups
        autoscale = boto3.client('autoscaling',region_name=reg)
        asg = autoscale.describe_auto_scaling_groups().get('AutoScalingGroups')
        if len(asg) > 0:
            csv_file.write("%s,%s,%s,%s\n" %('','','',''))
            csv_file.write("%s :%s\n"%('Autoscaling',regname))
            csv_file.write("%s,%s,%s,%s,%s,%s,%s,%s,%s\n" %(
                    'AutoScalingGroupName','AvailabilityZones','DesiredCapacity','Instances',
                    'LaunchConfigurationName','MaxSize','MinSize','LoadBalancerNames','VPCZoneIdentifier'))
            csv_file.flush()
            for group in asg:
                AutoScalingGroupName    = group['AutoScalingGroupName']
                AvailabilityZones       = group['AvailabilityZones']
                DesiredCapacity         = group['DesiredCapacity']
                Instances               = group['Instances']
                LaunchConfigurationName = group['LaunchConfigurationName']
                MaxSize                 = group['MaxSize']
                MinSize                 = group['MinSize']
                LoadBalancerNames       = group['LoadBalancerNames']
                VPCZoneIdentifier       = group['VPCZoneIdentifier']
                csv_file.write("%s,%s,%s,%s,%s,%s,%s,%s,%s\n" %(
                        AutoScalingGroupName,AvailabilityZones,DesiredCapacity,Instances,
                        LaunchConfigurationName,MaxSize,MinSize,LoadBalancerNames,VPCZoneIdentifier))


        # RDS Connection beginning
        rdscon = boto3.client('rds',region_name=reg)

        # boto3 library RDS API describe db instances page
        # http://boto3.readthedocs.org/en/latest/reference/services/rds.html#RDS.Client.describe_db_instances
        rdb = rdscon.describe_db_instances().get(
        'DBInstances',[]
        )
        rdblist = len(rdb)
        if rdblist > 0:
            csv_file.write("%s,%s,%s,%s\n" %('','','',''))
            csv_file.write("%s,%s\n"%('RDS INSTANCE',regname))
            csv_file.write("%s,%s,%s,%s\n" %('DBInstanceIdentifier','DBInstanceStatus','DBName','DBInstanceClass'))
            csv_file.flush()

        for dbinstance in rdb:
            DBInstanceIdentifier = dbinstance['DBInstanceIdentifier']
            DBInstanceClass = dbinstance['DBInstanceClass']
            DBInstanceStatus = dbinstance['DBInstanceStatus']
            try:
                DBName = dbinstance['DBName']
            except:
                DBName = "empty"
            csv_file.write("%s,%s,%s,%s\n" %(DBInstanceIdentifier,DBInstanceStatus,DBName,DBInstanceClass))
            csv_file.flush()

        # boto3 library dynamoDB API describe_table page
        # http://boto3.readthedocs.io/en/latest/reference/services/dynamodb.html#DynamoDB.Client.describe_table
        dynamodb = boto3.client('dynamodb',region_name=reg)
        ddblist = dynamodb.list_tables().get('TableNames', [])
        if len(ddblist) > 0:
            csv_file.write("%s,%s,%s,%s\n" %('','','',''))
            csv_file.write("%s,%s\n"%('DYNAMODB TABLES',regname))
            csv_file.write("%s,%s,%s\n" %('TableName','TableSizeBytes','ItemCount'))
            csv_file.flush()
            for table in ddblist:
                desctable = dynamodb.describe_table(TableName=table)['Table']
                csv_file.write("%s,%s,%s\n" %(desctable['TableName'],desctable['TableSizeBytes'],desctable['ItemCount']))
                csv_file.flush()  

        # ELB connection beginning
        elbcon = boto3.client('elb',region_name=reg)

        # boto3 library ELB API describe db instances page
        # http://boto3.readthedocs.org/en/latest/reference/services/elb.html#ElasticLoadBalancing.Client.describe_load_balancers
        loadbalancer = elbcon.describe_load_balancers().get('LoadBalancerDescriptions',[])
        loadbalancerlist = len(loadbalancer)
        if loadbalancerlist > 0:
            csv_file.write("%s,%s,%s,%s\n" % ('','','',''))
            csv_file.write("%s,%s\n"%('ELB INSTANCE',regname))
            csv_file.write("%s,%s,%s,%s\n" % ('LoadBalancerName','DNSName','CanonicalHostedZoneName','CanonicalHostedZoneNameID'))
            csv_file.flush()

        for load in loadbalancer:
            LoadBalancerName=load['LoadBalancerName']
            DNSName=load['DNSName']
            CanonicalHostedZoneName=load['CanonicalHostedZoneName']
            CanonicalHostedZoneNameID=load['CanonicalHostedZoneNameID']
            csv_file.write("%s,%s,%s,%s\n" % (LoadBalancerName,DNSName,CanonicalHostedZoneName,CanonicalHostedZoneNameID))
            csv_file.flush()

        

    date_fmt = strftime("%Y_%m_%d", gmtime())
    # Give your file path
    filepath ='/tmp/AWS_Resources_' + date_fmt + '.csv'
    enddate_fmt = strftime("%Y_%m_%d-%H%M%S", gmtime())
    print('Audit Complete', enddate_fmt)

if __name__ == '__main__':
    lambda_handler(None, None)
