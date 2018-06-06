import boto3
import collections
from datetime import datetime
from datetime import timedelta
import csv
from time import gmtime, strftime, time
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
    start_time = time()
    # Give your file path
    filepath ='AWS_Resources_' + date_fmt + '.csv'
    csv_file = open(filepath,'w+')

    print('Scanning Global Ojects : IAM')

    # IAM connection beginning
    iam = boto3.client('iam', region_name="us-east-1")

    thedate_fmt = strftime("%d-%m-%Y %H:%M:%S", gmtime())
    csv_file.write("%s %s\n" % ('AWS Inventory for account',ownerId))
    csv_file.write("%s %s\n" % ('Audit started -',thedate_fmt))

    # boto3 library IAM API
    # http://boto3.readthedocs.io/en/latest/reference/services/iam.html
    users = iam.list_users()['Users']
    if len(users) > 0:
        csv_file.write("%s,%s,%s,%s\n" % ('','','',''))
        csv_file.write("%s,%s\n"%('IAM','REGION : Global'))
        csv_file.write("%s,%s\n" % ('User','Policies'))
        csv_file.flush()
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
    if len(roles) > 0:
        csv_file.write("%s,%s,%s,%s\n" % ('','','',''))
        csv_file.write("%s,%s\n"%('IAM ROLES','REGION : Global'))
        csv_file.write("%s\n" % ('RoleName'))
        csv_file.flush()
        for role in roles.get('Roles'):
            csv_file.write("%s\n" % (role['RoleName']))

    # S3 Objects
    print('Scanning Global Ojects : S3')
    s3i = boto3.client('s3')
    #http://boto3.readthedocs.io/en/latest/reference/services/s3.html#client
    listbuckets = s3i.list_buckets()
    if len(listbuckets) > 0:
        csv_file.write("%s,%s,%s,%s\n" % ('','','',''))
        csv_file.write("%s,%s\n"%('S3 Buckets','REGION : Global'))
        csv_file.write("%s,%s,%s\n" % ('Name','Public','HostingWebsite'))
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
            try:
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
            except ClientError as ce:
                is_public = 'no'
            csv_file.write("%s,%s,%s\n" % (bucketname,is_public,has_website))
            csv_file.flush()

    # Route53 resources
    print('Scanning Global Ojects : Route53')
    r53i = boto3.client('route53')
    hosted_zones = r53i.list_hosted_zones()['HostedZones']
    if len(hosted_zones) > 0:
        csv_file.write("%s,%s,%s,%s\n" % ('','','',''))
        csv_file.write("%s,%s\n"%('Route 53','REGION : Global'))
        csv_file.write("%s,%s,%s\n" % ('ZoneName','PrivateZone','RecordCount'))
        csv_file.flush()
        for zone in hosted_zones:
            zone_name = zone['Name']
            zone_private = zone['Config']['PrivateZone']
            zone_recordcount = zone['ResourceRecordSetCount']
            csv_file.write("%s,%s,%s\n" % (zone_name, zone_private, zone_recordcount))
            csv_file.flush()

    # boto3 library ec2 API describe region page
    # http://boto3.readthedocs.org/en/latest/reference/services/ec2.html#EC2.Client.describe_regions
    regions = ec.describe_regions().get('Regions',[] )
    for region in regions:
        reg=region['RegionName']
        regname='REGION : ' + reg
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

        # VPC Peering
        vpcpeers = ec2con.describe_vpc_peering_connections()['VpcPeeringConnections']
        if len(vpcpeers) > 0:
            csv_file.write("%s,%s,%s,%s\n" % ('','','',''))
            csv_file.write("%s,%s\n"%('VPC Peering',regname))
            csv_file.write("%s,%s,%s,%s,%s\n" % ('SourceOwner','SourceVPCID','DestinationOwner','DestinationVPCID','Status'))
            csv_file.flush()
            for peer in vpcpeers:
                sowner = peer['AccepterVpcInfo']['OwnerId']
                svpcid = peer['AccepterVpcInfo']['VpcId']
                downer = peer['RequesterVpcInfo']['OwnerId']
                dvpcid = peer['RequesterVpcInfo']['VpcId']
                status = peer['Status']['Code']
                csv_file.write("%s,%s,%s,%s,%s\n" % (sowner,svpcid,downer,dvpcid,status))
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

        # Direct Connect
        directconnecti = boto3.client('directconnect',region_name=reg)
        directconnects = directconnecti.describe_connections()['connections']
        if len(directconnects) > 0:
            csv_file.write("%s,%s,%s,%s\n" % ('','','',''))
            csv_file.write("%s,%s\n"%('DirectConnect',regname))
            csv_file.write("%s,%s,%s,%s,%s,%s\n" % ('Name','Status','Region','Location','Bandwidth','PartnerName'))
            csv_file.flush()
            for directconnect in directconnects:
                name = directconnect['connectionName']
                status = directconnect['connectionState']
                region = directconnect['region']
                location = directconnect['location']
                bandwidth = directconnect['bandwidth']
                partnername = directconnect['partnerName']
                csv_file.write("%s,%s,%s,%s,%s,%s\n" % (name,status,region,location,bandwidth,partnername))
                csv_file.flush()

        # Directory Service
        if reg == 'eu-west-3': # TODO: Waiting for Boto3 to update the error handling for DS.
            print ("    INFO: Directory Service is not available in",reg)
        else:
            dsi = boto3.client('ds',region_name=reg)
            dss = dsi.describe_directories()['DirectoryDescriptions']
            if len(dss) > 0:
                csv_file.write("%s,%s,%s,%s\n" % ('','','',''))
                csv_file.write("%s,%s\n"%('Directory Services',regname))
                csv_file.write("%s,%s,%s,%s,%s,%s\n" % ('Name','Status','Type','Edition','LaunchTime','Description'))
                csv_file.flush()
                for ds in dss:
                    dsname = ds['Name']
                    dsstatus = ds['Stage']
                    dstype = ds['Type']
                    dsedition = ds['Edition']
                    dslaunchtime = ds['LaunchTime']
                    dsdescription = ds['Description']
                    csv_file.write("%s,%s,%s,%s,%s,%s\n" % (dsname,dsstatus,dstype,dsedition,dslaunchtime,dsdescription))
                    csv_file.flush()
        
        # Codestar
        try:
            codestari = boto3.client('codestar',region_name=reg)
            csprojects = codestari.list_projects()['projects']
            if len(csprojects) > 0:
                csv_file.write("%s,%s,%s,%s\n" % ('','','',''))
                csv_file.write("%s,%s\n"%('CodeStar',regname))
                csv_file.write("%s,%s\n" % ('ProjectID','ProjectARN'))
                csv_file.flush()
                for project in csprojects:
                    projectid = project['projectId']
                    projectarn = project['projectArn']
                    csv_file.write("%s,%s\n" % (projectid,projectarn))
                    csv_file.flush()
        except exceptions.EndpointConnectionError:
            print ("    INFO: CodeStar is not available in",reg)

        # Code Commit
        cci = boto3.client('codecommit',region_name=reg)
        ccs = cci.list_repositories()['repositories']
        if len(dss) > 0:
            csv_file.write("%s,%s,%s,%s\n" % ('','','',''))
            csv_file.write("%s,%s\n"%('Code Commit',regname))
            csv_file.write("%s,%s\n" % ('Name','RepoID'))
            csv_file.flush()
            for cs in css:
                csname = cs['Name']
                csrepoid = cs['Stage']
                csv_file.write("%s,%s\n" % (csname,csrepoid))
                csv_file.flush()

        # Kinesis
        kinei = boto3.client('kinesis',region_name=reg)
        kines = kinei.list_streams()['StreamNames']
        if len(kines) > 0:
            csv_file.write("%s,%s,%s,%s\n" % ('','','',''))
            csv_file.write("%s,%s\n"%('Kinesis',regname))
            csv_file.write("%s\n" % ('StreamName'))
            csv_file.flush()
            for i in range(len(kines)):
                kinename = kines[i]
                csv_file.write("%s\n" % (kinename))
                csv_file.flush()

        # Data Pipeline
        try:
            dpipei = boto3.client('datapipeline',region_name=reg)
            dpipes = dpipei.list_pipelines()['pipelineIdList']
            if len(dpipes) > 0:
                csv_file.write("%s,%s,%s,%s\n" % ('','','',''))
                csv_file.write("%s,%s\n"%('Data Pipeline',regname))
                csv_file.write("%s,%s\n" % ('Name','ID'))
                csv_file.flush()
                for dp in dpipes:
                    dpname = dp['name']
                    dpid = dp['id']
                    csv_file.write("%s,%s\n" % (dpname,dpid))
                    csv_file.flush()
        except exceptions.EndpointConnectionError:
            print ("    INFO: Data Pipeline is not available in",reg)

        # Cognito
        try:
            cognitoi = boto3.client('cognito-identity',region_name=reg)
            cognitos = cognitoi.list_identity_pools(MaxResults=10)['IdentityPools']
            if len(cognitos) > 0:
                csv_file.write("%s,%s,%s,%s\n" % ('','','',''))
                csv_file.write("%s,%s\n"%('Cognito',regname))
                csv_file.write("%s,%s\n" % ('Name','ID'))
                csv_file.flush()
                for cog in cognitos:
                    cogname = cog['name']
                    cogid = cog['id']
                    csv_file.write("%s,%s\n" % (cogname,cogid))
                    csv_file.flush()
        except exceptions.EndpointConnectionError:
            print ("    INFO: Cognito is not available in",reg)

        # KMS  
        try:
            kmsi = boto3.client('kms',region_name=reg)
            kmss = kmsi.list_keys()['Keys']
            if len(kmss) > 0:
                csv_file.write("%s,%s,%s,%s\n" % ('','','',''))
                csv_file.write("%s,%s\n"%('KMS',regname))
                csv_file.write("%s,%s\n" % ('ARN','ID'))
                csv_file.flush()
                for key in kmss:
                    keyarn = key['KeyArn']
                    keyid = key['KeyId']
                    csv_file.write("%s,%s\n" % (keyarn,keyid))
                    csv_file.flush()
        except exceptions.EndpointConnectionError:
            print ("    INFO: KMS is not available in",reg)

        # Redshift
        try:
            redshifti = boto3.client('redshift',region_name=reg)
            redshifts = redshifti.describe_clusters()['Clusters']
            if len(redshifts) > 0:
                csv_file.write("%s,%s,%s,%s\n" % ('','','',''))
                csv_file.write("%s,%s\n"%('Redshift',regname))
                csv_file.write("%s,%s,%s,%s,%s,%s\n" % ('ID','Type','Status','DBName','NodeCount','Public'))
                csv_file.flush()
                for rs in redshifts:
                    rsid = rs['ClusterIdentifier']
                    rstype = rs['NodeType']
                    rsstatus = rs['ClusterStatus']
                    rsdbname = rs['DBName']
                    rsnodecount = rs['NumberOfNodes']
                    rspublic = rs['PubliclyAccessible']
                    csv_file.write("%s,%s,%s,%s,%s,%s\n" % (rsid,rstype,rsstatus,rsdbname,rsnodecount,rspublic))
                    csv_file.flush()
        except exceptions.EndpointConnectionError:
            print ("    INFO: Redshift is not available in",reg)

        # SNS
        try:
            snsi = boto3.client('sns',region_name=reg)
            snss = snsi.list_topics()['Topics']
            if len(snss) > 0:
                csv_file.write("%s,%s,%s,%s\n" % ('','','',''))
                csv_file.write("%s,%s\n"%('SNS',regname))
                csv_file.write("%s\n" % ('TopicARN'))
                csv_file.flush()
                for sns in snss:
                    snsarn = sns['TopicArn']
                    csv_file.write("%s\n" % (snsarn))
                    csv_file.flush()
        except exceptions.EndpointConnectionError:
            print ("    INFO: SNS is not available in",reg)

        # SQS
        try:
            sqsi = boto3.client('sqs',region_name=reg)
            sqss = sqsi.list_queues()
            if len(sqss) > 0:
                csv_file.write("%s,%s,%s,%s\n" % ('','','',''))
                csv_file.write("%s,%s\n"%('SQS',regname))
                csv_file.write("%s\n" % ('SQSInUse'))
                csv_file.write("%s\n" % ('True'))
                csv_file.flush()
        except exceptions.EndpointConnectionError:
            print ("    INFO: SQS is not available in",reg)

        # Workspaces
        try:
            workspacesi = boto3.client('workspaces',region_name=reg)
            workspacess = workspacesi.describe_workspaces()['Workspaces']
            if len(workspacess) > 0:
                csv_file.write("%s,%s,%s,%s\n" % ('','','',''))
                csv_file.write("%s,%s\n"%('Workspaces',regname))
                csv_file.write("%s,%s\n" % ('WorkspaceId','State'))
                csv_file.flush()
                for workspace in workspacess:
                    workspaceid = workspace['WorkspaceId']
                    workspacestate = workspace['State']
                    csv_file.write("%s,%s\n" % (workspaceid,workspacestate))
                    csv_file.flush()
        except exceptions.EndpointConnectionError:
            print ("    INFO: Workspaces is not available in",reg)

        # Glue
        try:
            gluei = boto3.client('glue',region_name=reg)
            glues = gluei.get_jobs()['Jobs']
            if len(glues) > 0:
                csv_file.write("%s,%s,%s,%s\n" % ('','','',''))
                csv_file.write("%s,%s\n"%('Glue',regname))
                csv_file.write("%s,%s\n" % ('Name','Description'))
                csv_file.flush()
                for glue in glues:
                    gluename = glue['Name']
                    gluedesc = glue['Description']
                    csv_file.write("%s,%s\n" % (workspaceid,gluetate))
                    csv_file.flush()
        except exceptions.EndpointConnectionError:
            print ("    INFO: Glue is not available in",reg)

        # Lambda
        try:
            lambdai = boto3.client('lambda',region_name=reg)
            lambdas = lambdai.list_functions()['Functions']
            if len(lambdas) > 0:
                csv_file.write("%s,%s,%s,%s\n" % ('','','',''))
                csv_file.write("%s,%s\n"%('Lambda',regname))
                csv_file.write("%s,%s,%s,%s,%s\n" % ('FunctionName','Runtime','CodeSize','Description','MemorySize'))
                csv_file.flush()
                for lamb in lambdas:
                    lambfname = lamb['FunctionName']
                    lambrtime = lamb['Runtime']
                    lambcsize = lamb['CodeSize']
                    lambdescr = lamb['Description']
                    lambmsize = lamb['MemorySize']
                    csv_file.write("%s,%s,%s,%s,%s\n" % (lambfname,lambrtime,lambcsize,lambdescr,lambmsize))
                    csv_file.flush()
        except exceptions.EndpointConnectionError:
            print ("    INFO: Lambda is not available in",reg)


    end_time = time()
    running_time = str(int(end_time - start_time))
    enddate_fmt = strftime("%Y_%m_%d-%H%M%S", gmtime())
    csv_file.write("%s,%s,%s,%s\n" % ('','','',''))
    csv_file.write("%s %s\n"%('Audit complete -', enddate_fmt))
    csv_file.write("%s %s %s\n"%('Total running time', running_time, 'seconds'))
    date_fmt = strftime("%Y_%m_%d", gmtime())
    filepath ='/tmp/AWS_Resources_' + date_fmt + '.csv'
    print('Audit complete',enddate_fmt)
    print('Total running time',running_time,'seconds')

if __name__ == '__main__':
    lambda_handler(None, None)
