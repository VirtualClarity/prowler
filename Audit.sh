#!/bin/bash

# Obtain the account identifier
echo -e "##########################################################################################" >> AuditResults.csv
echo -e "Account Details" >> AuditResults.csv
echo -e "AccountName, AccountCanonicalID" >> AuditResults.csv
aws s3api list-buckets | jq -r '. | ({Name: .Owner.DisplayName, ID: .Owner.ID}) | [.[] | tostring] | @csv' >> AuditResults.csv

# Obtain the list of Roles
echo -e "##########################################################################################" >> AuditResults.csv
echo -e "IAM Roles" >> AuditResults.csv
echo -e "RoleName, Description, AssumeRolePolicy" >> AuditResults.csv
aws iam list-roles | jq -r '.Roles[] | ({RoleName: .RoleName, Description: .Description, AssumePolicy: .AssumeRolePolicyDocument}) | [.[] | tostring] | @csv' >> AuditResults.csv

# Obtain the list of Users
echo -e "##########################################################################################" >> AuditResults.csv
echo -e "IAM Users" >> AuditResults.csv
echo -e "UserName" >> AuditResults.csv
aws iam list-users | jq -r '.Users[] | ({UserName: .UserName}) | [.[] | tostring] | @csv' >> AuditResults.csv

# Obtain the list of SAML providers
echo -e "##########################################################################################" >> AuditResults.csv
echo -e "IAM SAML IDPs" >> AuditResults.csv
echo -e "SAMLIDPName, CreationDate" >> AuditResults.csv
aws iam list-saml-providers | jq -r '.SAMLProviderList[] | ({ARN: .Arn, CreateDate: .CreateDate}) | [.[] | tostring] | @csv' >> AuditResults.csv

# Obtain the list of OIDC providers
echo -e "##########################################################################################" >> AuditResults.csv
echo -e "IAM OIDC IDPs" >> AuditResults.csv
echo -e "OIDCIDPName" >> AuditResults.csv
aws iam list-open-id-connect-providers | jq -r '.OpenIDConnectProviderList[] | ({ARN: .Arn}) | [.[] | tostring] | @csv' >> AuditResults.csv

# Obtain Organization membership
echo -e "##########################################################################################" >> AuditResults.csv
echo -e "Organization Membership Details" >> AuditResults.csv
echo -e "AWSOrganizationStatus, MasterAccountId, MasterAccountEmail" >> AuditResults.csv
aws organizations describe-organization | jq -r '.[] | ({Status: .AvailablePolicyTypes[].Status, MasterAccountID: .MasterAccountId, MasterAccountEmail: .MasterAccountEmail}) | [.[] | tostring] | @csv' >> AuditResults.csv

# Obtain Region usage
echo -e "##########################################################################################" >> AuditResults.csv
echo -e "EC2 Regional Usage" >> AuditResults.csv
echo -e "Region, Usage" >> AuditResults.csv
for region in `aws ec2 describe-regions --output text | cut -f3`
do
  active=`aws ec2 describe-instances --region $region | jq '.Reservations[] | ( .Instances[] )'`
  if [ "$active" = "" ]; then
    echo $region',notactive' >> AuditResults.csv
  else
    echo $region',active' >> AuditResults.csv
  fi
done

# Obtain CIDR usage
echo -e "##########################################################################################" >> AuditResults.csv
echo -e "CIDR Usage" >> AuditResults.csv
echo -e "Region, CIDR, DefaultVPC" >> AuditResults.csv
for region in `aws ec2 describe-regions --output text | cut -f3`
do
  vpcinfo=`aws ec2 describe-vpcs --region $region | jq -r '.Vpcs[] | ({CIDR: .CidrBlock, Default: .IsDefault}) | [.[] | tostring] | @csv'`
  if [ "$vpcinfo" = "" ]; then
    echo $region',none' >> AuditResults.csv
  else
    for cidr in `aws ec2 describe-vpcs --region $region | jq -r '.Vpcs[] | ({CIDR: .CidrBlock, Default: .IsDefault}) | [.[] | tostring] | @csv'`
    do
      echo $region','$cidr >> AuditResults.csv
    done
  fi
done

# Obtain GuardDuty Status
echo -e "##########################################################################################" >> AuditResults.csv
echo -e "GuardDuty Regional Status" >> AuditResults.csv
echo -e "Region,Status" >> AuditResults.csv
for region in `aws ec2 describe-regions --output text | cut -f3`
do
  active=`aws guardduty list-detectors --output text`
  if [ "$active" = "" ]; then
    echo $region',disabled' >> AuditResults.csv
  else
    echo $region',enabled' >> AuditResults.csv
  fi
done
