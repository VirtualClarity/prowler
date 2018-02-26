#!/bin/bash

aws iam list-roles | jq '.Roles[] | ({RoleName: .RoleName, Description: .Description})' > IAM_Roles.txt
aws iam list-users | jq '.Users[] | ({RoleName: .UserName})' > IAM_Users.txt
aws iam list-saml-providers > IAM_SAML.txt
aws iam list-open-id-connect-providers > IAM_OIDC.txt
aws organizations describe-organization > OrgStatus.txt

for region in `aws ec2 describe-regions --output text | cut -f3`
do
     echo -e "\nListing SNS Topics in region:'$region'..." >> SNS.txt
     aws sns list-subscriptions --region $region | jq '.Subscriptions[] | ({Endpoint: .Endpoint, Protocol: .Protocol, TopicArn: .TopicArn})' >> SNS.txt
done

for region in `aws ec2 describe-regions --output text | cut -f3`
do
     echo -e "\nListing Instances in region:'$region'..." >> RegionUsage.txt
     aws ec2 describe-instances --region $region | jq '.Reservations[] | ( .Instances[] | {state: .State.Name, name: .KeyName, Tag_Name: .Tags[].Value,type: .InstanceType, key: .KeyName})' >> RegionUsage.txt
done

for region in `aws ec2 describe-regions --output text | cut -f3`
do
     echo -e "\nListing VPC CIDRs in region:'$region'..." >> VPC_CIDRs.txt
     aws ec2 describe-vpcs --region $region | jq '.Vpcs[] | ({CIDR: .CidrBlock, Default: .IsDefault})' >> VPC_CIDRs.txt
done
