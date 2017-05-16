#!/usr/bin/env python
"""
Created from JSON to Python (Troposphere) using cfn2py, then manually fixed by hand. Most of it is intact, although the InitConfig has been stripped out due to issues.
Template taken from http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/sample-templates-appframeworks-us-west-2.html
"""

from troposphere import Base64, Select, FindInMap, GetAtt, GetAZs, Join, Output, If, And, Not, Or, Equals, Condition
from troposphere import Parameter, Ref, Tags, Template
from troposphere.cloudformation import Init, InitConfig
from troposphere.cloudfront import Distribution, DistributionConfig
from troposphere.cloudfront import Origin, DefaultCacheBehavior
from troposphere.ec2 import PortRange
from troposphere.rds import DBSecurityGroup
from troposphere.ec2 import SecurityGroup
from troposphere.autoscaling import AutoScalingGroup
from troposphere.autoscaling import LaunchConfiguration
from troposphere.elasticloadbalancing import LoadBalancer, HealthCheck, ConnectionDrainingPolicy, AccessLoggingPolicy
from troposphere.rds import DBInstance


t = Template()

t.add_version("2010-09-09")

t.add_description("""\
AWS CloudFormation Sample Template LAMP_Multi_AZ: Create a highly available, scalable LAMP stack with an Amazon RDS database instance for the backend data store. This template demonstrates using the AWS CloudFormation bootstrap scripts to install the packages and files necessary to deploy the Apache web server and PHP at instance launch time. **WARNING** This template creates one or more Amazon EC2 instances, an Elastic Load Balancer and an Amazon RDS DB instance. You will be billed for the AWS resources used if you create a stack from this template.""")

MultiAZDatabase = t.add_parameter(Parameter(
    "MultiAZDatabase",
    Default="true",
    ConstraintDescription="must be either true or false.",
    Type="String",
    Description="Create a Multi-AZ MySQL Amazon RDS database instance",
    AllowedValues=["true", "false"],
))

DBAllocatedStorage = t.add_parameter(Parameter(
    "DBAllocatedStorage",
    Description="The size of the database (Gb)",
    Default="5",
    Type="Number",
    MaxValue="1024",
    MinValue="5",
    ConstraintDescription="must be between 5 and 1024Gb.",
))

InstanceType = t.add_parameter(Parameter(
    "InstanceType",
    Default="t2.small",
    ConstraintDescription="must be a valid EC2 instance type.",
    Type="String",
    Description="WebServer EC2 instance type",
    AllowedValues=["t1.micro", "t2.nano", "t2.micro", "t2.small", "t2.medium", "t2.large", "m1.small", "m1.medium", "m1.large", "m1.xlarge", "m2.xlarge", "m2.2xlarge", "m2.4xlarge", "m3.medium", "m3.large", "m3.xlarge", "m3.2xlarge", "m4.large", "m4.xlarge", "m4.2xlarge", "m4.4xlarge", "m4.10xlarge", "c1.medium", "c1.xlarge", "c3.large", "c3.xlarge", "c3.2xlarge", "c3.4xlarge", "c3.8xlarge", "c4.large", "c4.xlarge", "c4.2xlarge", "c4.4xlarge", "c4.8xlarge", "g2.2xlarge", "g2.8xlarge", "r3.large", "r3.xlarge", "r3.2xlarge", "r3.4xlarge", "r3.8xlarge", "i2.xlarge", "i2.2xlarge", "i2.4xlarge", "i2.8xlarge", "d2.xlarge", "d2.2xlarge", "d2.4xlarge", "d2.8xlarge", "hi1.4xlarge", "hs1.8xlarge", "cr1.8xlarge", "cc2.8xlarge", "cg1.4xlarge"],
))

SSHLocation = t.add_parameter(Parameter(
    "SSHLocation",
    ConstraintDescription="must be a valid IP CIDR range of the form x.x.x.x/x.",
    Description=" The IP address range that can be used to SSH to the EC2 instances",
    Default="0.0.0.0/0",
    MinLength="9",
    AllowedPattern="(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})/(\\d{1,2})",
    MaxLength="18",
    Type="String",
))

# @review @web:@web_group ssh keypair
# @transfers @cwe_311_missing_encryption_of_sensitive_data to @web:@web_group with mysql client TLS selection
KeyName = t.add_parameter(Parameter(
    "KeyName",
    ConstraintDescription="must be the name of an existing EC2 KeyPair.",
    Type="AWS::EC2::KeyPair::KeyName",
    Description="Name of an existing EC2 KeyPair to enable SSH access to the instances",
))

# @review @db:@db admin credentials
DBPassword = t.add_parameter(Parameter(
    "DBPassword",
    ConstraintDescription="must contain only alphanumeric characters.",
    Description="Password for MySQL database access",
    MinLength="8",
    AllowedPattern="[a-zA-Z0-9]*",
    NoEcho=True,
    MaxLength="41",
    Type="String",
))

DBUser = t.add_parameter(Parameter(
    "DBUser",
    ConstraintDescription="must begin with a letter and contain only alphanumeric characters.",
    Description="Username for MySQL database access",
    MinLength="1",
    AllowedPattern="[a-zA-Z][a-zA-Z0-9]*",
    NoEcho=True,
    MaxLength="16",
    Type="String",
))

DBInstanceClass = t.add_parameter(Parameter(
    "DBInstanceClass",
    Default="db.t2.small",
    ConstraintDescription="must select a valid database instance type.",
    Type="String",
    Description="The database instance type",
    AllowedValues=["db.t1.micro", "db.m1.small", "db.m1.medium", "db.m1.large", "db.m1.xlarge", "db.m2.xlarge", "db.m2.2xlarge", "db.m2.4xlarge", "db.m3.medium", "db.m3.large", "db.m3.xlarge", "db.m3.2xlarge", "db.m4.large", "db.m4.xlarge", "db.m4.2xlarge", "db.m4.4xlarge", "db.m4.10xlarge", "db.r3.large", "db.r3.xlarge", "db.r3.2xlarge", "db.r3.4xlarge", "db.r3.8xlarge", "db.m2.xlarge", "db.m2.2xlarge", "db.m2.4xlarge", "db.cr1.8xlarge", "db.t2.micro", "db.t2.small", "db.t2.medium", "db.t2.large"],
))

DBName = t.add_parameter(Parameter(
    "DBName",
    ConstraintDescription="must begin with a letter and contain only alphanumeric characters.",
    Description="MySQL database name",
    Default="myDatabase",
    MinLength="1",
    AllowedPattern="[a-zA-Z][a-zA-Z0-9]*",
    MaxLength="64",
    Type="String",
))

WebServerCapacity = t.add_parameter(Parameter(
    "WebServerCapacity",
    Description="The initial nuber of WebServer instances",
    Default="2",
    Type="Number",
    MaxValue="5",
    MinValue="1",
    ConstraintDescription="must be between 1 and 5 EC2 instances.",
))

t.add_condition("Is-EC2-Classic",
    Not(Condition("Is-EC2-VPC"))
)

t.add_condition("Is-EC2-VPC",
    Or(Equals(Ref("AWS::Region"), "eu-central-1"), Equals(Ref("AWS::Region"), "cn-north-1"), Equals(Ref("AWS::Region"), "ap-northeast-2"))
)

t.add_mapping("AWSInstanceType2Arch",
{u'c1.medium': {u'Arch': u'PV64'},
 u'c1.xlarge': {u'Arch': u'PV64'},
 u'c3.2xlarge': {u'Arch': u'HVM64'},
 u'c3.4xlarge': {u'Arch': u'HVM64'},
 u'c3.8xlarge': {u'Arch': u'HVM64'},
 u'c3.large': {u'Arch': u'HVM64'},
 u'c3.xlarge': {u'Arch': u'HVM64'},
 u'c4.2xlarge': {u'Arch': u'HVM64'},
 u'c4.4xlarge': {u'Arch': u'HVM64'},
 u'c4.8xlarge': {u'Arch': u'HVM64'},
 u'c4.large': {u'Arch': u'HVM64'},
 u'c4.xlarge': {u'Arch': u'HVM64'},
 u'cc2.8xlarge': {u'Arch': u'HVM64'},
 u'cr1.8xlarge': {u'Arch': u'HVM64'},
 u'd2.2xlarge': {u'Arch': u'HVM64'},
 u'd2.4xlarge': {u'Arch': u'HVM64'},
 u'd2.8xlarge': {u'Arch': u'HVM64'},
 u'd2.xlarge': {u'Arch': u'HVM64'},
 u'g2.2xlarge': {u'Arch': u'HVMG2'},
 u'g2.8xlarge': {u'Arch': u'HVMG2'},
 u'hi1.4xlarge': {u'Arch': u'HVM64'},
 u'hs1.8xlarge': {u'Arch': u'HVM64'},
 u'i2.2xlarge': {u'Arch': u'HVM64'},
 u'i2.4xlarge': {u'Arch': u'HVM64'},
 u'i2.8xlarge': {u'Arch': u'HVM64'},
 u'i2.xlarge': {u'Arch': u'HVM64'},
 u'm1.large': {u'Arch': u'PV64'},
 u'm1.medium': {u'Arch': u'PV64'},
 u'm1.small': {u'Arch': u'PV64'},
 u'm1.xlarge': {u'Arch': u'PV64'},
 u'm2.2xlarge': {u'Arch': u'PV64'},
 u'm2.4xlarge': {u'Arch': u'PV64'},
 u'm2.xlarge': {u'Arch': u'PV64'},
 u'm3.2xlarge': {u'Arch': u'HVM64'},
 u'm3.large': {u'Arch': u'HVM64'},
 u'm3.medium': {u'Arch': u'HVM64'},
 u'm3.xlarge': {u'Arch': u'HVM64'},
 u'm4.10xlarge': {u'Arch': u'HVM64'},
 u'm4.2xlarge': {u'Arch': u'HVM64'},
 u'm4.4xlarge': {u'Arch': u'HVM64'},
 u'm4.large': {u'Arch': u'HVM64'},
 u'm4.xlarge': {u'Arch': u'HVM64'},
 u'r3.2xlarge': {u'Arch': u'HVM64'},
 u'r3.4xlarge': {u'Arch': u'HVM64'},
 u'r3.8xlarge': {u'Arch': u'HVM64'},
 u'r3.large': {u'Arch': u'HVM64'},
 u'r3.xlarge': {u'Arch': u'HVM64'},
 u't1.micro': {u'Arch': u'PV64'},
 u't2.large': {u'Arch': u'HVM64'},
 u't2.medium': {u'Arch': u'HVM64'},
 u't2.micro': {u'Arch': u'HVM64'},
 u't2.nano': {u'Arch': u'HVM64'},
 u't2.small': {u'Arch': u'HVM64'}}
)

t.add_mapping("AWSInstanceType2NATArch",
{u'c1.medium': {u'Arch': u'NATPV64'},
 u'c1.xlarge': {u'Arch': u'NATPV64'},
 u'c3.2xlarge': {u'Arch': u'NATHVM64'},
 u'c3.4xlarge': {u'Arch': u'NATHVM64'},
 u'c3.8xlarge': {u'Arch': u'NATHVM64'},
 u'c3.large': {u'Arch': u'NATHVM64'},
 u'c3.xlarge': {u'Arch': u'NATHVM64'},
 u'c4.2xlarge': {u'Arch': u'NATHVM64'},
 u'c4.4xlarge': {u'Arch': u'NATHVM64'},
 u'c4.8xlarge': {u'Arch': u'NATHVM64'},
 u'c4.large': {u'Arch': u'NATHVM64'},
 u'c4.xlarge': {u'Arch': u'NATHVM64'},
 u'cc2.8xlarge': {u'Arch': u'NATHVM64'},
 u'cr1.8xlarge': {u'Arch': u'NATHVM64'},
 u'd2.2xlarge': {u'Arch': u'NATHVM64'},
 u'd2.4xlarge': {u'Arch': u'NATHVM64'},
 u'd2.8xlarge': {u'Arch': u'NATHVM64'},
 u'd2.xlarge': {u'Arch': u'NATHVM64'},
 u'g2.2xlarge': {u'Arch': u'NATHVMG2'},
 u'g2.8xlarge': {u'Arch': u'NATHVMG2'},
 u'hi1.4xlarge': {u'Arch': u'NATHVM64'},
 u'hs1.8xlarge': {u'Arch': u'NATHVM64'},
 u'i2.2xlarge': {u'Arch': u'NATHVM64'},
 u'i2.4xlarge': {u'Arch': u'NATHVM64'},
 u'i2.8xlarge': {u'Arch': u'NATHVM64'},
 u'i2.xlarge': {u'Arch': u'NATHVM64'},
 u'm1.large': {u'Arch': u'NATPV64'},
 u'm1.medium': {u'Arch': u'NATPV64'},
 u'm1.small': {u'Arch': u'NATPV64'},
 u'm1.xlarge': {u'Arch': u'NATPV64'},
 u'm2.2xlarge': {u'Arch': u'NATPV64'},
 u'm2.4xlarge': {u'Arch': u'NATPV64'},
 u'm2.xlarge': {u'Arch': u'NATPV64'},
 u'm3.2xlarge': {u'Arch': u'NATHVM64'},
 u'm3.large': {u'Arch': u'NATHVM64'},
 u'm3.medium': {u'Arch': u'NATHVM64'},
 u'm3.xlarge': {u'Arch': u'NATHVM64'},
 u'm4.10xlarge': {u'Arch': u'NATHVM64'},
 u'm4.2xlarge': {u'Arch': u'NATHVM64'},
 u'm4.4xlarge': {u'Arch': u'NATHVM64'},
 u'm4.large': {u'Arch': u'NATHVM64'},
 u'm4.xlarge': {u'Arch': u'NATHVM64'},
 u'r3.2xlarge': {u'Arch': u'NATHVM64'},
 u'r3.4xlarge': {u'Arch': u'NATHVM64'},
 u'r3.8xlarge': {u'Arch': u'NATHVM64'},
 u'r3.large': {u'Arch': u'NATHVM64'},
 u'r3.xlarge': {u'Arch': u'NATHVM64'},
 u't1.micro': {u'Arch': u'NATPV64'},
 u't2.large': {u'Arch': u'NATHVM64'},
 u't2.medium': {u'Arch': u'NATHVM64'},
 u't2.micro': {u'Arch': u'NATHVM64'},
 u't2.nano': {u'Arch': u'NATHVM64'},
 u't2.small': {u'Arch': u'NATHVM64'}}
)

t.add_mapping("AWSRegionArch2AMI",
{u'ap-northeast-1': {u'HVM64': u'ami-374db956',
                     u'HVMG2': u'ami-a7694fc0',
                     u'PV64': u'ami-3e42b65f'},
 u'ap-northeast-2': {u'HVM64': u'ami-2b408b45',
                     u'HVMG2': u'NOT_SUPPORTED',
                     u'PV64': u'NOT_SUPPORTED'},
 u'ap-south-1': {u'HVM64': u'ami-ffbdd790',
                 u'HVMG2': u'ami-d24a39bd',
                 u'PV64': u'NOT_SUPPORTED'},
 u'ap-southeast-1': {u'HVM64': u'ami-a59b49c6',
                     u'HVMG2': u'ami-fa75ca99',
                     u'PV64': u'ami-df9e4cbc'},
 u'ap-southeast-2': {u'HVM64': u'ami-dc361ebf',
                     u'HVMG2': u'ami-40a2ad23',
                     u'PV64': u'ami-63351d00'},
 u'ca-central-1': {u'HVM64': u'ami-730ebd17',
                   u'HVMG2': u'NOT_SUPPORTED',
                   u'PV64': u'NOT_SUPPORTED'},
 u'cn-north-1': {u'HVM64': u'ami-8e6aa0e3',
                 u'HVMG2': u'NOT_SUPPORTED',
                 u'PV64': u'ami-77559f1a'},
 u'eu-central-1': {u'HVM64': u'ami-ea26ce85',
                   u'HVMG2': u'ami-065d8d69',
                   u'PV64': u'ami-6527cf0a'},
 u'eu-west-1': {u'HVM64': u'ami-f9dd458a',
                u'HVMG2': u'ami-dc5861ba',
                u'PV64': u'ami-4cdd453f'},
 u'eu-west-2': {u'HVM64': u'ami-886369ec',
                u'HVMG2': u'NOT_SUPPORTED',
                u'PV64': u'NOT_SUPPORTED'},
 u'sa-east-1': {u'HVM64': u'ami-6dd04501',
                u'HVMG2': u'NOT_SUPPORTED',
                u'PV64': u'ami-1ad34676'},
 u'us-east-1': {u'HVM64': u'ami-6869aa05',
                u'HVMG2': u'ami-920f8984',
                u'PV64': u'ami-2a69aa47'},
 u'us-east-2': {u'HVM64': u'ami-f6035893',
                u'HVMG2': u'NOT_SUPPORTED',
                u'PV64': u'NOT_SUPPORTED'},
 u'us-west-1': {u'HVM64': u'ami-31490d51',
                u'HVMG2': u'ami-807f25e0',
                u'PV64': u'ami-a2490dc2'},
 u'us-west-2': {u'HVM64': u'ami-7172b611',
                u'HVMG2': u'ami-54d44234',
                u'PV64': u'ami-7f77b31f'}}
)

# @alias boundary @db to Database
# @alias component @db:@db_sg to DBSecurityGroup
# _connects @web:@web_sg to @db:@db_sg - disabled as it doesn't add clarity
DBSecurityGroup = t.add_resource(DBSecurityGroup(
    "DBSecurityGroup",
    DBSecurityGroupIngress=[{ "EC2SecurityGroupName": Ref("WebServerSecurityGroup") }],
    GroupDescription="database access",
    Condition="Is-EC2-Classic",
))

# @alias boundary @mgmt to Management
# @alias component @mgmt:@admin to Administrator
# @alias boundary @web to Web
# @alias component @web:@web_sg to WebServerSecurityGroup
# @connects @mgmt:@admin to @web:@web_sg as ssh tcp/22
# @mitigates @web:@web_sg against @cwe_306_missing_authentication_for_critical_function with use of secure shell
# @mitigates @web:@web_sg against @cwe_311_missing_encryption_of_sensitive_data with use of secure shell
# @connects @web:@elb to @web:@web_sg as http tcp/80
WebServerSecurityGroup = t.add_resource(SecurityGroup(
    "WebServerSecurityGroup",
    SecurityGroupIngress=[{ "ToPort": "80", "IpProtocol": "tcp", "SourceSecurityGroupOwnerId": GetAtt("ElasticLoadBalancer", "SourceSecurityGroup.OwnerAlias"), "SourceSecurityGroupName": GetAtt("ElasticLoadBalancer", "SourceSecurityGroup.GroupName"), "FromPort": "80" }, { "ToPort": "22", "IpProtocol": "tcp", "CidrIp": Ref(SSHLocation), "FromPort": "22" }],
    GroupDescription="Enable HTTP access via port 80 locked down to the ELB and SSH access",
))

# @alias component @web:@web_group to WebServerASGGroup
WebServerGroup = t.add_resource(AutoScalingGroup(
    "WebServerGroup",
    DesiredCapacity=Ref(WebServerCapacity),
    LaunchConfigurationName=Ref("LaunchConfig"),
    MinSize="1",
    MaxSize="5",
    LoadBalancerNames=[Ref("ElasticLoadBalancer")],
    AvailabilityZones=GetAZs(""),
))

init_config = { "config": InitConfig({})}

# @connects @web:@web_group with @web:@web_sg
# @transfers @cwe_807_reliance_on_untrusted_inputs_in_a_security_decision to @web:@web_group with lack of WAF
LaunchConfig = t.add_resource(LaunchConfiguration(
    "LaunchConfig",
    Metadata=Init(init_config),
    UserData=Base64(Join("", ["#!/bin/bash -xe\n", "yum update -y aws-cfn-bootstrap\n", "# Install the files and packages from the metadata\n", "/opt/aws/bin/cfn-init -v ", "         --stack ", Ref("AWS::StackName"), "         --resource LaunchConfig ", "         --region ", Ref("AWS::Region"), "\n", "# Signal the status from cfn-init\n", "/opt/aws/bin/cfn-signal -e $? ", "         --stack ", Ref("AWS::StackName"), "         --resource WebServerGroup ", "         --region ", Ref("AWS::Region"), "\n"])),
    KeyName=Ref(KeyName),
    SecurityGroups=[Ref(WebServerSecurityGroup)],
    InstanceType=Ref(InstanceType),
    ImageId=FindInMap("AWSRegionArch2AMI", Ref("AWS::Region"), FindInMap("AWSInstanceType2Arch", Ref(InstanceType), "Arch")),
))

# @alias component @db:@db_ec2_sg to DBEC2SecurityGroup
# @connects @db:@db_sg with @db:@db_ec2_sg
# @connects @web:@web_sg to @db:@db_ec2_sg as mysql tcp/3306
DBEC2SecurityGroup = t.add_resource(SecurityGroup(
    "DBEC2SecurityGroup",
    SecurityGroupIngress=[{ "ToPort": "3306", "IpProtocol": "tcp", "SourceSecurityGroupName": Ref(WebServerSecurityGroup), "FromPort": "3306" }],
    GroupDescription="Open database for access",
    Condition="Is-EC2-VPC",
))

# @alias component @web:@elb to ElasticLoadBalancer
# Who uses the ELB? Well, a user, so adding them in
# @alias boundary @external to External
# @alias component @external:@user to User
# @connects @external:@user to @web:@elb as http tcp/80
# @exposes @web:@elb to @cwe_311_missing_encryption_of_sensitive_data with lack of TLS
ElasticLoadBalancer = t.add_resource(LoadBalancer(
    "ElasticLoadBalancer",
    HealthCheck=HealthCheck(
        HealthyThreshold="2",
        Interval="10",
        Target="HTTP:80/",
        Timeout="5",
        UnhealthyThreshold="5",
    ),
    LBCookieStickinessPolicy=[{ "PolicyName": "CookieBasedPolicy", "CookieExpirationPeriod": "30" }],
    CrossZone="true",
    Listeners=[{ "InstancePort": "80", "PolicyNames": ["CookieBasedPolicy"], "LoadBalancerPort": "80", "Protocol": "HTTP" }],
    AvailabilityZones=GetAZs(""),
))

# @alias component @db:@db to MySQLDatabase
# @connects @db:@db_ec2_sg with @db:@db
# @connects @db:@db_sg with @db:@db
MySQLDatabase = t.add_resource(DBInstance(
    "MySQLDatabase",
    Engine="MySQL",
    MultiAZ=Ref(MultiAZDatabase),
    DBSecurityGroups=If("Is-EC2-Classic", [Ref(DBSecurityGroup)], Ref("AWS::NoValue")),
    MasterUsername=Ref(DBUser),
    MasterUserPassword=Ref(DBPassword),
    VPCSecurityGroups=If("Is-EC2-VPC", [GetAtt(DBEC2SecurityGroup, "GroupId")], Ref("AWS::NoValue")),
    AllocatedStorage=Ref(DBAllocatedStorage),
    DBInstanceClass=Ref(DBInstanceClass),
    DBName=Ref(DBName),
))

WebsiteURL = t.add_output(Output(
    "WebsiteURL",
    Description="URL for newly created LAMP stack",
    Value=Join("", ["http://", GetAtt(ElasticLoadBalancer, "DNSName")]),
))

print(t.to_json())
