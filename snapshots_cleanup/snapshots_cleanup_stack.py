from aws_cdk import (
    Fn,
    CfnParameter,
    RemovalPolicy,
    Duration,
    Stack,
    aws_iam as _iam,
    aws_lambda as _lambda,
    aws_events as _events,
    aws_events_targets as _targets,
    aws_sns as _sns,
    aws_sns_subscriptions as _subs,
    aws_kms as _kms,
    aws_s3 as _s3,
    aws_signer as _signer
)
from constructs import Construct
from os import environ


class SnapshotsCleanupStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        tag_key_param = CfnParameter(self, "tag_key", type="String",
                                     description="Tag key present in snapshots: used to filter snapshots list")
        tag_values_param = CfnParameter(self, "tag_values", type="String",
                                        description="comma sepparated possible values of the tag_key entered: used to filter snapshots list")
        region_param = CfnParameter(self, "region", type="String",
                                    description="target AWS region: used to filter snapshots list", default="us-east-1")
        max_days_param = CfnParameter(self, "max_days", type="String",
                                      description="Max days a snapshot is allowed in account: used to filter snapshots deletion", default="90")
        cleanup_last_snapshot_param = CfnParameter(self, "cleanup_last_snapshot", type="String",
                                                   description="Set to -> 1 if all snapshots are to be cleaned. Set to 0 if the last snapshot is NOT to be cleaned ", default="0")
        email_for_notification_param = CfnParameter(self, "email_for_notification", type="String",
                                                    description="Email address to suscribe for reports on executions")

        function_name = "snapshots-maintainer-production"
        role_name = "snapshots-maintainer-ServiceRole"
        account_id = Stack.of(self).account

        # CREATE THE REPORTS HOLDER BUCKET AND ACCESS LOGS BUCKET
        bucket_encryption = _s3.BucketEncryption.S3_MANAGED
        removal_policy = RemovalPolicy.RETAIN
        access_logs_bucket = _s3.Bucket(self, f"AccessLogsBucketFor-ReportHolder",
                                        encryption=bucket_encryption,
                                        removal_policy=removal_policy,
                                        enforce_ssl=True,
                                        server_access_logs_prefix="this_bucket_access_logs",
                                        block_public_access=_s3.BlockPublicAccess.BLOCK_ALL
                                        )

        s3_bucket = _s3.Bucket(self, f"Bucket-ReportHolder",
                               encryption=bucket_encryption,
                               removal_policy=removal_policy,
                               enforce_ssl=True,
                               object_ownership=_s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
                               server_access_logs_bucket=access_logs_bucket,
                               server_access_logs_prefix="logs",
                               block_public_access=_s3.BlockPublicAccess.BLOCK_ALL
                               )

        # ROLE INLINE POLICIES
        snapshot_access_policy = _iam.PolicyDocument(
            statements=[
                _iam.PolicyStatement(
                    actions=["ec2:DeleteSnapshot"
                             ],
                    resources=[
                        f"arn:aws:ec2:{region_param.value_as_string}:{account_id}:snapshot/*"
                    ],
                    conditions={
                        "ForAllValues:StringEquals": {
                            "aws:TagKeys": [tag_key_param.value_as_string],
                            "aws:TagValues": Fn.split(",", tag_values_param.value_as_string)
                        }
                    }

                ),
                _iam.PolicyStatement(
                    actions=[
                        "ec2:DescribeVolumes",
                        "ec2:DescribeSnapshots"
                    ],
                    resources=["*"],
                    conditions={
                        "ForAllValues:StringEquals": {
                            "aws:TagKeys": [tag_key_param.value_as_string],
                            "aws:TagValues": Fn.split(",", tag_values_param.value_as_string)
                        }
                    }

                ),
                _iam.PolicyStatement(
                    actions=[
                        "rds:DescribeDBSnapshots",
                        "rds:DeleteDBSnapshot"
                    ],
                    resources=[
                        f"arn:aws:rds:{region_param.value_as_string}:{account_id}:snapshot:*"
                    ],
                    conditions={
                        "ForAllValues:StringEquals": {
                            "aws:TagKeys": [tag_key_param.value_as_string],
                            "aws:TagValues": Fn.split(",", tag_values_param.value_as_string)
                        }
                    }

                )
            ]
        )
        bucket_access_policy = _iam.PolicyDocument(
            statements=[_iam.PolicyStatement(
                actions=["s3:PutObject"],
                resources=[
                    s3_bucket.arn_for_objects("*")
                ]
            )
            ]
        )

        # LAMBDA FUNCTION ROLE
        RoleDefinition = _iam.Role(self, f"Lambda-CleanUp-Snap-Role",
                                   assumed_by=_iam.ServicePrincipal(
                                       "lambda.amazonaws.com"),
                                   description=f"Role for Lambda {function_name}",
                                   managed_policies=[_iam.ManagedPolicy.from_aws_managed_policy_name(
                                       "service-role/AWSLambdaBasicExecutionRole")],
                                   role_name=role_name,
                                   inline_policies={
                                       "snapshotAccess": snapshot_access_policy,
                                       "bucketAccess": bucket_access_policy}
                                   )

        # CODE SIGNING CONFIGS
        signing_profile = _signer.SigningProfile(
            self, "SigningProfile", platform=_signer.Platform.AWS_LAMBDA_SHA384_ECDSA)

        code_signing_config = _lambda.CodeSigningConfig(
            self, "CodeSigningConfig", signing_profiles=[signing_profile])

        # LAMBDA FUNCTION
        python_code = open("src/lambda_function.py", "r")
        config_json_object = python_code.read()
        lambda_definition = _lambda.Function(self, function_name,
                                             code_signing_config=code_signing_config,
                                             function_name=function_name,
                                             runtime=_lambda.Runtime.PYTHON_3_9,
                                             handler="index.lambda_handler",
                                             code=_lambda.Code.from_inline(
                                                 config_json_object),
                                             role=RoleDefinition,
                                             timeout=Duration.seconds(300),
                                             memory_size=128,
                                             environment={
                                                 "tag_key": tag_key_param.value_as_string,
                                                 "tag_values": tag_values_param.value_as_string,
                                                 "region": region_param.value_as_string,
                                                 "max_days_gold": max_days_param.value_as_string,
                                                 "cleanup_last_snapshot": cleanup_last_snapshot_param.value_as_string,
                                                 "s3_bucket_name": s3_bucket.bucket_name
                                             }
                                             )

        # DAILY TRIGGER
        rule_name = "Daily-trigger-for-snapshotCleanup"
        schedule = "cron(00 01 ? * * *)"
        cloudwatch_rule = _events.Rule(self, f"Rule_CloudWatchT_{function_name}",
                                       schedule=_events.Schedule.expression(
                                           schedule),
                                       rule_name=rule_name
                                       )
        cloudwatch_rule.add_target(_targets.LambdaFunction(lambda_definition))

        # SNS NOTIFICATION WITH ENCRYPTION
        kms_key_for_topic = _kms.Key(self, f"kmskey_for_{function_name}_topic",
                                     enable_key_rotation=True, description=f"kms key to use in {function_name} sns notification", enabled=True)

        kms_key_for_topic.grant_encrypt_decrypt(grantee=lambda_definition)
        notification_topic = _sns.Topic(
            self, f"Topic_for_{function_name}", master_key=kms_key_for_topic)
        notification_topic.add_subscription(
            subscription=_subs.EmailSubscription(email_for_notification_param.value_as_string))

        lambda_definition.add_environment(
            "sns_topic_arn", notification_topic.topic_arn)

        # ADD ACCESS TO THE LAMBDA ROLE TO SEND NOTIFICATIONS
        RoleDefinition.add_to_policy(statement=_iam.PolicyStatement(
            actions=["sns:Publish"], resources=[notification_topic.topic_arn]))

        RoleDefinition.without_policy_updates()
