import boto3
from botocore import exceptions
import datetime
from logging import getLogger, INFO, DEBUG
from os import environ, chdir
import csv

# Logger setup
logger = getLogger()
logger.setLevel(INFO)

EBS_USECASE = "EBS"
RDS_USECASE = "RDS"

deleted_ebs_snapshots = []
skipped_ebs_snapshots = []

deleted_rds_snapshots = []
skipped_rds_snapshots = []

SUCCESS = "deleted"
FAILURE = "skipped"

ebs_object_keys = {"TopLevel": "Snapshots",
                   "ID": "SnapshotId",
                   "Time": "StartTime",
                   "VolumeId": "VolumeId"
                   }

rds_object_keys = {"TopLevel": "DBSnapshots",
                   "ID": "DBSnapshotIdentifier",
                   "Time": "SnapshotCreateTime",
                   "DBInstanceID": "DBInstanceIdentifier"
                   }


def send_report_to_s3():
    ebs_file_name = create_report_files(EBS_USECASE)
    rds_file_name = create_report_files(RDS_USECASE)
    bucket_name = environ["s3_bucket_name"]

    s3_client = boto3.client('s3')
    try:
        s3_client.upload_file(
            f"/tmp/{ebs_file_name}", bucket_name, ebs_file_name)
        s3_client.upload_file(
            f"/tmp/{rds_file_name}", bucket_name, rds_file_name)
    except exceptions.ClientError as e:
        logger.info(f"Error on Put opperation. Details: {e}")


def create_report_files(report_type):
    file_creation_date = datetime.datetime.now().date()
    chdir('/tmp')
    filename = f"{file_creation_date}-{report_type}-report.csv"
    file_tmp_path = f"/tmp/{filename}"
    file_handler = open(file_tmp_path, 'w')

    report_list = []
    if report_type == EBS_USECASE:
        # EBS csv headers
        fieldnames = ['SnapshotId', 'VolumeId', 'Status', 'Error']
        writer = csv.DictWriter(file_handler, fieldnames=fieldnames)
        writer.writeheader()
        report_list = deleted_ebs_snapshots + skipped_ebs_snapshots
        writer.writerows(report_list)
    else:
        # RDS csv headers
        fieldnames = ['DBSnapshotIdentifier',
                      'DBInstanceIdentifier', 'Status', 'Error']
        writer = csv.DictWriter(file_handler, fieldnames=fieldnames)
        writer.writeheader()
        report_list = deleted_rds_snapshots + skipped_rds_snapshots
        writer.writerows(report_list)

    file_handler.close()

    return filename


def check_snapshot_count(paginator_array, key):
    total_snapshot_in_filter = 0
    for page in paginator_array:
        total_snapshot_in_filter += len(page[key])
    return total_snapshot_in_filter


def build_snapshots_report(snapshot, report, snapshot_type, status, failure_reason="-"):
    if snapshot_type == EBS_USECASE:
        snapshot_data = {"SnapshotId": snapshot[ebs_object_keys["ID"]],
                         "VolumeId": snapshot[ebs_object_keys["VolumeId"]],
                         "Status": status, "Error": failure_reason}
    else:
        snapshot_data = {"DBSnapshotIdentifier": snapshot[rds_object_keys["ID"]],
                         "DBInstanceIdentifier": snapshot[rds_object_keys["DBInstanceID"]],
                         "Status": status, "Error": failure_reason}
    report.append(snapshot_data)


def send_notification_on_failure(snapshot_type, total_snapshot_scanned, aws_account_id, skipped_report):
    # TODO: Pass the bucket/file to reference the file containing the errors details
    sns = boto3.client("sns")
    skipped_snapshots_count = len(skipped_report) if len(
        skipped_report) > 0 else 0

    if skipped_snapshots_count > 0:
        bucket = environ["s3_bucket_name"]
        message = f"Total scanned: {total_snapshot_scanned}\n Total skipped(Need Attention!.Check today's report in bucket -> {bucket}): {skipped_snapshots_count}\n"
        target_region = environ["region"]
        sns.publish(
            TopicArn=environ["sns_topic_arn"],
            Message=message,
            Subject=f"{snapshot_type} snapshot cleanup failures in region: {target_region}, account: {aws_account_id} "
        )

        logger.info(f"Skipped {snapshot_type} Snapshots")
        logger.info(skipped_report)


def delete_snapshot(snapshot_type, page_iterator, client, aws_account_id, total_snapshot_count, clean_up_last):

    now_time = datetime.datetime.now().date()
    total_snapshot_scanned = 0
    total_snapshot_cleaned = 0
    snapshots_objects_keys = None
    if snapshot_type == EBS_USECASE:
        snapshots_objects_keys = ebs_object_keys
    else:
        snapshots_objects_keys = rds_object_keys

    for page in page_iterator:
        for snapshot in page[snapshots_objects_keys["TopLevel"]]:
            total_snapshot_scanned += 1
            snapshot_id = snapshot[snapshots_objects_keys["ID"]]
            logger.debug(f"Proccessing -> {snapshot_id}")
            snapshot_creation_date = snapshot[snapshots_objects_keys["Time"]].date(
            )
            logger.debug(f"Date Created -> {snapshot_creation_date}")
            # Calculate the difference
            existed_since = (now_time - snapshot_creation_date).days
            logger.debug(f"On for -> {existed_since} days")
            logger.info(f"{snapshot_id} On for -> {existed_since}")
            delete_older_than = int(environ["max_days_gold"])
            logger.info(f"delete older than -> {delete_older_than}")
            if (existed_since > delete_older_than):
                try:
                    logger.debug(f"Attempting to delete -> {snapshot_id}")
                    logger.debug(
                        f"total_{snapshot_type}_snapshot_count -> {total_snapshot_count}")
                    logger.debug(
                        f"total_{snapshot_type}_snapshot_cleaned -> {total_snapshot_cleaned}")
                    logger.debug(
                        f"total_{snapshot_type}_snapshot_count - total_{snapshot_type}_snapshot_cleaned -> {total_snapshot_count - total_snapshot_cleaned}")
                    logger.debug(f"clean_up_last -> {clean_up_last}")
                    if (total_snapshot_count - total_snapshot_cleaned) > 1 or ((total_snapshot_count - total_snapshot_cleaned) == 1 and clean_up_last == "1"):
                        if snapshot_type == EBS_USECASE:
                            client.delete_snapshot(
                                SnapshotId=snapshot_id)
                            total_snapshot_cleaned += 1
                            logger.info(f"deleted -> {snapshot_id}")
                        else:
                            client.delete_db_snapshot(
                                DBSnapshotIdentifier=snapshot_id)
                            total_snapshot_cleaned += 1
                            logger.info(f"deleted -> {snapshot_id}")
                        build_snapshots_report(
                            snapshot, deleted_ebs_snapshots, snapshot_type, SUCCESS)

                # Catch an exception if the snap is in use
                except exceptions.ClientError as err:
                    logger.info(f"exception deleting -> {snapshot_id}")
                    logger.info(f"error details -> {err}")
                    build_snapshots_report(
                        snapshot, skipped_ebs_snapshots, snapshot_type, FAILURE, f"{err}")
                    continue

    send_report_to_s3()
    send_notification_on_failure(snapshot_type, total_snapshot_scanned,
                                 aws_account_id, skipped_ebs_snapshots)


def lambda_handler(event, context):

    if "debug" in event:
        logger.setLevel(DEBUG)

    logger.info(event)
    aws_account_id = context.invoked_function_arn.split(":")[4]

    # filters
    tag_key = environ["tag_key"]
    tag_values = environ["tag_values"].split(",")
    target_region = environ["region"]
    clean_up_last = environ["cleanup_last_snapshot"]

    boto3_custom_region_session = boto3.session.Session(
        region_name=target_region)
    ec2 = boto3_custom_region_session.client("ec2")
    rds = boto3_custom_region_session.client("rds")

    ebs_page_iterator = ec2.get_paginator('describe_snapshots').paginate(Filters=[
        {"Name": f"tag:{tag_key}", "Values": tag_values}])

    total_ebs_snapshot_count = check_snapshot_count(
        ebs_page_iterator, "Snapshots")
    rds_page_iterator = rds.get_paginator(
        'describe_db_snapshots').paginate(Filters=[{"Name": "snapshot-type", "Values": ["manual"]}])

    total_rds_snapshot_count = check_snapshot_count(
        rds_page_iterator, "DBSnapshots")

    logger.debug("All EBS snapshots in list:")
    logger.debug(ebs_page_iterator)

    logger.debug("All RDS snapshots in list:")
    logger.debug(rds_page_iterator)

    logger.info(f"total snapshots in ebs list {total_ebs_snapshot_count}")
    logger.info(f"total snapshots in rds list {total_rds_snapshot_count}")

    flag_string_value = "TRUE" if clean_up_last == "1" else "FALSE"
    if total_ebs_snapshot_count > 1 or (total_ebs_snapshot_count == 1 and clean_up_last == "1"):
        delete_snapshot(EBS_USECASE, ebs_page_iterator, ec2,
                        aws_account_id, total_ebs_snapshot_count, clean_up_last)
    else:
        logger.info(
            f"EBS Snapshots count: {total_ebs_snapshot_count}. Flag to keep at least ONE snapshot set to: {flag_string_value}. Exiting")

    if total_rds_snapshot_count > 1 or (total_rds_snapshot_count == 1 and clean_up_last == 1):
        delete_snapshot(RDS_USECASE, rds_page_iterator, rds,
                        aws_account_id, total_rds_snapshot_count, clean_up_last)
    else:
        logger.info(
            f"RDS Snapshots count: {total_rds_snapshot_count}. Flag to keep at least ONE snapshot set to: {flag_string_value}. Exiting")
