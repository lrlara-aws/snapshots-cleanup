# Getting Started with this project

Project created using CDK development with Python.

The `cdk.json` file tells the CDK Toolkit how to execute your app.

This project is set up like a standard Python project. The initialization
process also creates a virtualenv within this project, stored under the `.venv`
directory. To create the virtualenv it assumes that there is a `python3`
(or `python` for Windows) executable in your path with access to the `venv`
package. If for any reason the automatic creation of the virtualenv fails,
you can create the virtualenv manually.

## Setup local workspace

```
$ python3 -m venv .venv
```

After the init process completes and the virtualenv is created, you can use the following
step to activate your virtualenv.

```
$ source .venv/bin/activate
```

If you are a Windows platform, you would activate the virtualenv like this:

```
% .venv\Scripts\activate.bat
```

Once the virtualenv is activated, you can install the required dependencies.

```
$ pip install -r requirements.txt
```

At this point you can now synthesize the CloudFormation template for this code.

```
$ cdk synth --output=template
```

To add additional dependencies, for example other CDK libraries, just add
them to your `setup.py` file and rerun the `pip install -r requirements.txt`
command.

## Useful commands

- `cdk ls` list all stacks in the app
- `cdk synth` emits the synthesized CloudFormation template
- `cdk deploy` deploy this stack to your default AWS account/region
- `cdk diff` compare deployed stack with current state
- `cdk docs` open CDK documentation

# Snapshots Cleanup

##### Note: This function only maintains EBS and RDS snapshots.

## Prerequisites

- install python 3.x from Python bundle [here](https://www.python.org/downloads/) or using [brew](https://docs.brew.sh/Homebrew-and-Python)
- install latest version of the [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
- install [AWS CDK Toolkit _cdk command_](https://docs.aws.amazon.com/cdk/v2/guide/cli.html)
- make sure you are properly [Configuring the AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html)

```
 - All snapshots *must* be tagged (The tag key:value pair will be provided to the Lambda via ENV vars)
 - Snapshots must exist in the selected region
```

## inputs

```
tag_key: Tag key present in snapshots: used to filter snapshots list
tag_values: Comma sepparated possible values of the tag_key entered: used to filter snapshots list
region: target AWS region: used to filter snapshots list, default="us-east-1"
max_days: Max days a snapshot is allowed in account: used to filter snapshots deletion, default="90"
cleanup_last_snapshot: Set to -> 1 if all snapshots are to be cleaned. Set to 0 if the last snapshot in account is NOT to be cleaned, default="0"
email_for_notification: Email address to suscribe for reports on executions

```

## triggers

```
Uses a Daily trigger to perform opperations and cleanu unwanted snapshots in account.
```

## usage

```
npx cdk deploy --parameters tagkey=YOUR_SNAPSHOTS_TAG_KEY --parameters tagvalues=YOUR_SANPSHOTS_TAG_VALUES[COMMA SEPPARATED] --parameters emailfornotification=DL_FOR_NOTIFICATIONS
```
