#!/usr/bin/env python3
import os

import aws_cdk as cdk

from snapshots_cleanup.snapshots_cleanup_stack import SnapshotsCleanupStack

account_id = os.environ["CDK_DEFAULT_ACCOUNT"]

env = cdk.Environment(account=account_id)
app = cdk.App()
SnapshotsCleanupStack(app, "SnapshotsCleanupStack", env=env)

app.synth()
