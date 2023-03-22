import aws_cdk as core
import aws_cdk.assertions as assertions

from snapshots_cleanup.snapshots_cleanup_stack import SnapshotsCleanupStack

# example tests. To run these tests, uncomment this file along with the example
# resource in snapshots_cleanup/snapshots_cleanup_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = SnapshotsCleanupStack(app, "snapshots-cleanup")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
