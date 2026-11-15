data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition

  trail_name                = "p5-lab-trail"
  trail_arn                 = "arn:${local.partition}:cloudtrail:${var.region}:${local.account_id}:trail/${local.trail_name}"
  stratus_trail_arn_pattern = "arn:${local.partition}:cloudtrail:${var.region}:${local.account_id}:trail/${var.stratus_prefix}*"

  fn_name = "p5-remediate-logging"
}

# ---------------------------------------------------------------------------
# Log bucket + trail (evidence store; detection itself does not depend on it)
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "trail_logs" {
  bucket        = "p5-trail-logs-${local.account_id}"
  force_destroy = true # lab bucket: must be destroyable at the end of every session
}

resource "aws_s3_bucket_public_access_block" "trail_logs" {
  bucket                  = aws_s3_bucket.trail_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id
  rule {
    id     = "expire-logs"
    status = "Enabled"
    filter {}
    expiration {
      days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

data "aws_iam_policy_document" "trail_bucket" {
  statement {
    sid       = "AWSCloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail_logs.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "AWSCloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail_logs.arn}/AWSLogs/${local.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "trail_logs" {
  bucket     = aws_s3_bucket.trail_logs.id
  policy     = data.aws_iam_policy_document.trail_bucket.json
  depends_on = [aws_s3_bucket_public_access_block.trail_logs]
}

resource "aws_cloudtrail" "lab" {
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.trail_logs.id
  include_global_service_events = true # IAM events are global and are recorded in us-east-1
  is_multi_region_trail         = false
  enable_log_file_validation    = true
  # Management events only (default). No data events: cost control.

  depends_on = [aws_s3_bucket_policy.trail_logs]
}

# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------
resource "aws_sns_topic" "alerts" {
  name              = "p5-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
  # The subscription stays "pending" until the confirmation email link is clicked.
}

# ---------------------------------------------------------------------------
# Scenario 1: logging tampered (StopLogging auto-fix, DeleteTrail alert-only)
# ---------------------------------------------------------------------------
data "archive_file" "remediate_logging" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda/stop-logging"
  output_path = "${path.module}/build/stop-logging.zip"
}

resource "aws_cloudwatch_log_group" "remediate_logging" {
  name              = "/aws/lambda/${local.fn_name}"
  retention_in_days = var.log_retention_days
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "remediate_logging" {
  name               = "p5-remediate-logging"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "remediate_logging" {
  # Reason: write its own logs only. The log group is created by Terraform, so no CreateLogGroup.
  statement {
    sid       = "OwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.remediate_logging.arn}:*"]
  }

  # Reason: send the alert. One topic only.
  statement {
    sid       = "PublishAlert"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }

  # Reason: check status (idempotency) and restart logging. Lab trail and Stratus-named trails only.
  statement {
    sid       = "FixLoggingInScope"
    actions   = ["cloudtrail:GetTrailStatus", "cloudtrail:StartLogging"]
    resources = [local.trail_arn, local.stratus_trail_arn_pattern]
  }
}

resource "aws_iam_role_policy" "remediate_logging" {
  name   = "least-privilege"
  role   = aws_iam_role.remediate_logging.id
  policy = data.aws_iam_policy_document.remediate_logging.json
}

resource "aws_lambda_function" "remediate_logging" {
  function_name    = local.fn_name
  role             = aws_iam_role.remediate_logging.arn
  runtime          = "nodejs22.x" # confirm: current supported Node runtime
  handler          = "index.handler"
  filename         = data.archive_file.remediate_logging.output_path
  source_code_hash = data.archive_file.remediate_logging.output_base64sha256
  timeout          = 30
  memory_size      = 128

  environment {
    variables = {
      SNS_TOPIC_ARN  = aws_sns_topic.alerts.arn
      LAB_TRAIL_NAME = local.trail_name
      SCOPE_PREFIXES = var.stratus_prefix
      REMEDIATE      = tostring(var.remediate)
    }
  }

  depends_on = [aws_cloudwatch_log_group.remediate_logging, aws_iam_role_policy.remediate_logging]
}

resource "aws_cloudwatch_event_rule" "logging_tampered" {
  name        = "p5-logging-tampered"
  description = "StopLogging / DeleteTrail on CloudTrail (MITRE T1562.008)"
  state       = var.detection_enabled ? "ENABLED" : "DISABLED"

  event_pattern = jsonencode({
    source      = ["aws.cloudtrail"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["cloudtrail.amazonaws.com"]
      eventName   = ["StopLogging", "DeleteTrail"]
    }
  })
}

resource "aws_cloudwatch_event_target" "logging_tampered" {
  rule = aws_cloudwatch_event_rule.logging_tampered.name
  arn  = aws_lambda_function.remediate_logging.arn
}

resource "aws_lambda_permission" "events_invoke_logging" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediate_logging.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.logging_tampered.arn
}
