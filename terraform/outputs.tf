output "trail_name" {
  value = aws_cloudtrail.lab.name
}

output "alert_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "lambda_name" {
  value = aws_lambda_function.remediate_logging.function_name
}

output "rule_state" {
  value = aws_cloudwatch_event_rule.logging_tampered.state
}
