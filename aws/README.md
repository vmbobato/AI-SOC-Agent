# AWS Integration (Lambda + CloudWatch + SES + S3)

This folder contains a Lambda-ready pipeline that:

1. Pulls logs from CloudWatch log groups (`nginx_access`, `nginx_error`, `web_stdout`).
2. Parses and runs detections.
3. Generates OpenAI summary markdown.
4. Uploads outputs to S3.
5. Sends SES email with summary and report links.

## Lambda Handler

- Handler path: `aws.lambda_handler.handler`

## Required Environment Variables

- `AWS_REGION` (example: `us-east-1`)
- `LOG_GROUP_NGINX_ACCESS`
- `LOG_GROUP_NGINX_ERROR`
- `LOG_GROUP_WEB_STDOUT`
- `REPORTS_BUCKET`
- `REPORTS_PREFIX` (optional, default: `soc-reports`)
- `WINDOW_MINUTES` (optional, default: `60`)
- `SES_SENDER`
- `SES_RECIPIENTS` (comma-separated)
- `OPENAI_API_KEY`
- `OPENAI_MODEL` (optional, default: `gpt-4.1-mini`)

Optional CloudWatch filter patterns:

- `FILTER_NGINX_ACCESS`
- `FILTER_NGINX_ERROR`
- `FILTER_WEB_STDOUT`

## IAM Permissions Needed

- CloudWatch Logs:
  - `logs:FilterLogEvents`
- S3:
  - `s3:PutObject`
- SES:
  - `ses:SendEmail`

## EventBridge Trigger

Example event payload:

```json
{
  "window_minutes": 30
}
```
