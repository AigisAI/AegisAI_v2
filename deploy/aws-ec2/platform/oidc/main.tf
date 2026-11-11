terraform {
  required_version = "= 1.17.1"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.72.0"
    }
  }
  backend "local" {
    path = "state/terraform.tfstate"
  }
}

provider "aws" {
  region              = "ap-northeast-2"
  allowed_account_ids = ["024139495514"]
}

resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

resource "aws_iam_role" "delivery_gate" {
  name                 = "aegisai-private-github-delivery-gate"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = "repo:AigisAI/AegisAI_v2:ref:refs/heads/release/375-private-aws-gate"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "delivery_gate" {
  name = "PrivateBucketConfigurationRead"
  role = aws_iam_role.delivery_gate.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:GetBucketLocation",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetEncryptionConfiguration"
      ]
      Resource = "arn:aws:s3:::aegisai-private-024139495514-apne2"
    }]
  })
}
