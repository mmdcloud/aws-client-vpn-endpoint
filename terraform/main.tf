# --------------------------------------------------------------------------------------
# VPC Configuration
# --------------------------------------------------------------------------------------
module "vpc" {
  source                  = "./modules/vpc"
  vpc_name                = "vpc"
  vpc_cidr                = "10.0.0.0/16"
  azs                     = var.azs
  public_subnets          = var.public_subnets
  private_subnets         = var.private_subnets
  enable_dns_hostnames    = true
  enable_dns_support      = true
  create_igw              = true
  map_public_ip_on_launch = true
  enable_nat_gateway      = true
  single_nat_gateway      = false
  one_nat_gateway_per_az  = true
  tags = {
    Project = "aws-vpn-endpoint"
  }
}

resource "aws_security_group" "lb_sg" {
  name   = "lb-sg"
  vpc_id = module.vpc.vpc_id

  ingress {
    description = "HTTP traffic"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS traffic"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "lb-sg"
  }
}

resource "aws_security_group" "asg_sg" {
  name   = "asg-sg"
  vpc_id = module.vpc.vpc_id

  ingress {
    description     = "HTTP traffic"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    cidr_blocks     = []
    security_groups = [aws_security_group.lb_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "asg-sg"
  }
}

resource "aws_security_group" "vpn" {
  name_prefix = "client-vpn-endpoint-sg"
  description = "Security group for Client VPN endpoint"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --------------------------------------------------------------------------------------
# Certificate Configuration
# --------------------------------------------------------------------------------------
resource "tls_private_key" "ca_key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "ca_cert" {
  private_key_pem = tls_private_key.ca_key.private_key_pem

  subject {
    common_name  = "VPN Root CA"
    organization = var.organization_name
    country      = "US"
  }

  validity_period_hours = 87600
  is_ca_certificate     = true

  allowed_uses = [
    "cert_signing",
    "crl_signing",
    "digital_signature",
    "key_encipherment"
  ]
}

resource "tls_private_key" "vpn_key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_cert_request" "vpn_csr" {
  private_key_pem = tls_private_key.vpn_key.private_key_pem

  subject {
    common_name  = var.vpn_domain
    organization = var.organization_name
    country      = "US"
  }
}

resource "tls_locally_signed_cert" "vpn_cert" {
  cert_request_pem   = tls_cert_request.vpn_csr.cert_request_pem
  ca_private_key_pem = tls_private_key.ca_key.private_key_pem
  ca_cert_pem        = tls_self_signed_cert.ca_cert.cert_pem

  validity_period_hours = 8760 # 1 year

  allowed_uses = [
    "digital_signature",
    "key_encipherment",
    "server_auth",
    "client_auth",
  ]

  set_subject_key_id = true
}

resource "tls_private_key" "client_key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_cert_request" "client_csr" {
  private_key_pem = tls_private_key.client_key.private_key_pem

  subject {
    common_name  = "client.${var.vpn_domain}"
    organization = var.organization_name
    country      = "US"
  }
}

resource "tls_locally_signed_cert" "client_cert" {
  cert_request_pem      = tls_cert_request.client_csr.cert_request_pem
  ca_private_key_pem    = tls_private_key.ca_key.private_key_pem
  ca_cert_pem           = tls_self_signed_cert.ca_cert.cert_pem
  validity_period_hours = var.certificate_validity_period_hours
  allowed_uses = [
    "digital_signature",
    "key_encipherment",
    "client_auth",
  ]
  set_subject_key_id = true
}

resource "aws_acm_certificate" "vpn_cert" {
  private_key       = tls_private_key.vpn_key.private_key_pem
  certificate_body  = tls_locally_signed_cert.vpn_cert.cert_pem
  certificate_chain = tls_self_signed_cert.ca_cert.cert_pem
}

resource "aws_acm_certificate" "ca_cert" {
  private_key      = tls_private_key.ca_key.private_key_pem
  certificate_body = tls_self_signed_cert.ca_cert.cert_pem
}

# -------------------------------------------------------------------------------
# Auto Scaling Group
# -------------------------------------------------------------------------------
resource "aws_iam_role" "ec2_role" {
  name = "ec2-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_instance_profile" "iam_instance_profile" {
  name = "ec2-instance-profile"
  role = aws_iam_role.ec2_role.name
}

# Instance template
module "launch_template" {
  source                               = "./modules/launch_template"
  name                                 = "launch_template"
  description                          = "launch_template"
  ebs_optimized                        = false
  image_id                             = "ami-005fc0f236362e99f"
  instance_type                        = "t2.micro"
  instance_initiated_shutdown_behavior = "stop"
  instance_profile_name                = aws_iam_instance_profile.iam_instance_profile.name
  key_name                             = "madmaxkeypair"
  network_interfaces = [
    {
      associate_public_ip_address = false
      security_groups             = [aws_security_group.asg_sg.id]
    }
  ]
  user_data = base64encode(templatefile("${path.module}/scripts/user_data.sh", {}))
}

# Auto Scaling Group for launch template
module "asg" {
  source                    = "./modules/auto_scaling_group"
  name                      = "asg"
  min_size                  = 3
  max_size                  = 50
  desired_capacity          = 3
  health_check_grace_period = 300
  health_check_type         = "ELB"
  force_delete              = true
  target_group_arns         = [module.lb.target_groups.lb_target_group.arn]
  vpc_zone_identifier       = module.vpc.private_subnets
  launch_template_id        = module.launch_template.id
  launch_template_version   = "$Latest"
}

# -------------------------------------------------------------------------------
# Load Balancer
# -------------------------------------------------------------------------------
module "lb_logs" {
  source        = "./modules/s3"
  bucket_name   = "lb-logs"
  objects       = []
  bucket_policy = ""
  cors = [
    {
      allowed_headers = ["*"]
      allowed_methods = ["GET"]
      allowed_origins = ["*"]
      max_age_seconds = 3000
    },
    {
      allowed_headers = ["*"]
      allowed_methods = ["PUT"]
      allowed_origins = ["*"]
      max_age_seconds = 3000
    }
  ]
  versioning_enabled = "Enabled"
  force_destroy      = true
}

module "lb" {
  source                     = "terraform-aws-modules/alb/aws"
  name                       = "lb"
  load_balancer_type         = "application"
  vpc_id                     = module.vpc.vpc_id
  subnets                    = module.vpc.public_subnets
  enable_deletion_protection = false
  drop_invalid_header_fields = true
  ip_address_type            = "ipv4"
  internal                   = false
  security_groups = [
    aws_security_group.lb_sg.id
  ]
  access_logs = {
    bucket = "${module.lb_logs.bucket}"
  }
  listeners = {
    lb_http_listener = {
      port     = 80
      protocol = "HTTP"
      forward = {
        target_group_key = "lb_target_group"
      }
    }
  }
  target_groups = {
    lb_target_group = {
      backend_protocol = "HTTP"
      backend_port     = 80
      target_type      = "instance"
      health_check = {
        enabled             = true
        healthy_threshold   = 3
        interval            = 30
        path                = "/"
        port                = 80
        protocol            = "HTTP"
        unhealthy_threshold = 3
      }
      create_attachment = false
    }
  }
  tags = {
    Project = "verified-access"
  }
}

# --------------------------------------------------------------------------------------
# Client VPN Endpoint Configuration
# --------------------------------------------------------------------------------------
resource "aws_ec2_client_vpn_endpoint" "vpn" {
  description            = "Client VPN endpoint"
  server_certificate_arn = aws_acm_certificate.vpn_cert.arn
  client_cidr_block      = var.client_cidr_block
  vpc_id                 = module.vpc.vpc_id
  split_tunnel           = var.split_tunnel
  authentication_options {
    type                       = "certificate-authentication"
    root_certificate_chain_arn = aws_acm_certificate.ca_cert.arn
  }
  transport_protocol = "tcp"
  security_group_ids = [aws_security_group.vpn.id]
  connection_log_options {
    enabled               = true
    cloudwatch_log_group  = aws_cloudwatch_log_group.vpn_logs.name
    cloudwatch_log_stream = aws_cloudwatch_log_stream.vpn_logs.name
  }
  dns_servers           = ["169.254.169.253"]
  session_timeout_hours = 8
  client_login_banner_options {
    enabled     = true
    banner_text = "This VPN is for authorized users only. All activities may be monitored and recorded."
  }
}

resource "aws_ec2_client_vpn_network_association" "vpn_subnet" {
  count                  = length(module.vpc.public_subnets)
  client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.vpn.id
  subnet_id              = module.vpc.public_subnets[count.index]
}

resource "aws_ec2_client_vpn_authorization_rule" "vpn_auth_rule" {
  count                  = length(module.vpc.public_subnets)
  client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.vpn.id
  target_network_cidr    = module.vpc.public_subnets_cidr_blocks[0]
  authorize_all_groups   = true
}

resource "aws_cloudwatch_log_group" "vpn_logs" {
  # encrypted by default
  name              = "/aws/vpn/${var.vpn_domain}"
  retention_in_days = 2192
}

resource "aws_cloudwatch_log_stream" "vpn_logs" {
  name           = "vpn-connection-logs"
  log_group_name = aws_cloudwatch_log_group.vpn_logs.name
}

data "aws_ec2_client_vpn_endpoint" "selected" {
  client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.vpn.id
  depends_on = [
    aws_ec2_client_vpn_endpoint.vpn
  ]
}

resource "local_file" "vpn_config" {
  filename        = "${path.root}/client.ovpn"
  content         = <<-EOT
client
dev tun
proto udp
remote ${aws_ec2_client_vpn_endpoint.vpn.dns_name} 443
remote-random-hostname
resolv-retry infinite
nobind
remote-cert-tls server
cipher AES-256-GCM
verify-x509-name ${var.vpn_domain} name
reneg-sec 0
verb 3

<ca>
${tls_self_signed_cert.ca_cert.cert_pem}
</ca>

<cert>
${tls_locally_signed_cert.client_cert.cert_pem}
</cert>

<key>
${tls_private_key.client_key.private_key_pem}
</key>
EOT
  file_permission = "0600"
  depends_on = [
    aws_ec2_client_vpn_endpoint.vpn,
    tls_locally_signed_cert.client_cert,
    tls_private_key.client_key,
    tls_self_signed_cert.ca_cert
  ]
}