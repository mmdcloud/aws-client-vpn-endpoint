# 🚀 AWS Client VPN with Auto-Scaling Web Application

Production-grade Terraform infrastructure for deploying a secure AWS Client VPN endpoint with an auto-scaling web application behind an Application Load Balancer.

## 📋 Table of Contents

- [Architecture Overview](#architecture-overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Security](#security)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)
- [Cost Estimation](#cost-estimation)
- [Contributing](#contributing)
- [License](#license)

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        AWS Cloud                            │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                    VPC (10.0.0.0/16)                 │  │
│  │                                                      │  │
│  │  ┌────────────────┐      ┌────────────────┐        │  │
│  │  │ Public Subnet  │      │ Public Subnet  │        │  │
│  │  │     AZ-1       │      │     AZ-2       │        │  │
│  │  │                │      │                │        │  │
│  │  │  ┌──────────┐  │      │  ┌──────────┐  │        │  │
│  │  │  │   ALB    │◄─┼──────┼─►│   ALB    │  │        │  │
│  │  │  └────┬─────┘  │      │  └────┬─────┘  │        │  │
│  │  │       │        │      │       │        │        │  │
│  │  │  ┌────▼─────┐  │      │  ┌────▼─────┐  │        │  │
│  │  │  │ Client   │  │      │  │ Client   │  │        │  │
│  │  │  │   VPN    │  │      │  │   VPN    │  │        │  │
│  │  │  │ Network  │  │      │  │ Network  │  │        │  │
│  │  │  │  Assoc   │  │      │  │  Assoc   │  │        │  │
│  │  │  └──────────┘  │      │  └──────────┘  │        │  │
│  │  └────────────────┘      └────────────────┘        │  │
│  │                                                      │  │
│  │  ┌────────────────┐      ┌────────────────┐        │  │
│  │  │ Private Subnet │      │ Private Subnet │        │  │
│  │  │     AZ-1       │      │     AZ-2       │        │  │
│  │  │                │      │                │        │  │
│  │  │  ┌──────────┐  │      │  ┌──────────┐  │        │  │
│  │  │  │   EC2    │  │      │  │   EC2    │  │        │  │
│  │  │  │  (ASG)   │  │      │  │  (ASG)   │  │        │  │
│  │  │  └──────────┘  │      │  └──────────┘  │        │  │
│  │  │  ┌──────────┐  │      │  ┌──────────┐  │        │  │
│  │  │  │   NAT    │  │      │  │   NAT    │  │        │  │
│  │  │  │ Gateway  │  │      │  │ Gateway  │  │        │  │
│  │  │  └──────────┘  │      │  └──────────┘  │        │  │
│  │  └────────────────┘      └────────────────┘        │  │
│  │                                                      │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │ CloudWatch   │  │     ACM      │  │      S3      │    │
│  │   Logs       │  │ Certificates │  │   (ALB Logs) │    │
│  └──────────────┘  └──────────────┘  └──────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

### Components

- **VPC**: Multi-AZ virtual private cloud with public and private subnets
- **Client VPN Endpoint**: Certificate-based VPN for secure remote access
- **Application Load Balancer**: Distributes traffic across multiple availability zones
- **Auto Scaling Group**: 3-50 EC2 instances with automatic scaling
- **NAT Gateways**: One per AZ for high availability
- **CloudWatch**: Centralized logging and monitoring
- **S3**: ALB access logs storage

## ✨ Features

- **High Availability**: Multi-AZ deployment with NAT Gateway per AZ
- **Auto Scaling**: Dynamic scaling (3-50 instances) based on demand
- **Security**: 
  - Certificate-based VPN authentication
  - Security groups with least privilege
  - Encrypted CloudWatch logs
  - TLS 1.2+ for all connections
- **Monitoring**: 
  - VPN connection logs
  - ALB access logs
  - CloudWatch metrics
- **Split Tunneling**: Configurable to route only specific traffic through VPN
- **Session Management**: 8-hour VPN session timeout
- **Infrastructure as Code**: 100% Terraform with modular design

## 📦 Prerequisites

- **Terraform**: >= 1.0
- **AWS CLI**: >= 2.0 (configured with appropriate credentials)
- **AWS Account**: With appropriate IAM permissions
- **OpenVPN Client**: For connecting to the VPN endpoint

### Required IAM Permissions

Your AWS credentials need permissions for:
- VPC and networking resources
- EC2 instances and Auto Scaling Groups
- Elastic Load Balancers
- ACM certificates
- Client VPN endpoints
- CloudWatch logs
- S3 buckets
- IAM roles and policies

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone <repository-url>
cd aws-client-vpn-infrastructure
```

### 2. Configure Variables

Create a `terraform.tfvars` file:

```hcl
# Region and Availability Zones
aws_region = "us-east-1"
azs        = ["us-east-1a", "us-east-1b"]

# Network Configuration
public_subnets  = ["10.0.1.0/24", "10.0.2.0/24"]
private_subnets = ["10.0.11.0/24", "10.0.12.0/24"]

# VPN Configuration
vpn_domain                          = "vpn.example.com"
organization_name                   = "YourCompany"
client_cidr_block                   = "172.16.0.0/22"
split_tunnel                        = true
certificate_validity_period_hours   = 8760  # 1 year
```

### 3. Initialize Terraform

```bash
terraform init
```

### 4. Review the Plan

```bash
terraform plan
```

### 5. Deploy Infrastructure

```bash
terraform apply
```

The deployment takes approximately 10-15 minutes.

### 6. Connect to VPN

After deployment, a `client.ovpn` file is generated in the project root:

```bash
# macOS/Linux
sudo openvpn --config client.ovpn

# Windows
# Import client.ovpn into OpenVPN GUI
```

## ⚙️ Configuration

### Network Settings

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `vpc_cidr` | VPC CIDR block | `10.0.0.0/16` | No |
| `public_subnets` | Public subnet CIDR blocks | - | Yes |
| `private_subnets` | Private subnet CIDR blocks | - | Yes |
| `azs` | Availability zones | - | Yes |

### VPN Settings

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `vpn_domain` | VPN endpoint domain | - | Yes |
| `client_cidr_block` | VPN client IP range | `172.16.0.0/22` | No |
| `split_tunnel` | Enable split tunneling | `true` | No |
| `organization_name` | Certificate organization | - | Yes |
| `certificate_validity_period_hours` | Client cert validity | `8760` | No |

### Auto Scaling Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `min_size` | Minimum instances | `3` |
| `max_size` | Maximum instances | `50` |
| `desired_capacity` | Desired instances | `3` |
| `instance_type` | EC2 instance type | `t2.micro` |

### Modifying Auto Scaling

Edit `main.tf`:

```hcl
module "asg" {
  # ... other configuration ...
  min_size         = 5
  max_size         = 100
  desired_capacity = 10
}
```

## 🔒 Security

### Certificate Management

This infrastructure uses self-signed certificates for demonstration. **For production:**

1. **Use ACM Private CA** for certificate management
2. **Implement certificate rotation** (certificates expire after 1 year)
3. **Store private keys securely** (AWS Secrets Manager, HashiCorp Vault)

### Rotation Process

```bash
# Generate new certificates
terraform apply -replace=tls_private_key.client_key

# Distribute new client.ovpn to users
# Revoke old certificates if needed
```

### Security Groups

- **Load Balancer SG**: Allows HTTP (80) and HTTPS (443) from internet
- **ASG SG**: Allows HTTP (80) only from Load Balancer
- **VPN SG**: Allows HTTPS (443) from internet for VPN connections

### Best Practices

- [ ] Enable AWS GuardDuty for threat detection
- [ ] Implement AWS Security Hub for compliance monitoring
- [ ] Use AWS Systems Manager Session Manager instead of SSH
- [ ] Enable VPC Flow Logs for network monitoring
- [ ] Implement AWS Config rules for configuration compliance
- [ ] Regular security audits and penetration testing

## 📊 Monitoring

### CloudWatch Logs

VPN connection logs are stored in:
```
/aws/vpn/<vpn_domain>
```

Retention: 2192 days (6 years)

### Key Metrics to Monitor

```bash
# Active VPN connections
aws cloudwatch get-metric-statistics \
  --namespace AWS/ClientVPN \
  --metric-name ActiveConnectionsCount \
  --dimensions Name=Endpoint,Value=<endpoint-id> \
  --start-time 2024-01-01T00:00:00Z \
  --end-time 2024-01-02T00:00:00Z \
  --period 3600 \
  --statistics Average

# ALB target health
aws elbv2 describe-target-health \
  --target-group-arn <target-group-arn>
```

### Recommended Alarms

1. **VPN Connection Failures** > 5 in 5 minutes
2. **ALB Unhealthy Hosts** > 0
3. **ASG CPU Utilization** > 80%
4. **NAT Gateway Errors** > 10

## 🔧 Troubleshooting

### VPN Connection Issues

**Problem**: Cannot connect to VPN

```bash
# Check endpoint status
aws ec2 describe-client-vpn-endpoints \
  --client-vpn-endpoint-ids <endpoint-id>

# Verify security group rules
aws ec2 describe-security-groups \
  --group-ids <vpn-sg-id>

# Check CloudWatch logs
aws logs tail /aws/vpn/<vpn_domain> --follow
```

**Problem**: Connected but cannot access resources

- Verify authorization rules: `aws ec2 describe-client-vpn-authorization-rules`
- Check route table associations
- Verify target network CIDR blocks

### Auto Scaling Issues

**Problem**: Instances not scaling

```bash
# Check ASG activity
aws autoscaling describe-scaling-activities \
  --auto-scaling-group-name asg

# Check instance health
aws autoscaling describe-auto-scaling-instances
```

### Load Balancer Issues

**Problem**: 502/503 errors

- Check target group health: `aws elbv2 describe-target-health`
- Review ALB access logs in S3
- Verify security group rules allow ALB → ASG traffic

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| Certificate validation failed | Clock skew or expired cert | Sync system time, regenerate certs |
| Authorization denied | Missing authorization rule | Add rule for target CIDR |
| Connection timeout | Security group blocking | Check SG rules and NACLs |

## 💰 Cost Estimation

### Monthly Cost Breakdown (us-east-1)

| Service | Usage | Cost |
|---------|-------|------|
| Client VPN Endpoint | 730 hours | ~$73 |
| Client VPN Connections | 10 users × 730 hours | ~$73 |
| NAT Gateway (2 AZs) | 2 × 730 hours + data | ~$65 |
| Application Load Balancer | 730 hours + LCUs | ~$23 |
| EC2 Instances (t2.micro) | 3 × 730 hours | ~$26 |
| S3 Storage | 10 GB logs | ~$0.23 |
| CloudWatch Logs | 5 GB ingested | ~$2.50 |
| Data Transfer | 100 GB out | ~$9 |

**Estimated Total**: ~$271/month (varies by usage)

### Cost Optimization Tips

1. Use split tunneling to reduce VPN data transfer
2. Implement Auto Scaling policies to scale down during off-hours
3. Use S3 lifecycle policies to archive old ALB logs
4. Consider AWS Savings Plans for consistent EC2 usage
5. Review CloudWatch log retention policies

## 🗂️ Project Structure

```
.
├── main.tf                    # Main infrastructure configuration
├── variables.tf               # Input variables
├── outputs.tf                 # Output values
├── terraform.tfvars          # Variable values (gitignored)
├── modules/
│   ├── vpc/                  # VPC module
│   ├── launch_template/      # EC2 launch template module
│   ├── auto_scaling_group/   # ASG module
│   └── s3/                   # S3 module
├── scripts/
│   └── user_data.sh         # EC2 instance initialization script
└── README.md
```

## 🔄 Maintenance

### Regular Tasks

**Weekly**:
- Review CloudWatch logs for anomalies
- Check VPN connection metrics
- Verify ASG scaling events

**Monthly**:
- Review AWS cost and usage reports
- Update AMIs for security patches
- Test disaster recovery procedures

**Quarterly**:
- Rotate VPN certificates
- Review and update security group rules
- Conduct security audits

### Updating Infrastructure

```bash
# Update Terraform modules
terraform init -upgrade

# Apply changes
terraform plan
terraform apply

# For critical updates, use blue-green deployment
```

## 🧪 Testing

### Infrastructure Testing

```bash
# Validate Terraform configuration
terraform validate

# Format Terraform files
terraform fmt -recursive

# Security scanning with tfsec
tfsec .

# Compliance checking with Checkov
checkov -d .
```

### VPN Connectivity Testing

```bash
# Test DNS resolution through VPN
nslookup google.com

# Test connectivity to private resources
curl http://<private-instance-ip>

# Verify split tunneling
traceroute 8.8.8.8  # Should NOT go through VPN
traceroute 10.0.1.10  # Should go through VPN
```

## 📝 Changelog

### Version 1.0.0 (2024-12-24)
- Initial release
- Multi-AZ VPC with public and private subnets
- Certificate-based Client VPN endpoint
- Auto-scaling web application
- Application Load Balancer with access logs
- CloudWatch monitoring and logging

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Coding Standards

- Follow Terraform best practices
- Use meaningful variable and resource names
- Include comments for complex logic
- Update documentation for changes
- Test changes in a dev environment first

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/your-org/repo/issues)
- **Documentation**: [Wiki](https://github.com/your-org/repo/wiki)
- **Email**: devops@yourcompany.com

## ⚠️ Disclaimer

This infrastructure is provided as-is for educational and demonstration purposes. Always review and customize security settings for your specific requirements before deploying to production.

## 🙏 Acknowledgments

- AWS Documentation
- Terraform AWS Provider
- OpenVPN Community

---

**Made with ❤️ by DevOps Team**

*Last Updated: December 24, 2024*
