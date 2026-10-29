# 🛡️ AWS Client VPN & Private Auto-Scaling Web Application

Enterprise-ready Infrastructure as Code (Terraform) deploying a secure, split-tunnel **AWS Client VPN Endpoint** granting authenticated remote access to an **Internal Application Load Balancer** and an **Auto-Scaling EC2 Application Fleet** isolated in private subnets.

---

## 📋 Table of Contents

- [Architecture Overview](#-architecture-overview)
- [Key Features](#-key-features)
- [Repository Structure](#-repository-structure)
- [Prerequisites](#-prerequisites)
- [Configuration & Variables](#-configuration--variables)
- [Deployment Guide](#-deployment-guide)
- [Client Connection & Testing](#-client-connection--testing)
- [Security & Production Hardening](#-security--production-hardening)
- [Production Readiness Roadmap](#-production-readiness-roadmap)
- [Monitoring & Operations](#-monitoring--operations)
- [Troubleshooting Runbook](#-troubleshooting-runbook)
- [Cost Estimation](#-cost-estimation)
- [License](#-license)

---

## 🏗️ Architecture Overview

The infrastructure isolates the application entirely inside **Private Subnets**. The Application Load Balancer is configured as **Internal** (`internal = true`), meaning it has no public IP addresses and cannot be reached from the internet. Remote developers and authorized systems connect securely via **AWS Client VPN** into the private network.

```
                      ┌───────────────────────────────────────────┐
                      │            Remote Client Device           │
                      │  (OpenVPN Client / AWS Client VPN App)    │
                      └─────────────────────┬─────────────────────┘
                                            │
                                            │ Encrypted OpenVPN Tunnel (UDP 443)
                                            │ [mssfix 1300 / Split-Tunnel]
                                            ▼
┌────────────────────────────────── AWS Cloud ──────────────────────────────────┐
│                                                                               │
│  AWS Managed Client VPN Endpoint (ap-southeast-2)                             │
│  ├─ Mutual TLS Authentication (ACM Root CA & Client Cert)                    │
│  ├─ CloudWatch Connection Logging (/aws/vpn/<domain>)                         │
│  └─ DNS: AmazonProvidedDNS (10.0.0.2) + Public Fallback (8.8.8.8)            │
│                                           │                                   │
│  ┌───────────────────────── VPC (10.0.0.0/16) ─────────────────────────────┐  │
│  │                                                                         │  │
│  │  Public Subnets (10.0.1.0/24, 10.0.2.0/24, 10.0.3.0/24)                 │  │
│  │  ┌──────────────────────┐  ┌──────────────────────┐                    │  │
│  │  │  Internet Gateway    │  │   NAT Gateway(s)     │                    │  │
│  │  │  (IGW for Outbound)  │  │   (Egress for ASG)   │                    │  │
│  │  └──────────────────────┘  └──────────────────────┘                    │  │
│  │                                                                         │  │
│  │  Private Subnets (10.0.4.0/24, 10.0.5.0/24, 10.0.6.0/24)                │  │
│  │  ┌──────────────────────────────────────────────────────────────────┐  │  │
│  │  │ Client VPN Network Interfaces (ENIs - Associated Subnets)        │  │  │
│  │  │ [Security Group: client-vpn-endpoint-sg]                         │  │  │
│  │  └─────────────────────────────────┬────────────────────────────────┘  │  │
│  │                                    │ Target Traffic (10.0.0.0/16)       │  │
│  │                                    ▼                                   │  │
│  │  ┌──────────────────────────────────────────────────────────────────┐  │  │
│  │  │ Internal Application Load Balancer (ALB)                         │  │  │
│  │  │ ├─ HTTP Listener (Port 80)  ──► 301 Redirect to HTTPS 443        │  │  │
│  │  │ ├─ HTTPS Listener (Port 443) ──► Target Group (Port 80)           │  │  │
│  │  │ └─ Security Group: lb-sg (Allows 80/443 from VPC & VPN SG)       │  │  │
│  │  └─────────────────────────────────┬────────────────────────────────┘  │  │
│  │                                    │ Reverse Proxy Routing             │  │
│  │                                    ▼                                   │  │
│  │  ┌──────────────────────────────────────────────────────────────────┐  │  │
│  │  │ Auto Scaling Group (2 to 10 Instances - t3.micro)                │  │  │
│  │  │ ├─ OS: Ubuntu Server 24.04 LTS (HVM gp3)                         │  │  │
│  │  │ ├─ Reverse Proxy: Nginx (Port 80 -> 3000)                        │  │  │
│  │  │ ├─ Process Manager: PM2 (Node.js runtime under unprivileged user)│  │  │
│  │  │ └─ Security Group: asg-sg (Inbound Port 80 from lb-sg only)      │  │  │
│  │  └──────────────────────────────────────────────────────────────────┘  │  │
│  │                                                                         │  │
│  └─────────────────────────────────────────────────────────────────────────┘  │
│                                                                               │
│  Supporting Platform Services:                                                │
│  ├─ S3 Bucket (lb-logs-*): Hardened ALB Access Logs (SSE-AES256, TLS Enforced)│
│  ├─ ACM: TLS Server & Client Certificates for mutual endpoint authentication  │
│  └─ CloudWatch: Centralized VPN Connection Logs & Audit Trail                 │
└───────────────────────────────────────────────────────────────────────────────┘
```

---

## ✨ Key Features

- **Private & Zero Public Ingress**: The web application and ALB are deployed strictly inside private subnets without public IP addresses.
- **Client VPN with Split Tunneling**: Only corporate VPC traffic (`10.0.0.0/16`) routes through the VPN tunnel; regular internet traffic stays on the client's local connection.
- **Path MTU Clamping (`mssfix 1300`)**: Prevents packet fragmentation drops (`EMSGSIZE Path-MTU=1480`) on client Wi-Fi/broadband connections.
- **Automated Client Profile Generation**: Generates a self-contained, pre-configured `client.ovpn` profile with embedded keys, certificates, and routing options.
- **Automatic HTTP-to-HTTPS Redirection**: Internal ALB enforces encrypted transport via HTTP 301 redirection to TLS port 443.
- **Hardened S3 Logging**: Access log bucket includes Server-Side Encryption (SSE-S3), full S3 Block Public Access, TLS-only enforcement (`aws:SecureTransport`), and zero wildcard CORS.
- **Non-Root Compute Runtime**: Application bootstraps under an unprivileged `ubuntu` service user with PM2 process manager configured for automatic systemd restart on reboot.
- **Modular Terraform Architecture**: Reusable submodules for VPC, S3, Security Groups, Launch Templates, and Auto Scaling Groups.

---

## 🗂️ Repository Structure

```
.
├── README.md                           # Documentation & operational runbook
├── .gitignore                          # Excludes secrets, keys, state, & .ovpn profiles
├── src/                                # Node.js web application source code
│   ├── server.mjs                      # Express HTTP server (port 3000)
│   ├── package.json                    # Application dependencies
│   ├── Dockerfile                      # Container build definition
│   └── scripts/default                 # Nginx reverse proxy configuration template
└── terraform/                          # Infrastructure as Code root
    ├── main.tf                         # Core infrastructure composition
    ├── variables.tf                    # Variable declarations and typing
    ├── outputs.tf                      # Exported endpoints and resource IDs
    ├── provider.tf                     # Required providers & remote backend setup
    ├── terraform.tfvars                # Regional and deployment variable values
    ├── client.ovpn                     # Generated VPN client profile (gitignored)
    ├── scripts/
    │   └── user_data.sh                # Hardened EC2 cloud-init provisioning script
    └── modules/
        ├── vpc/                        # VPC networking & gateway wrapper
        ├── security-groups/            # Reusable ingress/egress security group module
        ├── s3/                         # Encrypted S3 bucket module
        ├── launch_template/            # EC2 launch template with IAM instance profile
        ├── auto_scaling_group/         # Auto-scaling group and health check attachment
        └── cloudwatch/                 # CloudWatch log group & stream configurations
```

---

## 📦 Prerequisites

1. **Terraform**: `>= 1.5.0` installed locally or in CI/CD pipeline.
2. **AWS CLI**: `>= 2.0` configured with administrative credentials (`aws configure`).
3. **OpenVPN Client**:
   - **Linux / macOS**: OpenVPN CLI (`openvpn >= 2.5`) or [Tunnelblick](https://tunnelblick.net/).
   - **Windows / macOS**: [AWS Client VPN Desktop App](https://aws.amazon.com/vpn/client-vpn-download/) or [OpenVPN Connect v3](https://openvpn.net/client-connect-vpn-for-windows/).

---

## ⚙️ Configuration & Variables

All customizable variables are declared in [`terraform/variables.tf`](file:///home/shiv/mohit/aws-client-vpn-endpoint/terraform/variables.tf) and configured in [`terraform/terraform.tfvars`](file:///home/shiv/mohit/aws-client-vpn-endpoint/terraform/terraform.tfvars):

| Variable | Type | Description | Example / Default |
| :--- | :--- | :--- | :--- |
| `region` | `string` | AWS deployment region | `"ap-southeast-2"` |
| `azs` | `list(string)` | Availability zones for Multi-AZ deployment | `["ap-southeast-2a", "ap-southeast-2b", "ap-southeast-2c"]` |
| `public_subnets` | `list(string)` | CIDR blocks for public subnets (NAT Gateways) | `["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]` |
| `private_subnets` | `list(string)` | CIDR blocks for private subnets (ALB & ASG) | `["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]` |
| `organization_name` | `string` | X.509 Certificate Authority Organization | `"mohitd"` |
| `vpn_domain` | `string` | Domain identifier for certificates and logging | `"mohitd.xyz"` |
| `client_cidr_block` | `string` | Dedicated CIDR block assigned to VPN clients | `"172.16.0.0/22"` |
| `split_tunnel` | `bool` | Route only VPC CIDR across the VPN tunnel | `true` |
| `certificate_validity_period_hours` | `number` | Client & server certificate validity duration | `8760` (1 year) |

---

## 🚀 Deployment Guide

### 1. Configure Credentials
Ensure your AWS credentials have permission to create VPC, EC2, ELB, ACM, S3, IAM, and Client VPN resources:
```bash
aws sts get-caller-identity
```

### 2. Initialize Terraform
Navigate to the `terraform/` directory and initialize provider plugins and local modules:
```bash
cd terraform
terraform init
```

### 3. Review Execution Plan
```bash
terraform plan
```

### 4. Deploy Infrastructure
```bash
terraform apply
```
*Note: Provisioning the Client VPN endpoint associations and NAT Gateway typically takes **10–12 minutes**.*

### 5. Obtain Outputs
Upon completion, Terraform outputs the internal load balancer endpoint and generates the client profile:
```text
Outputs:
load_balancer_endpoint = "https://internal-lb-142372591.ap-southeast-2.elb.amazonaws.com"
```
The file `terraform/client.ovpn` will be created automatically.

---

## 💻 Client Connection & Testing

### 1. Establish the VPN Connection

#### Option A: Linux / macOS Terminal (CLI)
```bash
sudo openvpn --config client.ovpn
```
Look for the successful completion line:
```text
Initialization Sequence Completed
```

#### Option B: OpenVPN Connect / AWS Client VPN App (GUI)
1. Open **OpenVPN Connect** or **AWS Client VPN**.
2. Click **Add Profile** > **Upload File** and select `terraform/client.ovpn`.
3. Click **Connect**.

---

### 2. Verify Tunnel & Network Routes

While connected to the VPN, open a separate terminal on your client machine:

```bash
# Verify assigned VPN tunnel IP (should be in 172.16.0.0/22)
ip addr show tun0

# Verify that private VPC traffic is routed across tun0
ip route get 10.0.4.1

# Output should confirm:
# 10.0.4.1 via 172.16.0.33 dev tun0
```

---

### 3. Access the Internal Web Application

Test the load balancer endpoint using `curl`:
```bash
curl -kv https://internal-lb-142372591.ap-southeast-2.elb.amazonaws.com
```

> [!NOTE]
> The `-k` (`--insecure`) flag is expected when accessing the raw AWS internal ALB hostname because the generated self-signed certificate matches `var.vpn_domain` (`mohitd.xyz`).

#### Verify HTTP to HTTPS Redirection:
```bash
curl -I http://internal-lb-142372591.ap-southeast-2.elb.amazonaws.com
```
Expected output:
```http
HTTP/1.1 301 Moved Permanently
Location: https://internal-lb-142372591.ap-southeast-2.elb.amazonaws.com:443/
```

#### Browser Access:
1. Open your browser and navigate to:
   ```text
   https://internal-lb-142372591.ap-southeast-2.elb.amazonaws.com
   ```
2. Accept the self-signed certificate warning (`Advanced` > `Proceed`).
3. The Node.js application dashboard will load.

---

## 🔒 Security & Production Hardening

The current configuration includes the following security controls:

1. **Non-Root Execution**:
   - The Node.js runtime and PM2 process manager run strictly under the unprivileged `ubuntu` user (`user_data.sh`).
2. **Path MTU Blackhole Protection**:
   - Configured `mssfix 1300` in the client profile to ensure encapsulated UDP packets never exceed broadband/Wi-Fi MTU limits (1480 bytes).
3. **Internal Network Segmentation**:
   - ALB Security Group (`lb-sg`): Inbound 80 and 443 restricted to `10.0.0.0/16`, `var.client_cidr_block`, and the Client VPN ENI security group.
   - ASG Security Group (`asg-sg`): Inbound port 80 permitted **only** from the ALB security group (`module.lb_sg.id`). Direct client-to-instance access is blocked.
   - VPN ENI Security Group (`client-vpn-endpoint-sg`): Closed to inbound VPC ingress; allows outbound egress only into the VPC network.
4. **S3 Access Log Hardening**:
   - Wildcard CORS removed.
   - SSE-S3 encryption enabled by default.
   - All 4 S3 Block Public Access flags set to `true`.
   - Bucket policy explicitly rejects unencrypted HTTP access (`aws:SecureTransport: "false"`).
   - Deletion protection (`force_destroy = false`) prevents accidental loss of audit logs.
5. **Session Management**:
   - Client VPN enforces an 8-hour maximum session duration (`session_timeout_hours = 8`).

---

## 🛣️ Production Readiness Roadmap

To transition this infrastructure from a staging/demo baseline to a regulated corporate production environment, complete the following items:

- [ ] **Migrate to SAML 2.0 / IdP Authentication**:
  Replace the static shared mutual certificate with **AWS IAM Identity Center**, **Okta**, or **Microsoft Entra ID**. Enforces MFA, device health checks, and individual user deprovisioning.
- [ ] **Transition to AWS Private CA (ACM PCA)**:
  Replace the ephemeral Terraform `tls_private_key` resource with AWS Private CA or HashiCorp Vault to ensure private keys are securely kept within an HSM/KMS.
- [ ] **Multi-AZ NAT Gateways**:
  In [`terraform/main.tf`](file:///home/shiv/mohit/aws-client-vpn-endpoint/terraform/main.tf#L22-L23), set `single_nat_gateway = false` and `one_nat_gateway_per_az = true` for high availability across all availability zones.
- [ ] **Remote State Backend**:
  Uncomment the S3 backend block in [`terraform/provider.tf`](file:///home/shiv/mohit/aws-client-vpn-endpoint/terraform/provider.tf#L20-L26) to enable encrypted remote state storage with native state locking.
- [ ] **Pre-Baked Golden AMI (Packer)**:
  Replace dynamic `user_data.sh` package installations (`npm install`, `apt update`) with an immutable Golden AMI built via **HashiCorp Packer** or migrate to containerized workloads on **AWS ECS / EKS**.
- [ ] **Custom Domain & Valid Public ACM Certificate**:
  Create an Amazon Route 53 Private Hosted Zone (e.g. `app.internal.yourcompany.com`) and attach an ACM certificate to avoid self-signed browser warnings.
- [ ] **AWS WAF**:
  Attach an AWS Web Application Firewall (WAFv2) Web ACL to the Application Load Balancer to protect against SQLi, XSS, and layer-7 flood attacks.

---

## 📊 Monitoring & Operations

### CloudWatch Logs

VPN audit logs are streamed to CloudWatch:
- **Log Group**: `/aws/vpn/<vpn_domain>` (Retention: 6 years / 2192 days)
- **Log Stream**: `vpn-connection-logs`

```bash
# Stream active VPN connections
aws logs tail /aws/vpn/mohitd.xyz --follow
```

### ALB Access Logs

ALB access logs are delivered every 5 minutes to S3:
```bash
aws s3 ls s3://lb-logs-<random-id>/AWSLogs/<account-id>/elasticloadbalancing/ap-southeast-2/
```

### Essential Production CloudWatch Alarms

1. **ALB 5XX Errors**: Metric `HTTPCode_Target_5XX_Count` > 5 in a 1-minute period.
2. **Unhealthy Host Count**: Metric `UnHealthyHostCount` > 0 in target group `lb_target_group`.
3. **ASG High CPU**: Metric `CPUUtilization` > 75% for 5 consecutive minutes.
4. **VPN Connection Failures**: Metric `ActiveConnections` drop or sudden spikes in disconnection events.

---

## 🔧 Troubleshooting Runbook

| Symptom | Root Cause | Solution |
| :--- | :--- | :--- |
| `read UDPv4 [EMSGSIZE Path-MTU=1480]: Message too long` | Packet size exceeds client Wi-Fi or ISP Path MTU. | Ensure `mssfix 1300` is present in `client.ovpn`. Clamps TCP MSS to prevent packet drops. |
| `TLS Error: TLS key negotiation failed to occur within 60 seconds` | Security group or local firewall blocking UDP 443 outbound. | Confirm local network allows outbound UDP port 443. Check endpoint association status in AWS Console. |
| `net_route_v4_add: ... dev [NULL]` | OpenVPN 2.6 Netlink route logging. | Completely normal behavior on Linux; interface is bound via the gateway IP. |
| Connection succeeds, but browser cannot resolve ALB DNS | Local DNS not querying AmazonProvidedDNS (`10.0.0.2`). | In Linux CLI OpenVPN, use `resolvectl` or `systemd-resolved` to map DNS, or test with `curl -kv --resolve <host>:443:<private-ip>`. |
| `HTTP 503 Service Temporarily Unavailable` | EC2 instances bootstrapping or failed health checks. | Wait 2–3 minutes for initial `user_data.sh` completion. Check target group health: `aws elbv2 describe-target-health`. |
| `InvalidConfigurationRequest: Access Denied for bucket: lb-logs-*` | S3 bucket policy missing ELB service account write rights. | Verify `AWSELBAccountWrite` is present in the S3 bucket policy for `data.aws_elb_service_account.main.arn`. |

---

## 💰 Cost Estimation

Estimated monthly infrastructure costs (AWS `ap-southeast-2` / Sydney):

| Service | Configuration | Estimated Monthly Cost |
| :--- | :--- | :--- |
| **AWS Client VPN Endpoint** | 1 Endpoint × 730 hours ($0.15/hr) | ~$109.50 |
| **Client VPN Connections** | ~5 concurrent users × 160 hrs/mo ($0.05/hr) | ~$40.00 |
| **NAT Gateway** | 1 NAT Gateway × 730 hours ($0.059/hr) + Data | ~$45.00 |
| **Application Load Balancer** | 1 ALB × 730 hours ($0.0252/hr) + LCUs | ~$22.00 |
| **EC2 Auto Scaling Group** | 2 × `t3.micro` instances (Linux) | ~$17.50 |
| **S3 & CloudWatch Logs** | Storage & Log Ingestion (< 10 GB) | ~$3.00 |
| **Data Transfer** | Outbound across internet/AZs | ~$5.00 |
| **Total Estimated Cost** | Baseline Staging Deployment | **~$242.00 / month** |

*Tip: Disassociating subnets from the Client VPN endpoint when not actively testing stops hourly endpoint charges.*

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
