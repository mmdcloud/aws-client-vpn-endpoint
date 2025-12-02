variable "region" {
  type = string
}

variable "organization_name" {
  type = string
}

variable "vpn_domain" {
  type = string
}

variable "public_subnets" {
  type        = list(string)
  description = "Public Subnet CIDR values"
}

variable "private_subnets" {
  type        = list(string)
  description = "Private Subnet CIDR values"
}

variable "azs" {
  type        = list(string)
  description = "Availability Zones"
}   

variable "certificate_validity_period_hours" {
  type        = number
  description = "The validity period of the certificates in hours"
}

variable "split_tunnel" {
  type        = bool
  description = "Enable split tunneling"
}

variable "client_cidr_block" {
  type        = string
  description = "Client CIDR block for VPN"
}