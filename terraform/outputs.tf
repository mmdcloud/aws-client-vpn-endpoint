output "load_balancer_endpoint" {
  description = "Load balancer endpoint"
  value       = "https://${module.lb.dns_name}"
}