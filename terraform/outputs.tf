output "load_balancer_endpoint" {
  description = "Load balancer endpoint"
  value       = "http://${module.lb.dns_name}"
}