output "firewall_ip" {
  value       = var.panos_hostname
  description = "Management IP - folosit de Ansible"
}

output "firewall_hostname" {
  value       = var.panos_new_hostname
  description = "Hostname care va fi setat de Ansible"
}
