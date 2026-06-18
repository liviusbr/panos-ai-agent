output "untrust_ip" {
  value = split("/", var.untrust_ip)[0]
}

output "trust_ip" {
  value = split("/", var.trust_ip)[0]
}

output "virtual_router" {
  value = panos_virtual_router.vr.name
}

output "web_server_name" {
  value = panos_address_object.web_server.name
}
