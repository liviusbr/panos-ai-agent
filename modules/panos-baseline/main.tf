locals {
  untrust_ip_only = split("/", var.untrust_ip)[0]
  trust_ip_only   = split("/", var.trust_ip)[0]
  managed_by      = "terraform-${var.firewall_name}"
}

resource "panos_zone" "untrust" {
  name = var.untrust_zone
  mode = "layer3"
}

resource "panos_zone" "trust" {
  name = var.trust_zone
  mode = "layer3"
}

resource "panos_ethernet_interface" "untrust" {
  name               = var.untrust_interface
  mode               = "layer3"
  vsys               = "vsys1"
  enable_dhcp        = false
  static_ips         = [var.untrust_ip]
  comment            = "Managed by ${local.managed_by}"
  link_duplex        = "auto"
  link_speed         = "auto"
  link_state         = "auto"
  management_profile = "allow_ping"
}

resource "panos_ethernet_interface" "trust" {
  name               = var.trust_interface
  mode               = "layer3"
  vsys               = "vsys1"
  enable_dhcp        = false
  static_ips         = [var.trust_ip]
  comment            = "Managed by ${local.managed_by}"
  link_duplex        = "auto"
  link_speed         = "auto"
  link_state         = "auto"
  management_profile = "allow_ping"
}

resource "panos_virtual_router" "vr" {
  name                     = var.virtual_router_name
  ecmp_load_balance_method = "ip-modulo"
  interfaces = [
    panos_ethernet_interface.untrust.name,
    panos_ethernet_interface.trust.name
  ]
}

# No default route exists live right now. Left disabled on purpose —
# re-enable deliberately if/when you actually want 0.0.0.0/0 routed
# via var.default_gateway.
# resource "panos_static_route_ipv4" "default" {
#   name           = "default-route"
#   virtual_router = panos_virtual_router.vr.name
#   destination    = "0.0.0.0/0"
#   next_hop       = var.default_gateway
# }

resource "panos_address_object" "web_server" {
  name        = var.web_server_name
  value       = var.web_server_ip
  type        = "ip-netmask"
  description = "Managed by ${local.managed_by}"
}

# panos_security_policy.policies now lives in policies.tf,
# generated from rules.json by render_policy.py. Don't add it back here.
