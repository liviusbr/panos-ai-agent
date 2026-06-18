variable "untrust_zone" {
  type    = string
  default = "untrust"
}

variable "trust_zone" {
  type    = string
  default = "trust"
}

variable "untrust_interface" {
  type    = string
  default = "ethernet1/1"
}

variable "trust_interface" {
  type    = string
  default = "ethernet1/2"
}

variable "untrust_ip" {
  type        = string
  description = "IP interfata untrust cu prefix ex: 10.0.0.1/24"
}

variable "trust_ip" {
  type        = string
  description = "IP interfata trust cu prefix ex: 192.168.10.1/24"
}

variable "default_gateway" {
  type        = string
  description = "Default gateway"
}

variable "virtual_router_name" {
  type    = string
  default = "vr1"
}

variable "web_server_ip" {
  type        = string
  description = "IP web server intern cu prefix ex: 192.168.10.100/32"
}

variable "web_server_name" {
  type    = string
  default = "web-server"
}

variable "firewall_name" {
  type        = string
  description = "Nume identificator firewall - folosit in comentarii"
}
