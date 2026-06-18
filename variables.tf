variable "panos_hostname" {
  type = string
}

variable "panos_username" {
  type    = string
  default = "admin"
}

variable "panos_password" {
  type      = string
  sensitive = true
}

variable "panos_new_hostname" {
  type        = string
  description = "Hostname care va fi setat pe firewall via Ansible"
  default     = "PA-VM-Lab7"
}

variable "ntp_server" {
  type    = string
  default = "pool.ntp.org"
}

variable "dns_primary" {
  type    = string
  default = "8.8.8.8"
}

variable "dns_secondary" {
  type    = string
  default = "8.8.4.4"
}
