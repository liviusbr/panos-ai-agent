terraform {
  required_version = ">= 1.5.0"

  required_providers {
    panos = {
      source  = "PaloAltoNetworks/panos"
      version = "~> 1.11"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.4"
    }
  }
}

provider "panos" {
  hostname = var.panos_hostname
  username = var.panos_username
  password = var.panos_password
}
