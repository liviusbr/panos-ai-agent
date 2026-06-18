module "fw1" {
  source = "./modules/panos-baseline"
  firewall_name       = "fw1"
  untrust_ip          = "192.168.43.100/24"
  trust_ip            = "192.168.63.100/24"
  default_gateway     = "10.0.0.254"  # TODO: see note below — no live default route exists
  web_server_ip       = "192.168.10.100/32"
  web_server_name     = "web-server"
  virtual_router_name = "vr1"
}
# Genereaza inventory Ansible dinamic din outputs Terraform
resource "local_file" "ansible_inventory" {
  content = templatefile("${path.module}/inventory.tmpl", {
    firewall_ip       = var.panos_hostname
    firewall_hostname = var.panos_new_hostname
    username          = var.panos_username
    password          = var.panos_password
  })
  filename = "${path.module}/ansible/inventory.ini"
}
# Commit Terraform changes
resource "null_resource" "commit" {
  triggers = {
    always_run = timestamp()
  }
  provisioner "local-exec" {
    command = "python3 commit.py"
  }
  depends_on = [module.fw1]
}
# Ruleaza Ansible dupa commit
resource "null_resource" "ansible" {
  triggers = {
    always_run = timestamp()
  }
  provisioner "local-exec" {
    command = "ansible-playbook -i ansible/inventory.ini ansible/playbook.yml"
  }
  depends_on = [
    null_resource.commit,
    local_file.ansible_inventory
  ]
}
