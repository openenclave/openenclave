module "network" {
  source              = "Azure/network/azurerm"
  location            = var.location
  resource_group_name = var.resource_group_name
  vnet_name           = var.vnet_name
  address_space       = var.address_space
  subnet_prefixes     = var.subnet_prefixes
  subnet_names        = var.subnet_names
  tags                = var.tags
}

data "template_cloudinit_config" "jenkins-master" {
  gzip          = true
  base64_encode = true

  part {
    content_type = "text/cloud-config"
    content = templatefile("${path.module}/cloud-init.tpl",
      {
        jenkins_master_dns  = var.dns_name
        location            = var.location
        oeadmin_ssh_pub_key = file(var.oeadmin_ssh_pub_key)
      }
    )
  }
}

module "jenkins-master" {
  source              = "../modules/terraform-azurerm-compute"
  location            = var.location
  vm_os_simple        = "UbuntuServer"
  public_ip_dns       = [var.dns_name]
  vm_hostname         = "jenkins-master"
  vm_size             = var.vm_size
  vnet_subnet_id      = element(module.network.vnet_subnets, 0)
  resource_group_name = var.resource_group_name
  custom_data         = data.template_cloudinit_config.jenkins-master.rendered
  data_disk           = true
  data_disk_size_gb   = 200
  security_group_predefined_rules = [
    {
      name     = "SSH"
      priority = "500"
    },
    {
      name     = "HTTPS"
      priority = "100"
    },
    {
      name     = "HTTP"
      priority = "200"
    },
  ]
  security_group_custom_rules = [{
    name                   = "jnlp"
    priority               = "300"
    direction              = "Inbound"
    access                 = "Allow"
    protocol               = "tcp"
    destination_port_range = "50000"
    description            = "Jenkins_JNLP"
  }]
}

resource "azurerm_storage_account" "agents" {
  name                     = "agentsterraform"
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}
