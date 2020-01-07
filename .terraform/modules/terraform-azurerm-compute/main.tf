provider "azurerm" {
  version = ">= 1.1.0"
}

provider "random" {
  version = "~> 2.1"
}

module "os" {
  source       = "./os"
  vm_os_simple = var.vm_os_simple
}

resource "azurerm_resource_group" "vm" {
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags
}

resource "random_id" "vm-sa" {
  keepers = {
    vm_hostname = var.vm_hostname
  }

  byte_length = 6
}

resource "azurerm_storage_account" "vm-sa" {
  count                    = var.boot_diagnostics == "true" ? 1 : 0
  name                     = "bootdiag${lower(random_id.vm-sa.hex)}"
  resource_group_name      = azurerm_resource_group.vm.name
  location                 = var.location
  account_tier             = element(split("_", var.boot_diagnostics_sa_type), 0)
  account_replication_type = element(split("_", var.boot_diagnostics_sa_type), 1)
  tags                     = var.tags
}

resource "azurerm_virtual_machine" "vm-linux" {
  count                         = false == contains([var.vm_os_simple, var.vm_os_offer], "Windows") && var.is_windows_image != "true" && var.data_disk == "false" ? var.nb_instances : 0
  name                          = "${var.vm_hostname}${count.index}"
  location                      = var.location
  resource_group_name           = azurerm_resource_group.vm.name
  availability_set_id           = azurerm_availability_set.vm.id
  vm_size                       = var.vm_size
  network_interface_ids         = [element(azurerm_network_interface.vm.*.id, count.index)]
  delete_os_disk_on_termination = var.delete_os_disk_on_termination

  storage_image_reference {
    id        = var.vm_os_id
    publisher = var.vm_os_id == "" ? coalesce(var.vm_os_publisher, module.os.calculated_value_os_publisher) : ""
    offer     = var.vm_os_id == "" ? coalesce(var.vm_os_offer, module.os.calculated_value_os_offer) : ""
    sku       = var.vm_os_id == "" ? coalesce(var.vm_os_sku, module.os.calculated_value_os_sku) : ""
    version   = var.vm_os_id == "" ? var.vm_os_version : ""
  }

  storage_os_disk {
    name              = "osdisk-${var.vm_hostname}-${count.index}"
    create_option     = "FromImage"
    caching           = "ReadWrite"
    managed_disk_type = var.storage_account_type
  }

  os_profile {
    computer_name  = "${var.vm_hostname}${count.index}"
    admin_username = var.admin_username
    admin_password = var.admin_password
    custom_data    = var.custom_data
  }

  os_profile_linux_config {
    disable_password_authentication = true

    ssh_keys {
      path     = "/home/${var.admin_username}/.ssh/authorized_keys"
      key_data = file(var.ssh_key)
    }
  }

  tags = var.tags

  boot_diagnostics {
    enabled     = var.boot_diagnostics
    storage_uri = var.boot_diagnostics == "true" ? join(",", azurerm_storage_account.vm-sa.*.primary_blob_endpoint) : ""
  }
}

resource "azurerm_virtual_machine" "vm-linux-with-datadisk" {
  count                         = false == contains([var.vm_os_simple, var.vm_os_offer], "Windows") && var.is_windows_image != "true" && var.data_disk == "true" ? var.nb_instances : 0
  name                          = "${var.vm_hostname}${count.index}"
  location                      = var.location
  resource_group_name           = azurerm_resource_group.vm.name
  availability_set_id           = azurerm_availability_set.vm.id
  vm_size                       = var.vm_size
  network_interface_ids         = [element(azurerm_network_interface.vm.*.id, count.index)]
  delete_os_disk_on_termination = var.delete_os_disk_on_termination

  storage_image_reference {
    id        = var.vm_os_id
    publisher = var.vm_os_id == "" ? coalesce(var.vm_os_publisher, module.os.calculated_value_os_publisher) : ""
    offer     = var.vm_os_id == "" ? coalesce(var.vm_os_offer, module.os.calculated_value_os_offer) : ""
    sku       = var.vm_os_id == "" ? coalesce(var.vm_os_sku, module.os.calculated_value_os_sku) : ""
    version   = var.vm_os_id == "" ? var.vm_os_version : ""
  }

  storage_os_disk {
    name              = "osdisk-${var.vm_hostname}-${count.index}"
    create_option     = "FromImage"
    caching           = "ReadWrite"
    managed_disk_type = var.storage_account_type
  }

  storage_data_disk {
    name              = "datadisk-${var.vm_hostname}-${count.index}"
    create_option     = "Empty"
    lun               = 0
    disk_size_gb      = var.data_disk_size_gb
    managed_disk_type = var.data_sa_type
  }

  os_profile {
    computer_name  = "${var.vm_hostname}${count.index}"
    admin_username = var.admin_username
    admin_password = var.admin_password
    custom_data    = var.custom_data
  }

  os_profile_linux_config {
    disable_password_authentication = true

    ssh_keys {
      path     = "/home/${var.admin_username}/.ssh/authorized_keys"
      key_data = file(var.ssh_key)
    }
  }

  tags = var.tags

  boot_diagnostics {
    enabled     = var.boot_diagnostics
    storage_uri = var.boot_diagnostics == "true" ? join(",", azurerm_storage_account.vm-sa.*.primary_blob_endpoint) : ""
  }
}

resource "azurerm_virtual_machine" "vm-windows" {
  count                         = var.is_windows_image == "true" || contains([var.vm_os_simple, var.vm_os_offer], "Windows") && var.data_disk == "false" ? var.nb_instances : 0
  name                          = "${var.vm_hostname}${count.index}"
  location                      = var.location
  resource_group_name           = azurerm_resource_group.vm.name
  availability_set_id           = azurerm_availability_set.vm.id
  vm_size                       = var.vm_size
  network_interface_ids         = [element(azurerm_network_interface.vm.*.id, count.index)]
  delete_os_disk_on_termination = var.delete_os_disk_on_termination

  storage_image_reference {
    id        = var.vm_os_id
    publisher = var.vm_os_id == "" ? coalesce(var.vm_os_publisher, module.os.calculated_value_os_publisher) : ""
    offer     = var.vm_os_id == "" ? coalesce(var.vm_os_offer, module.os.calculated_value_os_offer) : ""
    sku       = var.vm_os_id == "" ? coalesce(var.vm_os_sku, module.os.calculated_value_os_sku) : ""
    version   = var.vm_os_id == "" ? var.vm_os_version : ""
  }

  storage_os_disk {
    name              = "osdisk-${var.vm_hostname}-${count.index}"
    create_option     = "FromImage"
    caching           = "ReadWrite"
    managed_disk_type = var.storage_account_type
  }

  os_profile {
    computer_name  = "${var.vm_hostname}${count.index}"
    admin_username = var.admin_username
    admin_password = var.admin_password
  }

  tags = var.tags

  os_profile_windows_config {
    provision_vm_agent = true
  }

  boot_diagnostics {
    enabled     = var.boot_diagnostics
    storage_uri = var.boot_diagnostics == "true" ? join(",", azurerm_storage_account.vm-sa.*.primary_blob_endpoint) : ""
  }
}

resource "azurerm_virtual_machine" "vm-windows-with-datadisk" {
  count                         = var.is_windows_image == "true" || contains([var.vm_os_simple, var.vm_os_offer], "Windows") && var.data_disk == "true" ? var.nb_instances : 0
  name                          = "${var.vm_hostname}${count.index}"
  location                      = var.location
  resource_group_name           = azurerm_resource_group.vm.name
  availability_set_id           = azurerm_availability_set.vm.id
  vm_size                       = var.vm_size
  network_interface_ids         = [element(azurerm_network_interface.vm.*.id, count.index)]
  delete_os_disk_on_termination = var.delete_os_disk_on_termination

  storage_image_reference {
    id        = var.vm_os_id
    publisher = var.vm_os_id == "" ? coalesce(var.vm_os_publisher, module.os.calculated_value_os_publisher) : ""
    offer     = var.vm_os_id == "" ? coalesce(var.vm_os_offer, module.os.calculated_value_os_offer) : ""
    sku       = var.vm_os_id == "" ? coalesce(var.vm_os_sku, module.os.calculated_value_os_sku) : ""
    version   = var.vm_os_id == "" ? var.vm_os_version : ""
  }

  storage_os_disk {
    name              = "osdisk-${var.vm_hostname}-${count.index}"
    create_option     = "FromImage"
    caching           = "ReadWrite"
    managed_disk_type = var.storage_account_type
  }

  storage_data_disk {
    name              = "datadisk-${var.vm_hostname}-${count.index}"
    create_option     = "Empty"
    lun               = 0
    disk_size_gb      = var.data_disk_size_gb
    managed_disk_type = var.data_sa_type
  }

  os_profile {
    computer_name  = "${var.vm_hostname}${count.index}"
    admin_username = var.admin_username
    admin_password = var.admin_password
  }

  tags = var.tags

  os_profile_windows_config {
    provision_vm_agent = true
  }

  boot_diagnostics {
    enabled     = var.boot_diagnostics
    storage_uri = var.boot_diagnostics == "true" ? join(",", azurerm_storage_account.vm-sa.*.primary_blob_endpoint) : ""
  }
}

resource "azurerm_availability_set" "vm" {
  name                         = "${var.vm_hostname}-avset"
  location                     = azurerm_resource_group.vm.location
  resource_group_name          = azurerm_resource_group.vm.name
  platform_fault_domain_count  = 2
  platform_update_domain_count = 2
  managed                      = true
  tags                         = var.tags
}

resource "azurerm_public_ip" "vm" {
  count                        = var.nb_public_ip
  name                         = "${var.vm_hostname}-${count.index}-publicIP"
  location                     = var.location
  resource_group_name          = azurerm_resource_group.vm.name
  allocation_method            = var.public_ip_address_allocation
  domain_name_label            = element(var.public_ip_dns, count.index)
  tags                         = var.tags
}

module "network-security-group" {
  source              = "Azure/network-security-group/azurerm"
  resource_group_name = azurerm_resource_group.vm.name
  location            = azurerm_resource_group.vm.location
  security_group_name = "${var.vm_hostname}-${coalesce(var.remote_port, module.os.calculated_remote_port)}-nsg"
  predefined_rules = var.security_group_predefined_rules
  custom_rules     = var.security_group_custom_rules
  tags = var.tags
}

resource "azurerm_network_interface" "vm" {
  count                         = var.nb_instances
  name                          = "nic-${var.vm_hostname}-${count.index}"
  location                      = azurerm_resource_group.vm.location
  resource_group_name           = azurerm_resource_group.vm.name
  network_security_group_id     = module.network-security-group.network_security_group_id
  enable_accelerated_networking = var.enable_accelerated_networking

  ip_configuration {
    name                          = "ipconfig${count.index}"
    subnet_id                     = var.vnet_subnet_id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = length(azurerm_public_ip.vm.*.id) > 0 ? element(concat(azurerm_public_ip.vm.*.id, [""]), count.index) : ""
  }

  tags = var.tags
}
