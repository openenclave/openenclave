output "calculated_value_os_publisher" {
  value = element(split(",", lookup(var.standard_os, var.vm_os_simple, "")), 0)
}

output "calculated_value_os_offer" {
  value = element(split(",", lookup(var.standard_os, var.vm_os_simple, "")), 1)
}

output "calculated_value_os_sku" {
  value = element(split(",", lookup(var.standard_os, var.vm_os_simple, "")), 2)
}

output "calculated_remote_port" {
  value = element(split(",", lookup(var.standard_os, var.vm_os_simple, "")), 0) == "MicrosoftWindowsServer" ? 3389 : 22
}

