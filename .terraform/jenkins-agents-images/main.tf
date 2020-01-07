variable "terraform-images" {
  type = map
  default = {
    "terraform-bionic" = {
      "os_type"  = "Linux"
      "blob_uri" = "https://oejenkinswesteurope.blob.core.windows.net/disks/jenkins-terraform-ubuntu-18.04.vhd"
    }
    "terraform-xenial" = {
      "os_type"  = "Linux"
      "blob_uri" = "https://oejenkinswesteurope.blob.core.windows.net/disks/jenkins-terraform-ubuntu-16.04.vhd"
    }
    "terraform-ubuntu-nonSGX" = {
      "os_type"  = "Linux"
      "blob_uri" = "https://oejenkinswesteurope.blob.core.windows.net/disks/jenkins-terraform-ubuntu-nonSGX.vhd"
    }
    "terraform-win2016" = {
      "os_type"  = "Windows"
      "blob_uri" = "https://oejenkinswesteurope.blob.core.windows.net/disks/jenkins-terraform-win-2016.vhd"
    }
    "terraform-win2016-dcap" = {
      "os_type"  = "Windows"
      "blob_uri" = "https://oejenkinswesteurope.blob.core.windows.net/disks/jenkins-terraform-win-dcap.vhd"
    }
    "terraform-win2016-nonSGX" = {
      "os_type"  = "Windows"
      "blob_uri" = "https://oejenkinswesteurope.blob.core.windows.net/disks/jenkins-terraform-win-nonSGX.vhd"
    }
  }
}

resource "azurerm_image" "terraform-image" {
  for_each            = var.terraform-images
  name                = each.key
  location            = "westeurope"
  resource_group_name = "OE-Jenkins-Terraform-Images"

  os_disk {
    os_type  = each.value["os_type"]
    os_state = "Generalized"
    blob_uri = each.value["blob_uri"]
    size_gb  = 50
  }
}
