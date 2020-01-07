terraform {
  backend "azurerm" {
    resource_group_name  = "oejenkinsautomation"
    storage_account_name = "oejenkinsautomation"
    container_name       = "jenkinsinabox"
    key                  = "oe-terraform/jenkins-master/terraform.tfstate"
  }
}

provider "azurerm" {
  version = "~> 1.0"
}
