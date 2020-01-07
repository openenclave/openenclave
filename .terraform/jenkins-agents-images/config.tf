terraform {
  backend "azurerm" {
    resource_group_name  = "oejenkinsautomation"
    storage_account_name = "oejenkinsautomation"
    container_name       = "jenkinsinabox"
    key                  = "oe-terraform/jenkins-agents-images/terraform.tfstate"
  }
}

provider "azurerm" {
  # https://github.com/SUSE/ha-sap-terraform-deployments/issues/188
  version = "<= 1.33"
}
