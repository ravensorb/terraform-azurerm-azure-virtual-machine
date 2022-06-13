locals {
  resource_group_name = element(coalescelist(data.azurerm_resource_group.rgrp[*].name, azurerm_resource_group.rg[*].name, [""]), 0)
  resource_prefix     = var.resource_prefix == "" ? local.resource_group_name : var.resource_prefix
  location            = element(coalescelist(data.azurerm_resource_group.rgrp[*].location, azurerm_resource_group.rg[*].location, [""]), 0)

  # Note: There are a few known issues with creating multiple vms related to NIC cards. For now we support either 0 or 1 instances to prevent those issues
  instances_count     = var.instances_count != 0 ? 1 : 0 
  
  storage_account_name= var.storage_account_name != null && var.storage_account_name != "" ? format("%s", lower(replace(var.storage_account_name, "/[[:^alnum:]]/", ""))) : format("%sstvhd", lower(replace(local.resource_prefix, "/[[:^alnum:]]/", "")))

  network_interfaces = { 
    for idx, network_interface in var.network_interfaces : network_interface.name => {
    idx : idx,
    network_interface : network_interface,
    }
  }

  vm_data_disks = { for idx, data_disk in var.data_disks : data_disk.name => {
    idx : idx,
    data_disk : data_disk,
    }
  }

  timeout_create  = "45m"
  timeout_update  = "15m"
  timeout_delete  = "15m"
  timeout_read    = "15m"
}

#---------------------------------------------------------------
# Generates SSH2 key Pair for Linux VM's (Dev Environment only)
#---------------------------------------------------------------

resource "tls_private_key" "rsa" {
  count     = var.generate_admin_ssh_key ? 1 : 0
  algorithm = "RSA"
  rsa_bits  = 4096
}

#---------------------------------------------------------
# Resource Group Creation or selection - Default is "true"
#----------------------------------------------------------

data "azurerm_resource_group" "rgrp" {
  count = var.create_resource_group == false ? 1 : 0
  name  = var.resource_group_name
}

resource "azurerm_resource_group" "rg" {
  count    = var.create_resource_group ? 1 : 0
  name     = lower(var.resource_group_name)
  location = var.location
  tags     = merge({ "ResourceName" = format("%s", var.resource_group_name) }, var.tags, )

  timeouts {
    create = local.timeout_create
    update = local.timeout_update
    read   = local.timeout_read
    delete = local.timeout_delete
  }
}

#--------------------------------------
# azurerm monitoring diagnostics 
#--------------------------------------

data "azurerm_log_analytics_workspace" "logws" {
  count               = var.log_analytics_workspace_name != null ? 1 : 0
  name                = var.log_analytics_workspace_name
  resource_group_name = var.log_analytics_workspace_resouce_group_name
}

#----------------------------------------------------------
# Random Resources
#----------------------------------------------------------

resource "random_password" "passwd" {
  count       = (var.os_flavor == "linux" && var.disable_password_authentication == false && var.admin_password == null ? 1 : (var.os_flavor == "windows" && var.admin_password == null ? 1 : 0))
  length      = var.random_password_length
  min_upper   = 4
  min_lower   = 2
  min_numeric = 4
  special     = false

  keepers = {
    admin_password = var.virtual_machine_name
  }
}

#-----------------------------------------------
# Storage Account for Disk Storage
#-----------------------------------------------

data "azurerm_resource_group" "storage_rg" {
  count = var.storage_account_resource_group_name != null ? 1 : 0

  name  = var.storage_account_resource_group_name 
}

data "azurerm_storage_account" "storage" {
  count               = var.create_storage_account == false ? 1 : 0

  name                = local.storage_account_name
  resource_group_name = var.storage_account_resource_group_name != null ? var.storage_account_resource_group_name : local.resource_group_name
}

resource "azurerm_storage_account" "storage" {
  count                     = var.create_storage_account ? 1 : 0

  name                      = local.storage_account_name
  resource_group_name       = var.storage_account_resource_group_name != null ? var.storage_account_resource_group_name : local.resource_group_name
  location                  = local.location
  account_kind              = "StorageV2"
  account_tier              = var.storage_account_tier_type
  account_replication_type  = var.storage_account_replication_type
  enable_https_traffic_only = true

  tags                      = merge({ "ResourceName" = local.storage_account_name }, var.tags, )

  timeouts {
    create = local.timeout_create
    update = local.timeout_update
    read   = local.timeout_read
    delete = local.timeout_delete
  }

}

#----------------------------------------------------------
# Subnet Resources
#----------------------------------------------------------

data "azurerm_subnet" "snet" {
  for_each             = { for k, v in local.network_interfaces : k => v if k != null && try(v.network_interface.subnet_name != null, false) }

  name                 = each.value.network_interface.subnet_name
  virtual_network_name = var.virtual_network_name
  resource_group_name  = var.virtual_network_resource_group_name == null ? local.resource_group_name : var.virtual_network_resource_group_name
}

#-----------------------------------
# Public IP for Virtual Machine
#-----------------------------------

data "azurerm_public_ip" "pip" {
  for_each                      = { for k, v in local.network_interfaces : k => v if k != null && try(v.network_interface.public_ip.create == false, false) }

  name                          = each.key
  resource_group_name           = local.resource_group_name
}

resource "azurerm_public_ip" "pip" {
  for_each              = { for k, v in local.network_interfaces : k => v if k != null && try(v.network_interface.public_ip.create, false) }

  name                  = lower("${local.resource_prefix}-vm-${var.virtual_machine_name}-pip-${each.key}")
  resource_group_name   = local.resource_group_name
  location              = var.location
  allocation_method     = try(each.value.network_interface.public_ip.allocation_method, "Static")
  sku                   = try(each.value.network_interface.public_ip.sku, "Standard")
  sku_tier              = try(each.value.network_interface.public_ip.sku_tier, "Regional")
  domain_name_label     = try(each.value.network_interface.public_ip.domain_label, null)
  public_ip_prefix_id   = try(each.value.network_interface.public_ip.prefix_id, null)

  tags                  = merge({ "ResourceName" = lower("${local.resource_prefix}-vm-${var.virtual_machine_name}-pip-${each.key}-0${each.value.idx + 1}") }, var.tags, )

  lifecycle {
    ignore_changes = [
      tags,
      ip_tags,
    ]
  }

  timeouts {
    create = local.timeout_create
    update = local.timeout_update
    read   = local.timeout_read
    delete = local.timeout_delete
  }

}

#---------------------------------------
# Network Interface for Virtual Machine
#---------------------------------------

resource "azurerm_network_interface" "nic" {
  for_each                      = { for k, v in local.network_interfaces : k => v if k != null && try(v.network_interface.private_ip != null, false) }

  name                          = lower("${local.resource_prefix}-vm-${var.virtual_machine_name}-nic-${each.key}")
  resource_group_name           = local.resource_group_name
  location                      = var.location
  dns_servers                   = try(each.value.network_interface.dns_servers, null)
  enable_ip_forwarding          = try(each.value.network_interface.enable_ip_forwarding, false)
  enable_accelerated_networking = try(each.value.network_interface.enable_accelerated_networking, false)
  internal_dns_name_label       = try(each.value.network_interface.internal_dns_name_label, null)

  tags                          = merge({ "ResourceName" = lower("${local.resource_prefix}-vm-${var.virtual_machine_name}-nic-${each.key}") }, var.tags, )

  ip_configuration {
    name                          = lower("${local.resource_prefix}-vm-${var.virtual_machine_name}-nic-${each.key}-ipconfig")
    primary                       = try(each.value.network_interface.primary, true)
    subnet_id                     = data.azurerm_subnet.snet[each.key].id
    private_ip_address_allocation = try(each.value.network_interface.private_ip.address_allocation_type, null)
    private_ip_address            = try(each.value.network_interface.private_ip.address_allocation_type == "Static", false) ? try(each.value.network_interface.private_ip.address, null) : null
    public_ip_address_id          = can(each.value.network_interface.public_ip) ? (each.value.network_interface.public_ip.create ? azurerm_public_ip.pip[each.key].id : data.azurerm_public_ip.pip[each.key].id) : null
  }

  lifecycle {
    ignore_changes = [
      tags,
    ]
  }
  
  depends_on = [
    data.azurerm_subnet.snet
  ]

  timeouts {
    create = local.timeout_create
    update = local.timeout_update
    read   = local.timeout_read
    delete = local.timeout_delete
  }

}

#---------------------------------------------------------------
# Network security group for Virtual Machine Network Interface
#---------------------------------------------------------------

data "azurerm_network_security_group" "nsg" {
  for_each              = { for k, v in local.network_interfaces : k => v if k != null && try(v.network_interface.network_security_group_name != null, false) }

  name                  = each.value.network_interface.network_security_group_name
  resource_group_name   = each.value.network_interface.network_security_resource_group_name
}

resource "azurerm_network_security_group" "nsg" {
  for_each            = { for k, v in local.network_interfaces : k => v if k != null && try(v.network_interface.network_security_group_name == null, false) }

  name                = lower("${local.resource_prefix}-vm-${var.virtual_machine_name}-nsg-${each.key}")
  resource_group_name = local.resource_group_name
  location            = local.location

  tags                = merge({ "ResourceName" = lower("${local.resource_prefix}-vm-${var.virtual_machine_name}-nsg-${each.key}") }, var.tags, )

  dynamic "security_rule" {
    for_each = concat(lookup(each.value.network_interface, "nsg_inbound_rules", []), lookup(each.value.network_interface, "nsg_outbound_rules", []))
    content {
      name                       = security_rule.value[0] == "" ? "Default_Rule" : security_rule.value[0]
      priority                   = security_rule.value[1]
      direction                  = security_rule.value[2] == "" ? "Inbound" : security_rule.value[2]
      access                     = security_rule.value[3] == "" ? "Allow" : security_rule.value[3]
      protocol                   = security_rule.value[4] == "" ? "Tcp" : security_rule.value[4]
      source_port_range          = "*"
      destination_port_range     = security_rule.value[5] == "" ? "*" : security_rule.value[5]
      source_address_prefix      = security_rule.value[6] == "" ? "Internet" : security_rule.value[6]
      destination_address_prefix = security_rule.value[7] == "" ? "VirtualNetwork" : security_rule.value[7] 
      description                = security_rule.value[8] == "" ? "${security_rule.value[2]}_Port_${security_rule.value[5]}" : security_rule.value[8]
    }
  }

  timeouts {
    create = local.timeout_create
    update = local.timeout_update
    read   = local.timeout_read
    delete = local.timeout_delete
  }
}

resource "azurerm_subnet_network_security_group_association" "nsg-assoc-new" {
  for_each                  = { for k, v in local.network_interfaces : k => v if k != null && try(v.network_interface.subnet_name != null, false) && try(v.network_interface.network_security_group_name == null, false) }

  subnet_id                 = data.azurerm_subnet.snet[each.key].id
  network_security_group_id = azurerm_network_security_group.nsg[each.key].id

  depends_on = [
    data.azurerm_subnet.snet
  ]

  timeouts {
    create = local.timeout_create
    update = local.timeout_update
    read   = local.timeout_read
    delete = local.timeout_delete
  }
}

resource "azurerm_subnet_network_security_group_association" "nsg-assoc-existing" {
  for_each                  = { for k, v in local.network_interfaces : k => v if k != null && try(v.network_interface.subnet_name != null, false) && try(v.network_interface.network_security_group_name != null, false) }

  subnet_id                 = data.azurerm_subnet.snet[each.key].id
  network_security_group_id = data.azurerm_network_security_group.nsg[each.key].id

  depends_on = [
    data.azurerm_subnet.snet
  ]

  timeouts {
    create = local.timeout_create
    update = local.timeout_update
    read   = local.timeout_read
    delete = local.timeout_delete
  }
  
}

#----------------------------------------------------------------------------------------------------
# Proximity placement group for virtual machines, virtual machine scale sets and availability sets.
#----------------------------------------------------------------------------------------------------

resource "azurerm_proximity_placement_group" "appgrp" {
  count               = var.enable_proximity_placement_group ? 1 : 0

  name                = lower("${local.resource_prefix}-vm-${var.virtual_machine_name}-proxigrp")
  resource_group_name = local.resource_group_name
  location            = var.location

  tags                = merge({ "ResourceName" = lower("${local.resource_prefix}-vm-${var.virtual_machine_name}-proxigrp") }, var.tags, )

  lifecycle {
    ignore_changes = [
      tags,
    ]
  }
}

#-----------------------------------------------------
# Manages an Availability Set for Virtual Machines.
#-----------------------------------------------------

resource "azurerm_availability_set" "aset" {
  count                        = var.enable_vm_availability_set ? 1 : 0

  name                         = lower("${local.resource_prefix}-vm-${var.virtual_machine_name}-avail")
  resource_group_name          = local.resource_group_name
  location                     = var.location
  platform_fault_domain_count  = var.platform_fault_domain_count
  platform_update_domain_count = var.platform_update_domain_count
  proximity_placement_group_id = var.enable_proximity_placement_group ? azurerm_proximity_placement_group.appgrp.0.id : null
  managed                      = true

  tags                         = merge({ "ResourceName" = lower("${local.resource_prefix}-vm-${var.virtual_machine_name}-avail") }, var.tags, )

  lifecycle {
    ignore_changes = [
      tags,
    ]
  }
}

#---------------------------------------
# Virutal machine Marketplace Agreement
#---------------------------------------

resource "azurerm_marketplace_agreement" "vm-linux" {
  count = var.accept_marketplace_agreement && (var.os_flavor == "linux") ? 1 : 0

  plan      = var.custom_image != null ? var.custom_image.sku : var.linux_distribution_list[lower(var.linux_distribution_name)]["sku"]
  offer     = var.custom_image != null ? var.custom_image.offer : var.linux_distribution_list[lower(var.linux_distribution_name)]["offer"]
  publisher = var.custom_image != null ? var.custom_image.publisher : var.linux_distribution_list[lower(var.linux_distribution_name)]["publisher"]
}

resource "azurerm_marketplace_agreement" "vm-win" {
  count = var.accept_marketplace_agreement && (var.os_flavor == "windows") ? 1 : 0

  plan      = var.custom_image != null ? var.custom_image.sku : var.windows_distribution_list[lower(var.windows_distribution_name)]["sku"]
  offer     = var.custom_image != null ? var.custom_image.offer : var.windows_distribution_list[lower(var.windows_distribution_name)]["offer"]
  publisher = var.custom_image != null ? var.custom_image.publisher : var.windows_distribution_list[lower(var.windows_distribution_name)]["publisher"]
}

#---------------------------------------
# Linux Virutal machine
#---------------------------------------

resource "azurerm_linux_virtual_machine" "linux_vm" {
  count                           = var.os_flavor == "linux" ? local.instances_count : 0

  name                            = lower("${local.resource_prefix}-vm-${var.virtual_machine_name}") # Might need to add count.index + 1 back into this line at some point
  
  computer_name                   = substr(lower(replace(var.virtual_machine_name, "/[^0-9A-Za-z\\-]/", "")), 0, 64)  # Might need to add count.index + 1 back into this line at some point
  resource_group_name             = local.resource_group_name
  location                        = var.location
  size                            = var.virtual_machine_size
  admin_username                  = var.admin_username
  admin_password                  = var.disable_password_authentication == false && var.admin_password == null ? element(concat(random_password.passwd[*].result, [""]), 0) : var.admin_password
  disable_password_authentication = var.disable_password_authentication
  network_interface_ids           = values(azurerm_network_interface.nic).*.id
  source_image_id                 = var.source_image_id != null ? var.source_image_id : null
  provision_vm_agent              = true
  allow_extension_operations      = true
  dedicated_host_id               = var.dedicated_host_id
  custom_data                     = var.custom_data != null ? var.custom_data : null
  availability_set_id             = var.enable_vm_availability_set == true ? element(concat(azurerm_availability_set.aset[*].id, [""]), 0) : null
  encryption_at_host_enabled      = var.enable_encryption_at_host
  proximity_placement_group_id    = var.enable_proximity_placement_group ? azurerm_proximity_placement_group.appgrp.0.id : null
  zone                            = var.vm_availability_zone
  vtpm_enabled                    = var.enable_tpm

  tags                            = merge({ "ResourceName" = lower("${local.resource_prefix}-vm-${var.virtual_machine_name}") }, var.tags, )

  dynamic "admin_ssh_key" {
    for_each = var.disable_password_authentication ? [1] : []

    content {
      username   = var.admin_username
      public_key = var.admin_ssh_key_data == null ? tls_private_key.rsa[0].public_key_openssh : file(var.admin_ssh_key_data)
    }
  }

  # do NOT include a plan block - https://stackoverflow.com/questions/72076412/unable-to-deploy-windows-vm-not-to-be-sold-in-market-us
  # If you use the plan block with one of Microsoft's marketplace images (e.g. publisher = "MicrosoftWindowsServer"). This may prevent the 
  #   purchase of the offer. An example Azure API error: The Offer: 'WindowsServer' cannot be purchased by subscription: '12345678-12234-5678-9012-123456789012' 
  #   as it is not to be sold in market: 'US'. Please choose a subscription which is associated with a different market.
  # dynamic "plan" {
  #   for_each = var.accept_marketplace_agreement ? [1] : [0]

  #   content {
  #     name      = var.custom_image != null ? var.custom_image.sku : var.linux_distribution_list[lower(var.linux_distribution_name)]["sku"]
  #     product   = var.custom_image != null ? var.custom_image.offer : var.linux_distribution_list[lower(var.linux_distribution_name)]["offer"]
  #     publisher = var.custom_image != null ? var.custom_image.publisher : var.linux_distribution_list[lower(var.linux_distribution_name)]["publisher"]
  #   }
  # }

  dynamic "source_image_reference" {
    for_each = var.source_image_id != null ? [] : [1]

    content {
      publisher = var.custom_image != null ? var.custom_image.publisher : var.linux_distribution_list[lower(var.linux_distribution_name)]["publisher"]
      offer     = var.custom_image != null ? var.custom_image.offer : var.linux_distribution_list[lower(var.linux_distribution_name)]["offer"]
      sku       = var.custom_image != null ? var.custom_image.sku : var.linux_distribution_list[lower(var.linux_distribution_name)]["sku"]
      version   = var.custom_image != null ? var.custom_image.version : var.linux_distribution_list[lower(var.linux_distribution_name)]["version"]
    }
  }

  os_disk {
    storage_account_type      = var.os_disk_storage_account_type
    caching                   = var.os_disk_caching
    disk_encryption_set_id    = var.disk_encryption_set_id
    disk_size_gb              = var.disk_size_gb
    write_accelerator_enabled = var.enable_os_disk_write_accelerator
    name                      = var.os_disk_name
  }

  additional_capabilities {
    ultra_ssd_enabled = var.enable_ultra_ssd_data_disk_storage_support
  }

  dynamic "identity" {
    for_each = var.managed_identity_type != null ? [1] : []

    content {
      type         = var.managed_identity_type
      identity_ids = var.managed_identity_type == "UserAssigned" || var.managed_identity_type == "SystemAssigned, UserAssigned" ? var.managed_identity_ids : null
    }
  }

  dynamic "boot_diagnostics" {
    for_each = var.enable_boot_diagnostics ? [1] : []

    content {
      storage_account_uri = element(coalescelist(azurerm_storage_account.storage.*.primary_blob_endpoint, data.azurerm_storage_account.storage.*.primary_blob_endpoint, [""]), 0) 
    }
  }

  lifecycle {
    ignore_changes = [
      tags,
    ]
  }

  timeouts {
    create = local.timeout_create
    update = local.timeout_update
    read   = local.timeout_read
    delete = local.timeout_delete
  }
}

#---------------------------------------
# Windows Virutal machine
#---------------------------------------

resource "azurerm_windows_virtual_machine" "win_vm" {
  count                        = var.os_flavor == "windows" ? local.instances_count : 0

  name                         = lower("${local.resource_prefix}-vm-${var.virtual_machine_name}")  # Might need to add count.index + 1 back into this line at some point

  computer_name                = substr(lower(replace(var.virtual_machine_name, "/[^0-9A-Za-z\\-]/", "")), 0, 15)  # Might need to add count.index + 1 back into this line at some point
  resource_group_name          = local.resource_group_name
  location                     = var.location
  size                         = var.virtual_machine_size
  admin_username               = var.admin_username
  admin_password               = var.admin_password == null ? element(concat(random_password.passwd[*].result, [""]), 0) : var.admin_password
  network_interface_ids        = values(azurerm_network_interface.nic).*.id
  source_image_id              = var.source_image_id != null ? var.source_image_id : null
  provision_vm_agent           = true
  allow_extension_operations   = true
  dedicated_host_id            = var.dedicated_host_id
  custom_data                  = var.custom_data != null ? var.custom_data : null
  enable_automatic_updates     = var.enable_automatic_updates
  license_type                 = var.license_type
  availability_set_id          = var.enable_vm_availability_set == true ? element(concat(azurerm_availability_set.aset[*].id, [""]), 0) : null
  encryption_at_host_enabled   = var.enable_encryption_at_host
  proximity_placement_group_id = var.enable_proximity_placement_group ? azurerm_proximity_placement_group.appgrp.0.id : null
  patch_mode                   = var.patch_mode
  zone                         = var.vm_availability_zone
  timezone                     = var.vm_time_zone
  vtpm_enabled                 = var.enable_tpm

  tags                         = merge({ "ResourceName" = lower("${local.resource_prefix}-vm-${var.virtual_machine_name}") }, var.tags, )

  # do NOT include a plan block - https://stackoverflow.com/questions/72076412/unable-to-deploy-windows-vm-not-to-be-sold-in-market-us
  # If you use the plan block with one of Microsoft's marketplace images (e.g. publisher = "MicrosoftWindowsServer"). This may prevent the 
  #   purchase of the offer. An example Azure API error: The Offer: 'WindowsServer' cannot be purchased by subscription: '12345678-12234-5678-9012-123456789012' 
  #   as it is not to be sold in market: 'US'. Please choose a subscription which is associated with a different market.
  # dynamic "plan" {
  #   for_each = var.accept_marketplace_agreement ? [1] : [0]

  #   content {
  #     name      = var.custom_image != null ? var.custom_image.sku : var.linux_distribution_list[lower(var.windows_distribution_name)]["sku"]
  #     product   = var.custom_image != null ? var.custom_image.offer : var.linux_distribution_list[lower(var.windows_distribution_name)]["offer"]
  #     publisher = var.custom_image != null ? var.custom_image.publisher : var.linux_distribution_list[lower(var.windows_distribution_name)]["publisher"]
  #   }
  # }

  dynamic "source_image_reference" {
    for_each = var.source_image_id != null ? [] : [1]
    content {
      publisher = var.custom_image != null ? var.custom_image.publisher : var.windows_distribution_list[lower(var.windows_distribution_name)]["publisher"]
      offer     = var.custom_image != null ? var.custom_image.offer : var.windows_distribution_list[lower(var.windows_distribution_name)]["offer"]
      sku       = var.custom_image != null ? var.custom_image.sku : var.windows_distribution_list[lower(var.windows_distribution_name)]["sku"]
      version   = var.custom_image != null ? var.custom_image.version : var.windows_distribution_list[lower(var.windows_distribution_name)]["version"]
    }
  }

  os_disk {
    storage_account_type      = var.os_disk_storage_account_type
    caching                   = var.os_disk_caching
    disk_encryption_set_id    = var.disk_encryption_set_id
    disk_size_gb              = var.disk_size_gb
    write_accelerator_enabled = var.enable_os_disk_write_accelerator
    name                      = var.os_disk_name
  }  

  additional_capabilities {
    ultra_ssd_enabled = var.enable_ultra_ssd_data_disk_storage_support
  }

  dynamic "identity" {
    for_each = var.managed_identity_type != null ? [1] : []
    content {
      type         = var.managed_identity_type
      identity_ids = var.managed_identity_type == "UserAssigned" || var.managed_identity_type == "SystemAssigned, UserAssigned" ? var.managed_identity_ids : null
    }
  }

  dynamic "winrm_listener" {
    for_each = var.winrm_protocol != null ? [1] : []
    content {
      protocol        = var.winrm_protocol
      certificate_url = var.winrm_protocol == "Https" ? var.key_vault_certificate_secret_url : null
    }
  }

  dynamic "additional_unattend_content" {
    for_each = var.additional_unattend_content != null ? [1] : []
    content {
      content = var.additional_unattend_content
      setting = var.additional_unattend_content_setting
    }
  }

  dynamic "boot_diagnostics" {
    for_each = var.enable_boot_diagnostics ? [1] : []
    content {
      storage_account_uri = element(coalescelist(azurerm_storage_account.storage.*.primary_blob_endpoint, data.azurerm_storage_account.storage.*.primary_blob_endpoint, [""]), 0) 
    }
  }

  lifecycle {
    ignore_changes = [
      tags,
      patch_mode,
    ]
  }

  timeouts {
    create = local.timeout_create
    update = local.timeout_update
    read   = local.timeout_read
    delete = local.timeout_delete
  }

}

#---------------------------------------
# Virtual machine data disks
#---------------------------------------

resource "azurerm_managed_disk" "data_disk" {
  for_each             = local.vm_data_disks

  name                 = "${local.resource_prefix}-vm-${var.virtual_machine_name}-datadisk-${each.value.idx}"
  resource_group_name  = local.resource_group_name
  location             = var.location
  storage_account_type = lookup(each.value.data_disk, "storage_account_type", "StandardSSD_LRS")
  create_option        = "Empty"
  disk_size_gb         = each.value.data_disk.disk_size_gb

  tags                 = merge({ "ResourceName" = "${local.resource_prefix}-vm-${var.virtual_machine_name}-datadisk-${each.value.idx}" }, var.tags, )

  lifecycle {
    ignore_changes = [
      tags,
    ]
  }

  timeouts {
    create = local.timeout_create
    update = local.timeout_update
    read   = local.timeout_read
    delete = local.timeout_delete
  }

}

resource "azurerm_virtual_machine_data_disk_attachment" "data_disk" {
  for_each           = local.vm_data_disks

  managed_disk_id    = azurerm_managed_disk.data_disk[each.key].id
  virtual_machine_id = var.os_flavor == "windows" ? azurerm_windows_virtual_machine.win_vm[0].id : azurerm_linux_virtual_machine.linux_vm[0].id
  lun                = each.value.idx
  caching            = "ReadWrite"

  depends_on = [
    azurerm_linux_virtual_machine.linux_vm,
    azurerm_windows_virtual_machine.win_vm
  ]

  timeouts {
    create = local.timeout_create
    update = local.timeout_update
    read   = local.timeout_read
    delete = local.timeout_delete
  }
}

#--------------------------------------------------------------
# Azure Log Analytics Workspace Agent Installation for windows
#--------------------------------------------------------------

resource "azurerm_virtual_machine_extension" "omsagentwin" {
  count                      = var.deploy_log_analytics_agent && data.azurerm_log_analytics_workspace.logws != null && var.os_flavor == "windows" ? local.instances_count : 0

  name                       = local.instances_count == 1 ? "OmsAgentForWindows" : format("%s%s", "OmsAgentForWindows", count.index + 1)
  virtual_machine_id         = azurerm_windows_virtual_machine.win_vm[count.index].id
  publisher                  = "Microsoft.EnterpriseCloud.Monitoring"
  type                       = "MicrosoftMonitoringAgent"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true

  settings = <<SETTINGS
    {
      "workspaceId": "${data.azurerm_log_analytics_workspace.logws.0.workspace_id}"
    }
  SETTINGS

  protected_settings = <<PROTECTED_SETTINGS
    {
    "workspaceKey": "${data.azurerm_log_analytics_workspace.logws.0.primary_shared_key}"
    }
  PROTECTED_SETTINGS

  timeouts {
    create = local.timeout_create
    update = local.timeout_update
    read   = local.timeout_read
    delete = local.timeout_delete
  }
}

#--------------------------------------------------------------
# Azure Log Analytics Workspace Agent Installation for Linux
#--------------------------------------------------------------

resource "azurerm_virtual_machine_extension" "omsagentlinux" {
  count                      = var.deploy_log_analytics_agent && data.azurerm_log_analytics_workspace.logws != null && var.os_flavor == "linux" ? local.instances_count : 0

  name                       = local.instances_count == 1 ? "OmsAgentForLinux" : format("%s%s", "OmsAgentForLinux", count.index + 1)
  virtual_machine_id         = azurerm_linux_virtual_machine.linux_vm[count.index].id
  publisher                  = "Microsoft.EnterpriseCloud.Monitoring"
  type                       = "OmsAgentForLinux"
  type_handler_version       = "1.13"
  auto_upgrade_minor_version = true

  settings = <<SETTINGS
    {
      "workspaceId": "${data.azurerm_log_analytics_workspace.logws.0.workspace_id}"
    }
  SETTINGS

  protected_settings = <<PROTECTED_SETTINGS
    {
    "workspaceKey": "${data.azurerm_log_analytics_workspace.logws.0.primary_shared_key}"
    }
  PROTECTED_SETTINGS

  timeouts {
    create = local.timeout_create
    update = local.timeout_update
    read   = local.timeout_read
    delete = local.timeout_delete
  }

}

#--------------------------------------
# monitoring diagnostics 
#--------------------------------------

resource "azurerm_monitor_diagnostic_setting" "nsg" {
  for_each                    = { for k, v in local.network_interfaces : k => v if k != null && var.log_analytics_workspace_name != null }
  
  name                        = lower("${local.resource_prefix}-vm-${var.virtual_machine_name}-nsg-diag-${ each.value.idx + 1}")
  target_resource_id          = can(azurerm_network_security_group.nsg[each.key].id) ? azurerm_network_security_group.nsg[each.key].id : data.azurerm_network_security_group.nsg[each.key].id
  storage_account_id          = var.log_analytics_workspace_storage_account_id != null ? var.log_analytics_workspace_storage_account_id : null
  log_analytics_workspace_id  = data.azurerm_log_analytics_workspace.logws.0.id

  dynamic "log" {
    for_each = var.nsg_diag_logs
    content {
      category = log.value
      enabled  = true

      retention_policy {
        enabled = false
        days    = 0
      }
    }
  }

  depends_on = [
    azurerm_network_security_group.nsg
  ]

  timeouts {
    create = local.timeout_create
    update = local.timeout_update
    read   = local.timeout_read
    delete = local.timeout_delete
  }
}
