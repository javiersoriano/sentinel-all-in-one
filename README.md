# Sentinel All In One

Sentinel All in One is a project that seeks to speed up deployment and initial configuration tasks of an Azure Sentinel environment. This is ideal for Proof of Concept scenarios and connector onboarding when high priviliged users are needed

The main script in this repository takes care of the following steps:

- Creates resource group (if given resource group doesn't exist yet)
- Creates Log Analytics workspace (if given workspace doesn't exist yet)
- Installs Azure Sentinel on top of the workspace (if not installed yet)
- Enables the following Data Connectors: 
    + Azure Activity
    + Azure Security Center
    + Azure Active Directory
    + Azure Active Directory Identity Protection
    + Office 365 (Sharepoint, Exchange and Teams)
    + Microsoft Cloud App Security
    + Azure Advanced Threat Protection
    + Microsoft Defender Advanced Threat Protection
    + Threat Intelligence
- Enables Analytics Rules for enabled Microsoft 1st party products 

## Getting started
These instructions will show you what you need to now to use Sentinel All in One.

### Prerequisites

- [PowerShell Core](https://github.com/PowerShell/PowerShell)

### Usage

Once you have PowerShell Core installed on your machine, you just need two files from this repo: 

* *connectors.json* - contains all the connectors that will be enabled. If you don't want some of the connectors to be enabled, just remove them from the your copy of the file.

* *SentinelAllInOne.ps1* - script that automates all the steps outlined above.

Open a PowerShell core terminal, navigate to the folder where these two files are located and execute *SentinelAllInOne.ps1*. You will be asked to enter the following parameters:

 - Resource Group - Resource Group that will contain the Azure Sentinel environment. If the provided resource group already exists, the script will skip its creation.
 - Workspace - Name of the Azure Sentinel workspace. If it already exists, the script will skip its creation.
 - Location - Location for the resource group and Azure Sentinel workspace.

 The script will then iterate through the connectors specified in the *connectors.json* file and enable them. It will also enable the corresponding Microsoft analytics rules.