// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using Azure;
using Azure.Core;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.ResourceManager.Samples.Common;
using Azure.ResourceManager.Resources;
using Azure.ResourceManager;
using Azure.ResourceManager.Sql;
using Azure.ResourceManager.Sql.Models;
using Azure.ResourceManager.Models;
using Azure.ResourceManager.KeyVault.Models;
using Azure.ResourceManager.KeyVault;

namespace ManageSqlServerKeysWithAzureKeyVaultKey
{
    public class Program

    {
        private static ResourceIdentifier? _resourceGroupId = null;
        /**
         * Azure SQL sample for managing SQL secrets (Server Keys) using Azure Key Vault -
         *  - Create a SQL Server with "system assigned" managed service identity.
         *  - Create an Azure Key Vault with giving access to the SQL Server
         *  - Create, get, list and delete SQL Server Keys
         *  - Delete SQL Server
         */
        public static async Task RunSample(ArmClient client)
        {
            try
            {
                // ============================================================
                //Get default subscription
                SubscriptionResource subscription = await client.GetDefaultSubscriptionAsync();

                //Create a resource group in the EastUS region
                string rgName = Utilities.CreateRandomName("rgSQLServer");
                Utilities.Log("Creating resource group...");
                var rgLro = await subscription.GetResourceGroups().CreateOrUpdateAsync(WaitUntil.Completed, rgName, new ResourceGroupData(AzureLocation.EastUS));
                ResourceGroupResource resourceGroup = rgLro.Value;
                _resourceGroupId = resourceGroup.Id;
                Utilities.Log($"Created a resource group with name: {resourceGroup.Data.Name} ");

                // ============================================================
                // Create a SQL Server with system assigned managed service identity.
                Utilities.Log("Creating a SQL Server with system assigned managed service identity...");

                string sqlServerName = Utilities.CreateRandomName("sqlserver-identitytest");
                string sqlAdmin = "sqladmin1234";
                string sqlAdminPwd = Utilities.CreatePassword();
                SqlServerData sqlServerData = new SqlServerData(AzureLocation.EastUS)
                {
                    AdministratorLogin = sqlAdmin,
                    AdministratorLoginPassword = sqlAdminPwd,
                    Identity = new ManagedServiceIdentity(ManagedServiceIdentityType.SystemAssigned)
                };
                var sqlServer = (await resourceGroup.GetSqlServers().CreateOrUpdateAsync(WaitUntil.Completed, sqlServerName, sqlServerData)).Value;
                Utilities.Log($"Created a SQL Server with system assigned managed service identity with name: {sqlServer.Data.Name} ");

                // ============================================================
                // Create an Azure Key Vault and set the access policies.
                Utilities.Log("Creating an Azure Key Vault and set the access policies...");
                var tenantId = Environment.GetEnvironmentVariable("TENANT_ID");
                var objectId = Environment.GetEnvironmentVariable("OBJECT_ID");
                var clientId = Environment.GetEnvironmentVariable("CLIENT_ID");
                if (tenantId == null || objectId == null || clientId==null)
                {
                    throw new ArgumentNullException("TenantId and ObjectId is null");
                }
                string keyVaultName = Utilities.CreateRandomName("sqlkv");
                var content = new KeyVaultCreateOrUpdateContent(AzureLocation.EastUS, new Azure.ResourceManager.KeyVault.Models.KeyVaultProperties(Guid.Parse(tenantId), new KeyVaultSku(KeyVaultSkuFamily.A, KeyVaultSkuName.Standard)))
                {
                    Properties =
                    {
                        AccessPolicies =
                        {
                            new KeyVaultAccessPolicy(Guid.Parse(tenantId),sqlServer.Data.Identity.PrincipalId.ToString(),new IdentityAccessPermissions()
                            {
                                Keys =
                                {
                                    IdentityAccessKeyPermission.WrapKey,IdentityAccessKeyPermission.UnwrapKey,IdentityAccessKeyPermission.Get,IdentityAccessKeyPermission.List
                                }
                            }),
                            new KeyVaultAccessPolicy(Guid.Parse(tenantId),objectId,new IdentityAccessPermissions()
                            {
                                Keys =
                                {
                                    IdentityAccessKeyPermission.All
                                }
                            })
                        },
                        EnabledForDeployment = true,
                        EnabledForDiskEncryption = true,
                        EnabledForTemplateDeployment = true,
                        PublicNetworkAccess = "Enabled",
                    }
                };
                var keyVault = (await resourceGroup.GetKeyVaults().CreateOrUpdateAsync(WaitUntil.Completed, keyVaultName, content)).Value;
                //Utilities.Log("Waiting 3 minutes to delyment...");
                //Thread.Sleep(TimeSpan.FromMinutes(3));
                //var operationKind = AccessPolicyUpdateKind.Add;
                //var permissions = new IdentityAccessPermissions()
                //{
                //    Keys =
                //    {
                //        IdentityAccessKeyPermission.All
                //    }
                //};
                //var policy = new KeyVaultAccessPolicy(Guid.Parse(tenantId), objectId, permissions);
                //var accessPolicies = new List<KeyVaultAccessPolicy>();
                //accessPolicies.Add(policy);
                //var AccessPolicyPropertie = new KeyVaultAccessPolicyProperties(accessPolicies);
                //var keyVaultAccessPolicyParameters = new KeyVaultAccessPolicyParameters(AccessPolicyPropertie);
                //_ = await keyVault.UpdateAccessPolicyAsync(operationKind, keyVaultAccessPolicyParameters);
                Utilities.Log("Waiting 3 minutes to delyment...");
                Thread.Sleep(TimeSpan.FromMinutes(3));
                Utilities.Log($"Created an Azure Key Vault and set the access policies with KeyVault name: {keyVault.Data.Name}");

                // ============================================================
                // Create a SQL server key with Azure Key Vault key.
                Utilities.Log("Creating a SQL server key with Azure Key Vault key...");

                string keyVaultUri = $"https://{keyVault.Data.Name}.vault.azure.net/";
                
                string keyName = Utilities.CreateRandomName("sqlkey");
                var kvClient = new KeyClient(new Uri(keyVaultUri), new DefaultAzureCredential());
                var keyBundle = (await kvClient.CreateKeyAsync(keyName,KeyType.Rsa)).Value;
                string keyUri = keyBundle.Key.Id;
                Utilities.Log($"Created a SQL server key with Azure Key Vault key name:{keyBundle.Name}");

                // Work around for SQL server key name must be formatted as "vault_key_version"
                string serverKeyName = $"{keyVault.Data.Name}_{keyName}_" +
                    keyUri.Substring(keyUri.LastIndexOf("/") + 1);
                var sqlServerKeyData = new SqlServerKeyData()
                {
                    ServerKeyType = SqlServerKeyType.AzureKeyVault,
                    Uri = new Uri(keyUri)
                };
                var sqlServerKey = (await sqlServer.GetSqlServerKeys().CreateOrUpdateAsync(WaitUntil.Completed, serverKeyName, sqlServerKeyData)).Value;

                Utilities.Log(sqlServerKey);

                // Validate key exists by getting key
                Utilities.Log("Validating key exists by getting the key...");

                sqlServerKey = await sqlServer.GetSqlServerKeyAsync(sqlServerKey.Data.Name);

                Utilities.Log($"Get key name: {sqlServerKey.Data.Name} and key type :{sqlServerKey.Data.ServerKeyType}");


                // Validate key exists by listing keys
                Utilities.Log("Validating key exists by listing keys...");

                var serverKeys = sqlServer.GetSqlServerKeys().ToList();
                foreach (var item in serverKeys)
                {
                    Utilities.Log($"List key name: {item.Data.Name}");
                }

                // Delete key
                Utilities.Log("Deleting the key...");
                await sqlServerKey.DeleteAsync(WaitUntil.Completed);

                // Delete the SQL Server.
                Utilities.Log("Deleting a Sql Server...");
                await sqlServer.DeleteAsync(WaitUntil.Completed);
            }
            finally
            {
                try
                {
                 if (_resourceGroupId is not null)
                    {
                        Utilities.Log($"Deleting Resource Group...");
                        await client.GetResourceGroupResource(_resourceGroupId).DeleteAsync(WaitUntil.Started);
                        Utilities.Log($"Deleted Resource Group: {_resourceGroupId.Name}");
                    }
                }
                catch (Exception e)
                {
                    Utilities.Log(e);
                }
            }
        }

        public static async Task Main(string[] args)
        {
            try
            {
                //=================================================================
                // Authenticate
                var clientId = Environment.GetEnvironmentVariable("CLIENT_ID");
                var clientSecret = Environment.GetEnvironmentVariable("CLIENT_SECRET");
                var tenantId = Environment.GetEnvironmentVariable("TENANT_ID");
                var subscription = Environment.GetEnvironmentVariable("SUBSCRIPTION_ID");
                ClientSecretCredential credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
                ArmClient client = new ArmClient(credential, subscription);

                await RunSample(client);
            }
            catch (Exception e)
            {
                Utilities.Log(e.ToString());
            }
        }
    }
}