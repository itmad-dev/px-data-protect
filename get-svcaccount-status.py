# REQUIREMENTS
#  logging modules
#  credentials files
#  configuration files
#   logs location
#   script output location
#
# SYNOPSIS
# Preliminary Kubernetes operations
#
# 
# DESCRIPTION
# 
#
# PARAMETER
# Mandatory. The full path, file name to a json configuration file containing local environment specific variables for log and report paths, api endpoints/FQDNs, XML credentials file, and SMTP mail object details

from kubernetes import client, config

config.load_kube_config()
v1 = client.CoreV1Api()
v1Object = client.V1ObjectMeta()

def getPodsAllNamespaces():
    ret = v1.list_pod_for_all_namespaces(watch=False)
    for i in ret.items:
        print("\t%s\t%s" % (i.metadata.namespace, i.metadata.name))

def getServiceAccountsDefaultNamespace():
    serviceAccounts = v1.list_namespaced_service_account(namespace='default')
    for s in serviceAccounts.items:
        print("%s\t%s\t%s" % (s.metadata.namespace, s.metadata.name, s.metadata.creation_timestamp))


# getPodsAllNamespaces()
getServiceAccountsDefaultNamespace()                    
