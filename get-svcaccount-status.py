#!/usr/bin/python

from kubernetes import client, config

# declare/use active kubeconfig
config.load_kube_config()

# kubernetes-client for python
# https://github.com/kubernetes-client/python
v1 = client.CoreV1Api()

# future use - object metadata details
# https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/V1ObjectMeta.md
# v1Object = client.V1ObjectMeta()

# simple function to confirm client api access to cluster
def getPodsAllNamespaces():
    ret = v1.list_pod_for_all_namespaces(watch=False)
    for i in ret.items:
        print("\t%s\t%s" % (i.metadata.namespace, i.metadata.name))

# get ServiceAccount selective details from hard-coded namespace
def getServiceAccountsDefaultNamespace():
    serviceAccounts = v1.list_namespaced_service_account(namespace='default')
    for s in serviceAccounts.items:
        print("%s\t%s\t%s" % (s.metadata.namespace, s.metadata.name, s.metadata.creation_timestamp))


# getPodsAllNamespaces()
getServiceAccountsDefaultNamespace()                    
