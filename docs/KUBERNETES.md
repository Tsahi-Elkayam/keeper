# Kubernetes

Keeper reads a cluster's API server with `GET` only, through the `http` runner and the `kubernetes` integration type.
No agent and no new runner: the checks are rules in `rules/kubernetes.yaml`.

## What it can read

Only the lists named in the integration type, cluster-wide: namespaces, nodes, pods, services, service accounts,
quotas and limit ranges, volumes and claims, deployments, daemon sets, stateful sets, replica sets, jobs and cron jobs,
autoscalers, roles, cluster roles and their bindings, network policies, ingresses, disruption budgets, storage
classes, admission webhooks and certificate signing requests.

It never reads **secrets, config maps, logs, exec, proxy, port-forward or a service account's token.** The runner
refuses any other path before anything is sent, so a rule file cannot widen this. Pods can still carry secrets
inline: environment values, command arguments and the `kubectl.kubernetes.io/last-applied-configuration`
annotation (the whole applied manifest, as text) are kept as `set`.

## Setting it up

A service account that can list those objects and nothing else (it cannot read secrets):

```yaml
apiVersion: v1
kind: ServiceAccount
metadata: { name: keeper-reader, namespace: keeper-system }
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: { name: keeper-read }
rules:
  - { apiGroups: [""], resources: [namespaces, nodes, pods, services, serviceaccounts, resourcequotas, limitranges, persistentvolumes, persistentvolumeclaims], verbs: [get, list] }
  - { apiGroups: [apps], resources: [deployments, daemonsets, statefulsets, replicasets], verbs: [get, list] }
  - { apiGroups: [batch], resources: [cronjobs, jobs], verbs: [get, list] }
  - { apiGroups: [rbac.authorization.k8s.io], resources: [clusterroles, clusterrolebindings, roles, rolebindings], verbs: [get, list] }
  - { apiGroups: [networking.k8s.io], resources: [networkpolicies, ingresses], verbs: [get, list] }
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: { name: keeper-read }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: keeper-read }
subjects: [{ kind: ServiceAccount, name: keeper-reader, namespace: keeper-system }]
```

Then `kubectl create token keeper-reader -n keeper-system --duration=24h` (or a long-lived token Secret), and:

```
keeper integration add prod --type kubernetes --auth bearer --endpoint https://<api-server>:6443 \
        --option "caCertificate=$(cat ca.crt)" --reason "..."
keeper qm run
keeper integration set-secret prod token --reason "..."      # paste the token
keeper scan kubernetes
```

`caCertificate` is the cluster's CA (the `certificate-authority-data` of its kubeconfig, as PEM). Only that CA is
trusted for this integration, the host name must still match, and an expired certificate is still refused. Without
it, a cluster with a private CA fails the TLS handshake and no token is sent. A private key is refused as a CA.
One integration per cluster, each with its own token.

## What the pack checks

Pods (outside `kube-system`): privileged containers, host network/PID/IPC, a mounted container-runtime socket, hostPath
volumes, dangerous added capabilities, containers told to run as root, `latest` or untagged images, no memory limit.
Nodes: not Ready. Access: cluster-admin granted beyond the built-in subjects, anonymous or unauthenticated users
holding a role, roles that allow every verb on every resource.
