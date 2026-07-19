# Deployment: Kubernetes

## DaemonSet

KernelTrace va distribuito come **DaemonSet**, non come Deployment
regolare: deve girare esattamente un'istanza per nodo, con accesso al
kernel host di quel nodo specifico.

```bash
kubectl apply -f deployment/kubernetes/rbac.yaml
kubectl apply -f deployment/kubernetes/configmap.yaml
kubectl apply -f deployment/kubernetes/daemonset.yaml
```

Vedi i manifest completi in
[`deployment/kubernetes/`](../../deployment/kubernetes/).

## Requisiti del DaemonSet

- `hostPID: true` — necessario per osservare tutti i processi del nodo,
  non solo quelli del proprio pod.
- `privileged: true` nel `securityContext` del container — necessario
  per caricare programmi eBPF (`CAP_BPF`, `CAP_SYS_ADMIN`).
- Volume `hostPath` su `/sys/kernel/debug` e `/sys/fs/cgroup`.

## Limiti noti sul riconoscimento dei pod

Come documentato in [architecture/overview.md](../architecture/overview.md)
e nel modulo `container::kubernetes`, il **nome del pod e il namespace**
non sono derivabili dal solo cgroup path (che contiene solo l'UID del
pod). La risoluzione completa via Kubelet API locale è pianificata in
[ROADMAP.md](../../ROADMAP.md); nel frattempo, il campo `pod_name`
negli eventi normalizzati riporta l'UID del pod, comunque sufficiente per
correlare eventi allo stesso pod tramite `kubectl get pods --field-selector
metadata.uid=<uid>` o strumenti equivalenti.

## ConfigMap per la configurazione

`deployment/kubernetes/configmap.yaml` monta `kerneltrace.yaml` come
volume nel pod, permettendo di aggiornare la configurazione con
`kubectl apply` senza ricostruire l'immagine del container.

## RBAC

Il DaemonSet non richiede permessi verso l'API server Kubernetes in
questa fase del progetto (il riconoscimento dei pod è basato solo su
cgroup, non su chiamate API); `rbac.yaml` predispone comunque un
ServiceAccount dedicato per future integrazioni (es. risoluzione nomi pod
via Kubelet API, Parte pianificata in ROADMAP.md).