# Deployment: Docker

## Perché eseguire KernelTrace fuori dal container che monitora

KernelTrace osserva l'**host** a livello kernel: le probe eBPF vedono
tutti i processi del sistema, inclusi quelli in esecuzione dentro
container. Eseguire l'agente **dentro** un container isolato dagli altri
richiederebbe comunque privilegi elevati e accesso al kernel host,
vanificando parte dell'isolamento del container stesso. Il pattern
raccomandato è eseguire l'agente **sull'host** (bare-metal o come
container privilegiato con accesso al kernel host), monitorando tutti i
container Docker in esecuzione contemporaneamente.

## Esecuzione come container privilegiato (opzionale)

```bash
docker build -t kerneltrace:latest -f deployment/docker/Dockerfile .

docker run -d \
  --name kerneltrace \
  --privileged \
  --pid=host \
  --network=host \
  -v /sys/kernel/debug:/sys/kernel/debug:rw \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  -v /etc/kerneltrace:/etc/kerneltrace:ro \
  -v /var/log/kerneltrace:/var/log/kerneltrace:rw \
  kerneltrace:latest
```

- `--privileged` e `--pid=host` sono necessari per caricare eBPF e
  osservare i processi dell'host, non solo del container.
- `/sys/fs/cgroup` in sola lettura è sufficiente per il container
  awareness (Parte 9): l'agente legge solo `/proc/<pid>/cgroup`, non
  necessita di scrivere sui cgroup.

## docker-compose

Vedi [`deployment/docker/docker-compose.yml`](../../deployment/docker/docker-compose.yml)
per un esempio completo con volumi di configurazione e log persistenti.

## Riconoscimento automatico dei container Docker monitorati

Nessuna configurazione aggiuntiva è richiesta: `container.docker: true`
(default) abilita il riconoscimento automatico tramite il path di cgroup
di ciascun processo (vedi
[architecture/overview.md](../architecture/overview.md)).