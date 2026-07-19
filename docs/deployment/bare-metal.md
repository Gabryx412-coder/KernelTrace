# Deployment: bare-metal (systemd)

## Installazione dell'unit systemd

```bash
sudo cp target/release/kerneltrace-agent /usr/local/bin/
sudo cp target/release/kerneltrace-cli /usr/local/bin/
sudo cp deployment/systemd/kerneltrace.service /etc/systemd/system/
sudo mkdir -p /etc/kerneltrace /var/log/kerneltrace
sudo cp config/kerneltrace.example.yaml /etc/kerneltrace/kerneltrace.yaml

sudo systemctl daemon-reload
sudo systemctl enable --now kerneltrace
```

## Gestione del servizio

```bash
sudo systemctl status kerneltrace
sudo systemctl restart kerneltrace
sudo journalctl -u kerneltrace -f
```

## Verifica dello stato tramite la CLI

```bash
kerneltrace-cli status
```

## Rotazione dei log

Se `logging.directory` è configurato, l'agente usa
`tracing-appender::rolling::daily` per la rotazione automatica giornaliera
dei log di diagnostica. Per il sink `json`/`file` (eventi di detection),
si raccomanda `logrotate` esterno, dato che questi file crescono in modo
continuo tramite append:

```
/var/log/kerneltrace/events.json {
    daily
    rotate 30
    compress
    missingok
    notifempty
    copytruncate
}
```