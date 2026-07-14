# step-ca — CA interna do control plane

CA interna (smallstep/step-ca) que emite certificados TLS para os serviços de gestão
(`*.apps.internal`) via ACME. O Traefik interno pede/renova automaticamente.

## Estado (crítico — não versionado)

O estado da CA vive **inteiramente** no named volume Docker `stepca-data` (`/home/step`):

```
/home/step/
├── certs/root_ca.crt            # raiz PÚBLICA — copiada para docker/traefik/certs/step-ca-root.crt
├── certs/intermediate_ca.crt
├── secrets/root_ca_key          # chaves privadas (cifradas)
├── secrets/intermediate_ca_key
├── secrets/password             # password que decifra as chaves (escrita no 1º arranque)
├── config/ca.json               # config da CA + provisioners (inclui ACME)
└── db/                          # badger DB de certs emitidos
```

**Nunca** montar este volume no Traefik nem versioná-lo em git — contém a chave intermédia
cifrada. Só o `root_ca.crt` público sai do volume.

## Inicialização

Auto-init no primeiro arranque (volume vazio) via env `DOCKER_STEPCA_INIT_*` no
`docker-compose.yml`. Cria raiz + intermédio + provisioner ACME. `DOCKER_STEPCA_INIT_NAME`
popula o subject dos certs (`Quelhas & Fernandes, Lda Root CA`).

## Fingerprint da raiz (guardar — necessário para o `step ca bootstrap` dos operadores)

```
docker compose logs step-ca | grep -i fingerprint
docker compose exec step-ca step certificate fingerprint /home/step/certs/root_ca.crt
```

## Saúde

```
docker compose exec step-ca step ca health --ca-url https://127.0.0.1:9000 \
  --root /home/step/certs/root_ca.crt      # esperado: ok
```

## Backup

O par (volume `stepca-data` + `.env`) é o ponto crítico do disaster recovery: sem a raiz,
todos os clientes precisam de re-bootstrap de trust. Incluir no backup cifrado do manager.
