# Multi-host — Control Plane Separado (`manager-komodo`)

> **Estado**: pendente, **não implementado**. Documento de design para decisão futura.
> **Última actualização**: 2026-06-30.

## Motivação

O actual `docker-compose.yml` é monolítico: cada host GIMS corre simultaneamente a aplicação
(Traefik, backend, frontend, postgres, workers, exporters) **e** a stack de observabilidade
(Prometheus, Grafana). Razões para separar:

- N pratos de Grafana + TSDB para manter (dashboards, recording rules, datasources
  replicados manualmente).
- Sem vista única do estado da frota.
- Annotations de deploy locais a cada host — sem histórico unificado.
- Carga de monitorização concorre com carga da aplicação no mesmo VPS.

## Arquitectura decidida

**Dois repositórios independentes:**

1. **`manager-komodo`** (novo — **ainda não criado**) — control plane **agnóstico à aplicação**.
   Pode servir múltiplas apps no futuro; para já só gere GIMS.
2. **`GIMSv2`** (este repo) — aplicação. Sofre alterações mínimas: expor `/metrics` no IP WireGuard,
   apagar TSDB/Grafana/exporters redundantes do compose, adaptar bloco de annotation do
   `update.sh` para apontar ao Grafana central via WireGuard.

**Componentes do control plane (`manager-komodo`):**

- **Headscale** — coordination WireGuard entre control plane e todos os hosts. Onboarding via
  pre-auth keys e cliente Tailscale nativo em cada host.
- **Komodo Core + Mongo** — orquestração de deploys (dispara `update.sh` em cada host).
- **VictoriaMetrics + vmalert** — TSDB + query engine (compatível com Prometheus/PromQL) e
  motor de recording rules. Scrapeia directamente todos os hosts via IPs Headscale.
- **Grafana central** — dashboards da plataforma + dashboards por app.
- **Traefik (dual)** — router público (só Headscale API + `bootstrap.sh` na porta 443) e router
  interno (Grafana, Komodo UI, Adminer, VM UI — bindados na interface Tailscale, HTTPS com
  step-ca).
- **step-ca** — Certificate Authority interna; emite certificados TLS para os serviços de
  gestão via ACME (Traefik interno pede automaticamente, renova sozinho).
- **(futuro)** Loki + Alertmanager.

**Componentes por host GIMS (o que fica no repo `GIMSv2`):**

- **Backend, Frontend, Postgres, Traefik, workers** — inalterados.
- **`postgres-exporter`** — mantém-se (Komodo não vê internals do PG).
- **Komodo Periphery** — em container Docker (Modelo 1 recomendado — ver secção adiante).
- **Descartados:** `node-exporter`, `cAdvisor`, `container-meta-exporter`, `netdata`,
  `prometheus`, `grafana` — todos cobertos por Komodo Periphery ou movidos para o control plane.

## Decisões tomadas

| Tópico | Decisão | Razão |
|--------|---------|-------|
| Escala-alvo | 2-3 hosts GIMS + 1 control plane | Dimensiona os trade-offs abaixo |
| Repositórios | Dois separados (`manager-komodo` + `GIMSv2`) | Control plane é plataforma reutilizável |
| Nome do control plane | `manager-komodo` | Escolhido pelo utilizador |
| VPN | **Headscale self-hosted** (clientes Tailscale) | ACLs declarativas, key rotation automática, 1 comando por host, migração para SaaS trivial se algum dia mudar de ideias. Ver secção "VPN — Headscale" adiante. |
| Gestão | Komodo (dispara `update.sh`; não substitui) | Preserva o script de deploy validado |
| Exporters magros | Só `postgres-exporter` por host | Komodo Periphery cobre os restantes |
| Dashboards por app | Vivem no repo do control plane em `apps/gims/` | Escolhido pelo utilizador |

## Decisão em aberto — Periphery containerizado ou nativo

### Modelo 1 — Periphery containerizado + `unattended-upgrades`

- Periphery corre em container Docker (linha no `docker-compose.yml` do GIMSv2).
- Komodo gere **só aplicação** (deploy, stats, logs).
- Cada host tem `unattended-upgrades` para security patches automáticos.
- Reboots e `apt full-upgrade` cirúrgicos manuais via SSH.

**Prós**: 0 mudanças de provisioning, Periphery isolado (não root no host), acesso ao Docker socket é tudo o que precisa.
**Contras**: 3 procedures úteis (`apt upgrade`, `reboot`, `cleanup disk`) continuam a exigir SSH.

### Modelo 2 — Periphery nativo no host

- Periphery instalado como systemd service, corre como **root**.
- Komodo gere **tudo** via Procedures (deploy + apt + reboot + cleanup).

**Prós**: single pane of glass; tudo no UI.
**Contras**: setup mais complexo (+5min por host); update do Periphery não-atómico; risco de segurança maior (se `KOMODO_PASSKEY` vazar, atacante tem root directo em todos os hosts); se uma Procedure partir o host, pode ser necessário console out-of-band (KVM).

### Recomendação

**Modelo 1** para 2-3 hosts. Documentar M2 como upgrade path se a frota crescer para 5+ hosts.

## Estrutura do repo `manager-komodo` (esboço)

```
manager-komodo/
├── docker-compose.yml               # headscale + komodo + grafana + victoriametrics + vmalert + traefik + step-ca
├── docker-compose.override.yml      # dev local
├── .env.example
├── docker/
│   ├── traefik/
│   │   ├── traefik.yml              # entrypoints public + internal, resolvers LE + step-ca
│   │   └── dynamic/                 # routers por serviço (grafana, komodo, vm, adminer)
│   ├── headscale/
│   │   ├── config.yaml              # config do server (SERVER_URL, prefixos IP, MagicDNS)
│   │   └── acl.hujson               # ACLs por tag (versionado)
│   ├── step-ca/
│   │   └── ca-config.json           # config da CA interna (issuers ACME)
│   ├── grafana/
│   │   ├── provisioning/
│   │   └── dashboards/
│   │       ├── platform/            # host stats, docker stats agregados
│   │       └── apps/
│   │           └── gims/            # dashboards da app GIMS
│   │               ├── api-metrics.json
│   │               ├── regressoes-rotas.json
│   │               ├── postgresql-metrics.json
│   │               └── gims-overview.json
│   ├── victoriametrics/
│   │   └── scrape.yml               # scrape config (formato Prometheus, lido pela VM)
│   ├── vmalert/
│   │   └── rules/
│   │       └── apps/
│   │           └── gims.yml         # recording rules do GIMS
│   └── prometheus-targets/          # file_sd_configs (lido pela VM via scrape.yml)
│       └── apps/
│           └── gims/
│               ├── backend.yml
│               └── postgresql.yml
├── bootstrap/
│   └── bootstrap.sh                 # script servido publicamente para onboarding
├── scripts/
│   ├── generate-setup-token.sh      # gera token one-shot para bootstrap
│   ├── update-control-plane.sh      # equivalente ao update.sh mas para o control plane
│   ├── backup-manager.sh            # backup diário do state para S3
│   └── restore-manager.sh           # restore em manager novo
└── docs/
    ├── README.md
    ├── APPS.md                      # como acrescentar uma nova app
    ├── OPS.md                       # operação diária
    └── DISASTER_RECOVERY.md         # playbook de restore do manager
```

## VPN — Headscale

Escolhido em vez de WireGuard puro para ganhar ACLs declarativas, key rotation automática e
onboarding com 1 comando por host. Debaixo do capot continua a ser WireGuard.

**Componente no manager**: um binário Go + SQLite. Idle ~30-50 MB RAM. Escala para 100+ nodes
sem stress.

**Clientes nos hosts**: cliente Tailscale nativo (`curl -fsSL https://tailscale.com/install.sh | sh`).
Já vem em Debian/Ubuntu recentes.

**Onboarding de host novo**:

```bash
# No manager, gerar pre-auth key
docker exec manager-headscale headscale preauthkeys create --user gims --expiration 1h --reusable=false
# Output: hskey-abc123...

# No host novo
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up --login-server https://control.jose.tld --auth-key hskey-abc123... --hostname gims-prod-1
```

Alternativa mais integrada: o `bootstrap.sh` que descreveremos abaixo faz isto tudo com um
único `curl | bash`, buscando a pre-auth key ao manager via HTTPS com um setup token.

**Espaço de IPs**: Headscale aloca automaticamente do prefixo configurável (default `100.64.0.0/10`,
recomendo restringir para `100.64.0.0/24`). MagicDNS resolve `gims-prod-1.headscale.jose.tld`
para o IP correspondente.

**ACLs**:

Ficheiro `acl.hujson` versionado no repo `manager-komodo`. Exemplo — laptop do operador pode
aceder a Postgres/Redis dos hosts das apps, mas hosts das apps não podem falar entre si:

```hujson
{
  "tagOwners": {
    "tag:operator": ["josef@jose.tld"],
    "tag:gims-app": ["josef@jose.tld"],
    "tag:manager":  ["josef@jose.tld"],
  },
  "acls": [
    // Operador (laptop) — acesso total à mesh (Grafana, Komodo UI, SSH aos hosts, BDs)
    { "action": "accept", "src": ["tag:operator"], "dst": ["*:*"] },
    // Manager (VictoriaMetrics, Komodo Core) — só /metrics + Periphery nos hosts das apps
    { "action": "accept", "src": ["tag:manager"], "dst": ["tag:gims-app:3000,9187,8120"] },
    // Hosts das apps — sem tráfego entre si nem para o manager (default deny)
  ]
}
```

Chave-de-leitura: o **operador é confiável** (acesso total à sua mesh); o **manager tem
privilégio mínimo** (só as portas que precisa de scrape); os **hosts das apps não iniciam
nenhum tráfego** para outros nodes da mesh (defensivo — se um for comprometido, não pivotar).

Isto é o "ZTNA feel" que faltava ao WireGuard puro — segregação declarativa por identidade em
vez de regras nftables custom por host.

**Blast radius se Headscale for comprometido**: as sessões WireGuard existentes continuam a
funcionar (chaves de sessão foram negociadas antes e não passam pelo coordinator). Perde-se
apenas a capacidade de adicionar/remover nodes ou aplicar ACLs novas. O tráfego entre hosts
existentes não é interrompido.

**Migração para SaaS trivial**: se algum dia quiseres deixar de operar o Headscale, basta correr
nos hosts `tailscale up --login-server https://login.tailscale.com --auth-key ts-...`. Zero
alterações à app; só troca de coordinator.

## Acesso e exposição pública — o modelo de segurança

**Princípio**: o único serviço público do manager é o Headscale. Toda a gestão (Grafana,
Komodo UI, Adminer, VictoriaMetrics UI, SSH aos hosts das apps, `psql`/`redis-cli` para
debugging) acontece **dentro da mesh** — o operador liga o cliente Tailscale no laptop e
acede via MagicDNS.

### Portas expostas ao mundo

Uma única porta pública, 1 IP, com Traefik a fazer routing por hostname/path:

| Endpoint | Porta | Propósito |
|----------|-------|-----------|
| `https://control.jose.tld/` | 443/tcp | Headscale API (autenticação e coordenação dos peers) |
| `https://control.jose.tld/bootstrap.sh` | 443/tcp | Script estático de bootstrap para hosts novos |
| `41641/udp` | 41641 | WireGuard direct connection (peer-to-peer tenta este porto) |

Tudo o resto: firewall fecha. `nftables` no VPS do manager corta 22, 80, tudo excepto o acima.
SSH ao manager também só via Tailscale (o `sshd` bindado em `100.64.0.1:22`, não em
`0.0.0.0:22`).

Alternativa considerada e rejeitada: bootstrap manual por SSH em vez de `curl | bash`. Decidiu-se
manter o bootstrap público porque o endpoint `/setup-token` (que liberta chaves reais) exige
token válido gerado pelo operador, com rate limiting agressivo. O `bootstrap.sh` sozinho é um
ficheiro estático inofensivo.

### Endpoints internos (só via Tailscale)

Traefik corre em **dois modos** no mesmo container, através de EntryPoints distintos:

- **`websecure-public`** — bindado em `0.0.0.0:443`; matches `control.jose.tld`.
- **`websecure-internal`** — bindado em `100.64.0.1:443`; matches `*.apps.internal`.

Routers Traefik por matcher:

| Hostname | EntryPoint | Serviço | Certificado |
|----------|-----------|---------|-------------|
| `control.jose.tld` | `websecure-public` | Headscale + bootstrap | Let's Encrypt (HTTP-01 ou DNS-01) |
| `komodo.apps.internal` | `websecure-internal` | Komodo Core UI | step-ca (ACME) |
| `grafana.apps.internal` | `websecure-internal` | Grafana | step-ca |
| `vm.apps.internal` | `websecure-internal` | VictoriaMetrics UI | step-ca |
| `adminer.apps.internal` | `websecure-internal` | Adminer (opcional) | step-ca |

`*.apps.internal` resolve via MagicDNS do Headscale (todos os hosts da mesh recebem `apps.internal`
como search domain).

### TLS interno via step-ca

Container `smallstep/step-ca` no manager. Traefik faz ACME contra ele para obter certificados
de `*.apps.internal` — o mesmo mecanismo que usa contra Let's Encrypt, apenas com URL do CA
diferente. Renovação automática, sem intervenção.

Setup uma vez:
1. `step-ca` gera raiz + intermédio na primeira arranque; guarda em volume persistente.
2. Cada host da mesh (incluindo o laptop do operador) instala o certificado raiz uma única vez
   (`step ca bootstrap --ca-url https://step-ca.apps.internal --fingerprint <fp>`), o que evita
   warnings do browser.
3. Traefik configurado com `certificatesResolvers.stepca.acme.caServer=https://step-ca.apps.internal/acme/acme/directory`
   e `certificatesResolvers.stepca.acme.email=...`; pede cert por router automaticamente.

### Onboarding do operador (laptop)

Uma vez, no laptop:

```bash
# Instalar cliente Tailscale
curl -fsSL https://tailscale.com/install.sh | sh

# Ligar à mesh do manager
sudo tailscale up --login-server https://control.jose.tld --auth-key hskey-<operador> --hostname josef-laptop

# Trust do CA interno (necessário para não ter warnings do browser)
step ca bootstrap --ca-url https://step-ca.apps.internal --fingerprint <fp>
```

A partir daqui:
- `https://grafana.apps.internal` — funciona no browser sem warnings
- `https://komodo.apps.internal` — idem
- `ssh gims-prod-1` — funciona por MagicDNS
- `psql -h gims-prod-1 -U postgres` — funciona (Postgres bindado no IP Tailscale do host)

Se algum dia o laptop for perdido/comprometido: no manager, `headscale nodes delete josef-laptop`
+ `headscale preauthkeys expire <key-do-operador>`. Acesso revogado em segundos, sem tocar em
nenhum outro host.

## Redundância do manager — decisão

Para 2-3 hosts GIMS, **HA multi-master do manager é overkill**. Razão principal: quando o
manager cai, **as apps continuam a servir tráfego público** — Traefik, backend, Postgres,
tudo vive nos hosts das apps, não no manager. O que se perde é apenas operação (deploys,
Grafana, capacidade de adicionar nodes ao Headscale) por 15-30 min.

Debaixo do capot, cada componente tem diferente HA-ness:

| Componente | HA-friendly? | Nota |
|-----------|--------------|------|
| Headscale | Sim (Postgres shared) | Mesh WireGuard continua a funcionar mesmo com o Headscale caído |
| Komodo Core | Não oficial | Activo-passivo com failover manual |
| VictoriaMetrics | Single-node é single-node; cluster mode existe mas pesado | Padrão single-node: 2 instâncias scraping em paralelo. Cluster mode (vmstorage + vminsert + vmselect) só se justifica com 10+ hosts |
| Grafana | Sim (DB externo partilhado) | |
| Traefik | Sim, com `acme.json` partilhado | |

**Recomendação: activo-passivo com restore rápido**, não activo-activo. Ver secção seguinte.

## Backup e disaster recovery do manager

O estado do manager vive em volumes bem definidos:

| Componente | State | Backup |
|-----------|-------|--------|
| Headscale | SQLite (`/var/lib/headscale/db.sqlite`) + `private.key` | `sqlite3 .backup` + `cp private.key` |
| Komodo Core | MongoDB volume | `mongodump` |
| VictoriaMetrics | TSDB (`/victoria-metrics-data`) | Snapshot API (`POST /snapshot/create`) — atómico, restore ainda mais simples que Prometheus |
| Grafana | SQLite (`grafana.db`) | `cp` |
| Traefik | `acme.json` (certs Let's Encrypt públicos + step-ca) | `cp` |
| step-ca | Raiz + intermédio + BD de certificados emitidos | `cp` do volume completo — **crítico** (perder a raiz obriga a reinstalar o CA em todos os clientes) |

Backup diário para S3, seguindo o padrão de `backend/services/BackupService.js` do GIMSv2.
Volume total esperado: **< 200 MB comprimido** (VictoriaMetrics comprime 2-7× melhor que
Prometheus para o mesmo volume de séries; 60d de retenção cabem confortavelmente).

**Playbook de restore para manager novo** (documentar em `manager-komodo/docs/DISASTER_RECOVERY.md`):

1. Provisionar VPS novo (~5 min).
2. `git clone manager-komodo` + `curl bootstrap` (~2 min).
3. Restaurar volumes do S3 (~5 min).
4. Actualizar DNS `control.jose.tld` para novo IP (~1 min + TTL de propagação).
5. `docker compose up -d` (~2 min).

**Ponto crítico**: preservar o `private.key` do Headscale e o DNS `SERVER_URL`. Se ambos
estiverem intactos, os clientes Tailscale nos hosts reconectam-se automaticamente ao Headscale
restaurado sem re-registration. Isto é o que torna o restore verdadeiramente indolor.

**Estimativa realista**: 15-30 min do desastre à operação restaurada, se o playbook estiver
escrito e testado uma vez. Testar o restore em ambiente de laboratório antes de precisar dele.

## Bootstrap de host novo — visão do utilizador

Ideal (1 comando):

```bash
curl -sSL https://control.jose.tld/bootstrap.sh | sudo bash -s -- \
    --setup-token <token-uso-único> \
    --hostname gims-prod-1 \
    --role gims-app \
    --app-repo git@github.com:user/GIMSv2.git
```

O `bootstrap.sh` (servido pelo Traefik do control plane) faz:

1. Instala Docker + Docker Compose.
2. Autentica-se no control plane com `--setup-token` e recebe:
   - Pre-auth key do Headscale (one-shot, TTL curto)
   - Passkey do Komodo Periphery para este host
3. Instala cliente Tailscale (`curl -fsSL https://tailscale.com/install.sh | sh`) e liga à mesh:
   `tailscale up --login-server https://control.jose.tld --auth-key <pre-auth-key> --hostname gims-prod-1 --advertise-tags=tag:gims-app`
4. Se `--role gims-app`: clona `--app-repo` para `/opt/gims`, copia `.env.example` para `.env`
   (com `LOCAL_BIND_IP`, `KOMODO_PASSKEY`, `GRAFANA_URL`, `GRAFANA_API_TOKEN` já preenchidos pelo
   bootstrap), aguarda o operador validar o `.env` e faz primeiro `./scripts/update.sh`.
5. Confirma que o Periphery aparece healthy no Komodo Core.

**Setup token**: gerado no control plane (via UI ou `scripts/generate-setup-token.sh`), TTL
curto (ex.: 1h), one-shot. O token dá permissão para o bootstrap **descarregar** as chaves
necessárias, mas as chaves em si são únicas por host.

## Contract entre control plane e aplicações

Cada aplicação hospedada precisa de garantir, no seu próprio repo:

1. `scripts/update.sh` — ponto de entrada de deploy idempotente (`git pull` + `docker compose` + migrações).
2. `.env.example` com pelo menos: `LOCAL_BIND_IP`, `GRAFANA_URL`, `GRAFANA_API_TOKEN`, `KOMODO_PASSKEY`, `HOSTNAME`.
3. Backend expõe `/metrics` (formato Prometheus) num porto bindado em `${LOCAL_BIND_IP}:PORT`.
4. Bloco de annotation no `update.sh` que faz POST a `${GRAFANA_URL}/api/annotations` com token.

Registo de uma app nova no control plane:
- Criar `docker/prometheus/targets/apps/<app>/` com os ficheiros de targets.
- Criar `docker/grafana/dashboards/apps/<app>/` com os JSON dos dashboards.
- (opcional) Criar `docker/prometheus/recording-rules/apps/<app>.yml`.
- Criar Procedure no Komodo Core "Update <app> host" que corre `cd /opt/<app> && ./scripts/update.sh`.
- Documentar em `docs/APPS.md` do control plane.

## Alterações necessárias no repo GIMSv2

### 1. Compose base

Remover do `docker-compose.yml` principal:
- `prometheus`, `grafana`
- `node-exporter`, `cadvisor`, `container-meta-exporter`
- Eliminar contexto de build `docker/container-meta-exporter/` se sem outros utilizadores.
- Apagar `docker/netdata/`.

Manter no `docker-compose.yml` principal:
- Toda a app + `postgres-exporter`.

Acrescentar bloco novo do Komodo Periphery (Modelo 1):
```yaml
periphery:
  image: ghcr.io/moghtech/komodo-periphery:latest
  container_name: gims-periphery
  restart: unless-stopped
  ports:
    - "${LOCAL_BIND_IP:?LOCAL_BIND_IP não definido}:8120:8120"  # mesh-only
  environment:
    PERIPHERY_PASSKEYS: ${KOMODO_PASSKEY:?KOMODO_PASSKEY não definido}
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock
    - /proc:/proc
    - periphery_data:/etc/komodo
    - ${PROJECT_DIR:-./}:/etc/komodo/repos/GIMSv2
  networks:
    - gims-network
```

Bindar backend e postgres-exporter no IP WireGuard:
```yaml
backend:
  ports:
    - "${LOCAL_BIND_IP:?LOCAL_BIND_IP não definido}:3000:3000"

postgres-exporter:
  ports:
    - "${LOCAL_BIND_IP}:9187:9187"
```

Mover `mailpit` e `adminer` para `docker-compose.override.yml` (só dev local).

### 2. `.env` novo por host

```bash
# IP onde a app binda os serviços (métricas/exporter). Em produção = IP da mesh (interface
# Tailscale, ex.: 100.64.0.x); em dev fora da mesh de controlo = localhost ou LAN interna.
LOCAL_BIND_IP=100.64.0.5

# Komodo Periphery — passkey partilhada com Komodo Core
KOMODO_PASSKEY=<segredo>

# Grafana central (para annotations do update.sh)
GRAFANA_URL=http://10.9.0.1:3000
GRAFANA_API_TOKEN=<token Editor gerado no Grafana central>

# Hostname informativo
HOSTNAME=gims-prod-1
```

### 3. `scripts/update.sh` — bloco de annotation

Substituir o `docker exec gims-grafana wget ...` actual por `curl` para o Grafana central:

```bash
COMMIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "?")
HOST_NAME="${HOSTNAME:-$(hostname)}"
ANNOTATION_PAYLOAD=$(printf '{"tags":["deploy","gims","%s"],"text":"Deploy %s @ %s em %s"}' \
    "$HOST_NAME" "$BRANCH" "$COMMIT_SHA" "$HOST_NAME")

if [ -n "${GRAFANA_URL:-}" ] && [ -n "${GRAFANA_API_TOKEN:-}" ]; then
    curl -fsS --max-time 5 \
        -H "Authorization: Bearer $GRAFANA_API_TOKEN" \
        -H "Content-Type: application/json" \
        -d "$ANNOTATION_PAYLOAD" \
        "${GRAFANA_URL%/}/api/annotations" >/dev/null 2>&1 \
        && echo "Annotation de deploy registada no Grafana central." \
        || echo "AVISO: annotation Grafana falhou (update OK)."
fi
```

## Dashboards Grafana — plano de migração

| Dashboard | Acção | Razão |
|-----------|-------|-------|
| `host-metrics.json` | **Apagar do GIMSv2** | Coberto pelo UI do Komodo |
| `docker-metrics.json` | **Apagar do GIMSv2** | Coberto pelo UI do Komodo |
| `api-metrics.json` | Mover para `manager-komodo/apps/gims/` + adaptar | Acrescentar variável `$host`, filtros `host=~"$host"` |
| `regressoes-rotas.json` | Mover + adaptar | Idem + acrescentar coluna `Host` na tabela |
| `postgresql-metrics.json` | Mover + adaptar | Idem |
| `gims-overview.json` | Mover | Só usa `gims_http_*`; sobrevive sem alterações de fundo |

Recording rules em `docker/prometheus/recording-rules.yml` → passam para
`manager-komodo/docker/vmalert/rules/apps/gims.yml`. Sintaxe YAML idêntica; muda apenas quem
avalia (era o Prometheus interno, passa a ser `vmalert` que escreve os resultados de volta
na VM). PromQL não muda — `sum by (route, method)` continua a funcionar; para per-host
acrescentar `host` ao `by`.

## VictoriaMetrics central — configuração

VictoriaMetrics single-node lê um ficheiro `scrape.yml` no formato Prometheus. Substituir
`static_configs` locais por `file_sd_configs`. Restam **2 jobs** para o GIMS:

```yaml
# manager-komodo/docker/victoriametrics/scrape.yml
scrape_configs:
  - job_name: 'gims-backend'
    file_sd_configs:
      - files: ['/etc/prometheus-targets/apps/gims/backend.yml']
    metrics_path: /metrics
    scrape_interval: 10s

  - job_name: 'gims-postgresql'
    file_sd_configs:
      - files: ['/etc/prometheus-targets/apps/gims/postgresql.yml']
```

Passado à VM via flag `-promscrape.config=/etc/victoriametrics/scrape.yml`.

Ficheiros de targets:

```yaml
# manager-komodo/docker/prometheus-targets/apps/gims/backend.yml
- targets: ['100.64.0.5:3000']
  labels:
    app: 'gims'
    host: 'gims-prod-1'
    provider: 'ovh'
- targets: ['100.64.0.6:3000']
  labels:
    app: 'gims'
    host: 'gims-prod-2'
    provider: 'hetzner'
```

Acrescentar host = editar o ficheiro de targets; VM relê automaticamente (mesmo comportamento
que Prometheus).

**Escala futura — Opção B (vmagent por host)**: se o número de jobs por host crescer ou a
latência da VPN for problema, passa-se para o modelo `vmagent` em cada host a fazer scrape
local e `remote_write` comprimido para a VM central. Migração trivial (acrescentar `vmagent`
ao compose do GIMSv2, remover jobs correspondentes do `scrape.yml` da VM). Para 2 jobs ×
3 hosts, é overhead desnecessário — começar em single-VM directa.

### vmalert (recording rules + alertas)

Container separado, corre em paralelo com a VM:

```yaml
vmalert:
  image: victoriametrics/vmalert:latest
  command:
    - '--datasource.url=http://victoriametrics:8428'
    - '--remoteWrite.url=http://victoriametrics:8428'
    - '--rule=/etc/vmalert/rules/apps/*.yml'
    - '--rule=/etc/vmalert/rules/platform/*.yml'
    # - '--notifier.url=http://alertmanager:9093'  # opcional, quando se acrescentar alertas
  volumes:
    - ./docker/vmalert/rules:/etc/vmalert/rules:ro
```

Para começar sem Alertmanager: as recording rules chegam. Quando se acrescentarem regras de
alerta (`alert:` em vez de `record:`), configurar `--notifier.url` para Alertmanager ou para
um webhook directo (o backend GIMS já tem endpoint de webhook de alertas — reaproveitar).

## Mapa de portas WireGuard

Tudo bindado em `${LOCAL_BIND_IP}`, nunca em `0.0.0.0`:

| Porta | Serviço | Direcção |
|-------|---------|----------|
| 3000  | Backend `/metrics` + API interna | VictoriaMetrics central → host |
| 9187  | `postgres-exporter` | VictoriaMetrics central → host |
| 8120  | Komodo Periphery | Komodo Core → host |
| 5432  | PostgreSQL (análise PGHero, **read-only**) | PGHero (manager) → host |

### Acesso PGHero à 5432 (análise read-only)

Originalmente o manager era *scrape-only* e a 5432 estava fora do ACL. Para o **PGHero**
(análise de piores queries, índices em falta/não usados, bloat) o manager precisa de SQL, não só
de métricas — o `postgres-exporter` não dá isso. Decisão consciente: abrir a 5432 **apenas** para
`tag:manager` no `acl.hujson`, com estas mitigações a manter o least-privilege:

- Role dedicada `monitor` em cada host, **só `pg_monitor`** (read-only; sem escrita, sem EXPLAIN).
- `pg_hba.conf` do host restringe a role `monitor` ao IP do manager (`100.64.0.1/32`).
- UI do PGHero só na mesh (`pghero.apps.internal`, atrás do step-ca) e com basic-auth.
- O manager guarda **apenas** a password read-only (`PGHERO_DB_PASSWORD`, igual em todos os hosts);
  as credenciais de escrita/master das apps continuam a **não** estar no manager.
- O histórico do PGHero é gravado num Postgres próprio do manager (`pghero-postgres`), pelo que as
  ligações às BDs das apps são sempre read-only.
- A análise **live** (piores queries, índices, bloat, ligações) e o **histórico de espaço** usam só
  `pg_monitor`. O **histórico de query-stats** é opcional e exige `GRANT EXECUTE` em
  `pg_stat_statements_reset` para o `monitor` (o PGHero faz reset por-base a cada hora) — decisão por
  host, documentada em `docs/pghero-host-setup.md`.

Setup por host (repo GIMSv2): ver `docs/pghero-host-setup.md`.

## Próximos passos (quando se decidir implementar)

1. **Provisionar VPS pequeno para control plane** (OVH ou outro). Dimensionamento: 2 vCPU,
   4 GB RAM, 60 GB SSD.
2. **Criar repo `manager-komodo`** com estrutura acima.
3. **Implementar Headscale + Traefik dual + step-ca**: `docker-compose.yml` do control plane
   com Headscale (público), Traefik com 2 entrypoints (público em `0.0.0.0:443`, interno em
   `${TAILSCALE_IP}:443`), step-ca a emitir para `*.apps.internal`. Definir ACLs em
   `acl.hujson`.
4. **Migrar hosts existentes de Netbird → Tailscale/Headscale**: gerar pre-auth keys,
   correr `tailscale up --login-server https://control.jose.tld --auth-key XXX` em cada host,
   confirmar mesh via `tailscale status`. Desligar Netbird.
5. **Onboarding do operador (laptop)**: `tailscale up` + `step ca bootstrap` para trust do CA
   interno. Validar acesso a `https://grafana.apps.internal` sem warnings.
6. **Provisionar Grafana + VictoriaMetrics + vmalert no control plane** (só bindados na
   interface interna). Migrar os 4 dashboards (datasource "Prometheus" apontado a VM) +
   recording rules para `apps/gims/`. Adicionar variável `$host`.
7. **Provisionar Komodo Core no control plane** (interface interna). Registar hosts existentes.
8. **Endurecer firewall do manager**: `nftables` fecha tudo excepto `443/tcp` e `41641/udp`.
   SSH bindado só na interface Tailscale.
9. **Configurar backups do state do manager para S3** (`backup-manager.sh` em cron horário).
   Testar restore em laboratório — atenção especial ao backup da raiz do step-ca.
8. **Aplicar alterações ao GIMSv2**:
   - Apagar `prometheus`, `grafana`, `node-exporter`, `cadvisor`, `container-meta-exporter`,
     `netdata` do compose e do repo.
   - Adicionar `periphery` ao compose.
   - Bindar backend e postgres-exporter em `${LOCAL_BIND_IP}` — em produção é o IP da mesh
     (interface Tailscale); em dev fora da mesh de controlo pode ser localhost/LAN interna.
   - Alterar bloco de annotation do `update.sh`.
   - Apagar dashboards `host-metrics.json` e `docker-metrics.json` do repo (já migraram para
     `manager-komodo`).
   - Actualizar `.env.example` com `LOCAL_BIND_IP`, `KOMODO_PASSKEY`, `GRAFANA_URL`, `GRAFANA_API_TOKEN`.
10. **Criar Komodo Procedure** "Update GIMS host" → `cd /opt/gims && ./scripts/update.sh`.
11. **Escrever `bootstrap.sh`** + endpoint `/setup-token` no Headscale/manager para libertar
    chaves mediante token válido, com rate limiting.
12. **Validar com 1 host de teste** antes de migrar produção.
13. **Documentar tudo em `docs/MULTIHOST.md` do GIMSv2** (referenciando o `manager-komodo`)
    e apagar este ficheiro `docs/TODO/multi-host-control-plane.md`.

## Bootstrap operacional

Guia executável para arrancar o manager e ligar o primeiro host. Assume o design das secções
anteriores. Cada passo tem verificação — só avançar quando o anterior estiver green.

### Decisões concretas (baseline)

| Item | Valor |
|------|-------|
| Provider VPS | OVH |
| Dimensão VPS manager | 2 vCPU / 4 GB RAM / 40 GB SSD |
| Domínio público | `control.<seu-domínio>` (registar antes de começar) |
| Emails admin | `admin@segcore.eu` |
| Search domain interno | `apps.internal` |
| Espaço IPs Headscale | `100.64.0.0/16` (CGNAT; zero risco de colisão; espaço para crescer sem regenerar IPs) |
| Organização step-ca (O=) | `Quelhas & Fernandes, Lda` |
| Retenção VictoriaMetrics | 60 dias |
| Bucket S3 backups | mesmo do GIMSv2 (prefixo `manager-komodo/`) |
| Modelo Periphery inicial | **M1 em todos os hosts** (M2 promovido pontualmente se necessário) |

### Sobre M1 e M2 coexistirem

Podem coexistir sem fricção. Do ponto de vista do Komodo Core, um Periphery é apenas um
agente a responder num endereço — não interessa se é container ou binário nativo. A distinção
só emerge em Procedures que tocam no host (ex.: `apt upgrade`) — essas só funcionam em M2.

**Convenção sugerida**: prefixar Procedures OS-level com `[M2 only]` e etiquetar hosts M2 com
tag `tag:host-managed` para clareza. Filtrar antes de disparar.

**Default**: M1 em todos. Promover para M2 só quando houver necessidade concreta (ex.: um host
específico ao qual nunca fazes SSH e queres poder correr `apt upgrade` remotamente).

### `.env` do manager e backup

O `.env` do manager contém secrets (KOMODO_PASSKEY, GRAFANA_ADMIN_PASSWORD, S3 credentials,
Headscale server private key indirecta, etc.). O `backup-manager.sh` **inclui o `.env` no
tarball** e cifra tudo com o mesmo mecanismo do `backend/utils/backupCrypto.js` do GIMSv2
(sufixo `.enc`, master key). Nunca deixar `.env` em backup não-encriptado.

O ponto crítico do backup é o par (raiz step-ca + `.env`): sem os dois, restore é impossível
sem re-emitir certificados em todos os clientes e re-gerar todas as passkeys.

### Sequência de execução

**Passo 0 — Pré-requisitos (fazer antes de tocar em código)**

- Registar/apontar DNS `control.<seu-domínio>` a IP público do futuro VPS (TTL curto: 300s
  durante setup).
- Confirmar acesso SSH ao VPS OVH (chave pública injectada via painel OVH ao provisionar).
- Preparar (mas não commitar) os secrets a colocar no `.env`: passwords admin Grafana/Komodo,
  API tokens iniciais, credenciais S3 (podem reutilizar-se as do GIMSv2 se o bucket for o mesmo).

**Passo 1 — Provisionar VPS OVH**

- OVH → Public Cloud ou VPS
- Imagem: **Debian 13** (ou Ubuntu 24.04 LTS) — mais recente, kernel novo, `wg` incluído
- Adicionar chave SSH ao provisionar
- Após provisionamento: hardening básico
  ```
  apt update && apt upgrade -y
  apt install -y docker.io docker-compose-plugin git ufw fail2ban
  systemctl enable --now docker
  # firewall
  ufw default deny incoming
  ufw allow 22/tcp        # temporário até SSH mudar para bind Tailscale
  ufw allow 443/tcp       # Headscale + bootstrap
  ufw allow 41641/udp     # WireGuard direct
  ufw enable
  # unattended-upgrades
  apt install -y unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades
  ```

**Passo 2 — Clonar repo `manager-komodo` vazio**

Repo criado no GitHub (privado). Clonar para `/opt/manager-komodo` no VPS:

```
cd /opt && git clone git@github.com:<user>/manager-komodo.git
cd manager-komodo
```

Copiar o design doc como referência viva do repo (durante o setup):

```
mkdir -p docs
cp <path-to>/multi-host-control-plane.md docs/DESIGN.md
```

**Passo 3 — Criar `.env` inicial**

`.env` versionado só como `.env.example`. `.env` real é git-ignored e vive apenas no VPS +
backup S3.

Preencher com os valores da tabela "Decisões concretas" + secrets gerados na hora
(`openssl rand -hex 32` para KOMODO_PASSKEY, etc.).

**Passo 4 — Implementar incrementalmente (uma peça de cada vez, validar antes de avançar)**

1. **Traefik + step-ca** — sobe primeiro; verificar `curl https://control.<dominio>/` responde
   (mesmo que 404, significa que Traefik está no ar com cert Let's Encrypt). Verificar step-ca
   responde em `https://step-ca.apps.internal/health` (via IP directo antes da mesh existir).
2. **Headscale** — sobe. Configurar user, criar pre-auth key para o próprio operador:
   ```
   docker exec manager-headscale headscale users create josef
   docker exec manager-headscale headscale preauthkeys create --user josef --reusable=false --expiration 1h --tags tag:operator
   ```
   No laptop: `tailscale up --login-server https://control.<dominio> --auth-key hskey-XXX`.
   Verificar `tailscale status` mostra os dois nodes (manager + laptop).
3. **CA trust no laptop**: `step ca bootstrap --ca-url https://step-ca.apps.internal --fingerprint <fp>`
   (fingerprint obtido no primeiro arranque do step-ca).
4. **VictoriaMetrics + vmalert** — sobem. Verificar `curl https://vm.apps.internal/health`
   via mesh do laptop; abrir UI no browser (deve funcionar sem warnings).
5. **Grafana** — sobe. Login inicial admin/admin, mudar password. Provisionar datasource
   apontado a `http://victoriametrics:8428`. Confirmar acesso em `https://grafana.apps.internal`.
6. **Komodo Core + Mongo** — sobem. Login inicial, criar user josef, mudar admin password.
   `https://komodo.apps.internal`.
7. **Endurecer firewall final**: `ufw delete allow 22/tcp` (SSH passa a ser só via Tailscale
   IP; configurar `sshd_config` com `ListenAddress 100.64.0.1` antes).
8. **Configurar `backup-manager.sh`** em cron horário + testar restore em VPS descartável.

**Passo 5 — Ligar primeiro host GIMS de teste**

Não em produção. Provisionar VPS descartável, seguir o `bootstrap.sh` documentado (ainda por
escrever nesta fase — pode-se fazer manualmente enquanto o script não existe). Registar no
Komodo, verificar Prometheus scrape em `https://vm.apps.internal/targets`, correr `update.sh`
via Procedure, confirmar annotation aparece no Grafana.

**Passo 6 — Migrar produção**

Só depois de tudo o acima estar green num ambiente de teste. Um host de cada vez.

### Handoff para uma nova sessão Claude

Prompt sugerido para arrancar a implementação num novo repo/sessão:

> Este repo é o `manager-komodo`, control plane para gerir hosts de aplicações do stack
> GIMS (e futuras). Lê `docs/DESIGN.md` para o contexto arquitectural completo — as
> decisões estão tomadas e a arquitectura é a que está descrita. VPS: `<IP>`, domínio
> público: `control.<seu-domínio>`. Vamos implementar seguindo a secção "Bootstrap
> operacional" do design doc, passo a passo, começando pelo Passo 4.1 (Traefik + step-ca).
> Pede-me apenas os secrets/valores que faltarem quando os precisares — evita perguntas
> sobre decisões arquitectónicas que já estão no doc.

Ponto crítico: a nova sessão deve **implementar sequencialmente** e **validar cada peça**
antes de avançar para a seguinte. Não criar tudo de uma vez.

## Notas finais

- **Backups continuam por host** (BackupService em cada host, push para S3). Não centralizar —
  backup central seria SPOF.
- **Postgres não é centralizado**: cada host tem o seu cluster. Multi-host cross-tenant migration
  é outro projecto.
- **Traefik por host das apps inalterado**: cada VPS continua a servir o seu tenant publicamente
  com o seu próprio certificado Let's Encrypt. Traefik do control plane só serve o próprio control
  plane (Komodo UI, Grafana, `bootstrap.sh`).
- **Não usar GitOps do Komodo** (sync de stacks a partir de git). Komodo aqui é apenas
  orquestrador de comandos. Razão: `update.sh` faz muito mais do que `docker compose up`
  (backup, migrations, manutenção) — GitOps seria refactor enorme com risco.
- **Este documento pode ser copiado para `manager-komodo/docs/OPS.md` (ou dividido em vários
  ficheiros) quando o repo for criado.** Aqui permanece apenas a referência às alterações
  ao GIMSv2.
