# OBJECTS Devnet Deployment Checklist

Checklist for deploying OBJECTS Protocol v0.1 devnet.

**Platform:** Google Cloud Platform (GCP)

---

## GCP Project Setup

```bash
# Install gcloud CLI
brew install google-cloud-sdk

# Login and create project
gcloud auth login
gcloud projects create objects-devnet --name="OBJECTS Devnet"
gcloud config set project objects-devnet

# Enable required APIs
gcloud services enable \
  run.googleapis.com \
  sqladmin.googleapis.com \
  compute.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com
```

- [ ] Create GCP project `objects-devnet`
- [ ] Enable billing (apply startup credits)
- [ ] Enable required APIs

---

## Infrastructure

### Identity Registry

```bash
# Create Cloud SQL Postgres (smallest tier)
gcloud sql instances create objects-registry-db \
  --database-version=POSTGRES_14 \
  --tier=db-f1-micro \
  --region=us-central1 \
  --storage-size=10GB

gcloud sql databases create registry --instance=objects-registry-db
gcloud sql users set-password postgres --instance=objects-registry-db --password=<password>

# Deploy to Cloud Run
gcloud run deploy objects-registry \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --memory 256Mi \
  --cpu 0.25 \
  --min-instances 1 \
  --add-cloudsql-instances objects-devnet:us-central1:objects-registry-db \
  --set-env-vars "DATABASE_URL=postgres://postgres:<password>@/registry?host=/cloudsql/objects-devnet:us-central1:objects-registry-db"

# Map custom domain
gcloud run domain-mappings create --service objects-registry --domain registry.objects.network --region us-central1
```

- [ ] Create Cloud SQL Postgres instance
- [ ] Implement registry service (REST + gRPC)
- [ ] Deploy to Cloud Run
- [ ] Map `registry.objects.network` domain
- [ ] Verify endpoints:
  - [ ] `POST /v1/identities`
  - [ ] `GET /v1/identities/{id}`
  - [ ] `GET /v1/identities?handle=`
  - [ ] `GET /v1/identities?signer=`
  - [ ] `GET /v1/identities?wallet=`
  - [ ] `POST /v1/identities/{id}/wallet`
  - [ ] `PATCH /v1/identities/{id}/handle`
  - [ ] `GET /health`

### Relay Server

```bash
# Create Compute Engine instance for relay (needs persistent connections)
gcloud compute instances create objects-relay \
  --machine-type=e2-micro \
  --zone=us-central1-a \
  --image-family=debian-12 \
  --image-project=debian-cloud \
  --tags=relay \
  --metadata=startup-script='#!/bin/bash
    apt-get update && apt-get install -y docker.io
    docker run -d --restart=always -p 443:443 -p 3478:3478/udp <registry>/objects-relay:latest'

# Open firewall for relay
gcloud compute firewall-rules create allow-relay \
  --allow tcp:443,udp:3478 \
  --target-tags=relay

# Reserve static IP
gcloud compute addresses create relay-ip --region=us-central1
gcloud compute instances add-access-config objects-relay --access-config-name="external-nat" --address=<static-ip>
```

- [ ] Create Compute Engine instance
- [ ] Deploy Iroh relay binary
- [ ] Configure TLS certificate
- [ ] Map `relay.objects.network` domain
- [ ] Document relay NodeId

### Bootstrap Nodes

```bash
# Generate keypairs locally
cargo run --bin objects-keygen > bootstrap-1-keys.json
cargo run --bin objects-keygen > bootstrap-2-keys.json

# Deploy bootstrap node 1 (US)
gcloud compute instances create objects-bootstrap-1 \
  --machine-type=e2-micro \
  --zone=us-central1-a \
  --image-family=debian-12 \
  --image-project=debian-cloud \
  --tags=bootstrap

# Deploy bootstrap node 2 (EU for geographic redundancy)
gcloud compute instances create objects-bootstrap-2 \
  --machine-type=e2-micro \
  --zone=europe-west1-b \
  --image-family=debian-12 \
  --image-project=debian-cloud \
  --tags=bootstrap

# Open firewall for QUIC
gcloud compute firewall-rules create allow-quic \
  --allow udp:7824 \
  --target-tags=bootstrap
```

- [ ] Generate Ed25519 keypair for bootstrap node 1
- [ ] Generate Ed25519 keypair for bootstrap node 2
- [ ] Deploy bootstrap node 1 (us-central1)
- [ ] Deploy bootstrap node 2 (europe-west1)
- [ ] Update RFC-002 with bootstrap NodeIds
- [ ] Verify nodes join discovery topic `/objects/devnet/0.1/discovery`

---

## Implementation

### Core Libraries

- [ ] `objects-identity` - Identity types, signature verification, ID derivation
- [ ] `objects-transport` - Iroh wrapper, ALPN `/objects/0.1`, discovery
- [ ] `objects-sync` - Blob sync, metadata sync (thin wrapper over iroh-blobs/iroh-docs)
- [ ] `objects-data` - Asset, Project, Reference types, SignedAsset

### Node Implementation

- [ ] Basic node that can:
  - [ ] Connect to relay
  - [ ] Join discovery topic
  - [ ] Broadcast DiscoveryAnnouncement
  - [ ] Receive and verify announcements
  - [ ] Connect to discovered peers
- [ ] Sync operations:
  - [ ] Create/sync replica (project)
  - [ ] Store/fetch blobs (asset content)
  - [ ] Create/sync entries (assets, references)
- [ ] Identity operations:
  - [ ] Create identity via registry
  - [ ] Sign assets with identity
  - [ ] Verify SignedAsset locally

### CLI Tool

- [ ] `objects init` - Initialize node
- [ ] `objects identity create` - Create identity
- [ ] `objects identity show` - Show current identity
- [ ] `objects project create` - Create project
- [ ] `objects project list` - List projects
- [ ] `objects asset add <file>` - Add asset to project
- [ ] `objects asset list` - List assets
- [ ] `objects sync` - Sync with peers
- [ ] `objects ticket create` - Generate share ticket
- [ ] `objects ticket redeem <ticket>` - Join via ticket

---

## Testing

### Unit Tests

- [ ] Identity ID derivation matches test vectors (RFC-001 Appendix B)
- [ ] Handle validation
- [ ] Signature verification (passkey + wallet)
- [ ] Asset signing and verification
- [ ] Protobuf serialization/deserialization

### Integration Tests

- [ ] Create identity via registry
- [ ] Two nodes discover each other via gossip
- [ ] Two nodes sync a project
- [ ] Blob transfer with verification
- [ ] Ticket-based sharing flow

### End-to-End Tests

- [ ] Full flow: create identity → create project → add asset → share ticket → recipient syncs

---

## Documentation

- [ ] Update RFC-002 with actual bootstrap NodeIds
- [ ] Write getting started guide
- [ ] Document CLI commands
- [ ] API reference for registry

---

## Launch Criteria

All items above complete, plus:

- [ ] Bootstrap nodes stable for 48+ hours
- [ ] Registry stable for 48+ hours
- [ ] Relay stable for 48+ hours
- [ ] At least 2 team members have successfully synced a project
- [ ] README with quickstart instructions

---

## Network Parameters (Devnet)

| Parameter | Value |
|-----------|-------|
| ALPN | `/objects/0.1` |
| Relay | `https://relay.objects.network` |
| Registry | `https://registry.objects.network` |
| Discovery Topic | `/objects/devnet/0.1/discovery` |
| Bootstrap Node 1 | TBD |
| Bootstrap Node 2 | TBD |

---

## GCP Cost Estimate

| Service | GCP Product | Spec | Monthly Cost |
|---------|-------------|------|--------------|
| Registry | Cloud Run | 256 MB, 0.25 vCPU, min 1 instance | ~$10 |
| Postgres | Cloud SQL | db-f1-micro, 10 GB | ~$10 |
| Relay | Compute Engine | e2-micro | ~$6 |
| Bootstrap 1 | Compute Engine | e2-micro | ~$6 |
| Bootstrap 2 | Compute Engine | e2-micro | ~$6 |
| **Total** | | | **~$38/month** |

With startup credits, this runs free for years.

---

## Post-Launch

- [ ] Monitor node count via discovery topic
- [ ] Monitor registry usage
- [ ] Collect feedback on pain points
- [ ] Plan v0.2 based on learnings
