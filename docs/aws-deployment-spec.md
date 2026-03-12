# AWS Deployment Spec

Historical note: this document describes the pre-Convex single-host container deployment option.
The current primary deployment path for this repo is Convex.

This document specifies a production deployment for `clawpushrelay` in an AWS account with a public DNS name and HTTPS.

## Recommended Topology

Use this layout for the current codebase:

- `Route 53` hosted zone for your domain
- `ACM` public certificate for `relay.example.com`
- Internet-facing `Application Load Balancer`
- One `EC2` instance running the Docker container
- One persistent `gp3 EBS` volume mounted for relay state
- `ECR` repository for the container image
- `Secrets Manager` secret that stores the production `.env`
- `CloudWatch Logs` for container logs

Recommended request flow:

`client -> Route 53 -> ALB (HTTPS) -> EC2:8787 -> container`

## Why This Shape

This service is not stateless today.

- Durable state is stored in `CLAWPUSHRELAY_STATE_DIR/relay-state.json`
- Challenges are in memory only
- Rate limiting is in memory only
- The local JSON state store is not safe for multiple writers

Because of that, the deployment should run exactly one writable application instance. A single EC2 host is the simplest AWS fit for the current implementation. Do not start with a multi-task ECS service or an Auto Scaling group with more than one instance unless the application is first changed to use shared backing stores for state, challenges, and rate limits.

## AWS Resources

Create these resources in one AWS region:

- `ECR` repository: `clawpushrelay`
- `VPC` with at least two public subnets in different AZs for the ALB
- `ALB` in two public subnets
- `Target group` using `Instance` targets on port `8787`
- `ACM` certificate for `relay.example.com`
- `EC2` instance: recommended starting size `t3.small`
- `EBS` volume: `20 GiB gp3` mounted at `/var/lib/clawpushrelay`
- `IAM instance profile` with:
  - `AmazonSSMManagedInstanceCore`
  - read access to the relay image in `ECR`
  - read access to the relay secret in `Secrets Manager`
  - permission to write logs to `CloudWatch Logs`
- `CloudWatch` log group: `/clawpushrelay/prod`

## Networking

Use these security groups:

- `alb-sg`
  - ingress `80/tcp` from `0.0.0.0/0`
  - ingress `443/tcp` from `0.0.0.0/0`
  - egress `8787/tcp` to `app-sg`
- `app-sg`
  - ingress `8787/tcp` from `alb-sg`
  - no SSH ingress
  - egress `443/tcp` to `0.0.0.0/0`

Notes:

- Keep the EC2 instance manageable through `SSM Session Manager` instead of SSH.
- The ALB must span two subnets. The application instance remains single-instance by design.
- A public subnet for the instance is acceptable here if inbound traffic is restricted to the ALB security group and SSH stays closed. That avoids NAT gateway cost for a small service.

## DNS And HTTPS

Use a dedicated hostname such as `relay.example.com`.

1. Request an ACM public certificate for `relay.example.com` in the same AWS region as the ALB.
2. Use DNS validation.
3. If the domain is hosted in Route 53, create the ACM validation records there.
4. Create an ALB HTTPS listener on `443` using the ACM certificate.
5. Create an ALB HTTP listener on `80` that redirects to HTTPS.
6. In Route 53, create an alias `A` record for `relay.example.com` pointing to the ALB.
7. Optionally create an alias `AAAA` record if you want IPv6 clients to resolve the name over IPv6 as well.

## Image Build And Registry

Build the image from this repository and push it to ECR.

Pick one runtime architecture and keep the image build aligned with it. Recommended default:

- EC2: `t3.small`
- image platform: `linux/amd64`

Example flow:

```bash
aws ecr create-repository --repository-name clawpushrelay

aws ecr get-login-password --region <region> | \
  docker login --username AWS --password-stdin <account>.dkr.ecr.<region>.amazonaws.com

docker buildx build \
  --platform linux/amd64 \
  -t clawpushrelay:prod-$(git rev-parse --short HEAD) \
  .

docker tag clawpushrelay:prod-$(git rev-parse --short HEAD) \
  <account>.dkr.ecr.<region>.amazonaws.com/clawpushrelay:prod-$(git rev-parse --short HEAD)

docker push <account>.dkr.ecr.<region>.amazonaws.com/clawpushrelay:prod-$(git rev-parse --short HEAD)
```

## Production Configuration

Store the production environment as one secret in `Secrets Manager`, for example `clawpushrelay/prod/env`.

Recommended contents:

```dotenv
CLAWPUSHRELAY_HOST=0.0.0.0
CLAWPUSHRELAY_PORT=8787
CLAWPUSHRELAY_TRUST_PROXY=true
CLAWPUSHRELAY_STATE_DIR=/app/data
CLAWPUSHRELAY_ENCRYPTION_KEY=<32-byte key in base64 or 64-char hex>
CLAWPUSHRELAY_GATEWAY_BEARER_TOKEN=<random secret>
CLAWPUSHRELAY_ALLOWED_BUNDLE_IDS=ai.openclaw.client
CLAWPUSHRELAY_APPLE_TEAM_ID=<apple team id>
CLAWPUSHRELAY_APP_ATTEST_ALLOW_DEVELOPMENT=false
CLAWPUSHRELAY_APNS_TEAM_ID=<apple team id>
CLAWPUSHRELAY_APNS_KEY_ID=<apns key id>
CLAWPUSHRELAY_APNS_PRIVATE_KEY_P8=-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----
# CLAWPUSHRELAY_APPLE_RECEIPT_SHARED_SECRET=<only if needed>
```

Notes:

- Generate `CLAWPUSHRELAY_ENCRYPTION_KEY` once and keep it stable. Restoring `relay-state.json` without the same key will break decryption of stored APNs tokens.
- Generate `CLAWPUSHRELAY_GATEWAY_BEARER_TOKEN` with high entropy and reuse the same value in the OpenClaw gateway config.
- `CLAWPUSHRELAY_TRUST_PROXY=true` is acceptable behind an ALB. If you want a stricter setting, replace it with your VPC CIDR allowlist.
- Prefer `CLAWPUSHRELAY_APNS_PRIVATE_KEY_P8` over a file path on AWS so the APNs key can stay fully in Secrets Manager.

Suggested secret generation:

```bash
openssl rand -base64 32
openssl rand -hex 32
```

## EC2 Host Setup

Use an Amazon Linux 2023 AMI.

Bootstrap steps:

1. Install Docker.
2. Mount the EBS volume at `/var/lib/clawpushrelay`.
3. Create `/etc/clawpushrelay.env` from the `Secrets Manager` secret at boot.
4. Log in to `ECR`.
5. Pull the pinned image tag.
6. Run the container with a restart policy or a `systemd` unit.

Container requirements:

- publish host port `8787` to container port `8787`
- bind mount `/var/lib/clawpushrelay` to `/app/data`
- set `CLAWPUSHRELAY_HOST=0.0.0.0`
- send stdout and stderr to CloudWatch Logs

Example container shape:

```bash
docker run -d \
  --name clawpushrelay \
  --restart unless-stopped \
  -p 8787:8787 \
  --env-file /etc/clawpushrelay.env \
  -v /var/lib/clawpushrelay:/app/data \
  <account>.dkr.ecr.<region>.amazonaws.com/clawpushrelay:<tag>
```

## Load Balancer Settings

Configure the target group like this:

- target type: `instance`
- protocol: `HTTP`
- port: `8787`
- health check path: `/healthz`
- success matcher: `200`
- deregistration delay: low, for example `15s`

Configure listeners:

- `80` -> redirect to `443`
- `443` -> forward to the relay target group using the ACM certificate

## Deployment Procedure

Use this sequence for each release:

1. Build and push a new image tag to `ECR`.
2. Connect through `SSM`.
3. Pull the new image tag on the instance.
4. Restart the container with the new image.
5. Wait for the ALB target to return healthy.
6. Run the smoke checks below.

Operational note:

- Because challenges and rate limits are stored in memory, restarts invalidate active challenge IDs and can briefly disrupt in-flight registrations.
- Because the service is single-instance, deployments are intentionally not zero-downtime.
- Schedule deploys for low-traffic windows and make the iOS client retry challenge and registration requests.

## Backups And Recovery

Back up both of these:

- the persistent state directory on the EBS volume
- the current value of `CLAWPUSHRELAY_ENCRYPTION_KEY`

Minimum backup policy:

- nightly EBS snapshot
- retain recent daily snapshots and a smaller set of weekly snapshots

Recovery runbook:

1. Launch a replacement EC2 instance in the same region.
2. Restore the EBS volume from the latest good snapshot.
3. Reattach the same `Secrets Manager` secret.
4. Pull the same or newer image.
5. Start the container.
6. Re-register the instance in the target group if needed.

## OpenClaw Integration Changes

After the relay is live, set these values in the other systems:

Gateway:

```dotenv
OPENCLAW_APNS_RELAY_BASE_URL=https://relay.example.com
OPENCLAW_APNS_RELAY_AUTH_TOKEN=<same value as CLAWPUSHRELAY_GATEWAY_BEARER_TOKEN>
```

Official iOS builds:

```dotenv
OPENCLAW_PUSH_RELAY_BASE_URL=https://relay.example.com
```

## Smoke Checks

After the first deploy and after every subsequent deploy:

```bash
curl -fsS https://relay.example.com/healthz
```

Also verify:

- one end-to-end registration from an official TestFlight or App Store build
- one end-to-end `push.test` send from the gateway
- container logs show successful startup with no config errors

## Future Upgrade Path

If you later want multi-AZ or multi-instance behavior, change the application first:

- move challenge storage out of memory
- move rate limiting out of memory
- move durable state out of the local JSON file
- add cross-instance locking or use a backing database

After that, migrate to `ECS/Fargate + ALB` or another managed container platform.
