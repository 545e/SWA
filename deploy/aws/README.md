# SWA AI — AWS Cloud Deployment Architecture

## Supported AWS Hosting Patterns

### Option 1: AWS ECS on AWS Fargate (Recommended Container Architecture)
- **Architecture**: Serverless container execution with AWS Application Load Balancer (ALB) and persistent Amazon EFS volume.
- **Task Definition**: [`deploy/aws/ecs-task-definition.json`](ecs-task-definition.json).
- **Prerequisites**:
  - AWS VPC with public & private subnets.
  - Amazon EFS file system created with access point for `/swa-data`.
  - Application Load Balancer pointing target group to port `8000` with health check path `/health`.
  - ACM TLS Certificate attached to HTTPS:443 listener.
- **Steps**:
  ```bash
  aws ecr create-repository --repository-name swa-ai
  docker build -t <ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/swa-ai:latest .
  docker push <ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/swa-ai:latest
  aws ecs register-task-definition --cli-input-json file://deploy/aws/ecs-task-definition.json
  aws ecs create-service --cluster swa-cluster --service-name swa-service --task-definition swa-ai-production:1 --desired-count 1 --launch-type FARGATE
  ```

### Option 2: AWS Elastic Compute Cloud (EC2)
- **Architecture**: Single t3.medium or t3.large instance running Docker Compose.
- **User Data Script**: Attach [`deploy/aws/ec2-user-data.sh`](ec2-user-data.sh) upon launch.
- **Security Group Rules**:
  - Inbound TCP 443 (HTTPS) from authorized management IPs.
  - Inbound TCP 8000 only if direct testing without ALB.
  - Outbound: All traffic (for target scanning).
- **Persistence**: Amazon EBS gp3 root volume.

---

## Backup & Disaster Recovery on AWS
- Automated AWS Backup plan configured to take daily snapshots of the Amazon EFS volume.
- S3 sync cron: `aws s3 sync /data/backups s3://your-company-swa-backups/`.
