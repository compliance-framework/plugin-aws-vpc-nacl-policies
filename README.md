# AWS VPC network ACL policies

Standalone OPA/Rego policy bundle for network ACL evidence emitted by the `plugin-aws-vpc` collector.

## Input schema

Each policy evaluates one AWS network ACL at a time using:

- `input.network_acl`
- `input.nacl_context`

Current network ACL context includes the parent VPC, associated subnets, route tables in the VPC, route tables for associated subnets, internet gateways for the VPC, related flow logs, related log groups, and network interfaces in associated subnets.

## Current coverage

This bundle currently checks network ACL posture such as:

- required network ACL tags
- subnet association presence
- default network ACL usage
- approved public ingress ports
- unrestricted public egress
- flow-log coverage for related resources
- shadowed deny rules
- administrative ingress source restrictions

## Policy data

Default baselines live in `policies/data.json` and can be overridden by agent-supplied policy data. Current settings cover required tags, whether default or unassociated ACLs are allowed, approved public ingress ports, approved administrative CIDRs and ports, and flow-log expectations.

## Testing

Run local checks with:

```shell
opa check policies
opa test policies
```

Or use the Makefile wrappers:

```shell
make validate
make test
```

## Bundling

Build the distributable bundle with:

```shell
make build
```

This writes `dist/bundle.tar.gz`.
