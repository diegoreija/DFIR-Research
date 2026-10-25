# Remote protocol status

The remote agent and transport are **not implemented** in IRX 0.1.0. There is no
`connect`, `sessions`, `host`, `processes`, or `network` command, and target
registration does not probe the endpoint. IRX must not be described as capable
of remote endpoint investigation in this release.

Before remote operations are added, the implementation must define an
allow-listed, versioned request schema with explicit operation names and
validated parameters. It must use mutually authenticated TLS with certificate
identity verification and explicit trust provisioning; invalid, expired, or
untrusted certificates must fail closed. Responses need bounded size and time,
request IDs, agent identity/version/capabilities, and structured partial/error
states. The agent must enforce local permissions and audit each operation.

No arbitrary shell or code execution endpoint is permitted. A future lab agent
must be launched and configured explicitly by an administrator, expose only
read-oriented collection methods, and document collection side effects. This
document is a design gate, not a claim of working transport or an executable
protocol specification.
