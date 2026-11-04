# eCapture internal packages

The production path runs from the Cobra commands through probe configuration,
factory construction, eBPF readers, event decoding, dispatch, and output
handlers. The [architecture guide](../docs/agent/architecture.md) describes
that flow and its lifecycle and concurrency constraints.

## Package map

| Package | Responsibility |
| --- | --- |
| `domain` | Probe, configuration, event, decoder, dispatcher, and output contracts |
| `config` | Shared serializable settings, validation, and common-field application |
| `builder` | Fluent configuration helpers |
| `errors` | Structured domain errors and context |
| `logger` | Runtime/probe logging abstraction |
| `factory` | Probe constructors registered during package initialization |
| `events` | Validated, synchronous dispatch to handlers that support an event |
| `probe/base` | Common initialization, readers, optional perf reorder, and shutdown |
| `probe/<name>` | Module configuration, event ABI, attachments, decoders, and lifecycle |
| `probe/bytecode` | Shared CO-RE/non-CO-RE selection and asset contracts |
| `output` | Borrowed process-lifetime output dependencies and operational-log adaptation |
| `output/writers` | Raw stdout/file/TCP/WebSocket sinks and keylog encoding |
| `output/pcapng` | Serialized packet/DSB representation and borrowed keylog adapter |
| `output/decrypt` | Live pcapng-to-decryptor SDK bridge and reconstructed HTTP output |
| `output/encoders` | Standalone encoder abstractions outside the production CLI path |

## Development references

- Read [probe development](../docs/agent/probe-development.md) before changing
  an attachment, event ABI, reader, configuration field, or capture mode.
- Read [output ownership and routing](../docs/agent/output-pipeline.md) before
  changing handlers, sinks, typed publishers, or their shutdown behavior.
- Follow [build and verification](../docs/agent/build-test.md) for targeted
  tests, full race checks, production-tag lint, and strict E2E. Compilation,
  lint, tests, and eBPF execution require Linux.

Keep the repository-wide [AGENTS.md](../AGENTS.md) contracts and the relevant
long-lived guide synchronized with implementation changes. Source and tests,
not migration checklists or historical coverage percentages, define current
behavior.
