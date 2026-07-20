"""NetGuard CLI — command-line interface for the intrusion detection system."""

from __future__ import annotations

import click


@click.group()
@click.version_option(version="0.1.0")
def main():
    """NetGuard - Real-time Network Intrusion Detection System"""
    pass


@main.command()
@click.option("--config", "-c", default="configs/default.yaml", help="Config file path")
def run(config):
    """Start the detection pipeline."""
    click.echo(f"Starting NetGuard with config: {config}")
    import asyncio

    from netguard.core.config import NetGuardConfig
    from netguard.core.engine import NetGuard

    try:
        cfg = NetGuardConfig.from_yaml(config)
        detector = NetGuard(config=cfg)
        asyncio.run(detector.start())
    except KeyboardInterrupt:
        click.echo("\nShutting down...")
    except FileNotFoundError:
        click.echo(f"Config file not found: {config}", err=True)
        raise SystemExit(1)


@main.command()
@click.option("--port", default=8080, help="Web UI port")
def demo(port):
    """Run demo mode with synthetic data (zero external dependencies)."""
    click.echo("Starting NetGuard in demo mode...")
    click.echo(f"  - Synthetic traffic generator (no Kafka needed)")
    click.echo(f"  - In-memory feature store (no Redis needed)")
    click.echo(f"  - Pre-trained online model")
    click.echo(f"  - Console output")
    click.echo(f"  - API at http://localhost:{port}")
    click.echo()

    import asyncio

    from netguard.core.config import NetGuardConfig
    from netguard.core.engine import NetGuard

    cfg = NetGuardConfig.from_yaml("configs/demo.yaml")
    detector = NetGuard(config=cfg)
    try:
        asyncio.run(detector.start())
    except KeyboardInterrupt:
        click.echo("\nDemo stopped.")


@main.command()
@click.option(
    "--profile",
    type=click.Choice(["normal", "mixed"]),
    default="mixed",
    help="Traffic profile",
)
@click.option(
    "--attack",
    type=click.Choice([
        "port_scan",
        "syn_flood",
        "brute_force",
        "c2_beacon",
        "lateral_movement",
        "dns_tunnel",
        "exfiltration",
    ]),
    default=None,
    help="Specific attack to generate",
)
@click.option(
    "--scenario",
    type=click.Choice(["apt_kill_chain", "botnet_recruitment"]),
    default=None,
    help="Multi-step attack scenario",
)
@click.option("--rate", default=100, help="Flows per second")
@click.option("--duration", default=60, help="Duration in seconds (0 = infinite)")
@click.option(
    "--attack-ratio", default=0.05, help="Ratio of attack traffic (for mixed profile)"
)
@click.option(
    "--output",
    "-o",
    default="stdout",
    help="Output: stdout, file path, or kafka://host:port/topic",
)
@click.option("--seed", default=42, help="Random seed for reproducibility")
def generate(profile, attack, scenario, rate, duration, attack_ratio, output, seed):
    """Generate synthetic network traffic."""
    import asyncio

    asyncio.run(
        _generate(profile, attack, scenario, rate, duration, attack_ratio, output, seed)
    )


async def _generate(
    profile, attack, scenario, rate, duration, attack_ratio, output, seed
):
    """Async implementation of generate command."""
    import json
    import time

    from netguard.testing.attacks import AttackGenerator
    from netguard.testing.generator import NetworkTrafficGenerator, TrafficProfile
    from netguard.testing.scenarios import AttackScenario

    click.echo(f"Generating traffic: profile={profile}, rate={rate}/s, duration={duration}s")

    gen = NetworkTrafficGenerator(seed=seed)

    # Determine output sink
    sink = _get_output_sink(output)

    flow_count = 0
    attack_count = 0
    start_time = time.time()

    if attack:
        # Generate specific attack only
        attacks = AttackGenerator(gen)
        method = getattr(attacks, f"generate_{attack}")
        async for flow in method():
            await sink(flow)
            attack_count += 1
            if duration and time.time() - start_time > duration:
                break
    elif scenario:
        # Run multi-step scenario
        attacks = AttackGenerator(gen)
        scenarios = AttackScenario(attacks)
        method = getattr(scenarios, scenario)
        async for flow in method():
            await sink(flow)
            flow_count += 1
    else:
        # Generate traffic (normal or mixed)
        include_attacks = profile == "mixed"
        async for flow in gen.stream(rate=rate, include_attacks=include_attacks):
            await sink(flow)
            flow_count += 1
            if flow.get("label") == "malicious":
                attack_count += 1
            if duration and time.time() - start_time > duration:
                break

    click.echo(
        f"\nGenerated {flow_count + attack_count} flows "
        f"({attack_count} attacks) in {time.time() - start_time:.1f}s"
    )


def _get_output_sink(output: str):
    """Return an async callable that writes flows to the specified output."""
    import json

    if output == "stdout" or output == "-":

        async def stdout_sink(flow):
            label = flow.get("label", "unknown")
            if label == "malicious":
                click.echo(click.style(json.dumps(flow), fg="red"))
            else:
                click.echo(json.dumps(flow))

        return stdout_sink

    elif output.startswith("kafka://"):
        # Parse kafka://host:port/topic
        parts = output.replace("kafka://", "").split("/", 1)
        brokers = parts[0]
        topic = parts[1] if len(parts) > 1 else "raw-flows"

        from netguard.adapters.kafka_producer import KafkaFlowProducer

        producer = KafkaFlowProducer(brokers=brokers, topic=topic)

        async def kafka_sink(flow):
            await producer.send(flow)

        return kafka_sink

    else:
        # File output
        f = None

        async def file_sink(flow):
            nonlocal f
            if f is None:
                f = open(output, "a")
            f.write(json.dumps(flow) + "\n")

        return file_sink


@main.command()
@click.option(
    "--input", "-i", "input_path", required=True, help="Input file (pcap, csv, jsonl)"
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["cicids", "jsonl", "pcap"]),
    default="jsonl",
)
@click.option(
    "--speed", default="1x", help="Replay speed multiplier (e.g., 10x, 100x)"
)
@click.option("--output", "-o", default="stdout", help="Output destination")
def replay(input_path, fmt, speed, output):
    """Replay a dataset or capture file."""
    speed_mult = float(speed.replace("x", ""))
    click.echo(f"Replaying {input_path} at {speed}...")

    import asyncio

    asyncio.run(_replay(input_path, fmt, speed_mult, output))


async def _replay(input_path, fmt, speed_mult, output):
    """Async implementation of replay command."""
    from netguard.testing.replay import CICIDSReplay

    sink = _get_output_sink(output)
    count = 0

    if fmt == "cicids":
        replayer = CICIDSReplay(data_dir=input_path, speed_multiplier=speed_mult)
        async for flow in replayer.stream():
            await sink(flow)
            count += 1
            if count % 1000 == 0:
                click.echo(f"  Replayed {count} flows...", nl=False)
                click.echo("\r", nl=False)

    click.echo(f"\nReplayed {count} flows total.")


@main.command()
@click.option(
    "--config", "-c", default="configs/default.yaml", help="Config file to validate"
)
def validate(config):
    """Validate a configuration file."""
    from netguard.core.config import NetGuardConfig

    try:
        cfg = NetGuardConfig.from_yaml(config)
        click.echo(click.style("Configuration valid!", fg="green"))
        click.echo(f"  Source: {cfg.source.type}")
        click.echo(f"  Models: {len(cfg.models)} configured")
        click.echo(f"  Outputs: {len(cfg.outputs)} configured")
        click.echo(
            f"  Server: {'enabled' if cfg.server.enabled else 'disabled'} "
            f"on port {cfg.server.port}"
        )
    except FileNotFoundError:
        click.echo(click.style(f"File not found: {config}", fg="red"), err=True)
        raise SystemExit(1)
    except Exception as e:
        click.echo(
            click.style(f"Invalid configuration: {e}", fg="red"), err=True
        )
        raise SystemExit(1)
