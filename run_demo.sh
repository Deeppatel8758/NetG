#!/bin/bash
# NetGuard Phase 1 Demo — Run with: ./run_demo.sh
# Ctrl+C to stop

cd "$(dirname "$0")"

# Use project venv if available, otherwise system python
if [ -f .venv/bin/python3 ]; then
    PYTHON=.venv/bin/python3
else
    PYTHON=python3
fi

echo "============================================"
echo "  NetGuard — Real-time Network IDS Demo"
echo "============================================"
echo ""
echo "Starting detection pipeline with mixed traffic..."
echo "(5% attacks injected into normal traffic)"
echo "Press Ctrl+C to stop"
echo ""

PYTHONPATH=src $PYTHON -c "
import asyncio, logging, random, time, sys
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

from netguard.core.config import NetGuardConfig
from netguard.core.pipeline import Pipeline
from netguard.testing.generator import NetworkTrafficGenerator
from netguard.testing.attacks import AttackGenerator

class MixedTrafficAdapter:
    def __init__(self, rate=200):
        self.gen = NetworkTrafficGenerator(seed=int(time.time()) % 10000)
        self.attacks = AttackGenerator(self.gen)
        self.rate = rate

    async def stream(self):
        interval = 1.0 / self.rate
        while True:
            if random.random() < 0.05:
                attack = random.choice(['port_scan', 'brute_force', 'dns_tunnel', 'c2_beacon'])
                method = getattr(self.attacks, f'generate_{attack}')
                if attack in ('port_scan', 'dns_tunnel'):
                    async for flow in method(**({'ports': 1} if attack == 'port_scan' else {'queries': 1})):
                        yield flow
                        break
                elif attack == 'brute_force':
                    async for flow in method(attempts=1):
                        yield flow
                        break
                elif attack == 'c2_beacon':
                    async for flow in method(beacon_count=1, interval_sec=0.1):
                        yield flow
                        break
            else:
                yield self.gen.generate_normal_flow()
            await asyncio.sleep(interval)

async def main():
    cfg = NetGuardConfig.from_yaml('configs/demo.yaml')
    pipeline = Pipeline(config=cfg)
    pipeline._source = MixedTrafficAdapter(rate=200)
    await pipeline.run()

try:
    asyncio.run(main())
except KeyboardInterrupt:
    print('\n\nDemo stopped.')
"
