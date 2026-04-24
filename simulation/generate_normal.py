from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from common import DEFAULT_SEED, build_normal_traffic, write_packets


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--connections", type=int, default=8000)
    parser.add_argument("--duration-minutes", type=float, default=30.0)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args()

    out_path = Path(args.out)
    rng = random.Random(args.seed)
    packets = build_normal_traffic(
        connections=args.connections,
        duration_seconds=max(args.duration_minutes, 1.0) * 60.0,
        rng=rng,
    )
    write_packets(out_path, packets)

    print(f"[OK] PCAP normal generado en {out_path}")
    print(f"[INFO] conexiones={args.connections}, paquetes={len(packets)}, seed={args.seed}")


if __name__ == "__main__":
    main()
