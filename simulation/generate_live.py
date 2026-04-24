from __future__ import annotations

import argparse
import random
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from common import ATTACK_BUILDERS, DEFAULT_SEED, build_normal_traffic, next_capture_name, write_packets


def parse_attack_sequence(raw: str) -> list[str]:
    choices = [item.strip() for item in raw.split(",") if item.strip()]
    invalid = [choice for choice in choices if choice not in ATTACK_BUILDERS]
    if invalid:
        valid = ", ".join(sorted(ATTACK_BUILDERS))
        raise SystemExit(f"[ERROR] attack-sequence invalida: {invalid}. Valores validos: {valid}")
    return choices


def write_capture(outdir: Path, prefix: str, packets: list) -> Path:
    final_path = next_capture_name(outdir, prefix)
    temp_path = final_path.with_suffix(".tmp")
    write_packets(temp_path, packets)
    temp_path.replace(final_path)
    return final_path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--outdir", required=True)
    parser.add_argument("--interval", type=float, default=3.0)
    parser.add_argument("--min-connections", type=int, default=5)
    parser.add_argument("--max-connections", type=int, default=15)
    parser.add_argument("--attack-every", type=int, default=0)
    parser.add_argument("--attack-sequence", default="1,2,3,4,5")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(args.seed)
    attack_sequence = parse_attack_sequence(args.attack_sequence) if args.attack_every > 0 else []
    attack_index = 0
    capture_index = 0

    while True:
        connections = rng.randint(args.min_connections, args.max_connections)
        packets = build_normal_traffic(
            connections=connections,
            duration_seconds=max(args.interval - 0.4, 0.8),
            rng=rng,
            start_ts=time.time(),
        )
        final_path = write_capture(outdir, "normal", packets)
        capture_index += 1
        print(f"[LIVE] {final_path.name}: conexiones={connections}, paquetes={len(packets)}", flush=True)

        if attack_sequence and capture_index % args.attack_every == 0:
            choice = attack_sequence[attack_index % len(attack_sequence)]
            label, builder = ATTACK_BUILDERS[choice]
            attack_packets, _ = builder(time.time(), rng)
            attack_path = write_capture(outdir, "attack", attack_packets)
            attack_index += 1
            print(
                f"[LIVE][ATTACK] {attack_path.name}: {label}, paquetes={len(attack_packets)}",
                flush=True,
            )

        time.sleep(args.interval)


if __name__ == "__main__":
    main()
