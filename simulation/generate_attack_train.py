from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from common import (
    ATTACK_BUILDERS,
    BASE_TS,
    DEFAULT_SEED,
    generate_bruteforce_http,
    generate_data_exfil,
    generate_dns_exfil,
    generate_port_scan,
    generate_sql_injection,
    write_packets,
)


def build_variant(choice: str, ts: float, rng: random.Random) -> tuple[list, float]:
    if choice == "1":
        return generate_port_scan(ts, rng, ports=rng.randint(28, 80))
    if choice == "2":
        return generate_dns_exfil(ts, rng, queries=rng.randint(14, 36))
    if choice == "3":
        return generate_bruteforce_http(ts, rng, attempts=rng.randint(18, 55))
    if choice == "4":
        return generate_sql_injection(ts, rng, attempts=rng.randint(4, 14))
    if choice == "5":
        return generate_data_exfil(ts, rng, body_size=rng.randint(650_000, 3_000_000))
    _, builder = ATTACK_BUILDERS[choice]
    return builder(ts, rng)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--choice", required=True, choices=sorted(ATTACK_BUILDERS))
    parser.add_argument("--repeats", type=int, default=12)
    parser.add_argument("--spacing-seconds", type=float, default=20.0)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args()

    label, _ = ATTACK_BUILDERS[args.choice]
    rng = random.Random(args.seed)
    packets = []
    repeats = max(args.repeats, 1)

    for index in range(repeats):
        ts = BASE_TS + index * max(args.spacing_seconds, 1.0)
        built, _ = build_variant(args.choice, ts, rng)
        packets.extend(built)

    write_packets(Path(args.out), sorted(packets, key=lambda pkt: float(getattr(pkt, "time", 0.0))))
    print(f"[OK] PCAP entrenamiento ataque generado: {label} repeats={repeats} packets={len(packets)} -> {args.out}")


if __name__ == "__main__":
    main()
