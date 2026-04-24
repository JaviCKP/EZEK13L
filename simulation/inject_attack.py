from __future__ import annotations

import argparse
import random
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from common import ATTACK_BUILDERS, DEFAULT_SEED, next_capture_name, write_packets

MENU = """\
+==========================================+
|       EZEK13L - ATTACK INJECTOR          |
+==========================================+
|  1) Port Scan (SYN scan)                 |
|  2) DNS Exfiltration                     |
|  3) Brute Force HTTP                     |
|  4) SQL Injection                        |
|  5) Data Exfiltration                    |
|  0) Salir                                |
+==========================================+
"""


def inject(choice: str, outdir: Path, rng: random.Random) -> Path:
    label, builder = ATTACK_BUILDERS[choice]
    packets, _ = builder(time.time(), rng)
    final_path = next_capture_name(outdir, "attack")
    temp_path = final_path.with_suffix(".tmp")
    write_packets(temp_path, packets)
    temp_path.replace(final_path)
    print(f"[OK] {label} -> {final_path.name} ({len(packets)} paquetes)")
    return final_path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--outdir", default="/app/data/live_in")
    parser.add_argument("--choice")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(args.seed)

    if args.choice:
        if args.choice not in ATTACK_BUILDERS:
            raise SystemExit(f"[ERROR] Ataque no valido: {args.choice}")
        inject(args.choice, outdir, rng)
        return

    while True:
        print(MENU)
        choice = input("> ").strip()
        if choice == "0":
            return
        if choice not in ATTACK_BUILDERS:
            print("[ERROR] Opcion no valida")
            continue
        inject(choice, outdir, rng)


if __name__ == "__main__":
    main()
