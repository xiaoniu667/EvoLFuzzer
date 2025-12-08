"""
Entry point for running different seed-generation methods on a chosen dataset.

Usage example:
    python main.py --dataset HumanEval --method evolfuzzer --epochs 3
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional


# Project root directory
ROOT = Path(__file__).resolve().parent

# Supported datasets and their jsonl locations
DATASETS: Dict[str, Path] = {
    "HumanEval": ROOT / "datasets" / "HumanEval.jsonl",
    "CWEval": ROOT / "datasets" / "CWEval.jsonl",
    "MBPP": ROOT / "datasets" / "MBPP.jsonl",
    "LLMSecurity": ROOT / "datasets" / "LLMSecurity.jsonl",
    "SecurityEval": ROOT / "datasets" / "SecurityEval.jsonl",
}

DEFAULT_DATASET = "HumanEval"

# Supported fuzzing / seed generation methods (multi-threaded variants)
METHOD_SCRIPTS: Dict[str, Path] = {
    "evolfuzzer": ROOT / "create_seed_evolfuzzer_mutithread.py",
    "ea": ROOT / "create_seed_ea_mutithread.py",
    "ga": ROOT / "create_seed_ga_mutithread.py",
    "pso": ROOT / "create_seed_pso_mutithread.py",
    "aco": ROOT / "create_seed_aco_mutithread.py",
    "rma": ROOT / "create_seed_rma_mutithread.py",
}

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run seed generation on the selected dataset with a chosen method."
    )
    parser.add_argument(
        "--dataset",
        choices=sorted(DATASETS.keys()),
        default=DEFAULT_DATASET,
        help="Dataset to use (stored under datasets/).",
    )
    parser.add_argument(
        "--method",
        choices=sorted(METHOD_SCRIPTS.keys()),
        default="evolfuzzer",
        help="Seed generation method to run.",
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=5,
        help="Number of times to run the method to generate seeds.",
    )
    parser.add_argument(
        "--pass-through",
        nargs=argparse.REMAINDER,
        help="Optional extra args forwarded to the underlying method script.",
    )
    return parser.parse_args()


def run(
    dataset: str = DEFAULT_DATASET,
    method: str = "evolfuzzer",
    epochs: int = 1,
    pass_through: Optional[Iterable[str]] = None,
) -> int:
    """
    Programmatic entry: run seed generation on the selected dataset with given method.
    epochs controls how many times the method script is executed.
    pass_through can be any iterable of extra CLI args for the method script.
    """
    dataset = dataset.strip()
    method = method.strip()

    if dataset not in DATASETS:
        print(f"[ERROR] Unsupported dataset: {dataset}. Choices: {sorted(DATASETS)}")
        return 1
    if method not in METHOD_SCRIPTS:
        print(f"[ERROR] Unsupported method: {method}. Choices: {sorted(METHOD_SCRIPTS)}")
        return 1
    if epochs < 1:
        print("[ERROR] epochs must be >= 1")
        return 1

    dataset_path = DATASETS[dataset]
    script_path = METHOD_SCRIPTS[method]

    if not dataset_path.exists():
        print(f"[ERROR] Dataset file not found: {dataset_path}")
        return 1
    if not script_path.exists():
        print(f"[ERROR] Method script not found: {script_path}")
        return 1

    print(f"[INFO] Using dataset : {dataset_path}")
    print(f"[INFO] Using method  : {script_path.name}")
    if epochs > 1:
        print(f"[INFO] Epochs       : {epochs}")

    command: List[str] = [sys.executable, str(script_path)]
    if pass_through:
        command.extend(list(pass_through))

    try:
        env = os.environ.copy()
        env["VULNERABILITY_DATA_FILE"] = str(dataset_path)
        return_code = 0
        for idx in range(1, epochs + 1):
            if epochs > 1:
                print(f"[INFO] Starting epoch {idx}/{epochs}")
            completed = subprocess.run(command, cwd=ROOT, check=True, env=env)
            return_code = completed.returncode
        return return_code
    except subprocess.CalledProcessError as exc:
        print(f"[ERROR] Method script failed with code {exc.returncode}")
        return exc.returncode


def main() -> int:
    args = parse_args()
    return run(
        dataset=args.dataset,
        method=args.method,
        epochs=args.epochs,
        pass_through=args.pass_through,
    )


if __name__ == "__main__":
    sys.exit(main())

