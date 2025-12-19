# MIESC v4.1 Scalability Benchmark Report

**Date:** 2025-12-09 09:11
**Platform:** Darwin 24.6.0

## Results Summary

| Benchmark | Contracts | Time (s) | Throughput | Memory (MB) | Workers |
|-----------|-----------|----------|------------|-------------|----------|
| sequential_small | 20 | 12.2 | 98.4/min | 2.7 | 1 |
| parallel_2 | 20 | 6.1 | 198.1/min | 4.5 | 2 |
| parallel_4 | 20 | 3.5 | 346.5/min | 4.2 | 4 |

## Key Findings

- **Parallel Speedup:** 3.53x with 4 workers
- **Peak Throughput:** 346.5 contracts/minute
- **Memory Efficiency:** Peak 4.5 MB
