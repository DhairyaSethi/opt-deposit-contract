### Benchmark
```bash
✗ forge test --gas-report
```

| Function Name                         | min             | avg  | median | max  | # calls |
|---------------------------------------|-----------------|------|--------|------|---------|
| zerosFromPointer                      | 534             | 534  | 534    | 534  | 32      |
| zerosFromPointerWithoutTheExtraStop   | 507             | 647  | 507    | 5007 | 32      |
| zerosFromStorage                      | 2478            | 2478 | 2478   | 2478 | 32      |
| zerosFromSwitch                       | 328             | 684  | 684    | 1041 | 32      |
