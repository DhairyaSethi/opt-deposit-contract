### Benchmark

```bash
✗ forge test --gas-report
```

| Function Name                       | min  | avg  | median | max  | # calls |
| ----------------------------------- | ---- | ---- | ------ | ---- | ------- |
| zerosFromPointerWithoutTheExtraStop | 507  | 647  | 507    | 5007 | 32      |
| zerosFromPointer                    | 534  | 534  | 534    | 534  | 32      |
| zerosFromStorage                    | 2478 | 2478 | 2478   | 2478 | 32      |
| zerosFromSwitch                     | 328  | 684  | 684    | 1041 | 32      |

pointer deployment - https://sepolia.etherscan.io/address/0x00000018a9d0361af14f887eb5515c2800e0d9f6
