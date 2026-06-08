# Windows 10 Enterprise legacy baseline

The original `CIS LEVEL 1.bat` and `password policy.inf` remain at the repository root for historical reference. New work should use the data-driven PowerShell framework in `benchmarks/windows/common/` and copy only authorized Windows 10 controls into this folder if Windows 10 support is still required.

Windows 10 Enterprise is retained as a legacy target because the latest Windows desktop benchmark tracked in `benchmarks/manifest.json` is Windows 11 Enterprise.
