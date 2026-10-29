"""Check a scan against what actually happened when the project ran.

The oracle is an observation file from `eval/dynamic/observe.py`: the modules loaded and the
functions executed while a workload drove the real project. A clear is falsified if its module
loaded; a call path is confirmed if its vulnerable function executed. The scan itself never
runs target code; only this optional evaluation does, in a throwaway environment.
"""
