# Dangee Framework

Dangee framework provides information of elements (function, variable etc.) in android binaries. Users can therefore, use these information to construct the analysis, find potential malicious activites or security vulnerabilities.

## Installation

```bash
pip install -U Dangee
```

## QuickStart

```python
from dangee.core import Dangee

d = Dangee("Roaming_Mantis.dex")
```

### Usage

1. Show all method

```python
d.value
```

2. Show Android native API

```python
d.isNative().value
```

3. Show self-defined method

```python
d.isSelfDefine().value
```
4. Matching method by case-insensitive words

```python
d.isNative().match("package").value
```

Multi-level match

```python
d.isNative().match("package").match("UsageStats").value
```

5. Crossreferences (XREFs)

```python

# XREFs FROM:
m1 = d.isNative().match("usage")
m1.get_xref_from().value

# XREFs TO:
m2 = d.isSelfDefine().match("getTopActivityName$loader_release")
m2.get_xref_to().value
```

6. Data flow check

```python
m1 = d.isNative().match("usage")
m2 = d.isNative().match("package")

m1.dataFlowto(m2)
```
> list[ {tuple(method1, method2) : result_of_data_flow_to_found } ]

