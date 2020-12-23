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

5. Mutual parent function check

```python
m1 = d.isNative().match("usage")
m2 = d.isNative().match("package")

m1.hasMutualParentFunctionWith(m2)
```
> [{(<analysis.MethodAnalysis Landroid/app/usage/UsageStats;->getPackageName()Ljava/lang/String;>, <analysis.MethodAnalysis Landroid/app/usage/UsageStats;->getPackageName()Ljava/lang/String;>): {<analysis.MethodAnalysis Lcom/Loader;->getTopActivityName$loader_release(Landroid/content/Context;)Ljava/lang/String; [access_flags=public final] @ 0x30ec4>}}...


6. Data flow check

```python
m1 = d.isNative().match("usage")
m2 = d.isNative().match("package")

m1.dataFlowto(m2)
```
> [{(<analysis.MethodAnalysis Landroid/app/usage/UsageStatsManager;->queryUsageStats(I J J)Ljava/util/List;>, <analysis.MethodAnalysis Landroid/app/usage/UsageStats;->getPackageName()Ljava/lang/String;>): {<analysis.MethodAnalysis Lcom/Loader;->getTopActivityName$loader_release(Landroid/content/Context;)Ljava/lang/String; [access_flags=public final] @ 0x30ec4>}}]

