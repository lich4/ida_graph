* [For English](#Introduction)

![](https://raw.githubusercontent.com/lich4/ida_graph/main/screenshots/cfgraph.png)

## 简介

此插件用于绘制函数流程图，辅助分析`OLLVM`。图形渲染基于`mermaid`, 支持平移/缩放。

## 安装及使用

* 用`idapython`对应的`python/pip`安装`Requirements.txt`中的依赖，python版本不低于`3.11`
* 将本项目拷贝到`IDA Pro`的`plugins`目录下
* 启动`IDA Pro`，加载可执行文件并将光标定位到任意函数中，从菜单选择`Edit - CFGraph - Open`，弹出的网页中会显示函数信息及流程图

### 选项说明

Show microcode
* 关闭，绘制节点为基于汇编的基本块
* 开启，绘制节点为基于微代码(类似LLVM IR)的基本块

## 常见问题

### 定位`IDA`所使用的`python`/`pip`

**问题**：我需要给`IDA`安装第三方`python`模块, 如何定位对应的的`python`/`pip`路径？不记得之前`idapyswitch`指定的`python`路径了

**解决**：这是个常见问题, 在`IDA`的`Python`命令行中执行`print(sys.prefix)`，然后得到对应pip路径安装模块
* `Linux/Mac`：例如得到`/usr/local/opt/python@3.12/Frameworks/Python.framework/Versions/3.12`，那么`python`/`pip`可执行文件位于子目录`bin`下
* `Windows`：例如得到`C:\Users\test\AppData\Local\Programs\Python\Python39`，那么`python`/`pip`可执行文件分别位于当前目录和`Scripts`下

### 在`IDA`中使用`venv`环境中的模块

**问题**：我的`python`模块是在`venv`环境下安装的，`IDA`无法`import`该模块怎么办？

**解决**：以下方式只影响`idapython`，不影响其他`python`环境
* 在`IDA`安装目录定位到`init.py`文件，如`python/init.py`/`python/3/init.py`
* 获取`venv`的`site-packages`路径: `import site;print(site.getsitepackages())`
* 在`init.py`文件结尾将`site-packages`路径加入`path`，如添加一行`import sys; sys.path.append("/Users/test/.venv/lib/python3.12/site-packages")`

&nbsp;  
&nbsp;  
&nbsp;  
&nbsp;  
&nbsp;  
&nbsp;  
&nbsp;  
&nbsp;  

## Introduction

This plugin is designed to visualize function control-flow graphs to assist in analyzing `OLLVM`.
Graph rendering is based on `mermaid`, with support for panning and zooming.

## Installation & Usage

* Use the `python/pip` corresponding to `idapython` to install dependencies listed in `Requirements.txt`. The Python version must be `3.11` or higher.
* Copy this project into the plugins directory of your IDA Pro installation.
* Launch IDA Pro, load a binary, and place the cursor inside any function. Then select Edit → CFGraph → Open from the menu. A web page will pop up displaying the function information and its control-flow graph.

### Options

Show microcode
* Off – Nodes represent assembly-level basic blocks.
* On – Nodes represent microcode-level basic blocks (similar to LLVM IR).

## FAQ

### How to locate the python/pip used by IDA

**Question**: I need to install third-party Python modules for `IDA`, but I don’t remember which `python/pip` is using (e.g., after switching with `idapyswitch`).

**Answer**: This is a common issue. In `idapython` console, run `print(sys.prefix)`, Then, use the corresponding pip under that path to install your module.
* For `Linux/Mac`: If the output is `/usr/local/opt/python@3.12/Frameworks/Python.framework/Versions/3.12`,
then `python/pip` are located in the `bin` subdirectory.
* For `Windows`: If the output is `C:\Users\test\AppData\Local\Programs\Python\Python312`, then `python/pip` are in the current directory and the `Scripts` subdirectory, respectively.

### Using modules from a venv inside IDA

**Question**: My Python modules are installed in a virtual environment (venv), and IDA can’t import them. What should I do?
**Answer**: The following change affects only `idapython`, not other python environments.
* Locate the `init.py` file in your IDA installation path, e.g. `python/init.py` or `python/3/init.py`.
* Locate `site-packages` path for `venv`: `import site;print(site.getsitepackages())`
* Append that path to `sys.path` at the end of `init.py`. e.g. `import sys; sys.path.append("/Users/test/.venv/lib/python3.12/site-packages")`

