# v2ray_to_clash
## 简体中文|English
将v2ray格式的节点配置链接转换为可用的Clash yaml格式。
仅支持在amd64平台上运行。
## 正文
### 命令解释
1. clash，转换类型为`clash yaml`，将v2ray配置链接格式转换为Clash客户端上订阅的配置文件格式，示例：
```
Subc.exe clash xxx.txt to xxx.yaml
```
2. Base64编码，转换类型为`base64`，将v2ray配置链接格式转换为v2ray客户端上订阅的配置文件格式，示例：
```
Subc.exe base64 xxx.txt to xxx.txt
```
3. 源文件（路径），在`Subc.exe 转换类型 源文件 to 结果文件`中，源文件就是储存源数据的地方。
4. 结果文件，结果文件就是储存转换成功后结果的地方。
### 输出解释
绿字如`Success`一律表示成功解析并处理；
黄字如`Waring`表示警告，可能个别节点无法处理;
红字如`Error`表示读取失败、全部处理失败。
### 手动打包
安装依赖
```
pip install pyinstaller pyyaml
```
打包命令，在目录下执行命令
```
pyinstaller --onefile --name=ClashConfigTool --clean --console sc.py
```
## 使用教程
1. 下载好后进入文件所在的目录：
- 用`cmd`覆盖文件管理器上的目录一栏的路径信息后回车进入命令行终端；
- 也可以直接进入终端，然后执行命令`cd 可执行文件路径`手动进入路径。
2. 执行命令：
```
Subc.exe clash xxx.txt to xxx.yaml
```
3. 查看输出文件结果，正常情况下编码正确的话整体内容就符合规范。
