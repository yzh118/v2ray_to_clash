# V2Ray to Clash  
## [简体中文](https://github.com/yzh118/v2ray_to_clash)|English  
Convert v2ray format node configuration links into usable Clash yaml format.  
Only supports running on amd64 platforms.  

## Main Content  
### Command Explanation  
1. `clash`: The conversion type is `clash yaml`, which converts the v2ray configuration link format into the configuration file format for subscriptions on the Clash client. Example:  
```
Subc.exe clash xxx.txt to xxx.yaml  
```  
2. `Base64 encoding`: The conversion type is `base64`, which converts the v2ray configuration link format into the configuration file format for subscriptions on the v2ray client. Example:  
```
Subc.exe base64 xxx.txt to xxx.txt  
```  
3. **Source file (path)**: In `Subc.exe conversion type source file to result file`, the source file is where the original data is stored.  
4. **Result file**: The result file is where the successfully converted results are stored.  

### Output Explanation  
- Green text like `Success` always indicates successful parsing and processing.  
- Yellow text like `Warning` indicates a warning, meaning some nodes may not be processed.  
- Red text like `Error` indicates a read failure or complete processing failure.  

### Manual Packaging  
Install dependencies:  
```
pip install pyinstaller pyyaml  
```  
Packaging command (execute in the directory):  
```
pyinstaller --onefile --name=ClashConfigTool --clean --console sc.py  
```  

## Usage Tutorial  
1. After downloading, navigate to the directory where the file is located:  
   - Use `cmd` to overwrite the path in the file manager's address bar and press Enter to enter the command-line terminal.  
   - Alternatively, directly open the terminal and execute the command `cd executable file path` to manually navigate to the path.  
2. Execute the command:  
```
Subc.exe clash xxx.txt to xxx.yaml  
```  
3. Check the output file results. If the encoding is correct, the overall content should comply with the specifications.
