# RunDll
A spin on microsoft's rundll32.exe

# Usage
1) loader.exe .\mydll.dll
2) loader.exe .\mydll.dll:\<function name> \<optional arg>

# Example
loader.exe .\mydll.dll:myfunc hello   <- loads mydll and calls myfunc with parameter "hello"