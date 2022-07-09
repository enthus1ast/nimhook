# nimhook
## A small (and quite naive) amd64 api hooking library


### Manual
```nim
import nimhook

var hook: Hook # <- info to disable the hook etc...
var trampFunctionA: pointer # <- a pointer to a stub that calls the original function
type
  FunctionA = proc (aa: bool, ii: int): float {.stdcall.}

proc functionA(aa: bool, ii: int): float {.stdcall.} =
  echo "AAAAAAAAAAAAAAA"
  echo "AAAAAAAAAAAAAAA"
  echo "==============="
  return 80.80

proc functionB(aa: bool, ii: int): float {.stdcall.} =
  echo "BBBBBBBBBBBBBBB"
  echo "BBBBBBBBBBBBBBB"
  echo "==============="
  if not trampFunctionA.isNil:
    echo "was: ", cast[FunctionA](trampFunctionA)(aa, ii) # <- calls the original
  return 13.37

echo "press button for calling hook"
discard readline(stdin)

hook = setHook(functionA, functionB) # <- this detours calls from functionA to functionB
trampFunctionA = createTrampolin(hook) # <- this creates a stub so that you can call the original

while true:
  echo functionA(true, 1234)
  echo hook.testHook() # <- tests if the hook is still in place
  hook.enableHook( not hook.testHook() ) # <- disables and enables the hook temporarily
  discard readline(stdin)

```

### same with `nimhook` macro

```nim
import nimhook

proc functionA(aa: bool, ii: int): float {.stdcall.} =
  echo "AAAAAAAAAAAAAAA"
  echo "AAAAAAAAAAAAAAA"
  echo "==============="
  return 80.80

proc functionB(aa: bool, ii: int): float {.stdcall, nimhook: functionA.} =
  echo "BBBBBBBBBBBBBBB"
  echo "BBBBBBBBBBBBBBB"
  echo "==============="
  echo "was: ", functionA(aa, ii) # if inside the detour, functionA calls the trampoline!
  return 13.37

for _ in 0 ..< 5:
  echo functionA(true, 1234)
  ## CURRENTLY the nimhook macro implicitly
  ## creates variables for the hook and trampoline:
  echo nimhookFunctionA.testHook()
  nimhookFunctionA.enableHook( not nimhookFunctionA.testHook() )
  discard readline(stdin)
nimhookFunctionA.unsetHook()

```



### Dll injection tests using mavinject.exe

```bat
for /F "TOKENS=1,2,*" %a in ('tasklist /NH /FO table /FI "IMAGENAME eq notepad.exe"') do C:\Windows\System32\mavinject.exe %b /INJECTRUNNING  C:\path\to\my\dll.dll
```