## A small (and quite naive) amd64 api hooking library

## Wording:
##  orginalFunc := The function to hook
##  detourFunc := Our function, that replaces `orginalFunc`
##  trampoline := To call the original function from the detourFunc (or anywhere), also a far jump helper.
##  farJumpHelper := asm code, that is placed nearby the originalFunc in memory, to reach the detourFunc

## TODO
# [ ] Take care of RIP code etc
#   [ ] Use capstone?
# [ ] Cleanup !!!
# [x] Do nice macros?

import winim, strformat, strutils, macros


template getOffset(aa, bb: untyped): int =
  cast[int](bb) - cast[int](aa)

template windbg(body: untyped) =
  when not defined release:
    echo body
    OutputDebugString(body)

proc `&`[I, J: static int; Type](a: array[I, Type], b: array[J, Type]): array[I + J, Type] =
  ## concatenate for arrays
  var c = 0
  for i in a:
    result[c] = i
    inc c
  for i in b:
    result[c] = i
    inc c

proc `&`[A; B: int|int32|uint|uint32|uint64|pointer](aa: A, bb: B): auto =
  aa & cast[array[sizeof(B), byte]](bb)

proc `+`(pp: pointer, ii: uint32): pointer =
  cast[pointer](cast[uint32](pp) + ii)

proc dumpMem(pp: pointer, size: int) =
  let oa = cast[ptr UncheckedArray[byte]](pp)
  for idx in 0..size - 1:
    let address = cast[int](pp) + idx
    echo fmt"0x{address.toHex().align(sizeof(pointer))} -> {oa[idx].toHex()} {oa[idx]}"

type
  JmpArr = array[5, byte] ## Array large enough to hold a `jmp` + 32bit offset
  FarJmpArr = array[13, byte] ## Array large enough to hold a encoded far jump
  Hook* = object
    orginalFunc*: pointer ## pointer to the original function
    orgData*: JmpArr ## the original data contained at the 5 byte
    farJumpHelper*: pointer ## pointer to the far jump helper, that later jumps to the
    farJumpHelperSize*: uint64 ## how much memory we actually have allocated for the FJH
    hookData*: JmpArr ## the bytes we have written at the start of the proc

proc `$`(hook: Hook): string =
  result.add "orginalFunc: \n" & cast[int](hook.orginalFunc).toHex() & "\n"
  result.add "orgData: " & (repr hook.orgData) & "\n"
  result.add "farJumpHelper: \n" & cast[int](hook.farJumpHelper).toHex() & "\n"
  result.add "hookData: " & (repr hook.hookData) & "\n"

template withWriteableMem(pfunc: pointer, size: int, body: untyped) =
  var oldProtect: DWORD
  VirtualProtect(
    pfunc,
    size.SIZE_T,
    PAGE_EXECUTE_READWRITE,
    addr oldProtect
  )
  body
  VirtualProtect(
    pfunc,
    size.SIZE_T,
    oldProtect,
    addr oldProtect
  )
  FlushInstructionCache(GetCurrentProcess(), pfunc, size)

proc unsetHook*(hook: Hook) =
  ## Destroys the hook and all its artifacts.
  withWriteableMem(hook.orginalFunc, sizeof(JmpArr)):
    windbg "Restore original"
    copyMem(hook.orginalFunc, unsafeAddr hook.orgData, sizeof(hook.orgData))
  if not hook.farJumpHelper.isNil:
    windbg "Dealloc farJumpHelper"
    VirtualFree(hook.farJumpHelper, hook.farJumpHelperSize.SIZE_T, MEM_RELEASE)


proc allocatePageNearAddress(targetAddr: pointer): tuple[p: pointer, size: uint64] =
  ## http://kylehalladay.com/blog/2020/11/13/Hooking-By-Example.html
  windbg("allocatePageNearAddress starts")
  var sysInfo: SYSTEM_INFO

  windbg("GetSystemInfo starts")
  GetSystemInfo(addr(sysInfo))
  var PAGE_SIZE: uint64 = sysInfo.dwPageSize.uint64
  var startAddr: uint64 = (cast[uint64](targetAddr) and not (PAGE_SIZE - 1))
  ## round down to nearest page boundary
  var minAddr: uint64 = min(startAddr - 0x7FFFFF00,
                          cast[uint64](sysInfo.lpMinimumApplicationAddress))
  var maxAddr: uint64 = max(startAddr + 0x7FFFFF00,
                          cast[uint64](sysInfo.lpMaximumApplicationAddress))
  var startPage: uint64 = (startAddr - (startAddr mod PAGE_SIZE))
  var pageOffset: uint64 = 1
  while true:
    var byteOffset: uint64 = pageOffset * PAGE_SIZE
    var highAddr: uint64 = startPage + byteOffset
    var lowAddr: uint64 = if (startPage > byteOffset): startPage - byteOffset else: 0
    var needsExit: bool = highAddr > maxAddr and lowAddr < minAddr
    if highAddr < maxAddr:
      var outAddr: pointer = VirtualAlloc(cast[LPVOID](highAddr), PAGE_SIZE.SIZE_T,
                                      MEM_COMMIT or MEM_RESERVE,
                                      PAGE_EXECUTE_READWRITE)
      if outAddr != nil:
        return (outAddr, PAGE_SIZE)

    if lowAddr > minAddr:
      var outAddr: pointer = VirtualAlloc(cast[LPVOID](lowAddr), PAGE_SIZE.SIZE_T,
                                      MEM_COMMIT or MEM_RESERVE,
                                      PAGE_EXECUTE_READWRITE)
      if outAddr != nil:
        return (outAddr, PAGE_SIZE)

    inc(pageOffset)
    if needsExit:
      break
  return (cast[pointer](0), 0.uint64)


proc setHook*(orginalFunc, detourFunc: pointer): Hook =
  ## sets a hook; any calls to `originalFunc` is detoured to the `detourFunc`.
  ##
  ##
  ## .. code-block:: nim
  ##
  ##  var hook: Hook
  ##  var trampFunctionA: pointer
  ##  type
  ##    FunctionA = proc (aa: bool, ii: int): float {.stdcall.}
  ##
  ##  proc functionA(aa: bool, ii: int): float {.stdcall.} =
  ##    echo "AAAAAAAAAAAAAAA"
  ##    echo "==============="
  ##    return 80.80
  ##
  ##  proc functionB(aa: bool, ii: int): float {.stdcall.} =
  ##    echo "BBBBBBBBBBBBBBB"
  ##    echo "==============="
  ##    if not trampFunctionA.isNil:
  ##      echo "was: ", cast[FunctionA](trampFunctionA)(aa, ii)
  ##    return 13.37
  ##
  ##  hook = setHook(functionA, functionB)
  ##  trampFunctionA = createTrampolin(hook)
  ##
  ##  while true:
  ##    echo functionA(true, 1234)
  ##    echo hook.testHook()
  ##    hook.enableHook( not hook.testHook() )
  ##    discard readline(stdin)
  withWriteableMem(orginalFunc, sizeof(JmpArr)):
    ## Instead of jumping directly to the detourFunc, we jump to the farJumpHelper
    ## which in turn will do a far jump to the detourFunc
    result = Hook()
    result.orginalFunc = orginalFunc
    (result.farJumpHelper, result.farJumpHelperSize) = allocatePageNearAddress(orginalFunc) # TODO we only need a far jump helper when the offset is larger than near jump
    if result.farJumpHelper.isNil:
      windbg("farJumpHelper is nil")
      return
    windbg("got farJumpHelper helper" & $(repr result.farJumpHelper) )
    # var offsetOriginalFuncToFarJumpHelper: uint32 = getOffset(orginalFunc, farJumpHelper) - sizeof(JmpArr).uint32
    var offsetOriginalFuncToFarJumpHelper: int32 = getOffset(orginalFunc, result.farJumpHelper).int32 - sizeof(JmpArr).int32
    windbg("offsetOriginalFuncToFarJumpHelper:" & $offsetOriginalFuncToFarJumpHelper)
    result.hookData = [0xE9.byte] & offsetOriginalFuncToFarJumpHelper
    # print jmpInstruction
    var trampolineData: FarJmpArr = [0x49.byte, 0xBA] & detourFunc & [0x41.byte, 0xff, 0xe2]
    copyMem(result.farJumpHelper, unsafeAddr trampolineData, sizeof(trampolineData)) # install trampoline
    # echo "farJumpHelper: ", cast[int](farJumpHelper).toHex()

    copyMem(addr result.orgData, orginalFunc, sizeof(result.hookData)) # save for later
    copyMem(orginalFunc, addr result.hookData, sizeof(result.hookData)) # install the hook

proc testHook*(hook: Hook): bool =
  ## tests if the hook is still in place
  ## returns `true` if it is `false` otherwise
  cast[ptr JmpArr](hook.orginalFunc)[] == hook.hookData

proc enableHook*(hook: Hook, enable = true) =
  ## if enable is `true`:
  ##  (re)enables a hook, also repairs the detour of the org function
  ## if enable is `false`:
  ##  disables the hook, by restoring the original data on the org function
  ##  for cleaning up all hooking artifacts use `unsetHook`
  ##
  ## Note: when a hook is created through `setHook`, the hook is enabled already.
  if enable:
    if testHook(hook): return # hook is still good
    withWriteableMem(hook.orginalFunc, sizeOf(hook.orgData)):
      copyMem(hook.orginalFunc, unsafeAddr hook.hookData, sizeOf(hook.hookData))
  else:
    if not testHook(hook): return # hool ist already disabled
    withWriteableMem(hook.orginalFunc, sizeOf(hook.orgData)):
      copyMem(hook.orginalFunc, unsafeAddr hook.orgData, sizeOf(hook.orgData))

proc createTrampolin*(hook: Hook): pointer =
  ## creates a "trampoline" that calls the original function code
  ## This executes the original function bytes, then jumps to the hooked function
  ## but after the the jmpInstruction (+5)
  ## Use this to call the original function from inside a hook.
  const size = sizeOf(hook.orgData) + sizeof(FarJmpArr)
  result = alloc(size)
  var oldProtect: DWORD
  VirtualProtect(
    result,
    size,
    PAGE_EXECUTE_READWRITE,
    addr oldProtect
  )
  copyMem(result, unsafeAddr hook.orgData, sizeof(hook.orgData)) # backup org data
  var trampolineData: FarJmpArr = [0x49.byte, 0xBA] & hook.orginalFunc + sizeof(hook.orgData).uint32 & [0x41.byte, 0xff, 0xe2]
  var data = hook.orgData & trampolineData
  copyMem(result, unsafeAddr data, sizeof(data)) # move trampoline
  return result

macro nimhook(funcToHook, body: untyped): untyped =
  let newFuncName = body[0]
  let procty = newTree(nnkProcTy, body.params, body.pragma)
  var nbody = body
  let hookName = newIdentNode("nimhook" & $funcToHook)
  let trampolineName = newIdentNode("nimhookTrampoline" & $funcToHook)
  nbody[6].insert 0, quote do:
    let `funcToHook` = cast[`procty`](`trampolineName`)
  # echo repr nbody
  result = newStmtList()
  result.add quote do:
    var `hookName`: Hook
  result.add quote do:
    var `trampolineName`: `procty` #pointer
  result.add body
  result.add quote do:
    `hookName` = setHook(`funcToHook`,`newFuncName`)
  result.add quote do:
    `trampolineName` = cast[`procty`](createTrampolin(`hookName`))
  echo repr result

when false:
  import print
  var hook: Hook
  var trampFunctionA: pointer
  type
    FunctionA = proc (aa: bool, ii: int): float {.stdcall.}

  proc functionA(aa: bool, ii: int): float {.stdcall.} =
    echo "AAAAAAAAAAAAAAA"
    echo "AAAAAAAAAAAAAAA"
    echo "AAAAAAAAAAAAAAA"
    echo "AAAAAAAAAAAAAAA"
    echo "AAAAAAAAAAAAAAA"
    echo "==============="
    return 80.80

  proc functionB(aa: bool, ii: int): float {.stdcall.} =
    echo "BBBBBBBBBBBBBBB"
    echo "BBBBBBBBBBBBBBB"
    echo "BBBBBBBBBBBBBBB"
    echo "BBBBBBBBBBBBBBB"
    echo "BBBBBBBBBBBBBBB"
    echo "==============="
    if not trampFunctionA.isNil:
      echo "was: ", cast[FunctionA](trampFunctionA)(aa, ii)
    return 13.37


  template info(aa, bb: untyped) =
    print cast[int](aa).toHex()
    print cast[int](bb).toHex()
    print getOffset(aa, bb)


  info(functionA, functionB)

  echo functionA(true, 1234)
  echo functionB(true, 1234)
  echo "->"

  # hook = setHook(functionA, functionB)
  # dumpMem(functionA, 5)
  echo "press button for calling hook"
  discard readline(stdin)
  hook = setHook(functionA, functionB)
  trampFunctionA = createTrampolin(hook)

  while true:
    echo functionA(true, 1234)
    print hook.testHook()
    hook.enableHook( not hook.testHook() )
    discard readline(stdin)

when false:
  import print

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
    ## CURRENTLY the nimhook macro implicitly creates variables for the hook and trampoline:
    print nimhookFunctionA.testHook()
    nimhookFunctionA.enableHook( not nimhookFunctionA.testHook() )
    discard readline(stdin)
  nimhookFunctionA.unsetHook()


when false:
  import os
  type
    Sleep = proc(ms:int) {.nimcall.}
  proc mySleep(ms: int) =
    echo "WOULD SLEEP"

  var hookInfo = setHook(sleep, mySleep)

  sleep(1000)

  var tramp = cast[Sleep](hookInfo.createTrampolin())
  echo "tramp: ", cast[int](tramp).toHex()
  echo "org: ", cast[int](hookInfo.orginalFunc).toHex()
  var nearOrg = allocatePageNearAddress(hookInfo.orginalFunc)
  echo "near org:", cast[int](nearOrg).toHex()

  echo "calling trampoline"
  discard readline(stdin)
  tramp(1000)

  echo "done"


when false:
  ## injected into cstub
  type
    Foo = proc(aa: int, ii: int): float {.stdcall.}
  import print

  var hookInfo: Hook
  var trampFoo: pointer

  proc myFoo(aa: int, ii: int): float {.stdcall.} =
    print "MYFOO: ", aa, ii
    echo "now org func:"
    if not trampFoo.isNil:
      echo cast[Foo](trampFoo)(aa * 2, ii * 2)
    echo "########################"
    return 66.66

  var pcfoo = cast[pointer](0x0000000000401550) # cstub foo function
  hookInfo = setHook(pcfoo, myFoo)
  trampFoo = createTrampolin(hookInfo)
  echo "hook set"

when false:
  import winim, strformat
  # destroy task manager
  OutputDebugString("starting!!")

  # Disable killing of any process
  # proc NtOpenProcess(processHandle: PHANDLE; accessMask: AccessMask;
  #     objectAttributes: POBJECT_ATTRIBUTES;
  #     clientId: PCLIENT_ID): NTSTATUS {.stdcall, dynlib: "ntdll.dll",
  #     importc: "NtOpenProcess".}
  # proc HookedNtOpenProcess(processHandle: PHANDLE; accessMask: AccessMask;
  #     objectAttributes: POBJECT_ATTRIBUTES;
  #     clientId: PCLIENT_ID): NTSTATUS {.stdcall.} =
  #   return STATUS_ACCESS_DENIED
  # var hookInfoNtOpenProcess = setHook(NtOpenProcess, HookedNtOpenProcess)
  # assert hookInfoNtOpenProcess.testHook()
  # unsetHook(hookInfoNtOpenProcess)
  # assert false == hookInfoNtOpenProcess.testHook()

  # OutputDebugString("NtOpenProcess: 0x" & cast[uint](NtOpenProcess).toHex())

  var nimhookTrampolineNtQuerySystemInformation: proc (
    SystemInformationClass: SYSTEM_INFORMATION_CLASS; SystemInformation: PVOID;
    SystemInformationLength: ULONG; ReturnLength: PULONG): NTSTATUS {.stdcall.}

  proc HookedNtQuerySystemInformation(SystemInformationClass: SYSTEM_INFORMATION_CLASS;
                                SystemInformation: PVOID;
                                SystemInformationLength: ULONG;
                                ReturnLength: PULONG): NTSTATUS {.stdcall.} =
    return STATUS_ACCESS_DENIED # disables eg taskmanager completely, but crashes taskmgr -.- (was also crashing with minhook, find out why)
    # OutputDebugString(fmt"NtQuerySystemInformation call: {SystemInformationClass} {cast[uint](SystemInformation).toHex()} {SystemInformationLength} {ReturnLength[]}")
    # return nimhookTrampolineNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength)
    # return

  OutputDebugString("NtQuerySystemInformation: 0x" & cast[uint](NtQuerySystemInformation).toHex())
  # var hookInfoNtQuerySystemInformation = setHook(NtQuerySystemInformation, HookedNtQuerySystemInformation)
  var nimhookNtQuerySystemInformation = setHook(NtQuerySystemInformation,
    HookedNtQuerySystemInformation)
  OutputDebugString($nimhookNtQuerySystemInformation)
  nimhookTrampolineNtQuerySystemInformation = cast[proc (
      SystemInformationClass: SYSTEM_INFORMATION_CLASS; SystemInformation: PVOID;
      SystemInformationLength: ULONG; ReturnLength: PULONG): NTSTATUS {.stdcall.}](createTrampolin(
      nimhookNtQuerySystemInformation))
  echo $nimhookNtQuerySystemInformation

when false:
  # LoadLibrary()
  # proc MyLoadLibrary1(lpLibFileName: LPCWSTR): HMODULE {.stdcall.} =
  #   OutputDebugString("Process wants to load: " & $lpLibFileName)
  #   return 0.HMODULE

  # setHook(LoadLibrary)
  import strutils

  proc MyLoadLibraryA(lpLibFileName: LPCSTR): HMODULE {.stdcall, nimhook: LoadLibraryA.} =
    OutputDebugString("LoadLibraryA " & $lpLibFileName)
    # return 0.HMODULE
    if ($lpLibFileName).contains("stub"):
      return 0.HMODULE
    else:
      return LoadLibraryA(lpLibFileName)
  # discard setHook(LoadLibraryA, MyLoadLibraryA)


  proc MyLoadLibraryW(lpLibFileName: LPCWSTR): HMODULE {.stdcall, nimhook: LoadLibraryW.} =
    OutputDebugString("LoadLibraryW " & $lpLibFileName)
    if ($lpLibFileName).contains("stub"):
      return 0.HMODULE
    else:
      return LoadLibraryW(lpLibFileName)
  # discard setHook(LoadLibraryW, MyLoadLibraryW)

  OutputDebugString("loaded")

