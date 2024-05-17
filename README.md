# APC-PE-Injector
APC Injection is a code injecting technique which bypasses TLS callback protections (Windows OS). This works by the OS telling a thread to execute a memory location at its next convenient time, and requires at least one thread in the target process to enter an alertable state.

## How it works:
1. The current PE Image bytes are copied to into memory of a target process using `VirtualAllocEx` and `WriteProcessMemory`
2. The offset to our payload function from the start of the image is calculated
3. `QueueUserAPC` is called on each thread of the target process with the thread task starting at the memory address we allocated (from VirtualAllocEx) + the offset to our payload function. This acts as a relocation to our payload function.
4. The target process then executes our thread task the next time the thread enters an alertable state, and our payload function is executed. Because we copied our entire PE image to the target, we now have our full process injected into the target.

## Benefits:
TLS callbacks are bypassed using this method, allowing us to inject code regardless of whether or not the target processes is rejecting threads via TLS Callbacks. This means that we can now gain a foothold into a target process where traditional DLL/PE injection would fail (as they rely on CreateRemoteThread for payload execution).

## How to use:
`./APCInjector.exe targetprocess.exe` - By default the payload function `APCFunction` is executed, and you can change this in the source code if needed. Ensure that you're building in x64 when using this example.

![Example](https://github.com/AlSch092/APC-PE-Injector/assets/94417808/9bc1d6dc-5a79-4a81-83e8-52f429852209)
