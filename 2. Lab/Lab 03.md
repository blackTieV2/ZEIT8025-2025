### **Lab 3 - Crackme1 Summary**

#### **Objective**  
We need to **perform static analysis** on `crackme1.exe` to determine how to run it successfully from the command line.  

---

### **Step 1: Locate `main()` in the Binary**  
From `crackme1-symbols.txt`:
- `main()` is at **`0x401260`**.  

Checking `crackme1.c` (provided source code):  
```c
int main(int argc, char *argv[]) {
    if (argc != 2)
        exit(1);
    if (strcmp(argv[1], "open_sesame") == 0) {
        printf("You won!\n");
        exit(0);
    } else {
        printf("You lost.\nTry again.\n");
        exit(2);
    }
}
```
---

### **Step 2: Reverse Engineering the Execution Flow**  
#### **Condition 1: Check Command-Line Argument Count**  
From `crackme1-asm.txt`:  
```
401263: 83 7d 08 02   ; cmp [ebp+0x8], 2  (argc == 2?)
401267: 74 0a         ; je 0x401273 (If argc == 2, continue)
```
If there are **not exactly 2 arguments**, the program exits.

✅ **Solution:** We must provide exactly **1 argument** (since `argv[0]` is the program name).

---

#### **Condition 2: Checking the Input String**  
From `crackme1-solution.txt`:
```
401287: e8 44 2f 00 00   ; Call strcmp(argv[1], "open_sesame")
40128F: 85 c0            ; test eax, eax
401291: 75 19            ; jne 0x4012ac  (If not equal, jump to "You lost.")
```
- The argument must match `"open_sesame"`.  
- If the comparison fails, the program prints `"You lost.\nTry again."` and exits.

✅ **Solution:** Run the program as:  
```bash
crackme1.exe open_sesame
```
---

### **Step 3: Validation**
If `"open_sesame"` is entered as an argument:
```
401293: 68 0c 80 41 00   ; Push "You won!"
401298: e8 73 00 00 00   ; Call printf()
```
Output will be:
```
You won!
```

---

### **Final Summary**
✅ **Static Analysis Findings**:
- The binary checks for **exactly 1 argument**.
- The argument must be `"open_sesame"` to win.

✅ **Execution Command:**
```bash
crackme1.exe open_sesame
```
🚀 **We bypassed the check using static analysis without executing the binary!** 🎯

---

### **Crackme2 - Static Analysis Solution**  

Yes! Your assumption is correct. Running:  
```bash
crackme2.exe 42
```
should print `"You won!"`. ✅  

---

### **Breakdown of the Code Execution**  
#### **Step 1: Understanding `main()`**  
From `crackme2.c`:  
```c
int main(int argc, char *argv[]) {
    if (argc == 2)   // Ensure a single argument is passed
        exit(f(atoi(argv[1])));  // Convert argument to integer and pass to f()
    exit(2);  // Exit if no argument is given
}
```
- The program requires **one command-line argument**.  
- This argument is converted into an **integer** using `atoi()`.  
- The integer is passed to function `f()`.  

---

#### **Step 2: Function `f(int key)`**
```c
int f(int key) {
    if (key == 42) {
        printf("You won!\n");
        return 0;
    } else {
        printf("You lost.\nTry again.\n");
        return 1;
    }   
}
```
- If `key == 42`, the program prints `"You won!"` and exits successfully (`return 0`).  
- Otherwise, it prints `"You lost."` and exits with error code `1`.  

---

### **Step 3: Reverse Engineering from Assembly**  
Looking at `crackme2-asm.txt`, we find:  
```
401263:  cmp eax, 0x2a     ; Compare EAX with 42 (0x2A in hex)
401267:  jne 0x40127C      ; Jump to "You lost." if not equal
401269:  push 0x418000     ; Address of "You won!"
40126E:  call 0x401310     ; Call printf()
```
This confirms that **EAX must be 42 to win**.

---

### **Final Execution Command**
✅ **To win, run:**  
```bash
crackme2.exe 42
```
This ensures `EAX == 42`, passing the check and printing `"You won!"`. 🎯🚀

---

Here’s your **transcribed assembly** with **detailed comments** explaining each instruction:  

```assembly
401260:  55                      push   %ebp             ; Save old base pointer
401261:  8b ec                   mov    %esp,%ebp        ; Set up new stack frame
401263:  83 ec 0c                sub    $0xc,%esp        ; Allocate 12 bytes on stack

; Call IsDebuggerPresent()
401266:  ff 15 0c 11 41 00       call   *0x41110c        ; Call IsDebuggerPresent
40126c:  85 c0                   test   %eax,%eax        ; Check if return value is 0
40126e:  74 14                   je     0x401284         ; Jump if no debugger detected

; Print "Debugger detected!" and exit if a debugger is present
401270:  68 00 80 41 00          push   $0x418000        ; Push "Debugger detected!"
401275:  e8 d6 00 00 00          call   0x401350         ; Call printf()
40127a:  83 c4 04                add    $0x4,%esp        ; Adjust stack
40127d:  6a 42                   push   $0x42            ; Push exit code 42
40127f:  e8 54 2f 00 00          call   0x4041d8         ; Call exit(42)

; Ensure correct number of arguments (argc == 3)
401284:  83 7d 08 03             cmpl   $0x3,0x8(%ebp)   ; Compare argc with 3
401288:  75 6c                   jne    0x4012f6         ; If argc != 3, exit

; Load first argument
40128a:  b8 04 00 00 00          mov    $0x4,%eax        ; Set EAX = 4 (offset)
40128f:  c1 e0 00                shl    $0x0,%eax        ; Shift left (no effect)
401292:  8b 4d 0c                mov    0xc(%ebp),%ecx   ; Load pointer to argv[]
401295:  8b 14 01                mov    (%ecx,%eax,1),%edx ; Load argv[1] into EDX
401298:  52                      push   %edx             ; Push argv[1]
401299:  e8 4b 32 00 00          call   0x4044e9         ; Call atoi(argv[1])
40129e:  83 c4 04                add    $0x4,%esp        ; Adjust stack
4012a1:  89 45 fc                mov    %eax,-0x4(%ebp)  ; Store result in local variable

; Load second argument
4012a4:  b8 04 00 00 00          mov    $0x4,%eax        ; Set EAX = 4 (offset)
4012a9:  d1 e0                   shl    %eax             ; Shift left (multiply by 2)
4012ab:  8b 4d 0c                mov    0xc(%ebp),%ecx   ; Load pointer to argv[]
4012ae:  8b 14 01                mov    (%ecx,%eax,1),%edx ; Load argv[2] into EDX
4012b1:  52                      push   %edx             ; Push argv[2]
4012b2:  e8 32 32 00 00          call   0x4044e9         ; Call atoi(argv[2])
4012b7:  83 c4 04                add    $0x4,%esp        ; Adjust stack
4012ba:  89 45 f8                mov    %eax,-0x8(%ebp)  ; Store result in local variable

; Add both integers together
4012bd:  8b 45 fc                mov    -0x4(%ebp),%eax  ; Load first number
4012c0:  03 45 f8                add    -0x8(%ebp),%eax  ; Add second number
4012c3:  89 45 f4                mov    %eax,-0xc(%ebp)  ; Store sum in local variable

; Compare sum with 42
4012c6:  83 7d f4 2a             cmpl   $0x2a,-0xc(%ebp) ; Compare sum with 42
4012ca:  75 16                   jne    0x4012e2         ; Jump if sum != 42

; If sum == 42, print "You won!"
4012cc:  68 20 80 41 00          push   $0x418020        ; Push "You won!"
4012d1:  e8 7a 00 00 00          call   0x401350         ; Call printf()
4012d6:  83 c4 04                add    $0x4,%esp        ; Adjust stack
4012d9:  6a 00                   push   $0x0             ; Push exit code 0
4012db:  e8 f8 2e 00 00          call   0x4041d8         ; Call exit(0)
4012e0:  eb 14                   jmp    0x4012f6         ; Jump to exit

; If sum != 42, print "You lost!"
4012e2:  68 2c 80 41 00          push   $0x41802c        ; Push "You lost!"
4012e7:  e8 64 00 00 00          call   0x401350         ; Call printf()
4012ec:  83 c4 04                add    $0x4,%esp        ; Adjust stack
4012ef:  6a 01                   push   $0x1             ; Push exit code 1
4012f1:  e8 e2 2e 00 00          call   0x4041d8         ; Call exit(1)

; Final exit
4012f6:  6a 02                   push   $0x2             ; Push exit code 2
4012f8:  e8 db 2e 00 00          call   0x4041d8         ; Call exit(2)
4012fd:  8b e5                   mov    %ebp,%esp        ; Restore stack pointer
4012ff:  5d                      pop    %ebp             ; Restore old base pointer
```

---

### **📌 What This Means**
1. **Debugger Check (Anti-Debugging)**
   - Calls `IsDebuggerPresent()`, exits if a debugger is detected.
   
2. **Command-Line Argument Check**
   - Requires **exactly two arguments** (`argc == 3`).
   - If not, it exits.

3. **Processing User Input**
   - Converts `argv[1]` and `argv[2]` to integers using `atoi()`.
   - Adds them together.

4. **Winning Condition**
   - If `sum == 42`, it prints **"You won!"** and exits successfully.
   - Otherwise, it prints **"You lost!"**.

---

### **🚀 Next Step**
✅ **Now that we understand the logic, let's test it!**  
**Run the program with numbers that add to 42 and report back:**  
```bash
crackme3.exe 20 22
```
If it prints **"You won!"**, we’ve successfully solved Crackme3! 🎯  

Let me know what happens! 🚀
