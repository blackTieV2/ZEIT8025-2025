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
