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
