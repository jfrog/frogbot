

---
## 🎯 Static Application Security Testing (SAST) Vulnerability

---
| Severity                | Finding                  |
| :---------------------: | :-----------------------------------: |
| Low | Stack Trace Exposure |

---
### Full description

---

### Overview
Stack trace exposure is a type of security vulnerability that occurs when a program reveals
sensitive information, such as the names and locations of internal files and variables,
in error messages or other diagnostic output. This can happen when a program crashes or
encounters an error, and the stack trace (a record of the program's call stack at the time
of the error) is included in the output.

---
### Code Flows

---


---
#### Vulnerable data flow analysis result

---

↘️ `other-snippet` (at file2 line 1)

↘️ `snippet` (at file line 0)


---
#### Vulnerable data flow analysis result

---

↘️ `a-snippet` (at file line 10)

↘️ `snippet` (at file line 0)
