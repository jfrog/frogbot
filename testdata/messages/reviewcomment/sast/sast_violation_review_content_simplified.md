

---
## 🎯 Static Application Security Testing (SAST) Violation

---
| Severity                | ID                  | Finding                  | Watch Name                  | Policies                  |
| :---------------------: | :-----------------------------------: | :-----------------------------------: | :-----------------------------------: | :-----------------------------------: |
| Low | sast-violation-id | Found a Use of Insecure Random | jas-watch | policy1, policy2 |
| High | sast-violation-id-2 | Found a Use of Insecure Random | jas-watch2 | policy3 |
| High | sast-violation-id-3 | Found An Express Not Using Helmet | jas-watch2 | policy3 |


---
### [ Express Not Using Helmet ]

---



---
### Violation Details

---
|                 |                   |
| --------------------- | :-----------------------------------: |
| **Rule ID:** | js-express-without-helmet |

Scanner Description....



---
### [ Use of Insecure Random ]

---



---
### Violation Details

---
|                 |                   |
| --------------------- | :-----------------------------------: |
| **CWE:** | CWE-798, CWE-799 |
| **Rule ID:** | js-insecure-random |

Scanner Description....



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
