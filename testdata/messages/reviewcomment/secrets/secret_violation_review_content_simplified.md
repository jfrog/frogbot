

---
## 🤫 Secret Violation

---
| Severity                | ID                  | Token Validation                  | Token Info                  | Origin                  | Finding                  | Watch Name                  | Policies                  |
| :---------------------: | :-----------------------------------: | :-----------------------------------: | :-----------------------------------: | :-----------------------------------: | :-----------------------------------: | :-----------------------------------: | :-----------------------------------: |
| High | secret-violation-id | Active | The token was validated and found to be active. This indicates that the secret is currently in use. | JFrog | Secret keys were found | jas-watch | policy1 |
| Critical | secret-violation-id-2 | Inactive | The token was validated and found to be inactive. This indicates that the secret is no longer in use. | JFrog | Secret keys were found | jas-watch2 | policy1, policy2 |


---
### Full description

---



---
### Violation Details

---
|                 |                   |
| --------------------- | :-----------------------------------: |
| **CWE:** | CWE-798, CWE-799 |
| **Abbreviation:** | rule-id |

Scanner Description....

