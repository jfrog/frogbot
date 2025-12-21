
## 🤫 Secret Violation
<div align='center'>

| Severity                | ID                  | Token Validation                  | Token Info                  | Origin                  | Finding                  | Watch Name                  | Policies                  |
| :---------------------: | :-----------------------------------: | :-----------------------------------: | :-----------------------------------: | :-----------------------------------: | :-----------------------------------: | :-----------------------------------: | :-----------------------------------: |
| ![high](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | secret-violation-id | Active | The token was validated and found to be active. This indicates that the secret is currently in use. | JFrog | Secret keys were found | jas-watch | policy1 |
| ![critical (not applicable)](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/notApplicableCritical.png)<br>Critical | secret-violation-id-2 | Inactive | The token was validated and found to be inactive. This indicates that the secret is no longer in use. | JFrog | Secret keys were found | jas-watch2 | policy1<br>policy2 |

</div>


<details><summary><b>Full description</b></summary>

### Violation Details
|                 |                   |
| --------------------- | :-----------------------------------: |
| **CWE:** | CWE-798<br>CWE-799 |
| **Abbreviation:** | rule-id |

Scanner Description....

<br></details>