
## 🎯 Static Application Security Testing (SAST) Violation
<div align='center'>

| Severity                | ID                  | Finding                  | Watch Name                  | Policies                  |
| :---------------------: | :-----------------------------------: | :-----------------------------------: | :-----------------------------------: | :-----------------------------------: |
| ![low](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableLowSeverity.png)<br>     Low | sast-violation-id | Found a Use of Insecure Random | jas-watch | policy1<br>policy2 |
| ![high](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | sast-violation-id-2 | Found a Use of Insecure Random | jas-watch2 | policy3 |
| ![high](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | sast-violation-id-3 | Found An Express Not Using Helmet | jas-watch2 | policy3 |

</div>


<details><summary><b>[ Express Not Using Helmet ]</b></summary>

### Violation Details
|                 |                   |
| --------------------- | :-----------------------------------: |
| **Rule ID:** | js-express-without-helmet |

Scanner Description....

<br></details>
<details><summary><b>[ Use of Insecure Random ]</b></summary>

### Violation Details
|                 |                   |
| --------------------- | :-----------------------------------: |
| **CWE:** | CWE-798<br>CWE-799 |
| **Rule ID:** | js-insecure-random |

Scanner Description....


<details><summary><b>Code Flows</b></summary>
<details><summary><b>Vulnerable data flow analysis result</b></summary>

↘️ `other-snippet` (at file2 line 1)

↘️ `snippet` (at file line 0)
<br></details>
<details><summary><b>Vulnerable data flow analysis result</b></summary>

↘️ `a-snippet` (at file line 10)

↘️ `snippet` (at file line 0)
<br></details><br></details><br></details>