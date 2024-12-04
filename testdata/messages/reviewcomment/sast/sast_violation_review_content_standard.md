
## 🎯 Static Application Security Testing (SAST) Violation
<div align='center'>

| Severity                | ID                  | Finding                  |
| :---------------------: | :-----------------------------------: |:-----------------------------------: |
| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableLowSeverity.png)<br>     Low | VIOLATION_ID | Stack Trace Exposure |

</div>

<details id="violation2">
<summary><b>Full description</b></summary>

### Violation Details
|  |  |
| :--- | :--- |
__Policies:__| xsc-policy-1
__Watch Name:__| xsc-watch
__CWE:__| CWE-89
__Rule ID:__| java-sql-injection


### Overview
Stack trace exposure is a type of security vulnerability that occurs when a program reveals
sensitive information, such as the names and locations of internal files and variables,
in error messages or other diagnostic output. This can happen when a program crashes or
encounters an error, and the stack trace (a record of the program's call stack at the time
of the error) is included in the output.

</details>

<details>
<summary> <b>Code Flows</b> </summary>
<br>


<details>
<summary> <b>Vulnerable data flow analysis result</b> </summary>
<br>


↘️ `other-snippet` (at file2 line 1)

↘️ `snippet` (at file line 0)


</details>

<details>
<summary> <b>Vulnerable data flow analysis result</b> </summary>
<br>


↘️ `a-snippet` (at file line 10)

↘️ `snippet` (at file line 0)


</details>


</details>
