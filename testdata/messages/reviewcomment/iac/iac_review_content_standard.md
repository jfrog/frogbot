
## 🛠️ Infrastructure as Code Vulnerability
<div align='center'>

| Severity                | Finding                  |
| :---------------------: | :-----------------------------------: |
| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableMediumSeverity.png)<br>  Medium | Missing auto upgrade was detected |

</div>

<details>
<summary> <b>Full description</b> </summary>
<br>

Resource `google_container_node_pool` should have `management.auto_upgrade=true`

Vulnerable example - 
```
resource "google_container_node_pool" "vulnerable_example" {
    management {
     auto_upgrade = false
   }
}
```


</details>
