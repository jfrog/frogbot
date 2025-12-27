# Maven Package Handler - Test Cases & Limitations

## Test Repository
https://github.com/eyalk007/maven-test-repo

## Supported Features

### ✅ Test Case 1: Simple Vulnerable Dependency
**File:** `backend/pom.xml`
```xml
<dependency>
    <groupId>commons-collections</groupId>
    <artifactId>commons-collections</artifactId>
    <version>3.2.1</version>
</dependency>
```
**Result:** ✅ Updates version directly in `<version>` tag

---

### ✅ Test Case 2: Property-Based Version
**File:** `frontend/pom.xml`
```xml
<properties>
    <jackson.version>2.9.8</jackson.version>
</properties>
<dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
    <version>${jackson.version}</version>
</dependency>
```
**Result:** ✅ Updates property value in `<properties>` section

---

### ❌ Test Case 3: Parent POM Version (ENGINE LIMITATION)
**File:** `pom.xml`
```xml
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.5.0</version>
</parent>
```
**Result:** ❌ **ENGINE LIMITATION** - SBOM generator cannot resolve versions inherited from external parent POMs without running Maven CLI. Shows `version: unknown` in SBOM.

**Handler Support:** ✅ Handler CAN update parent versions (text-based replacement works)  
**Engine Support:** ❌ Engine does not detect vulnerabilities in external parent POMs

---

### ✅ Test Case 4: DependencyManagement
**File:** `pom.xml`
```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>commons-fileupload</groupId>
            <artifactId>commons-fileupload</artifactId>
            <version>1.3.1</version>
        </dependency>
    </dependencies>
</dependencyManagement>
```
**Result:** ✅ Updates version in `<dependencyManagement>` section

---

### ✅ Test Case 5: Multi-Module Maven Project
**Structure:**
```
root/pom.xml (aggregator)
backend/pom.xml (commons-collections:3.2.1)
frontend/pom.xml (commons-collections:3.2.1)
```
**Result:** ✅ Creates ONE PR updating BOTH modules  
**Engine Behavior:** Returns 2 `ComponentRow` entries with different `Location.File` values

---

## Known Limitations

### 1. Non-Standard POM Names (ENGINE LIMITATION)
**Pattern:** `pom-dev.xml`, `pom-prod.xml`, `pom-test.xml`

**Renovate/Dependabot:** ✅ Support via regex `/(^|/|\.)pom\.xml$/`  
**JFrog Engine:** ❌ Only scans standard `pom.xml` files

**Test:** Added `pom-dev.xml` with `log4j:1.2.17` to test repo  
**Result:** Not detected in SBOM

**Handler Support:** ✅ Handler would work if engine provided the file path  
**Engine Support:** ❌ Engine does not scan non-standard pom names

**Impact:** Projects using environment-specific POMs (common practice) won't have those files scanned

---

### 2. Indirect Dependencies
**Status:** ❌ Not supported (by design)

Maven does not support forcing transitive dependency versions without declaring them directly (unlike npm's `resolutions`).

**Workaround:** Users must add direct dependency declarations

---

### 3. Settings.xml & Extensions.xml
**Files:** `settings.xml`, `.mvn/extensions.xml`

**Renovate:** Scans these files  
**Frogbot:** ❌ Not needed - these are configuration files, not dependency manifests

**Reason:** SBOM generator only reports runtime dependencies from `pom.xml`, not build-time config

---

## Implementation Details

### Text-Based Replacement
The handler uses **text-based replacement** (like Renovate/Dependabot) instead of XML unmarshal/marshal:

1. **Parse XML** to understand structure (`encoding/xml`)
2. **Use regex** to replace ONLY the version text
3. **Preserves** all formatting, namespaces, comments, blank lines

**Result:** Minimal diffs - only version numbers change

### Multi-Module Support
- Loops through all `Component.Location.File` paths
- Updates each `pom.xml` independently
- All changes go into ONE pull request

---

## Recommendations for Engine Team

1. **Support non-standard POM names** - Scan files matching `/(^|/|\.)pom\.xml$/`
2. **Resolve parent POM versions** - Download and parse external parent POMs to get inherited versions
3. **Document limitations** - Clearly state what Maven patterns are supported

---

## Testing Checklist

- [x] Simple dependency update
- [x] Property-based version update
- [x] Parent POM update (handler works, engine limitation)
- [x] DependencyManagement update
- [x] Multi-module project (multiple files in one PR)
- [x] Indirect dependency rejection
- [x] Non-standard pom names (engine limitation documented)
- [x] Formatting preservation (text-based replacement)
- [x] All tests pass

