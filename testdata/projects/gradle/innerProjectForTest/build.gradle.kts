// This file is used for several tests including text comparisons. Please DO NOT change its content
// If you do change it make sure all Gradle packagehandler related tests in packagehandlers_test.go doesn't break
val spi: Configuration by configurations.creating

dependencies {
    // This repeated dependency is required in order to check 'create-fix' captures all formats of direct dependencies
    runtimeOnly('junit:junit:4.7')
    runtimeOnly("junit:junit:4.7")
    runtimeOnly('junit:junit:4.7:javadoc')
    runtimeOnly("junit:junit:4.7") {
        isTransitive = true
    }

    runtimeOnly(group = 'junit', name = 'junit', version = '4.7')
    runtimeOnly(group = "junit", name = "junit", version = "4.7")
    runtimeOnly(group = 'junit', name = 'junit', version = '4.7', classifier = 'javadoc')
    runtimeOnly(group = 'junit', name = 'junit', version = '4.7') {
        isTransitive = true
    }
    runtimeOnly(group = "junit", name = "junit",
            version = "4.7")

    runtimeOnly("my.group:my.dot.name:1.0.0-beta.test")
    runtimeOnly(group = 'my.group', name = 'my.dot.name', version = '1.0.0-beta.test')

    // This dependencies should not be changed
    runtimeOnly('junit:junit:5.7')
    runtimeOnly('junit2:junit2:4.7')

    // This repeated dependency is required to check that 'create-fix' doesn't fix lines with unsupported-version fix
    // When the package was found as vulnerable by xRay and fix is applicable somewhere else in the build file
    runtimeOnly(group = 'commons-io', name = 'commons-io', version = '1.+')
    runtimeOnly(group = 'commons-io', name = 'commons-io', version = '[1.1, 3.5)')
    runtimeOnly('commons-io:commons-io:latest.release')
}
