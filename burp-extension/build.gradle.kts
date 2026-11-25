// Optional Gradle build (IDE support). ./build.sh builds the same jar without Gradle.
plugins {
    java
}

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.7")
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

tasks.jar {
    archiveFileName.set("ptreport-burp.jar")
}
