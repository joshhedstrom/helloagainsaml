# helloAgainSAML

This is a hello world utilizing SAML 2.0

### Prerequisites

To run this project, you will need Maven 3.2.5 and JDK 1.6. You also need to have made an account on [SSOCircle](https://idp.ssocircle.com/sso/UI/Login)

If you don't know what version of Maven you have installed, run
```
$ mvn --version
```

Maven 3.2.5 can be downloaded from [https://archive.apache.org/dist/maven/maven-3/3.2.5/](https://archive.apache.org/dist/maven/maven-3/3.2.5/)

### Installing and Running the Application

To get the app up and running, first update the certificate from SSO Circle
```
$ cd src/main/resources/saml/ && ./update-certificate.sh && cd ../../../../
```

The package up the app with Maven
```
$ mvn clean package -e
```

And then run the app
```
$ java -jar target/helloagainsaml-2.0.1-SNAPSHOT.jar
```

## Built With

* [Java 6](https://www.oracle.com/technetwork/java/javase/downloads/java-archive-downloads-javase6-419409.html)
* [Spring Boot(https://spring.io/projects/spring-boot)
* [Spring Security](https://spring.io/projects/spring-security)
* [SAML 2.0](http://saml.xml.org/saml-specifications)
* [Maven](https://maven.apache.org/)
* [Thymeleaf](https://www.thymeleaf.org/documentation.html)

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* Initially based off of [https://github.com/vdenotaris/spring-boot-security-saml-sample](https://github.com/vdenotaris/spring-boot-security-saml-sample)
