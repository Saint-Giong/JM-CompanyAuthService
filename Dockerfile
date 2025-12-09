# APPLICATION BUILD
FROM eclipse-temurin:17-jdk AS builder
WORKDIR /app

# Maven runner
COPY mvnw .
COPY .mvn .mvn

# Dependency
COPY pom.xml ./pom.xml
COPY CompanyAuthApi/pom.xml ./CompanyAuthApi/pom.xml
COPY CompanyAuthService/pom.xml ./CompanyAuthService/pom.xml

# COPY settings.xml .
# RUN --mount=type=secret,id=github-username,env=GITHUB_USERNAME,required=true \
#   --mount=type=secret,id=github-token,env=GITHUB_TOKEN,required=true \
#   --mount=type=cache,target=/root/.m2 \
#   cp ./settings.xml /root/.m2 && \
#   ./mvnw dependency:go-offline -U

RUN ./mvnw dependency:go-offline -U

# Copy the full source code
COPY CompanyAuthApi/src ./CompanyAuthApi/src
COPY CompanyAuthService/src ./CompanyAuthService/src

# Build the Spring Boot application
RUN ./mvnw clean package -DskipTests

# Application Run
FROM eclipse-temurin:17-jdk AS runner

## Add a non-root user for security
#RUN addgroup -S spring && adduser -S spring -G spring
#USER spring:spring

WORKDIR /app

# Copy the built jar from the builder stage
COPY --from=builder /app/CompanyAuthService/target/*.jar app.jar

# Expose the default Spring Boot port (you can override in compose)
EXPOSE 8080

# Run the application
ENTRYPOINT ["java","-jar","/app/app.jar"]