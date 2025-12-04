# APPLICATION BUILD
ARG MODULE_ORIGIN=CompanyAuth
FROM eclipse-temurin:21-jdk-alpine AS builder
WORKDIR /app
ARG MODULE_ORIGIN

# Maven runner
COPY mvnw .
COPY .mvn .mvn

# Dependency
COPY pom.xml .
COPY ${MODULE_ORIGIN}Api/pom.xml ${MODULE_ORIGIN}Api/pom.xml
COPY ${MODULE_ORIGIN}Service/pom.xml ${MODULE_ORIGIN}Service/pom.xml

# COPY settings.xml .

# RUN --mount=type=secret,id=github-username,env=GITHUB_USERNAME,required=true \
#   --mount=type=secret,id=github-token,env=GITHUB_TOKEN,required=true \
#   --mount=type=cache,target=/root/.m2 \
#   cp ./settings.xml /root/.m2 && \
#   ./mvnw dependency:go-offline -U

RUN ./mvnw dependency:go-offline -U

# Copy the full source code
COPY ${MODULE_ORIGIN}Api/src ${MODULE_ORIGIN}Api/src
COPY ${MODULE_ORIGIN}Service/src ${MODULE_ORIGIN}Service/src

# Build the Spring Boot application
RUN ./mvnw clean package -DskipTests

# Application Run
FROM eclipse-temurin:21-jre-alpine AS runner
ARG MODULE_ORIGIN

# Add a non-root user for security
RUN addgroup -S spring && adduser -S spring -G spring
USER spring:spring

WORKDIR /app

# Copy the built jar from the builder stage
COPY --from=builder /app/${MODULE_ORIGIN}Service/target/*.jar app.jar

# Expose the default Spring Boot port (you can override in compose)
EXPOSE 8080

# Run the application
ENTRYPOINT ["java","-jar","/app/app.jar"]