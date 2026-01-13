# JM-CompanyAuthService

Authentication and Authorization service for company accounts in the Job Manager platform.

## Overview

The Company Auth Service handles all authentication-related operations for company accounts, including registration, login, password management, and JWT token generation/validation. It serves as the security gateway for company-facing services.

## Features

- **User Registration**: Create new company accounts with email verification
- **Authentication**: Secure login with JWT token generation
- **Password Management**: Hashing with BCrypt, password reset functionality
- **Token Management**: JWE (JSON Web Encryption) token generation and validation
- **SSO Support**: Single Sign-On token management
- **Account Activation**: Email-based account activation flow

## Tech Stack

- **Java 17+**
- **Spring Boot 3.x**
- **Spring Security**: Authentication and authorization
- **Spring Data JPA**: Database persistence
- **PostgreSQL**: Primary database
- **Kafka**: Event-driven communication
- **JWE (JSON Web Encryption)**: Secure token management
- **BCrypt**: Password hashing
- **Lombok**: Reduce boilerplate code

## Prerequisites

- Java 17 or higher
- Maven 3.8+
- PostgreSQL database
- Kafka broker (for event publishing)
- RSA key pair for JWE encryption

## Database Schema

### Table: `company_auth`

| Column            | Type      | Description                     |
| ----------------- | --------- | ------------------------------- |
| `company_id`      | UUID (PK) | Unique company identifier       |
| `email`           | VARCHAR   | Company email (unique)          |
| `hashed_password` | VARCHAR   | BCrypt hashed password          |
| `sso_token`       | VARCHAR   | Single Sign-On token (nullable) |
| `is_activated`    | BOOLEAN   | Account activation status       |
| `created_at`      | TIMESTAMP | Account creation timestamp      |
| `updated_at`      | TIMESTAMP | Last update timestamp           |

## Data Seeding

The service automatically seeds 4 company accounts on startup:

### Freemium Companies (2)

1. **NAB (National Australia Bank)**

   - Email: `nab@gmail.com`
   - Password: `SecuredPass123!!`
   - Status: Expired subscription

2. **Google Vietnam**
   - Email: `google@gmail.com`
   - Password: `SecuredPass123!!`
   - Status: Cancelled subscription

### Premium Companies (2)

3. **Netcompany**

   - Email: `netcompany@gmail.com`
   - Password: `SecuredPass123!`
   - Status: Active subscription
   - Focus: Software Engineering

4. **Shopee Singapore**
   - Email: `shopee@gmail.com`
   - Password: `SecuredPass123!`
   - Status: Active subscription
   - Focus: Data Engineering

> **Note**: UUIDs are predefined to maintain consistency across microservices. The entity has `@GeneratedValue` commented out to support manual UUID assignment.
