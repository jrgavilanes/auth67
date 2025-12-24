# 🔐 Auth67 - JWT Authentication Service

![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.9-green) ![Java](https://img.shields.io/badge/Java-21-orange) ![Security](https://img.shields.io/badge/JWT-Secure-blue) ![License](https://img.shields.io/badge/License-MIT-lightgrey)

**Auth67** is a robust authentication and authorization microservice built with Spring Boot 3. It implements a modern security architecture based on **JWT (JSON Web Tokens)** featuring role-based access control, token refreshing, and account locking mechanisms.

---

## 🚀 Main Features

*   **Stateless Authentication:** Session management using JWT (Access Token + Refresh Token).
*   **Role-Based Access Control (RBAC):**
    *   `ROLE_ADMIN`: User management and registration.
    *   `ROLE_USER`: Default role for standard users.
*   **Hardened Security:**
    *   Passwords encrypted with BCrypt.
    *   Global Exception Handling with unified error responses.
    *   Protection against locked/banned accounts.
*   **Lightweight Database:** Integrated SQLite for quick and easy deployment (easily migratable to PostgreSQL/MySQL).
*   **Validation:** Strict input data control using Jakarta Validation on DTOs.

---

## 🛠️ Technology Stack

*   **Core:** Java 21, Spring Boot 3.5.9
*   **Security:** Spring Security, JJWT (Java JWT)
*   **Persistence:** Spring Data JPA, Hibernate, SQLite
*   **Testing:** JUnit 5, MockMvc
*   **Tools:** Gradle, Lombok

---

## ⚙️ Configuration

The project is auto-configured with sensible defaults, but you can customize them in `src/main/resources/application.properties`.

### Key Properties
| Property | Description | Default Value |
| :--- | :--- | :--- |
| `application.security.jwt.expiration` | Access Token lifetime (ms) | `300000` (5 min) |
| `application.security.jwt.refresh-token.expiration` | Refresh Token lifetime (ms) | `86400000` (24 h) |
| `application.security.admin.username` | Initial Admin Username | `admin` |
| `application.security.admin.password` | Initial Admin Password | `admin123` |

---

## 🏃‍♂️ How to Run

### Prerequisites
*   Java 21 installed.

### Commands
1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-user/auth67.git
    cd auth67
    ```

2.  **Run the application:**
    ```bash
    ./gradlew bootRun
    ```
    *An ADMIN user is automatically created on startup if it doesn't exist.*

3.  **Run tests:**
    ```bash
    ./gradlew test
    ```

---

## 🔌 API Endpoints

### 🔓 Public Endpoints
*   `POST /api/auth/login`: Authenticate and get tokens.
    *   **Body:** `{"username": "...", "password": "..."}`
    *   **Response:** `access_token`, `refresh_token`.

### 🔒 Secured Endpoints (Require `Authorization: Bearer <token>` header)

*   `POST /api/auth/refresh-token`: Get a new access token.
    *   **Body:** `{"refresh_token": "..."}`
*   `POST /api/auth/logout`: Log out (Client should remove tokens locally).

### 👮 Admin Only (`ROLE_ADMIN`)

*   `POST /api/auth/register`: Register new users.
    *   **Body:** `{"username": "...", "password": "...", "roles": ["ROLE_USER"]}`

---

## 🛡️ Error Handling

The API returns structured error responses for all exceptions:

```json
{
  "timestamp": "2025-12-24T12:00:00",
  "status": 403,
  "error": "Access Denied",
  "message": "You do not have permission to access this resource",
  "path": "/api/auth/register"
}
```

---

Made with ❤️ by **janrax**.