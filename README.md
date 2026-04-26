# 🚀 Zenith Cloud - Secure Backend System

A robust and scalable backend architecture built with **NestJS**, **Prisma**, and **PostgreSQL (Neon)**. This system implements industry-standard security practices including **JWT Authentication** and **Bcrypt** password hashing.

---

## 🛠️ Quick Start Guide (For Collaborators)

Follow these steps to set up the environment on your local machine:

### 1. Clone the Repository
```bash
git clone [YOUR_REPOSITORY_URL]
cd zenith
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Environment Configuration
* Create a file named `.env` in the root directory.
* Copy the structure from `.env.example` into your new `.env` file.
* Contact **Radouane** to get the actual values for `DATABASE_URL` and `JWT_SECRET`.

### 4. Database Synchronization
Generate the Prisma client to sync with the Neon database schema:
```bash
npx prisma generate
```

### 5. Run the Application
```bash
# Development mode
npm run start:dev
```

---

## 🔒 Security & Architecture
* **Environment Protection:** The `.env` file is strictly ignored by Git to prevent sensitive credential leaks.
* **Authentication:** Stateless authentication using JSON Web Tokens (JWT).
* **Database:** Powered by Prisma ORM for type-safe database queries and migrations.

---
**Developed by:** Radouane Djoudi
