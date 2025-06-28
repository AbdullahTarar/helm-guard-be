
# HelmGuard Backend

## 🛡️ Overview

**HelmGuard Backend** is the backend service for [HelmGuard](https://github.com/AbdullahTarar/helm-guard), a tool designed to analyze Helm charts for:
- **Security vulnerabilities**
- **Resource prediction** (what Kubernetes resources will be created)
- **Best practices validation**

It helps DevOps teams improve deployment safety and maintain compliance across environments by auditing Helm charts before deployment.

## 📑 Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
- [Configuration](#configuration)
- [Contributing](#contributing)
- [License](#license)

## 🚀 Features

- Detects **security vulnerabilities** in Helm charts
- Lists **Kubernetes resources** that will be created
- Reports **violated and followed best practices**
- Easy-to-use REST API backend
- Modular and scalable architecture in Go

## 🧰 Installation

### Requirements

- [Go 1.18+](https://golang.org/dl/)
- Git

### Clone the Repo

```bash
git clone https://github.com/AbdullahTarar/helm-guard-be.git
cd helm-guard-be
```

## 🧪 Usage

To run the server:

```bash
go run main.go
```

For development, ensure Go modules are installed:

```bash
go mod tidy
```

Then you can make HTTP requests to the API endpoints (e.g., via Postman or `curl`) to analyze Helm charts.

## 📬 API Endpoints

### `POST /api/scan/public`
Scans a public Helm chart repository for vulnerabilities, best practices, and resource predictions.

### `POST /api/scan/private`
Scans a private Helm chart repository. Authentication via GitHub is required.

### `GET /api/scan/results/{id}`
Fetches the results of a scan using the provided scan ID.

### `GET /api/github/auth`
Initiates the OAuth process for GitHub login.

### `GET /api/github/callback`
Callback endpoint for GitHub OAuth after user authorization.

### `GET /api/github/repos`
Retrieves the authenticated user's GitHub repositories.

### `GET /api/auth/status`
Checks the current authentication status of the user.

## ⚙️ Configuration

Some configuration may be done via `.env` or internal config files. If present, ensure to:

```bash
cp .env.example .env
# edit values as necessary
```

## 👨‍💻 Contributing

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/fooBar`)
3. Commit your changes (`git commit -am 'Add some fooBar'`)
4. Push to the branch (`git push origin feature/fooBar`)
5. Create a new Pull Request

