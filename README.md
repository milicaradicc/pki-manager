# PKI Management System

**Course:** Information Security, SIIT 2025  
**Project Type:** Web Application / PKI Management  

---

## Project Overview
This project implements a **Public Key Infrastructure (PKI) management system** for issuing, storing, and revoking digital certificates. It supports multiple user roles and enforces secure communication and access control. The system allows administrators and CA users to manage certificates across organizations, while regular users can generate, upload, and download certificates safely.

---

## User Roles & Permissions

### Administrator
- Add new CA users
- Add CA certificates for organizations
- Issue all types of certificates: Root, Intermediate, End-Entity (EE)
- View, download, and revoke any certificate

### CA User
- Issue Intermediate and End-Entity certificates for their organization
- View and download certificates in their chain
- Create and use certificate templates

### Regular User
- Upload CSR and private key or generate keys and certificates via form
- Choose CA certificate for issuance
- Download certificates and private keys
- View personal certificates
- Revoke certificates with reason (X.509 standard)

---

## Key Functionalities
- **Registration & Login:** Secure registration with email verification; login with JWT access and refresh tokens.
- **Certificate Issuance:** Supports Root, Intermediate, and End-Entity certificates with X.500 name data, extensions, and validity checks.
- **Certificate Storage:** Encrypted private keys; per-organization encryption; secure storage of all certificates.
- **Certificate Download:** Certificates packaged in
