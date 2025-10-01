#!/bin/sh
pg_isready -U user -d pki || exit 1
pg_isready -U user -d keycloak || exit 1