# SecureQA Sentinel — frontend (React/Vite) image
# Place this file at: secureqa-sentinel/frontend/Dockerfile

# ---- Build stage ----
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .

# Vite env vars are baked in AT BUILD TIME, not runtime — this is the backend
# URL the BROWSER will call, so it must be the host-mapped port (localhost:5000),
# not the docker-compose service name "backend" (browsers can't resolve that).
ARG VITE_API_URL=http://localhost:5000
ENV VITE_API_URL=$VITE_API_URL
RUN npm run build

# ---- Serve stage ----
FROM nginx:alpine AS serve
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.frontend.conf /etc/nginx/conf.d/default.conf
EXPOSE 80