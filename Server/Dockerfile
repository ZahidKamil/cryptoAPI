# Stage 1: Build stage
FROM alpine:latest AS build

# Install build dependencies
RUN apk add --no-cache build-base gcc

# Set the working directory
WORKDIR /app

# Copy the source files
COPY server.c .

# Compile the server application
RUN gcc -o server server.c

# Stage 2: Runtime stage
FROM alpine:latest

# Set the working directory
WORKDIR /app

# Copy the compiled server binary from the build stage
COPY --from=build /app/server /app/server

# Set the entry point for the container
ENTRYPOINT ["./server"]
