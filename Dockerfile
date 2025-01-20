FROM golang:1.22 as builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

# Build the Go application using build-time arguments
# to specify the target OS and architecture run "docker build --build-arg GOOS=linux --build-arg GOARCH=amd64 ."
ARG GOOS=linux
ARG GOARCH=amd64
RUN CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -o main .

FROM scratch

# Use a non-root user with UID 10001 for security
USER 10001

COPY --from=builder /app/main /main

EXPOSE 8080

ENTRYPOINT ["/main"]