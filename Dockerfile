FROM golang:1.13-alpine as builder

# Setup
RUN mkdir -p /go/src/github.com/pnocera/oidc-forwardauth
WORKDIR /go/src/github.com/pnocera/oidc-forwardauth

# Add libraries
RUN apk add --no-cache git

# Copy & build
ADD . /go/src/github.com/pnocera/oidc-forwardauth/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -installsuffix nocgo -o /oidc-forwardauth github.com/pnocera/oidc-forwardauth/cmd

# Copy into scratch container
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /oidc-forwardauth ./
ENTRYPOINT ["./oidc-forwardauth"]
