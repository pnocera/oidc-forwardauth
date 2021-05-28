FROM golang:alpine as builder

RUN apk update && apk add --no-cache git ca-certificates tzdata && update-ca-certificates

ENV USER=appuser
ENV UID=10001

RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    "${USER}"

# Setup
RUN mkdir -p /go/src/github.com/pnocera/oidc-forwardauth
WORKDIR /go/src/github.com/pnocera/oidc-forwardauth


# Copy
ADD . /go/src/github.com/pnocera/oidc-forwardauth/

# Fetch dependencies.
# RUN go get -d -v

# build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build \
    -ldflags='-w -s -extldflags "-static"' -a -installsuffix nocgo -o /oidc-forwardauth github.com/pnocera/oidc-forwardauth/cmd

# Copy into scratch container
FROM scratch
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

COPY --from=builder /oidc-forwardauth ./

# Use an unprivileged user.
USER appuser:appuser

ENTRYPOINT ["./oidc-forwardauth"]
